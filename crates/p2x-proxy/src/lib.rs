//! Bounded opaque-byte tunnelling for futures and Tokio I/O streams.

use futures::{
    future::poll_fn,
    io::{AsyncRead, AsyncWrite},
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::sync::watch;

pub const MIN_COPY_BUFFER: usize = 4 * 1024;
pub const MAX_COPY_BUFFER: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    Complete,
    IdleTimeout,
    Cancelled,
    LocalIo,
    RemoteIo,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PumpResult {
    pub local_to_remote_bytes: u64,
    pub remote_to_local_bytes: u64,
    pub local_eof: bool,
    pub remote_eof: bool,
    pub duration: Duration,
    pub terminal: Terminal,
}

/// A bounded prefix is read before the wrapped I/O object and is then discarded.
/// The prefix is owned by this adapter, so no application byte can be sent before
/// the caller explicitly starts the tunnel.
pub struct PrefixedIo<T> {
    prefix: io::Cursor<Vec<u8>>,
    inner: T,
}
impl<T> PrefixedIo<T> {
    pub fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix: io::Cursor::new(prefix),
            inner,
        }
    }
    pub fn into_inner(self) -> T {
        self.inner
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for PrefixedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let position = self.prefix.position() as usize;
        if position < self.prefix.get_ref().len() {
            let available = self.prefix.get_ref().len() - position;
            let count = available.min(buf.len());
            buf[..count].copy_from_slice(&self.prefix.get_ref()[position..position + count]);
            self.prefix.set_position((position + count) as u64);
            return Poll::Ready(Ok(count));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for PrefixedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

fn valid_buffer(buffer_size: usize) -> io::Result<()> {
    if (MIN_COPY_BUFFER..=MAX_COPY_BUFFER).contains(&buffer_size) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "copy buffer is out of bounds",
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectionPhase {
    Read,
    Write,
    Close,
    Done,
}

struct Direction {
    buffer: Vec<u8>,
    filled: usize,
    offset: usize,
    bytes: u64,
    eof: bool,
    phase: DirectionPhase,
}

impl Direction {
    fn new(buffer_size: usize) -> Self {
        Self {
            buffer: vec![0; buffer_size],
            filled: 0,
            offset: 0,
            bytes: 0,
            eof: false,
            phase: DirectionPhase::Read,
        }
    }
}

fn poll_direction<R, W>(
    cx: &mut Context<'_>,
    reader: Pin<&mut R>,
    writer: Pin<&mut W>,
    direction: &mut Direction,
    activity: &watch::Sender<Instant>,
    terminal: Terminal,
) -> Poll<Result<bool, Terminal>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match direction.phase {
        DirectionPhase::Read => match reader.poll_read(cx, &mut direction.buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(terminal)),
            Poll::Ready(Ok(0)) => {
                direction.eof = true;
                direction.phase = DirectionPhase::Close;
                Poll::Ready(Ok(true))
            }
            Poll::Ready(Ok(count)) => {
                direction.filled = count;
                direction.offset = 0;
                direction.phase = DirectionPhase::Write;
                Poll::Ready(Ok(true))
            }
        },
        DirectionPhase::Write => {
            match writer.poll_write(cx, &direction.buffer[direction.offset..direction.filled]) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(_)) => Poll::Ready(Err(terminal)),
                Poll::Ready(Ok(0)) => Poll::Ready(Err(terminal)),
                Poll::Ready(Ok(count)) => {
                    direction.offset += count;
                    direction.bytes = direction.bytes.saturating_add(count as u64);
                    let _ = activity.send(Instant::now());
                    if direction.offset == direction.filled {
                        direction.filled = 0;
                        direction.offset = 0;
                        direction.phase = DirectionPhase::Read;
                    }
                    Poll::Ready(Ok(true))
                }
            }
        }
        DirectionPhase::Close => match writer.poll_close(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(terminal)),
            Poll::Ready(Ok(())) => {
                direction.phase = DirectionPhase::Done;
                Poll::Ready(Ok(true))
            }
        },
        DirectionPhase::Done => Poll::Ready(Ok(false)),
    }
}

const POLL_BUDGET: usize = 64;

fn poll_pump<L, R>(
    cx: &mut Context<'_>,
    local: &mut Pin<Box<L>>,
    remote: &mut Pin<Box<R>>,
    local_to_remote: &mut Direction,
    remote_to_local: &mut Direction,
    activity: &watch::Sender<Instant>,
) -> Poll<Result<(), Terminal>>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    for _ in 0..POLL_BUDGET {
        let mut progressed = false;
        match poll_direction(
            cx,
            local.as_mut(),
            remote.as_mut(),
            local_to_remote,
            activity,
            Terminal::LocalIo,
        ) {
            Poll::Pending => {}
            Poll::Ready(Ok(step)) => progressed |= step,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        }
        match poll_direction(
            cx,
            remote.as_mut(),
            local.as_mut(),
            remote_to_local,
            activity,
            Terminal::RemoteIo,
        ) {
            Poll::Pending => {}
            Poll::Ready(Ok(step)) => progressed |= step,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        }
        if local_to_remote.phase == DirectionPhase::Done
            && remote_to_local.phase == DirectionPhase::Done
        {
            return Poll::Ready(Ok(()));
        }
        if !progressed {
            return Poll::Pending;
        }
    }
    cx.waker().wake_by_ref();
    Poll::Pending
}

/// Copies both directions with one fixed buffer per direction and one shared idle timer.
pub async fn pump<L, R>(
    local: L,
    remote: R,
    buffer_size: usize,
    idle_timeout: Duration,
    cancel: impl std::future::Future<Output = ()> + Send,
) -> io::Result<PumpResult>
where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    valid_buffer(buffer_size)?;
    if idle_timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "idle timeout is zero",
        ));
    }
    pump_inner(local, remote, buffer_size, Some(idle_timeout), cancel).await
}

/// Copies both directions without a client-side idle deadline.
pub async fn pump_no_idle<L, R>(
    local: L,
    remote: R,
    buffer_size: usize,
    cancel: impl std::future::Future<Output = ()> + Send,
) -> io::Result<PumpResult>
where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    valid_buffer(buffer_size)?;
    pump_inner(local, remote, buffer_size, None, cancel).await
}

async fn pump_inner<L, R>(
    local: L,
    remote: R,
    buffer_size: usize,
    idle_timeout: Option<Duration>,
    cancel: impl std::future::Future<Output = ()> + Send,
) -> io::Result<PumpResult>
where
    L: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let started = Instant::now();
    let (activity_tx, mut activity_rx) = watch::channel(started);
    let mut local = Box::pin(local);
    let mut remote = Box::pin(remote);
    let mut local_to_remote = Direction::new(buffer_size);
    let mut remote_to_local = Direction::new(buffer_size);
    let mut cancel = Box::pin(cancel);
    let terminal = loop {
        if local_to_remote.phase == DirectionPhase::Done
            && remote_to_local.phase == DirectionPhase::Done
        {
            break Terminal::Complete;
        }
        let idle_enabled = idle_timeout.is_some();
        let deadline =
            tokio::time::sleep_until(tokio::time::Instant::from_std(idle_timeout.map_or(
                Instant::now() + Duration::from_secs(60 * 60 * 24 * 365),
                |timeout| *activity_rx.borrow() + timeout,
            )));
        tokio::pin!(deadline);
        let pump = poll_fn(|cx| {
            poll_pump(
                cx,
                &mut local,
                &mut remote,
                &mut local_to_remote,
                &mut remote_to_local,
                &activity_tx,
            )
        });
        tokio::pin!(pump);
        tokio::select! {
            result = &mut pump => {
                match result {
                    Ok(()) => break Terminal::Complete,
                    Err(terminal) => break terminal,
                }
            }
            _ = activity_rx.changed() => {}
            _ = &mut deadline, if idle_enabled => break Terminal::IdleTimeout,
            _ = &mut cancel => break Terminal::Cancelled,
        }
    };
    let local_to_remote_bytes = local_to_remote.bytes;
    let remote_to_local_bytes = remote_to_local.bytes;
    let local_eof = local_to_remote.eof;
    let remote_eof = remote_to_local.eof;
    Ok(PumpResult {
        local_to_remote_bytes,
        remote_to_local_bytes,
        local_eof,
        remote_eof,
        duration: started.elapsed(),
        terminal,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::AsyncReadExt as FuturesReadExt;
    use std::{
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    struct ScriptedState {
        input: Vec<u8>,
        read_at: usize,
        repeat_read: bool,
        output: Vec<u8>,
        fail_read: bool,
        fail_write_after: Option<usize>,
        block_write: bool,
        pending_read: bool,
        max_write: usize,
        closed: bool,
        drops: AtomicUsize,
    }

    struct ScriptedIo {
        state: Arc<std::sync::Mutex<ScriptedState>>,
    }

    impl ScriptedIo {
        fn new(input: &[u8]) -> (Self, Arc<std::sync::Mutex<ScriptedState>>) {
            let state = Arc::new(std::sync::Mutex::new(ScriptedState {
                input: input.to_vec(),
                read_at: 0,
                repeat_read: false,
                output: Vec::new(),
                fail_read: false,
                fail_write_after: None,
                block_write: false,
                pending_read: false,
                max_write: 0,
                closed: false,
                drops: AtomicUsize::new(0),
            }));
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    impl Drop for ScriptedIo {
        fn drop(&mut self) {
            self.state
                .lock()
                .unwrap()
                .drops
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    impl futures::io::AsyncRead for ScriptedIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.state.lock().unwrap();
            if state.pending_read {
                return Poll::Pending;
            }
            if state.fail_read {
                state.fail_read = false;
                return Poll::Ready(Err(io::Error::other("scripted read")));
            }
            if state.read_at == state.input.len() {
                if state.repeat_read {
                    state.read_at = 0;
                } else {
                    return Poll::Ready(Ok(0));
                }
            }
            let count = (state.input.len() - state.read_at).min(buf.len());
            buf[..count].copy_from_slice(&state.input[state.read_at..state.read_at + count]);
            state.read_at += count;
            Poll::Ready(Ok(count))
        }
    }

    impl futures::io::AsyncWrite for ScriptedIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.state.lock().unwrap();
            state.max_write = state.max_write.max(buf.len());
            if state.block_write {
                return Poll::Pending;
            }
            if state
                .fail_write_after
                .is_some_and(|limit| state.output.len() >= limit)
            {
                return Poll::Ready(Err(io::Error::other("scripted write")));
            }
            let count = state.fail_write_after.map_or(buf.len(), |limit| {
                limit.saturating_sub(state.output.len()).min(buf.len())
            });
            if count == 0 {
                return Poll::Ready(Err(io::Error::other("scripted write")));
            }
            state.output.extend_from_slice(&buf[..count]);
            Poll::Ready(Ok(count))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().state.lock().unwrap().closed = true;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn prefix_is_delivered_before_inner_bytes() {
        let (mut writer, reader) = tokio::io::duplex(16);
        writer.write_all(b"inner").await.unwrap();
        let mut prefixed = PrefixedIo::new(b"prefix".to_vec(), reader.compat());
        let mut bytes = [0; 11];
        FuturesReadExt::read_exact(&mut prefixed, &mut bytes)
            .await
            .unwrap();
        assert_eq!(&bytes, b"prefixinner");
    }

    #[tokio::test]
    async fn pump_forwards_both_directions_and_counts_after_write() {
        let (mut local_peer, local) = tokio::io::duplex(64);
        let (remote, mut remote_peer) = tokio::io::duplex(64);
        let task = tokio::spawn(pump(
            local.compat(),
            remote.compat(),
            MIN_COPY_BUFFER,
            Duration::from_secs(1),
            futures::future::pending(),
        ));
        local_peer.write_all(b"left").await.unwrap();
        let mut left = [0; 4];
        remote_peer.read_exact(&mut left).await.unwrap();
        assert_eq!(&left, b"left");
        local_peer.shutdown().await.unwrap();
        let mut eof = [0; 1];
        assert_eq!(remote_peer.read(&mut eof).await.unwrap(), 0);
        remote_peer.write_all(b"right").await.unwrap();
        let mut right = [0; 5];
        local_peer.read_exact(&mut right).await.unwrap();
        assert_eq!(&right, b"right");
        remote_peer.shutdown().await.unwrap();
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.local_to_remote_bytes, 4, "{result:?}");
        assert_eq!(result.remote_to_local_bytes, 5, "{result:?}");
        assert!(result.local_eof && result.remote_eof);
        assert_eq!(result.terminal, Terminal::Complete);
    }

    #[tokio::test]
    async fn pump_handles_large_flow_control_without_deadlock() {
        let (mut local_peer, local) = tokio::io::duplex(64 * 1024);
        let (remote, mut remote_peer) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(pump(
            local.compat(),
            remote.compat(),
            MIN_COPY_BUFFER,
            Duration::from_secs(5),
            futures::future::pending(),
        ));
        let size = 16 * 1024 * 1024;
        let send = async move {
            let payload = vec![0x5a; size];
            local_peer.write_all(&payload).await.unwrap();
            local_peer.shutdown().await.unwrap();
        };
        let receive = async move {
            let mut received = vec![0; size];
            remote_peer.read_exact(&mut received).await.unwrap();
            let mut eof = [0; 1];
            assert_eq!(remote_peer.read(&mut eof).await.unwrap(), 0);
            remote_peer.shutdown().await.unwrap();
            received
        };
        let (_, received) = tokio::join!(send, receive);
        assert!(received.iter().all(|byte| *byte == 0x5a));
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.local_to_remote_bytes, size as u64);
        assert_eq!(result.remote_to_local_bytes, 0);
        assert!(result.local_eof && result.remote_eof);
        assert_eq!(result.terminal, Terminal::Complete);
    }

    #[tokio::test]
    async fn scheduler_budget_runs_a_heartbeat_during_hot_copy() {
        let (local, local_state) = ScriptedIo::new(&[0x41; MIN_COPY_BUFFER]);
        local_state.lock().unwrap().repeat_read = true;
        let (remote, remote_state) = ScriptedIo::new(b"");
        remote_state.lock().unwrap().pending_read = true;
        let heartbeat = Arc::new(AtomicBool::new(false));
        let heartbeat_seen = heartbeat.clone();
        let copied = remote_state.clone();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let heartbeat_task = tokio::spawn(async move {
            while copied.lock().unwrap().output.is_empty() {
                tokio::task::yield_now().await;
            }
            heartbeat_seen.store(true, Ordering::Relaxed);
            cancel_tx.send(()).unwrap();
        });
        let result = pump_no_idle(local, remote, MIN_COPY_BUFFER, async {
            let _ = cancel_rx.await;
        })
        .await
        .unwrap();
        heartbeat_task.await.unwrap();
        assert_eq!(result.terminal, Terminal::Cancelled);
        assert!(heartbeat.load(Ordering::Relaxed));
        assert!(!remote_state.lock().unwrap().output.is_empty());
    }

    #[tokio::test]
    async fn scripted_local_read_failure_preserves_prior_committed_bytes() {
        let (local, local_state) = ScriptedIo::new(b"local");
        local_state.lock().unwrap().fail_read = true;
        let (remote, remote_state) = ScriptedIo::new(b"");
        let result = pump_no_idle(local, remote, MIN_COPY_BUFFER, futures::future::pending())
            .await
            .unwrap();
        assert_eq!(result.terminal, Terminal::LocalIo);
        assert_eq!(result.local_to_remote_bytes, 0);
        assert_eq!(result.remote_to_local_bytes, 0);
        assert_eq!(local_state.lock().unwrap().drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            remote_state.lock().unwrap().drops.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn scripted_local_to_remote_write_failure_preserves_committed_prefix() {
        let (local, _local_state) = ScriptedIo::new(b"local");
        let (remote, remote_state) = ScriptedIo::new(b"");
        remote_state.lock().unwrap().fail_write_after = Some(2);
        let result = pump_no_idle(local, remote, MIN_COPY_BUFFER, futures::future::pending())
            .await
            .unwrap();
        assert_eq!(result.terminal, Terminal::LocalIo);
        assert_eq!(result.local_to_remote_bytes, 2);
        assert_eq!(remote_state.lock().unwrap().output, b"lo");
    }

    #[tokio::test]
    async fn scripted_remote_read_failure_is_remote_io() {
        let (local, _local_state) = ScriptedIo::new(b"");
        let (remote, remote_state) = ScriptedIo::new(b"remote");
        remote_state.lock().unwrap().fail_read = true;
        let result = pump_no_idle(local, remote, MIN_COPY_BUFFER, futures::future::pending())
            .await
            .unwrap();
        assert_eq!(result.terminal, Terminal::RemoteIo);
        assert_eq!(result.local_to_remote_bytes, 0);
        assert_eq!(result.remote_to_local_bytes, 0);
    }

    #[tokio::test]
    async fn scripted_remote_to_local_write_failure_preserves_committed_prefix() {
        let (local, local_state) = ScriptedIo::new(b"");
        local_state.lock().unwrap().fail_write_after = Some(2);
        let (remote, _remote_state) = ScriptedIo::new(b"remote");
        let result = pump_no_idle(local, remote, MIN_COPY_BUFFER, futures::future::pending())
            .await
            .unwrap();
        assert_eq!(result.terminal, Terminal::RemoteIo);
        assert_eq!(result.remote_to_local_bytes, 2);
        assert_eq!(local_state.lock().unwrap().output, b"re");
    }

    #[tokio::test]
    async fn blocked_writer_reaches_idle_without_growing_beyond_one_buffer() {
        let (local, _local_state) = ScriptedIo::new(b"payload");
        let (remote, remote_state) = ScriptedIo::new(b"");
        remote_state.lock().unwrap().block_write = true;
        let result = pump(
            local,
            remote,
            MIN_COPY_BUFFER,
            Duration::from_millis(10),
            futures::future::pending(),
        )
        .await
        .unwrap();
        assert_eq!(result.terminal, Terminal::IdleTimeout);
        assert!(remote_state.lock().unwrap().max_write <= MIN_COPY_BUFFER);
    }

    #[tokio::test]
    async fn cancellation_drops_both_scripted_objects() {
        let (local, local_state) = ScriptedIo::new(b"");
        let (remote, remote_state) = ScriptedIo::new(b"");
        local_state.lock().unwrap().pending_read = true;
        remote_state.lock().unwrap().pending_read = true;
        let result = pump_no_idle(local, remote, MIN_COPY_BUFFER, async {})
            .await
            .unwrap();
        assert_eq!(result.terminal, Terminal::Cancelled);
        assert_eq!(local_state.lock().unwrap().drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            remote_state.lock().unwrap().drops.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn cancellation_interrupts_a_blocked_write() {
        let (local, local_state) = ScriptedIo::new(b"payload");
        let (remote, remote_state) = ScriptedIo::new(b"");
        remote_state.lock().unwrap().block_write = true;
        let result = pump_no_idle(local, remote, MIN_COPY_BUFFER, async {
            tokio::time::sleep(Duration::from_millis(10)).await;
        })
        .await
        .unwrap();
        assert_eq!(result.terminal, Terminal::Cancelled);
        assert_eq!(local_state.lock().unwrap().drops.load(Ordering::Relaxed), 1);
        assert_eq!(
            remote_state.lock().unwrap().drops.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn either_direction_resets_the_shared_idle_deadline() {
        let (mut local_peer, local) = tokio::io::duplex(16);
        let (remote, mut remote_peer) = tokio::io::duplex(16);
        let task = tokio::spawn(pump(
            local.compat(),
            remote.compat(),
            MIN_COPY_BUFFER,
            Duration::from_millis(100),
            futures::future::pending(),
        ));
        tokio::time::sleep(Duration::from_millis(60)).await;
        local_peer.write_all(b"left").await.unwrap();
        let mut left = [0; 4];
        remote_peer.read_exact(&mut left).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        remote_peer.write_all(b"right").await.unwrap();
        let mut right = [0; 5];
        local_peer.read_exact(&mut right).await.unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        local_peer.shutdown().await.unwrap();
        remote_peer.shutdown().await.unwrap();
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.terminal, Terminal::Complete);
        assert_eq!(result.local_to_remote_bytes, 4);
        assert_eq!(result.remote_to_local_bytes, 5);
    }

    #[tokio::test]
    async fn remote_half_close_keeps_local_to_remote_open() {
        let (mut local_peer, local) = tokio::io::duplex(16);
        let (remote, mut remote_peer) = tokio::io::duplex(16);
        let task = tokio::spawn(pump_no_idle(
            local.compat(),
            remote.compat(),
            MIN_COPY_BUFFER,
            futures::future::pending(),
        ));
        remote_peer.write_all(b"request").await.unwrap();
        remote_peer.shutdown().await.unwrap();
        let mut request = [0; 7];
        local_peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        local_peer.write_all(b"response").await.unwrap();
        local_peer.shutdown().await.unwrap();
        let mut response = [0; 8];
        remote_peer.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");
        let result = task.await.unwrap().unwrap();
        assert_eq!(result.terminal, Terminal::Complete);
        assert!(result.local_eof && result.remote_eof);
    }

    #[test]
    fn invalid_copy_buffer_is_rejected_before_io_is_started() {
        let error = futures::executor::block_on(pump_no_idle(
            futures::io::Cursor::new(Vec::<u8>::new()),
            futures::io::Cursor::new(Vec::<u8>::new()),
            MIN_COPY_BUFFER - 1,
            futures::future::pending(),
        ))
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn idle_timeout_and_cancellation_are_terminal_and_bounded() {
        let (_local_peer, local) = tokio::io::duplex(16);
        let (_remote_peer, remote) = tokio::io::duplex(16);
        let result = pump(
            local.compat(),
            remote.compat(),
            MIN_COPY_BUFFER,
            Duration::from_millis(10),
            futures::future::pending(),
        )
        .await
        .unwrap();
        assert_eq!(result.terminal, Terminal::IdleTimeout);
        let (_local_peer, local) = tokio::io::duplex(16);
        let (_remote_peer, remote) = tokio::io::duplex(16);
        let result = pump(
            local.compat(),
            remote.compat(),
            MIN_COPY_BUFFER,
            Duration::from_secs(1),
            async {},
        )
        .await
        .unwrap();
        assert_eq!(result.terminal, Terminal::Cancelled);
    }
}
