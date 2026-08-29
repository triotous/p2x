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
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::compat::TokioAsyncReadCompatExt;

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
    async fn scheduler_budget_allows_a_heartbeat_during_hot_copy() {
        let (mut local_peer, local) = tokio::io::duplex(64 * 1024);
        let (remote, mut remote_peer) = tokio::io::duplex(64 * 1024);
        let heartbeat = Arc::new(AtomicBool::new(false));
        let heartbeat_seen = heartbeat.clone();
        let heartbeat_task = tokio::spawn(async move {
            for _ in 0..32 {
                heartbeat_seen.store(true, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        });
        let pump = tokio::spawn(pump_no_idle(
            local.compat(),
            remote.compat(),
            MIN_COPY_BUFFER,
            async {
                tokio::time::sleep(Duration::from_millis(10)).await;
            },
        ));
        let writer = tokio::spawn(async move {
            let block = vec![0x41; MIN_COPY_BUFFER];
            for _ in 0..64 {
                if local_peer.write_all(&block).await.is_err() {
                    break;
                }
            }
        });
        let reader = tokio::spawn(async move {
            let mut block = vec![0; MIN_COPY_BUFFER];
            while remote_peer.read_exact(&mut block).await.is_ok() {}
        });
        heartbeat_task.await.unwrap();
        assert!(heartbeat.load(Ordering::Relaxed));
        let _ = pump.await;
        writer.abort();
        reader.abort();
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
