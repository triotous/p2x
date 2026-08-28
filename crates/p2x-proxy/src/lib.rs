//! Bounded opaque-byte tunnelling for futures and Tokio I/O streams.

use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    buffer_size: usize,
    activity: watch::Sender<Instant>,
) -> (u64, bool, Option<io::Error>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0; buffer_size];
    let mut bytes = 0u64;
    loop {
        let count = match reader.read(&mut buffer).await {
            Ok(count) => count,
            Err(error) => return (bytes, false, Some(error)),
        };
        if count == 0 {
            return match writer.close().await {
                Ok(()) => (bytes, true, None),
                Err(error) => (bytes, false, Some(error)),
            };
        }
        if let Err(error) = writer.write_all(&buffer[..count]).await {
            return (bytes, false, Some(error));
        }
        bytes = bytes.saturating_add(count as u64);
        let _ = activity.send(Instant::now());
    }
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
    let started = Instant::now();
    let (activity_tx, mut activity_rx) = watch::channel(started);
    let (local_reader, local_writer) = local.split();
    let (remote_reader, remote_writer) = remote.split();
    let local_to_remote = tokio::spawn(copy_direction(
        local_reader,
        remote_writer,
        buffer_size,
        activity_tx.clone(),
    ));
    let remote_to_local = tokio::spawn(copy_direction(
        remote_reader,
        local_writer,
        buffer_size,
        activity_tx,
    ));
    let mut local_result = Box::pin(local_to_remote);
    let mut remote_result = Box::pin(remote_to_local);
    let mut cancel = Box::pin(cancel);
    let mut local_done = None;
    let mut remote_done = None;
    let terminal = loop {
        if local_done.is_some() && remote_done.is_some() {
            break Terminal::Complete;
        }
        let last_activity = *activity_rx.borrow();
        let deadline =
            tokio::time::sleep_until(tokio::time::Instant::from_std(last_activity + idle_timeout));
        tokio::pin!(deadline);
        tokio::select! {
            result = &mut local_result, if local_done.is_none() => {
                let result = result.map_err(io::Error::other)?;
                let failed = result.2.is_some();
                local_done = Some(result);
                if failed { break Terminal::LocalIo; }
            }
            result = &mut remote_result, if remote_done.is_none() => {
                let result = result.map_err(io::Error::other)?;
                let failed = result.2.is_some();
                remote_done = Some(result);
                if failed { break Terminal::RemoteIo; }
            }
            changed = activity_rx.changed() => {
                if changed.is_err() {
                    if local_done.is_none() {
                        local_done = Some((&mut local_result).await.map_err(io::Error::other)?);
                    }
                    if remote_done.is_none() {
                        remote_done = Some((&mut remote_result).await.map_err(io::Error::other)?);
                    }
                    break Terminal::Complete;
                }
            }
            _ = &mut deadline => break Terminal::IdleTimeout,
            _ = &mut cancel => break Terminal::Cancelled,
        }
    };
    if terminal != Terminal::Complete {
        if local_done.is_none() {
            local_result.as_mut().abort();
            let _ = (&mut local_result).await;
        }
        if remote_done.is_none() {
            remote_result.as_mut().abort();
            let _ = (&mut remote_result).await;
        }
    }
    let (local_to_remote_bytes, local_eof) = local_done
        .as_ref()
        .map_or((0, false), |(bytes, eof, _)| (*bytes, *eof));
    let (remote_to_local_bytes, remote_eof) = remote_done
        .as_ref()
        .map_or((0, false), |(bytes, eof, _)| (*bytes, *eof));
    let terminal = if terminal == Terminal::Complete {
        if local_done.as_ref().is_some_and(|result| result.2.is_some()) {
            Terminal::LocalIo
        } else if remote_done
            .as_ref()
            .is_some_and(|result| result.2.is_some())
        {
            Terminal::RemoteIo
        } else {
            Terminal::Complete
        }
    } else {
        terminal
    };
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
