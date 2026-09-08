use crate::http::{HttpError, HttpRequestGate, HttpResponseGate, UpgradeDecision};
use futures::io::{AsyncRead, AsyncWrite};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

#[derive(Clone, Default)]
pub struct HttpGuardStatus(Arc<Mutex<Option<HttpError>>>);
impl HttpGuardStatus {
    pub fn error(&self) -> Option<HttpError> {
        self.0.lock().expect("HTTP guard status poisoned").clone()
    }
    fn set(&self, error: HttpError) {
        *self.0.lock().expect("HTTP guard status poisoned") = Some(error);
    }
}

pub struct HttpGuardedIo<T> {
    inner: T,
    gate: HttpRequestGate,
    responses: HttpResponseGate,
    scratch: Vec<u8>,
    ready: Vec<u8>,
    response_ready: Vec<u8>,
    response_input_len: usize,
    pending_upgrade: Option<UpgradeDecision>,
    error: Option<HttpError>,
    status: HttpGuardStatus,
    read_waker: Option<std::task::Waker>,
    parse_timeout: Duration,
    partial_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    upgrade_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}
impl<T> HttpGuardedIo<T> {
    pub fn new(inner: T, max_head: usize, read_size: usize) -> Result<Self, HttpError> {
        Ok(Self {
            inner,
            gate: HttpRequestGate::new(max_head)?,
            responses: HttpResponseGate::new(),
            scratch: vec![0; read_size.max(1)],
            ready: Vec::new(),
            response_ready: Vec::new(),
            response_input_len: 0,
            pending_upgrade: None,
            error: None,
            status: HttpGuardStatus::default(),
            read_waker: None,
            parse_timeout: Duration::from_secs(5),
            partial_deadline: None,
            upgrade_deadline: None,
        })
    }
    pub fn with_state(inner: T, gate: HttpRequestGate, ready: Vec<u8>, read_size: usize) -> Self {
        Self::with_state_and_timeout(inner, gate, ready, read_size, Duration::from_secs(5))
    }

    pub fn with_state_and_timeout(
        inner: T,
        mut gate: HttpRequestGate,
        ready: Vec<u8>,
        read_size: usize,
        parse_timeout: Duration,
    ) -> Self {
        let mut responses = HttpResponseGate::with_limit(gate.max_head())
            .expect("request gate has a valid response head limit");
        for metadata in gate.take_metadata() {
            let _ = responses.queue_request(metadata);
        }
        Self {
            inner,
            gate,
            responses,
            scratch: vec![0; read_size.max(1)],
            ready,
            response_ready: Vec::new(),
            response_input_len: 0,
            pending_upgrade: None,
            error: None,
            status: HttpGuardStatus::default(),
            read_waker: None,
            parse_timeout,
            partial_deadline: None,
            upgrade_deadline: None,
        }
    }

    pub fn guard_error(&self) -> Option<&HttpError> {
        self.error.as_ref()
    }
    pub fn status(&self) -> HttpGuardStatus {
        self.status.clone()
    }
    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn response_pending(&self) -> bool {
        !self.response_ready.is_empty() || self.response_input_len != 0
    }

    pub fn upgrade_pending(&self) -> bool {
        self.responses.pending_upgrade()
    }

    fn update_deadlines(&mut self) {
        if self.gate.is_waiting_for_upgrade() {
            self.partial_deadline = None;
            if self.upgrade_deadline.is_none() {
                self.upgrade_deadline = Some(Box::pin(tokio::time::sleep(Duration::from_secs(5))));
            }
        } else {
            self.upgrade_deadline = None;
            if self.gate.has_buffered_input() {
                if self.partial_deadline.is_none() {
                    self.partial_deadline = Some(Box::pin(tokio::time::sleep(self.parse_timeout)));
                }
            } else {
                self.partial_deadline = None;
            }
        }
    }

    fn poll_deadlines(&mut self, cx: &mut Context<'_>) -> Result<(), HttpError> {
        let expired = self
            .partial_deadline
            .as_mut()
            .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready())
            || self
                .upgrade_deadline
                .as_mut()
                .is_some_and(|deadline| deadline.as_mut().poll(cx).is_ready());
        if expired {
            Err(HttpError::Timeout)
        } else {
            Ok(())
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for HttpGuardedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.ready.is_empty() {
            let count = self.ready.len().min(buf.len());
            buf[..count].copy_from_slice(&self.ready[..count]);
            self.ready.drain(..count);
            return Poll::Ready(Ok(count));
        }
        if self.error.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP ingress guard failed",
            )));
        }
        let this = self.get_mut();
        if this.gate.stopped() {
            return Poll::Ready(Ok(0));
        }
        this.update_deadlines();
        if let Err(error) = this.poll_deadlines(cx) {
            this.status.set(error.clone());
            this.error = Some(error);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP ingress parse timed out",
            )));
        }
        let available = 32usize.saturating_sub(this.responses.pending_requests());
        if this.gate.has_buffered_input() && !this.gate.is_waiting_for_upgrade() && available != 0 {
            match this.gate.feed_limited(&[], available) {
                Ok(output) => {
                    for metadata in this.gate.take_metadata() {
                        if let Err(error) = this.responses.queue_request(metadata) {
                            this.status.set(error.clone());
                            this.error = Some(error);
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "HTTP response queue failed",
                            )));
                        }
                    }
                    if !output.is_empty() {
                        this.ready.extend(output);
                        return Pin::new(this).poll_read(cx, buf);
                    }
                    this.update_deadlines();
                }
                Err(error) => {
                    this.status.set(error.clone());
                    this.error = Some(error);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP ingress guard failed",
                    )));
                }
            }
        }
        if this.gate.is_waiting_for_upgrade() || available == 0 {
            this.read_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        match Pin::new(&mut this.inner).poll_read(cx, &mut this.scratch) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(0)) => match this.responses.finish_eof() {
                Ok(()) => Poll::Ready(Ok(0)),
                Err(error) => {
                    this.status.set(error.clone());
                    this.error = Some(error);
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "HTTP response ended before the message completed",
                    )))
                }
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(count)) => {
                let result = this.gate.feed_limited(&this.scratch[..count], available);
                match result {
                    Ok(output) => {
                        for metadata in this.gate.take_metadata() {
                            if let Err(error) = this.responses.queue_request(metadata) {
                                this.status.set(error.clone());
                                this.error = Some(error);
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "HTTP response queue failed",
                                )));
                            }
                        }
                        if !output.is_empty() {
                            this.ready.extend(output);
                        }
                        this.update_deadlines();
                        Pin::new(this).poll_read(cx, buf)
                    }
                    Err(error) => {
                        this.status.set(error.clone());
                        this.error = Some(error);
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "HTTP ingress guard failed",
                        )))
                    }
                }
            }
        }
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for HttpGuardedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if this.error.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP response guard failed",
            )));
        }
        if this.response_input_len == 0 {
            let pending_before = this.responses.pending_requests();
            let (output, decision) = match this.responses.feed(buf) {
                Ok(result) => result,
                Err(error) => {
                    this.status.set(error.clone());
                    this.error = Some(error);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP response guard failed",
                    )));
                }
            };
            let final_started = this.responses.take_final_started();
            if final_started && pending_before == 1 && this.gate.upload_in_progress() {
                this.gate.stop_upload();
                if let Some(waker) = this.read_waker.take() {
                    waker.wake();
                }
            }
            this.response_ready.extend(output);
            this.response_input_len = buf.len();
            if this.responses.should_close() {
                this.gate.close();
            }
            if decision != UpgradeDecision::None {
                this.pending_upgrade = Some(decision);
            }
        }
        while !this.response_ready.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.response_ready) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "HTTP response write made no progress",
                    )));
                }
                Poll::Ready(Ok(count)) => {
                    this.response_ready.drain(..count);
                }
            }
        }
        if let Some(decision) = this.pending_upgrade.take() {
            match decision {
                UpgradeDecision::Accepted => this.ready.extend(this.gate.release_opaque()),
                UpgradeDecision::Declined => match this.gate.upgrade_declined() {
                    Ok(bytes) => this.ready.extend(bytes),
                    Err(error) => {
                        this.status.set(error.clone());
                        this.error = Some(error);
                        // The validated response bytes have already reached the
                        // caller. Acknowledge exactly those bytes so pump
                        // accounting remains truthful; the paired read side
                        // reports the held request violation and closes.
                        let count = this.response_input_len;
                        this.response_input_len = 0;
                        if let Some(waker) = this.read_waker.take() {
                            waker.wake();
                        }
                        return Poll::Ready(Ok(count));
                    }
                },
                UpgradeDecision::None => {}
            }
        }
        this.update_deadlines();
        let count = this.response_input_len;
        this.response_input_len = 0;
        if let Some(waker) = this.read_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::{AsyncReadExt as FuturesReadExt, AsyncWriteExt as FuturesWriteExt};
    use tokio::io::{AsyncReadExt as TokioReadExt, AsyncWriteExt as TokioWriteExt};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    const FIRST: &[u8] = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const UPGRADE: &[u8] = b"GET /chat HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

    #[tokio::test]
    async fn short_response_is_delivered_without_an_extra_flush_or_remote_byte() {
        let (mut caller, local) = tokio::io::duplex(1024);
        caller.write_all(FIRST).await.unwrap();
        let mut guarded = HttpGuardedIo::new(local.compat(), 1024, 256).unwrap();
        let mut request = vec![0; FIRST.len()];
        guarded.read_exact(&mut request).await.unwrap();
        assert_eq!(request, FIRST);

        let response = b"HTTP/1.1 204 No Content\r\n\r\n";
        guarded.write_all(response).await.unwrap();
        let mut received = vec![0; response.len()];
        caller.read_exact(&mut received).await.unwrap();
        assert_eq!(received, response);
    }

    #[tokio::test]
    async fn same_read_cross_authority_bytes_never_leave_the_gate() {
        let (mut caller, local) = tokio::io::duplex(2048);
        let second = b"GET /secret HTTP/1.1\r\nHost: other.example\r\n\r\n";
        caller
            .write_all(&[FIRST, second.as_slice()].concat())
            .await
            .unwrap();
        let mut guarded = HttpGuardedIo::new(local.compat(), 1024, 2048).unwrap();
        let mut first = vec![0; FIRST.len()];
        guarded.read_exact(&mut first).await.unwrap();
        assert_eq!(first, FIRST);
        let mut byte = [0; 1];
        assert!(guarded.read(&mut byte).await.is_err());
        assert_eq!(guarded.status().error(), Some(HttpError::AuthorityMismatch));
    }

    #[tokio::test]
    async fn partial_later_head_uses_one_absolute_timeout() {
        let (mut caller, local) = tokio::io::duplex(1024);
        caller.write_all(b"GET /later").await.unwrap();
        let mut gate = HttpRequestGate::new(1024).unwrap();
        let ready = gate.feed(FIRST).unwrap();
        let mut guarded = HttpGuardedIo::with_state_and_timeout(
            local.compat(),
            gate,
            ready,
            256,
            Duration::from_millis(20),
        );
        let mut first = vec![0; FIRST.len()];
        guarded.read_exact(&mut first).await.unwrap();
        let mut byte = [0; 1];
        assert!(guarded.read(&mut byte).await.is_err());
        assert_eq!(guarded.status().error(), Some(HttpError::Timeout));
    }

    #[tokio::test]
    async fn websocket_early_bytes_wait_for_an_associated_101_then_turn_opaque() {
        let (mut caller, local) = tokio::io::duplex(2048);
        caller
            .write_all(&[UPGRADE, b"early".as_slice()].concat())
            .await
            .unwrap();
        let mut guarded = HttpGuardedIo::new(local.compat(), 1024, 2048).unwrap();
        let mut head = vec![0; UPGRADE.len()];
        guarded.read_exact(&mut head).await.unwrap();
        assert_eq!(head, UPGRADE);

        let mut early = [0; 5];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), guarded.read_exact(&mut early))
                .await
                .is_err()
        );
        let response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        guarded.write_all(response).await.unwrap();
        guarded.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"early");

        caller.write_all(b"opaque").await.unwrap();
        let mut opaque = [0; 6];
        guarded.read_exact(&mut opaque).await.unwrap();
        assert_eq!(&opaque, b"opaque");
    }

    #[tokio::test]
    async fn early_final_response_abandons_the_remaining_upload() {
        let (mut caller, local) = tokio::io::duplex(2048);
        let initial = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\nabc";
        caller.write_all(initial).await.unwrap();
        let mut guarded = HttpGuardedIo::new(local.compat(), 1024, 2048).unwrap();
        let mut forwarded = vec![0; initial.len()];
        guarded.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, initial);

        let response = b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n";
        guarded.write_all(response).await.unwrap();
        caller.write_all(b"remaining upload").await.unwrap();
        let mut byte = [0; 1];
        assert_eq!(guarded.read(&mut byte).await.unwrap(), 0);
    }
}
