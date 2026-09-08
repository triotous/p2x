use crate::http::{HttpError, HttpRequestGate};
use futures::io::{AsyncRead, AsyncWrite};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

pub struct HttpGuardedIo<T> {
    inner: T,
    gate: HttpRequestGate,
    scratch: Vec<u8>,
    ready: Vec<u8>,
    error: Option<HttpError>,
}
impl<T> HttpGuardedIo<T> {
    pub fn new(inner: T, max_head: usize, read_size: usize) -> Result<Self, HttpError> {
        Ok(Self {
            inner,
            gate: HttpRequestGate::new(max_head)?,
            scratch: vec![0; read_size.max(1)],
            ready: Vec::new(),
            error: None,
        })
    }
    pub fn with_state(inner: T, gate: HttpRequestGate, ready: Vec<u8>, read_size: usize) -> Self {
        Self {
            inner,
            gate,
            scratch: vec![0; read_size.max(1)],
            ready,
            error: None,
        }
    }

    pub fn guard_error(&self) -> Option<&HttpError> {
        self.error.as_ref()
    }
    pub fn into_inner(self) -> T {
        self.inner
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
        match Pin::new(&mut this.inner).poll_read(cx, &mut this.scratch) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(count)) => {
                let result = this.gate.feed(&this.scratch[..count]);
                match result {
                    Ok(output) if output.is_empty() => Pin::new(this).poll_read(cx, buf),
                    Ok(output) => {
                        this.ready = output;
                        Pin::new(this).poll_read(cx, buf)
                    }
                    Err(error) => {
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
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
