use std::io::{Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use std::fs::File;

use tokio::io::{AsyncRead, AsyncWrite, Result};

#[derive(Debug)]
pub struct TestStream {
    pub file: File,
    pub buffer: Vec<u8>,
}

impl TestStream {
    pub fn new(file: File) -> Self {
        TestStream {
            file,
            buffer: Vec::new(),
        }
    }
}

impl AsyncRead for TestStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        Poll::Ready(self.as_mut().file.read(buf))
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(mut self: Pin<&mut Self>, _cx: &mut Context, buf: &[u8]) -> Poll<Result<usize>> {
        Poll::Ready(self.as_mut().buffer.write(buf))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<()>> {
        Poll::Ready(self.as_mut().buffer.flush())
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }
}
