use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

pub trait ReconnectStream: Sized {
    type ReconnectData: std::fmt::Debug + std::clone::Clone;
    type Error: std::fmt::Debug;

    fn try_connect(data: &Self::ReconnectData) -> Result<Self, Self::Error>;
}

impl ReconnectStream for std::net::TcpStream {
    type ReconnectData = Vec<std::net::SocketAddr>;
    type Error = io::Error;

    fn try_connect(data: &Self::ReconnectData) -> Result<Self, Self::Error> {
        std::net::TcpStream::connect(&data[..])
    }
}

#[derive(Debug)]
pub struct ClonableStream<T: Read + Write + ReconnectStream>(
    Arc<Mutex<T>>,
    <T as ReconnectStream>::ReconnectData,
);

impl<T: Read + Write + ReconnectStream> ClonableStream<T> {
    pub fn new(
        data: <T as ReconnectStream>::ReconnectData,
    ) -> Result<Self, <T as ReconnectStream>::Error> {
        Ok(Self(Arc::new(Mutex::new(T::try_connect(&data)?)), data))
    }

    pub fn try_reconnect(&mut self) -> Result<(), <T as ReconnectStream>::Error> {
        self.0 = Arc::new(Mutex::new(T::try_connect(&self.1)?));
        debug!("ClonableStream::try_reconnect() successful");

        Ok(())
    }
}

impl<T: Read + Write + ReconnectStream> Read for ClonableStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().read(buf)
    }
}

impl<T: Read + Write + ReconnectStream> Write for ClonableStream<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

// For some reason this fails saying that there's a conflicting implementation in core ??
/* impl<T: Read + Write + ReconnectStream> TryFrom<<T as ReconnectStream>::ReconnectData> for ClonableStream<T> {
    type Error = <T as ReconnectStream>::Error;

    fn try_from(data: <T as ReconnectStream>::ReconnectData) -> Result<Self, Self::Error> {
        Ok(Self(Arc::new(Mutex::new(T::try_connect(&data)?)), data))
    }
}*/

impl<T: Read + Write + ReconnectStream> Clone for ClonableStream<T> {
    fn clone(&self) -> Self {
        ClonableStream(Arc::clone(&self.0), self.1.clone())
    }
}

#[cfg(test)]
impl<T: Read + Write + ReconnectStream> ClonableStream<T> {
    pub fn stream(&self) -> Arc<Mutex<T>> {
        Arc::clone(&self.0)
    }
}
