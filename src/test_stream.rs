use std::io::{Read, Result, Write};

use std::fs::File;

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

impl Read for TestStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.file.read(buf)
    }
}

impl Write for TestStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.buffer.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.buffer.flush()
    }
}
