pub trait Itertools: Sized + Iterator {
    fn chunk(self, len: usize) -> ChunkIter<Self> {
        ChunkIter {
            inner: self,
            chunk_size: len,
        }
    }
}
impl<I: Iterator + Sized> Itertools for I {}

pub struct ChunkIter<I>
where
    I: Iterator + Sized,
{
    inner: I,
    chunk_size: usize,
}

impl<I: Iterator> Iterator for ChunkIter<I> {
    type Item = Vec<I::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        let take_it = &mut self.inner;
        let chunk: Self::Item = take_it.take(self.chunk_size).collect();
        if chunk.is_empty() {
            None
        } else {
            Some(chunk)
        }
    }
}

#[cfg(test)]
mod test {
    use util::Itertools;

    #[test]
    fn chunk_iter() {
        assert_eq!((0..128).into_iter().chunk(64).count(), 2);
        assert_eq!((0..128).into_iter().chunk(2).count(), 64);
        assert_eq!((0..0).into_iter().chunk(2).count(), 0);
        assert_eq!((0..1).into_iter().chunk(2).count(), 1);
        assert_eq!((0..2).into_iter().chunk(2).count(), 1);
        assert_eq!((0..3).into_iter().chunk(2).count(), 2);

        assert_eq!(
            (0..3).into_iter().chunk(2).collect::<Vec<_>>(),
            vec![vec![0, 1], vec![2]]
        );
    }
}
