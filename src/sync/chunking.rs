//! The immutable v4 wire chunking profile. Changes require a protocol revision.
use super::compare::{Block, CompareError, Manifest, same_version};
use fastcdc::v2020::{Normalization, StreamCDC};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

pub(super) const MIN: usize = 64 * 1024;
pub(super) const AVG: usize = 256 * 1024;
pub(super) const MAX: usize = 1024 * 1024;
pub(super) const MAX_BLOCKS: usize = 1_048_576;
pub(super) const PROFILE: &str = "fastcdc-5.0.0-v2020-64k-256k-1m-n1-seed0-sha256";

// StreamCDC fills its buffer across short reads. Retry EINTR before it sees it.
struct Retry<R>(R);
impl<R: Read> Read for Retry<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.0.read(buffer) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }
}

pub(super) fn chunks<R: Read>(
    reader: R,
) -> impl Iterator<Item = Result<fastcdc::v2020::ChunkData, fastcdc::v2020::Error>> {
    StreamCDC::with_level_and_seed(Retry(reader), MIN, AVG, MAX, Normalization::Level1, 0)
}

pub(super) fn manifest(path: &Path) -> Result<Manifest, CompareError> {
    scan(path, true)
}
/// Integrity/commit checks need only the whole-file hash, not a block index.
pub(super) fn digest_file(path: &Path) -> Result<Manifest, CompareError> {
    scan(path, false)
}
fn scan(path: &Path, index: bool) -> Result<Manifest, CompareError> {
    let error = |source| CompareError::Io {
        path: path.to_owned(),
        source,
    };
    let before = fs::symlink_metadata(path).map_err(error)?;
    if !before.is_file() || super::platform::is_link(&before) {
        return Err(CompareError::Unsupported(path.to_owned()));
    }
    if before.len() > super::remote::MAX_FILE {
        return Err(CompareError::Limit(path.to_owned()));
    }
    let mut file = File::open(path).map_err(error)?;
    if !same_version(&before, &file.metadata().map_err(error)?) {
        return Err(CompareError::Changed(path.to_owned()));
    }
    let mut hash = Sha256::new();
    let mut size = 0_u64;
    let mut blocks = Vec::new();
    if index {
        for result in chunks((&mut file).take(before.len() + 1)) {
            let chunk = result.map_err(|e| error(io::Error::other(e.to_string())))?;
            if blocks.len() == MAX_BLOCKS {
                return Err(CompareError::BlockLimit(path.to_owned()));
            }
            size += chunk.length as u64;
            if size > before.len() {
                return Err(CompareError::Changed(path.to_owned()));
            }
            hash.update(&chunk.data);
            blocks.push(Block {
                hash: Sha256::digest(&chunk.data).into(),
                length: chunk.length,
            });
        }
    } else {
        let mut buffer = vec![0; MIN];
        let mut reader = Retry((&mut file).take(before.len() + 1));
        loop {
            let used = reader.read(&mut buffer).map_err(error)?;
            if used == 0 {
                break;
            }
            hash.update(&buffer[..used]);
            size += used as u64;
        }
    }
    let named = fs::symlink_metadata(path).map_err(error)?;
    if size != before.len()
        || super::platform::is_link(&named)
        || !same_version(&before, &file.metadata().map_err(error)?)
        || !same_version(&before, &named)
    {
        return Err(CompareError::Changed(path.to_owned()));
    }
    Ok(Manifest {
        hash: hash.finalize().into(),
        size,
        blocks,
    })
}

/// Validate peer-controlled lengths before allocating/reading file data. Offsets
/// are derived locally; peers cannot specify overlapping or out-of-range writes.
pub(super) fn offsets(blocks: &[Block], size: u64) -> Result<Vec<u64>, &'static str> {
    if blocks.len() > MAX_BLOCKS {
        return Err("CDC block count exceeds 1,048,576 limit");
    }
    let mut result = Vec::with_capacity(blocks.len());
    let mut total = 0_u64;
    for (i, block) in blocks.iter().enumerate() {
        if block.length == 0 || block.length > MAX || (i + 1 < blocks.len() && block.length < MIN) {
            return Err("invalid CDC block length");
        }
        result.push(total);
        total = total
            .checked_add(block.length as u64)
            .ok_or("block size overflow")?;
        if total > size {
            return Err("block lengths exceed file size");
        }
    }
    if total != size {
        return Err("block lengths do not cover file size");
    }
    Ok(result)
}

#[cfg(test)]
pub(super) fn fixture(size: usize) -> Vec<u8> {
    let mut state = 0x123456789abcdef_u64;
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcdc::v2020::FastCDC;
    use std::collections::HashSet;

    struct ShortReads<'a> {
        remaining: &'a [u8],
        limit: usize,
        interrupt: bool,
    }
    impl Read for ShortReads<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let size = buffer.len().min(self.limit).min(self.remaining.len());
            buffer[..size].copy_from_slice(&self.remaining[..size]);
            self.remaining = &self.remaining[size..];
            Ok(size)
        }
    }

    #[test]
    fn streaming_boundaries_match_upstream_and_ignore_read_fragmentation() {
        let data = fixture(4 * MAX + 127);
        let expected: Vec<_> =
            FastCDC::with_level_and_seed(&data, MIN, AVG, MAX, Normalization::Level1, 0)
                .map(|c| (c.offset as u64, c.length))
                .collect();
        assert!(expected.len() > 4);
        for limit in [7, 4093, MAX] {
            let reader = ShortReads {
                remaining: &data,
                limit,
                interrupt: false,
            };
            let mut actual = Vec::new();
            for result in chunks(reader) {
                let c = result.unwrap();
                assert_eq!(
                    c.data,
                    data[c.offset as usize..c.offset as usize + c.length]
                );
                actual.push((c.offset, c.length));
            }
            assert_eq!(actual, expected);
        }
    }

    fn descriptors(data: &[u8]) -> Vec<Block> {
        chunks(data)
            .map(|c| {
                let c = c.unwrap();
                Block {
                    hash: Sha256::digest(c.data).into(),
                    length: c.length,
                }
            })
            .collect()
    }

    #[test]
    fn insert_delete_overwrite_and_append_reuse_most_content() {
        let original = fixture(8 * MAX);
        let old: HashSet<_> = descriptors(&original).into_iter().collect();
        for position in [0, original.len() / 2] {
            let mut changed = original.clone();
            changed.insert(position, 42);
            assert!(
                reused(&old, &changed) > original.len() * 3 / 4,
                "insertion at {position}"
            );
            changed = original.clone();
            changed.drain(position..position + 100);
            assert!(
                reused(&old, &changed) > original.len() * 3 / 4,
                "deletion at {position}"
            );
            changed = original.clone();
            changed[position] ^= 1;
            assert!(
                reused(&old, &changed) > original.len() * 3 / 4,
                "overwrite at {position}"
            );
        }
        let mut appended = original.clone();
        appended.extend_from_slice(b"appended content");
        assert!(reused(&old, &appended) > original.len() - MAX);
    }
    fn reused(old: &HashSet<Block>, data: &[u8]) -> usize {
        descriptors(data)
            .iter()
            .filter(|b| old.contains(*b))
            .map(|b| b.length)
            .sum()
    }

    #[test]
    fn empty_short_and_repetitive_inputs_and_untrusted_lengths() {
        for data in [vec![], vec![1], vec![0; 3 * MAX + 7], vec![0xff; 2 * MAX]] {
            let blocks = descriptors(&data);
            let positions = offsets(&blocks, data.len() as u64).unwrap();
            assert_eq!(blocks.iter().map(|b| b.length).sum::<usize>(), data.len());
            for (offset, block) in positions.into_iter().zip(&blocks) {
                assert_eq!(
                    block.hash,
                    <[u8; 32]>::from(Sha256::digest(
                        &data[offset as usize..offset as usize + block.length]
                    ))
                );
            }
        }
        let block = |length| Block {
            hash: [0; 32],
            length,
        };
        assert!(offsets(&[block(0)], 0).is_err());
        assert!(offsets(&[block(MAX + 1)], (MAX + 1) as u64).is_err());
        assert!(offsets(&[block(1), block(MIN)], (MIN + 1) as u64).is_err());
        assert!(offsets(&[block(MIN)], MIN as u64 - 1).is_err());
        assert!(offsets(&[block(MIN)], MIN as u64 + 1).is_err());
        assert!(offsets(&[], 1).is_err());
        assert!(offsets(&vec![block(MIN); MAX_BLOCKS + 1], u64::MAX).is_err());
    }
}
