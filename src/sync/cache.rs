//! Session-local, bounded hash cache. Metadata is a hint; periodic rehashes and
//! uncached pre-commit checks remain the integrity boundary.
use super::compare::{CompareError, Manifest, manifest, same_version};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

pub(super) const RECHECK: Duration = Duration::from_secs(60);
const MAX_BLOCKS: usize = 65_536;
const MAX_ENTRIES: usize = 10_000;

#[derive(Default)]
pub(super) struct ManifestCache {
    entries: BTreeMap<PathBuf, (fs::Metadata, Instant, Rc<Manifest>)>,
    blocks: usize,
    chunk: Option<usize>,
}

impl ManifestCache {
    pub fn clear(&mut self) {
        self.entries.clear();
        self.blocks = 0;
    }

    pub fn get(&mut self, path: &Path, chunk: usize) -> Result<Rc<Manifest>, CompareError> {
        if self.chunk != Some(chunk) {
            self.clear();
            self.chunk = Some(chunk);
        }
        let before = fs::symlink_metadata(path).map_err(|source| CompareError::Io {
            path: path.to_owned(),
            source,
        })?;
        if before.is_file()
            && let Some((metadata, checked, value)) = self.entries.get(path)
            && checked.elapsed() < RECHECK
            && same_version(metadata, &before)
        {
            return Ok(Rc::clone(value));
        }
        if let Some((_, _, old)) = self.entries.remove(path) {
            self.blocks -= old.blocks.len();
        }
        let value = Rc::new(manifest(path, chunk)?);
        let after = fs::symlink_metadata(path).map_err(|source| CompareError::Io {
            path: path.to_owned(),
            source,
        })?;
        if !same_version(&before, &after) {
            return Err(CompareError::Changed(path.to_owned()));
        }
        if value.blocks.len() <= MAX_BLOCKS {
            if self.blocks + value.blocks.len() > MAX_BLOCKS || self.entries.len() >= MAX_ENTRIES {
                self.clear();
            }
            self.blocks += value.blocks.len();
            self.entries
                .insert(path.to_owned(), (after, Instant::now(), Rc::clone(&value)));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reuse_invalidate_and_expire() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, b"before").unwrap();
        let mut cache = ManifestCache::default();
        let first = cache.get(&file, 4096).unwrap();
        assert!(Rc::ptr_eq(&first, &cache.get(&file, 4096).unwrap()));
        fs::write(&file, b"after!").unwrap();
        let next = cache.get(&file, 4096).unwrap();
        assert_ne!(first.hash, next.hash);
        cache.entries.get_mut(&file).unwrap().1 = Instant::now() - RECHECK;
        assert!(!Rc::ptr_eq(&next, &cache.get(&file, 4096).unwrap()));
        fs::remove_file(&file).unwrap();
        assert!(cache.get(&file, 4096).is_err());
    }
}
