use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, Metadata},
    io::{self, Read},
    path::{Path, PathBuf},
};

const MAX_ENTRIES: usize = 100_000;
const MAX_BLOCKS_PER_FILE: u64 = 1_000_000;
const MAX_DEPTH: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum CompareError {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("unsupported file type or symbolic link: {0}")]
    Unsupported(PathBuf),
    #[error("file changed while being scanned: {0}")]
    Changed(PathBuf),
    #[error("scan resource limit exceeded at {0}")]
    Limit(PathBuf),
    #[error("root must be a directory: {0}")]
    NotDirectory(PathBuf),
    #[error("path is not valid UTF-8: {0:?}")]
    Encoding(PathBuf),
    #[error("chunk size must be between 4096 and 1048576 bytes")]
    ChunkSize,
}

fn io_error(path: &Path, source: io::Error) -> CompareError {
    CompareError::Io {
        path: path.to_owned(),
        source,
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    CreateFile,
    UpdateFile,
    CreateDirectory,
    Unchanged,
    TargetOnly,
    TypeConflict,
}

#[derive(Debug, Serialize)]
pub struct Entry {
    pub path: String,
    pub action: Action,
    pub source_bytes: u64,
    /// Estimated file payload only; excludes manifests and transport overhead.
    pub missing_bytes: u64,
    pub reusable_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct Plan {
    pub chunk_size: usize,
    pub entries: Vec<Entry>,
    pub missing_bytes: u64,
    pub reusable_bytes: u64,
    /// This report is not a snapshot or an authorization to overwrite anything.
    pub read_only: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Kind {
    File,
    Directory,
}

pub(super) fn inventory(root: &Path) -> Result<BTreeMap<PathBuf, Kind>, CompareError> {
    let meta = fs::symlink_metadata(root).map_err(|e| io_error(root, e))?;
    if !meta.is_dir() {
        return Err(CompareError::NotDirectory(root.to_owned()));
    }
    let mut result = BTreeMap::new();
    let mut pending = vec![(PathBuf::new(), 0)];
    while let Some((relative, depth)) = pending.pop() {
        let directory = root.join(&relative);
        if depth > MAX_DEPTH {
            return Err(CompareError::Limit(directory));
        }
        // Catch directory replacement before traversal (not a hostile-filesystem sandbox).
        let metadata = fs::symlink_metadata(&directory).map_err(|e| io_error(&directory, e))?;
        if !metadata.is_dir() {
            return Err(CompareError::Changed(directory));
        }
        for item in fs::read_dir(&directory).map_err(|e| io_error(&directory, e))? {
            let item = item.map_err(|e| io_error(&directory, e))?;
            let path = item.path();
            let relative_path = relative.join(item.file_name());
            if relative_path.to_str().is_none() {
                return Err(CompareError::Encoding(path));
            }
            let kind = item.file_type().map_err(|e| io_error(&path, e))?;
            let kind = if kind.is_dir() {
                Kind::Directory
            } else if kind.is_file() {
                Kind::File
            } else {
                return Err(CompareError::Unsupported(path));
            };
            if result.len() >= MAX_ENTRIES {
                return Err(CompareError::Limit(path));
            }
            if kind == Kind::Directory {
                pending.push((relative_path.clone(), depth + 1));
            }
            result.insert(relative_path, kind);
        }
    }
    Ok(result)
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub(super) struct Block {
    pub(super) hash: [u8; 32],
    pub(super) length: usize,
}
pub(super) struct Manifest {
    pub(super) hash: [u8; 32],
    pub(super) blocks: Vec<Block>,
    pub(super) size: u64,
}

pub(super) fn same_version(a: &Metadata, b: &Metadata) -> bool {
    let basic = a.len() == b.len() && a.modified().ok() == b.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        basic
            && a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        basic
    }
}

pub(super) fn manifest(path: &Path, chunk_size: usize) -> Result<Manifest, CompareError> {
    let before = fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
    if !before.is_file() {
        return Err(CompareError::Unsupported(path.to_owned()));
    }
    if before.len().div_ceil(chunk_size as u64) > MAX_BLOCKS_PER_FILE {
        return Err(CompareError::Limit(path.to_owned()));
    }
    let mut file = File::open(path).map_err(|e| io_error(path, e))?;
    let opened = file.metadata().map_err(|e| io_error(path, e))?;
    if !same_version(&before, &opened) {
        return Err(CompareError::Changed(path.to_owned()));
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0; chunk_size];
    let mut blocks = Vec::new();
    let mut size = 0;
    loop {
        let mut used = 0;
        while used < chunk_size {
            match file.read(&mut buffer[used..]) {
                Ok(0) => break,
                Ok(n) => used += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(io_error(path, e)),
            }
        }
        if used == 0 {
            break;
        }
        if blocks.len() as u64 >= MAX_BLOCKS_PER_FILE {
            return Err(CompareError::Limit(path.to_owned()));
        }
        size += used as u64;
        if size > before.len() {
            return Err(CompareError::Changed(path.to_owned()));
        }
        hash.update(&buffer[..used]);
        blocks.push(Block {
            hash: Sha256::digest(&buffer[..used]).into(),
            length: used,
        });
    }
    let after = file.metadata().map_err(|e| io_error(path, e))?;
    let named = fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
    if size != before.len()
        || !named.is_file()
        || !same_version(&before, &after)
        || !same_version(&before, &named)
    {
        return Err(CompareError::Changed(path.to_owned()));
    }
    Ok(Manifest {
        hash: hash.finalize().into(),
        blocks,
        size,
    })
}

/// Hashes all files involved in a comparison. Never modifies either directory.
/// Reuse estimates consider blocks in the same target file, even at other offsets.
/// There is no common baseline yet, so UpdateFile means a difference, NOT permission
/// to overwrite. Concurrent changes between files require rerunning the comparison.
pub fn compare_directories(
    source: &Path,
    target: &Path,
    chunk_size: usize,
) -> Result<Plan, CompareError> {
    if !(4096..=1024 * 1024).contains(&chunk_size) {
        return Err(CompareError::ChunkSize);
    }
    let source_files = inventory(source)?;
    let mut target_files = inventory(target)?;
    let mut plan = Plan {
        chunk_size,
        entries: Vec::new(),
        missing_bytes: 0,
        reusable_bytes: 0,
        read_only: true,
    };
    let mut blocked = Vec::<PathBuf>::new();
    for (relative, source_kind) in source_files {
        let target_kind = target_files.remove(&relative);
        let mut entry = Entry {
            path: relative
                .to_str()
                .expect("validated UTF-8")
                .replace(std::path::MAIN_SEPARATOR, "/"),
            action: Action::Unchanged,
            source_bytes: 0,
            missing_bytes: 0,
            reusable_bytes: 0,
        };
        if blocked.iter().any(|parent| relative.starts_with(parent)) {
            entry.action = Action::TypeConflict;
        } else if target_kind.is_some_and(|kind| kind != source_kind) {
            entry.action = Action::TypeConflict;
            blocked.push(relative.clone());
        } else if source_kind == Kind::Directory {
            if target_kind.is_none() {
                entry.action = Action::CreateDirectory;
            }
        } else {
            let source_manifest = manifest(&source.join(&relative), chunk_size)?;
            entry.source_bytes = source_manifest.size;
            if target_kind.is_none() {
                entry.action = Action::CreateFile;
                entry.missing_bytes = source_manifest.size;
            } else {
                let target_manifest = manifest(&target.join(&relative), chunk_size)?;
                if source_manifest.hash == target_manifest.hash
                    && source_manifest.size == target_manifest.size
                {
                    entry.reusable_bytes = source_manifest.size;
                } else {
                    entry.action = Action::UpdateFile;
                    let existing: HashSet<_> = target_manifest.blocks.into_iter().collect();
                    for block in source_manifest.blocks {
                        if existing.contains(&block) {
                            entry.reusable_bytes += block.length as u64;
                        } else {
                            entry.missing_bytes += block.length as u64;
                        }
                    }
                }
            }
        }
        plan.missing_bytes += entry.missing_bytes;
        plan.reusable_bytes += entry.reusable_bytes;
        plan.entries.push(entry);
    }
    for (relative, _) in target_files {
        plan.entries.push(Entry {
            path: relative
                .to_str()
                .expect("validated UTF-8")
                .replace(std::path::MAIN_SEPARATOR, "/"),
            action: Action::TargetOnly,
            source_bytes: 0,
            missing_bytes: 0,
            reusable_bytes: 0,
        });
    }
    plan.entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn single_byte_change_only_requires_one_block() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        let original: Vec<u8> = (0..3).flat_map(|v| vec![v; 4096]).collect();
        fs::write(b.path().join("data"), &original).unwrap();
        let mut changed = original;
        changed[4100] = 5;
        fs::write(a.path().join("data"), changed).unwrap();
        let plan = compare_directories(a.path(), b.path(), 4096).unwrap();
        assert_eq!(plan.missing_bytes, 4096);
        assert_eq!(plan.reusable_bytes, 8192);
        assert_eq!(plan.entries[0].action, Action::UpdateFile);
    }

    #[test]
    fn repeated_blocks_can_reuse_other_offsets_and_truncate() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        fs::write(a.path().join("data"), vec![1; 4096]).unwrap();
        fs::write(
            b.path().join("data"),
            [vec![0; 4096], vec![1; 4096]].concat(),
        )
        .unwrap();
        let plan = compare_directories(a.path(), b.path(), 4096).unwrap();
        assert_eq!(plan.missing_bytes, 0);
        assert_eq!(plan.entries[0].action, Action::UpdateFile);
    }

    #[test]
    fn empty_files_directories_and_target_only_are_preserved() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        fs::write(a.path().join("empty"), []).unwrap();
        fs::write(b.path().join("empty"), []).unwrap();
        fs::write(b.path().join("local"), b"keep").unwrap();
        fs::create_dir(a.path().join("目录")).unwrap();
        fs::write(a.path().join("目录/new"), b"new").unwrap();
        let plan = compare_directories(a.path(), b.path(), 4096).unwrap();
        assert_eq!(plan.missing_bytes, 3);
        assert_eq!(plan.entries[0].action, Action::Unchanged);
        assert_eq!(plan.entries[1].action, Action::TargetOnly);
        assert_eq!(fs::read(b.path().join("local")).unwrap(), b"keep");
        assert!(!b.path().join("目录").exists());
    }

    #[test]
    fn content_not_size_determines_equality() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        fs::write(a.path().join("same"), b"abcd").unwrap();
        fs::write(b.path().join("same"), b"dcba").unwrap();
        let plan = compare_directories(a.path(), b.path(), 4096).unwrap();
        assert_eq!(plan.missing_bytes, 4);
        fs::create_dir(a.path().join("kind")).unwrap();
        fs::write(b.path().join("kind"), []).unwrap();
        let plan = compare_directories(a.path(), b.path(), 4096).unwrap();
        assert_eq!(plan.entries[0].action, Action::TypeConflict);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks() {
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        std::os::unix::fs::symlink(b.path(), a.path().join("escape")).unwrap();
        assert!(matches!(
            compare_directories(a.path(), b.path(), 4096),
            Err(CompareError::Unsupported(_))
        ));
    }
}
