use super::{
    compare::manifest,
    remote::{CHUNK, MAX_FILE, MAX_FILES, Message, Offer, Report, Version, read, write},
};
use crate::{crypto::direct::Error, protocol::frame::Framed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use tempfile::{Builder, NamedTempFile};
use tokio::io::{AsyncRead, AsyncWrite};

const STATE_LIMIT: u64 = 16 * 1024 * 1024;

pub(super) fn validate_path(path: &str) -> Result<(), Error> {
    if path.is_empty() || path.len() > 1024 || path.split('/').count() > 128 {
        return Err("invalid relative path".into());
    }
    for part in path.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.eq_ignore_ascii_case(".cayman")
            || part.ends_with(['.', ' '])
            || part.contains(['\\', ':'])
            || part.chars().any(char::is_control)
        {
            return Err("unsafe or reserved relative path".into());
        }
    }
    Ok(())
}

pub(super) fn validate_offer(offer: &Offer) -> Result<(), Error> {
    validate_path(&offer.path)?;
    if offer.version.size > MAX_FILE
        || offer.blocks.len()
            != if offer.directory {
                0
            } else {
                offer.version.size.div_ceil(CHUNK as u64) as usize
            }
    {
        return Err("invalid file size or block count".into());
    }
    if offer.directory && (offer.version.size != 0 || offer.version.hash != [0; 32]) {
        return Err("invalid directory offer".into());
    }
    Ok(())
}

pub(super) fn validate_summary(offer: &Offer) -> Result<(), Error> {
    validate_path(&offer.path)?;
    if !offer.blocks.is_empty()
        || offer.version.size > MAX_FILE
        || (offer.directory && (offer.version.size != 0 || offer.version.hash != [0; 32]))
    {
        return Err("invalid file summary".into());
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    path: String,
    desired: Version,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    format: u32,
    baseline: BTreeMap<String, Version>,
    pending: Option<Pending>,
}

pub(super) struct Storage {
    root: PathBuf,
    internal: PathBuf,
    state: State,
    replace_existing: bool,
    _lock: File,
    cache: super::cache::ManifestCache,
}

fn sync_dir(path: &Path) -> Result<(), Error> {
    File::open(path)?.sync_all()?;
    Ok(())
}

impl Storage {
    pub fn open(root: &Path, replace_existing: bool) -> Result<Self, Error> {
        if !cfg!(unix) {
            return Err("receiver writes currently require Unix directory locks and fsync".into());
        }
        fs::create_dir_all(root)?;
        if !fs::symlink_metadata(root)?.is_dir() {
            return Err("output must be a real directory".into());
        }
        let root = root.canonicalize()?;
        let lock = File::open(&root)?;
        lock.try_lock()
            .map_err(|_| "another receiver owns this output directory")?;
        let internal = root.join(".cayman");
        if !internal.try_exists()? {
            fs::create_dir(&internal)?;
        }
        if !fs::symlink_metadata(&internal)?.is_dir() {
            return Err("invalid receiver state directory".into());
        }
        let state_path = internal.join("state.json");
        let state = match fs::symlink_metadata(&state_path) {
            Ok(m) => {
                if !m.is_file() || m.len() > STATE_LIMIT {
                    return Err("invalid receiver state".into());
                }
                let mut bytes = Vec::new();
                File::open(&state_path)?
                    .take(STATE_LIMIT + 1)
                    .read_to_end(&mut bytes)?;
                if bytes.len() as u64 > STATE_LIMIT {
                    return Err("receiver state too large".into());
                }
                let state: State = serde_json::from_slice(&bytes)?;
                if state.format != 1 || state.baseline.len() > MAX_FILES {
                    return Err("unsupported receiver state".into());
                }
                for path in state.baseline.keys() {
                    validate_path(path)?;
                }
                state
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if fs::read_dir(&internal)?.next().is_some() {
                    return Err(
                        "refusing to adopt nonempty .cayman directory without valid state".into(),
                    );
                }
                State {
                    format: 1,
                    baseline: BTreeMap::new(),
                    pending: None,
                }
            }
            Err(e) => return Err(e.into()),
        };
        let mut storage = Self {
            root,
            internal,
            state,
            replace_existing,
            _lock: lock,
            cache: super::cache::ManifestCache::default(),
        };
        if let Some(pending) = storage.state.pending.take() {
            validate_path(&pending.path)?;
            if let Some(path) = storage.path(&pending.path)?
                && storage.version(&path)?.as_ref() == Some(&pending.desired)
            {
                storage.state.baseline.insert(pending.path, pending.desired);
            }
        }
        storage.save()?;
        sync_dir(&storage.root)?;
        for entry in fs::read_dir(&storage.internal)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if entry.file_type()?.is_file()
                && (name.starts_with(".stage-") || name.starts_with(".state-"))
            {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(storage)
    }

    fn save(&self) -> Result<(), Error> {
        if self.state.baseline.len() > MAX_FILES {
            return Err("baseline capacity exceeded".into());
        }
        let data = serde_json::to_vec(&self.state)?;
        if data.len() as u64 > STATE_LIMIT {
            return Err("state too large".into());
        }
        let mut temp = Builder::new()
            .prefix(".state-")
            .tempfile_in(&self.internal)?;
        temp.write_all(&data)?;
        temp.as_file().sync_all()?;
        temp.persist(self.internal.join("state.json"))
            .map_err(|e| e.error)?;
        sync_dir(&self.internal)
    }

    pub(super) fn clear_cache(&mut self) {
        self.cache.clear();
    }

    fn path(&self, relative: &str) -> Result<Option<PathBuf>, Error> {
        validate_path(relative)?;
        // Local roots are trusted; reject symlinks/types at every observed component.
        // Directory-handle-based protection against hostile local renames is future work.
        if !fs::symlink_metadata(&self.root)?.is_dir() {
            return Err("output root disappeared".into());
        }
        let mut path = self.root.clone();
        let parts: Vec<_> = relative.split('/').collect();
        for (index, part) in parts.iter().enumerate() {
            path.push(part);
            match fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_symlink() => return Ok(None),
                Ok(m) if index + 1 < parts.len() && !m.is_dir() => return Ok(None),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound && index + 1 == parts.len() => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(Some(path))
    }

    fn version(&self, path: &Path) -> Result<Option<Version>, Error> {
        match fs::symlink_metadata(path) {
            Ok(m) if m.is_file() => {
                if m.len() > MAX_FILE {
                    return Err("existing target file exceeds size limit".into());
                }
                let m = manifest(path, CHUNK)?;
                Ok(Some(Version {
                    hash: m.hash,
                    size: m.size,
                }))
            }
            Ok(_) => Err("target is not a regular file".into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn conflict<S: AsyncRead + AsyncWrite + Unpin>(
        io: &mut Framed<S>,
        report: &mut Report,
        path: String,
    ) -> Result<(), Error> {
        report.conflicts.push(path);
        write(io, &Message::Conflict).await
    }

    #[cfg(test)]
    pub async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        io: &mut Framed<S>,
        offer: Offer,
        report: &mut Report,
    ) -> Result<(), Error> {
        self.handle_with_progress(io, offer, report, &mut |_, _| {})
            .await
    }

    pub async fn handle_with_progress<S: AsyncRead + AsyncWrite + Unpin>(
        &mut self,
        io: &mut Framed<S>,
        mut offer: Offer,
        report: &mut Report,
        progress: &mut impl FnMut(u64, u64),
    ) -> Result<(), Error> {
        validate_summary(&offer)?;
        let Some(path) = self.path(&offer.path)? else {
            return Self::conflict(io, report, offer.path).await;
        };
        let metadata = match fs::symlink_metadata(&path) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        if offer.directory {
            if metadata.as_ref().is_some_and(|m| !m.is_dir()) {
                return Self::conflict(io, report, offer.path).await;
            }
            if metadata.is_none() {
                progress(0, 0);
                fs::create_dir(&path)?;
                sync_dir(path.parent().ok_or("missing parent")?)?;
            }
            return write(io, &Message::Skip).await;
        }
        if metadata.as_ref().is_some_and(|m| !m.is_file()) {
            return Self::conflict(io, report, offer.path).await;
        }
        if metadata.as_ref().is_some_and(|m| m.len() > MAX_FILE) {
            return Err("existing target file exceeds size limit".into());
        }
        let existing = if metadata.is_some() {
            let m = self.cache.get(&path, CHUNK)?;
            Some(Version {
                hash: m.hash,
                size: m.size,
            })
        } else {
            None
        };
        if existing.as_ref() == Some(&offer.version) {
            if self.state.baseline.get(&offer.path) != Some(&offer.version) {
                self.state.baseline.insert(offer.path, offer.version);
                self.save()?;
            }
            report.unchanged += 1;
            return write(io, &Message::Skip).await;
        }
        let baseline = self.state.baseline.get(&offer.path);
        if existing.as_ref() != baseline
            && !(baseline.is_none() && existing.is_some() && self.replace_existing)
        {
            return Self::conflict(io, report, offer.path).await;
        }
        if !self.state.baseline.contains_key(&offer.path) && self.state.baseline.len() >= MAX_FILES
        {
            return Err("baseline capacity exceeded".into());
        }
        write(io, &Message::NeedBlocks).await?;
        let Message::Blocks { hashes } = read(io).await? else {
            return Err("expected requested block list".into());
        };
        offer.blocks = hashes;
        validate_offer(&offer)?;
        let mut staged = Builder::new()
            .prefix(".stage-")
            .tempfile_in(&self.internal)?;
        staged.as_file().set_len(offer.version.size)?;
        let mut needed = Vec::new();
        let mut reused = 0_u64;
        let mut old_blocks = HashMap::new();
        let mut old = None;
        if existing.is_some() {
            let m = self.cache.get(&path, CHUNK)?;
            for (i, block) in m.blocks.iter().enumerate() {
                old_blocks
                    .entry((block.hash, block.length))
                    .or_insert(i as u64 * CHUNK as u64);
            }
            old = Some(File::open(&path)?);
        }
        let mut buffer = vec![0; CHUNK];
        for (index, expected) in offer.blocks.iter().enumerate() {
            let offset = index as u64 * CHUNK as u64;
            let len = (offer.version.size - offset).min(CHUNK as u64) as usize;
            if let Some(&old_offset) = old_blocks.get(&(*expected, len)) {
                let file = old.as_mut().ok_or("missing reusable file")?;
                file.seek(SeekFrom::Start(old_offset))?;
                file.read_exact(&mut buffer[..len])?;
                let actual: [u8; 32] = Sha256::digest(&buffer[..len]).into();
                if actual != *expected {
                    return Err("local reusable block changed".into());
                }
                staged.seek(SeekFrom::Start(offset))?;
                staged.write_all(&buffer[..len])?;
                reused += len as u64;
            } else {
                needed.push(index);
            }
        }
        write(
            io,
            &Message::Need {
                indices: needed.clone(),
            },
        )
        .await?;
        progress(0, offer.version.size - reused);
        let mut transferred = 0_u64;
        for expected_index in needed {
            let Message::Data { index, bytes } = read(io).await? else {
                return Err("expected requested block".into());
            };
            let offset = expected_index as u64 * CHUNK as u64;
            let len = (offer.version.size - offset).min(CHUNK as u64) as usize;
            if index != expected_index || bytes.len() != len {
                return Err("unexpected block index or length".into());
            }
            let hash: [u8; 32] = Sha256::digest(&bytes).into();
            if hash != offer.blocks[index] {
                return Err("block integrity failure".into());
            }
            staged.seek(SeekFrom::Start(offset))?;
            staged.write_all(&bytes)?;
            transferred += len as u64;
            progress(transferred, offer.version.size - reused);
        }
        if !matches!(read(io).await?, Message::Finish) {
            return Err("expected file finish".into());
        }
        if self.version(staged.path())?.as_ref() != Some(&offer.version) {
            return Err("whole-file integrity failure".into());
        }
        staged.as_file().sync_all()?;
        if self.path(&offer.path)?.is_none() || self.version(&path)? != existing {
            return Self::conflict(io, report, offer.path).await;
        }
        if let Some(version) = &existing {
            self.backup(&path, &offer.path, version)?;
        }
        self.state.pending = Some(Pending {
            path: offer.path.clone(),
            desired: offer.version.clone(),
        });
        self.save()?;
        self.install(staged, &path, existing.is_some())?;
        self.state.baseline.insert(offer.path, offer.version);
        self.state.pending = None;
        self.save()?;
        report.installed += 1;
        report.transferred_bytes += transferred;
        report.reused_bytes += reused;
        write(io, &Message::Committed).await
    }

    fn install(&self, staged: NamedTempFile, path: &Path, replace: bool) -> Result<(), Error> {
        if replace {
            staged.persist(path).map_err(|e| e.error)?;
        } else {
            staged.persist_noclobber(path).map_err(|e| e.error)?;
        }
        sync_dir(path.parent().ok_or("missing parent")?)?;
        sync_dir(&self.internal)
    }

    fn backup(&self, target: &Path, relative: &str, expected: &Version) -> Result<(), Error> {
        let mut history = Builder::new()
            .prefix("history-")
            .tempfile_in(&self.internal)?;
        io::copy(
            &mut File::open(target)?.take(expected.size + 1),
            &mut history,
        )?;
        history.as_file().sync_all()?;
        if self.version(history.path())?.as_ref() != Some(expected) {
            return Err("target changed while backing up".into());
        }
        let (_, saved) = history.keep().map_err(|e| e.error)?;
        let mut info = Builder::new()
            .prefix("backup-info-")
            .tempfile_in(&self.internal)?;
        serde_json::to_writer(
            &mut info,
            &serde_json::json!({"path": relative, "file": saved.file_name(), "version": expected}),
        )?;
        info.as_file().sync_all()?;
        info.keep().map_err(|e| e.error)?;
        sync_dir(&self.internal)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn untrusted_paths_and_offer_shapes_are_rejected() {
        for path in [
            "",
            "/tmp/file",
            "../file",
            "a/../file",
            "a//b",
            "a\\b",
            ".cayman/state.json",
            "a/./b",
            "a:",
            "file\n",
        ] {
            assert!(validate_path(path).is_err(), "{path:?}");
        }
        validate_path("目录/file.txt").unwrap();
        let mut offer = Offer {
            path: "file".into(),
            directory: false,
            version: Version {
                hash: [0; 32],
                size: 1,
            },
            blocks: vec![],
        };
        assert!(validate_offer(&offer).is_err());
        offer.blocks.push([0; 32]);
        assert!(validate_offer(&offer).is_ok());
        offer.version.size = MAX_FILE + 1;
        assert!(validate_offer(&offer).is_err());
    }

    #[test]
    fn lock_and_symlink_guards_and_journal_recovery() {
        let output = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let mut storage = Storage::open(output.path(), false).unwrap();
        assert!(Storage::open(output.path(), false).is_err());
        std::os::unix::fs::symlink(outside.path(), output.path().join("escape")).unwrap();
        assert!(storage.path("escape/file").unwrap().is_none());
        fs::write(output.path().join("file"), b"installed").unwrap();
        let version = storage
            .version(&output.path().join("file"))
            .unwrap()
            .unwrap();
        storage.state.pending = Some(Pending {
            path: "file".into(),
            desired: version.clone(),
        });
        storage.save().unwrap();
        drop(storage);
        let storage = Storage::open(output.path(), false).unwrap();
        assert!(storage.state.pending.is_none());
        assert!(storage.state.baseline.get("file") == Some(&version));
    }
}
