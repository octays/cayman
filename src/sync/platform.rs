use std::{
    fs::{self, File, Metadata},
    io,
    path::Path,
};

pub(super) fn is_link(meta: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Includes junctions and other reparse points, not just symbolic links.
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

pub(super) fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // Windows has no portable directory fsync. File contents and journals
        // are flushed before atomic replacement; power-loss guarantees differ.
        let _ = path;
        Ok(())
    }
}

pub(super) fn lock_root(root: &Path, internal: &Path) -> io::Result<File> {
    #[cfg(unix)]
    let file = {
        let _ = internal;
        File::open(root)?
    };
    #[cfg(not(unix))]
    let file = {
        let _ = root;
        let path = internal.join("receiver.lock");
        if let Ok(meta) = fs::symlink_metadata(&path)
            && (is_link(&meta) || !meta.is_file())
        {
            return Err(io::Error::other("unsafe lock file"));
        }
        File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?
    };
    file.try_lock()
        .map_err(|e| io::Error::other(format!("output directory is locked: {e}")))?;
    Ok(file)
}

pub(super) fn real_directory(path: &Path) -> io::Result<bool> {
    let meta = fs::symlink_metadata(path)?;
    Ok(meta.is_dir() && !is_link(&meta))
}
