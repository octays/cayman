//! Native notification hints, always backed by periodic reconciliation.
use crate::crypto::direct::Error;
use std::path::Path;

pub(super) struct Watch {
    native: Option<Native>,
}
impl Watch {
    pub fn new(root: &Path) -> Self {
        match Native::new(root) {
            Ok(native) => Self {
                native: Some(native),
            },
            Err(error) => {
                eprintln!("Native watcher unavailable ({error}); using metadata polling.");
                Self { native: None }
            }
        }
    }
    pub fn changed(&mut self) -> bool {
        match self.native.as_mut().map(Native::changed) {
            Some(Ok(changed)) => changed,
            Some(Err(_)) => {
                self.native = None;
                true
            }
            None => true,
        }
    }
    pub fn is_native(&self) -> bool {
        self.native.is_some()
    }
}

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(target_os = "macos")]
use std::fs::File;

#[cfg(target_os = "macos")]
struct Native {
    queue: OwnedFd,
    _files: Vec<File>,
}
#[cfg(target_os = "macos")]
impl Native {
    fn new(root: &Path) -> Result<Self, Error> {
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: kqueue returned a new owned descriptor.
        let queue = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut paths = vec![root.to_owned()];
        if root.is_dir() {
            paths.extend(
                super::compare::inventory(root)?
                    .into_keys()
                    .map(|p| root.join(p)),
            );
        }
        let mut files = Vec::new();
        for path in paths {
            let file = File::open(path)?;
            let event = libc::kevent {
                ident: file.as_raw_fd() as usize,
                filter: libc::EVFILT_VNODE,
                flags: libc::EV_ADD | libc::EV_CLEAR,
                fflags: libc::NOTE_WRITE
                    | libc::NOTE_EXTEND
                    | libc::NOTE_ATTRIB
                    | libc::NOTE_DELETE
                    | libc::NOTE_RENAME
                    | libc::NOTE_REVOKE,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            // SAFETY: pointers refer to one initialized event, no output array.
            if unsafe {
                libc::kevent(
                    queue.as_raw_fd(),
                    &event,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            } < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            files.push(file);
        }
        Ok(Self {
            queue,
            _files: files,
        })
    }
    fn changed(&mut self) -> Result<bool, Error> {
        let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
        let wait = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid queue, space for one event and a zero-timeout poll.
        let n = unsafe {
            libc::kevent(
                self.queue.as_raw_fd(),
                std::ptr::null(),
                0,
                event.as_mut_ptr(),
                1,
                &wait,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(n > 0)
    }
}

#[cfg(target_os = "linux")]
struct Native {
    fd: OwnedFd,
}
#[cfg(target_os = "linux")]
impl Native {
    fn new(root: &Path) -> Result<Self, Error> {
        use std::os::unix::ffi::OsStrExt;
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut paths = vec![root.to_owned()];
        if root.is_dir() {
            paths.extend(
                super::compare::inventory(root)?
                    .into_iter()
                    .filter(|(_, kind)| *kind == super::compare::Kind::Directory)
                    .map(|(p, _)| root.join(p)),
            );
        } else if let Some(parent) = root.parent() {
            paths.push(parent.to_owned());
        }
        for path in paths {
            let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
            let mask = libc::IN_CLOSE_WRITE
                | libc::IN_MODIFY
                | libc::IN_ATTRIB
                | libc::IN_CREATE
                | libc::IN_DELETE
                | libc::IN_MOVED_FROM
                | libc::IN_MOVED_TO
                | libc::IN_DELETE_SELF
                | libc::IN_MOVE_SELF;
            if unsafe { libc::inotify_add_watch(fd.as_raw_fd(), name.as_ptr(), mask) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(Self { fd })
    }
    fn changed(&mut self) -> Result<bool, Error> {
        let mut buffer = [0_u8; 8192];
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if n >= 0 {
            return Ok(n > 0);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(error.into())
        }
    }
}

#[cfg(windows)]
struct Native {
    handle: windows_sys::Win32::Foundation::HANDLE,
}
#[cfg(windows)]
impl Native {
    fn new(root: &Path) -> Result<Self, Error> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        let directory = if root.is_dir() {
            root
        } else {
            root.parent().ok_or("missing parent")?
        };
        let name: Vec<u16> = directory.as_os_str().encode_wide().chain(Some(0)).collect();
        let handle = unsafe {
            FindFirstChangeNotificationW(
                name.as_ptr(),
                1,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_SIZE
                    | FILE_NOTIFY_CHANGE_LAST_WRITE
                    | FILE_NOTIFY_CHANGE_ATTRIBUTES,
            )
        };
        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { handle })
    }
    fn changed(&mut self) -> Result<bool, Error> {
        use windows_sys::Win32::{
            Foundation::*, Storage::FileSystem::FindNextChangeNotification,
            System::Threading::WaitForSingleObject,
        };
        match unsafe { WaitForSingleObject(self.handle, 0) } {
            WAIT_OBJECT_0 => {
                if unsafe { FindNextChangeNotification(self.handle) } == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                Ok(true)
            }
            WAIT_TIMEOUT => Ok(false),
            _ => Err(std::io::Error::last_os_error().into()),
        }
    }
}
#[cfg(windows)]
impl Drop for Native {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Storage::FileSystem::FindCloseChangeNotification(self.handle);
        }
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
struct Native;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl Native {
    fn new(_: &Path) -> Result<Self, Error> {
        Err("native watcher not implemented on this platform".into())
    }
    fn changed(&mut self) -> Result<bool, Error> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_events_report_file_writes_and_new_entries() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("file");
        std::fs::write(&path, b"before").unwrap();
        let mut watch = Native::new(root.path()).unwrap();
        std::fs::write(&path, b"after").unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !watch.changed().unwrap() {
            assert!(
                std::time::Instant::now() < until,
                "native watcher missed file write"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::fs::write(root.path().join("new"), b"new file").unwrap();
        while !watch.changed().unwrap() {
            assert!(
                std::time::Instant::now() < until,
                "native watcher missed creation"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
