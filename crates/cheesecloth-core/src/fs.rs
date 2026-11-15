//! Private files and directories, and directory sync. The OS code is in
//! `fs/unix.rs` and `fs/windows.rs`.

use std::{io, path::Path};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as os;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
use windows as os;

/// Creates `dir` and its parents. Only this user, root or SYSTEM, and on
/// Windows Administrators, may use `dir` (0700 on Unix). An existing `dir`
/// gets the same permissions.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    os::create_private_dir(dir)
}

/// Writes a file that only this user, root or SYSTEM, and on Windows
/// Administrators, may read (0600 on Unix). The file is written beside
/// `path` and then renamed, so `path` always holds a whole file.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    // A file left by an earlier attempt would keep its permissions, so the
    // new file is always created from nothing.
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    {
        use std::io::Write;
        let mut f = os::create_private_file(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Reads the 32-byte key stored at `path`. If there is no file, makes a key
/// with `generate` and stores it there (see `write_private`). The one way a
/// node's keys are loaded.
pub fn load_or_create_key(
    path: &Path,
    generate: impl FnOnce() -> [u8; 32],
) -> io::Result<[u8; 32]> {
    match std::fs::read(path) {
        Ok(bytes) => bytes.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} must be 32 bytes", path.display()),
            )
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = generate();
            write_private(path, &key)?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

/// Makes the creation, renaming and removal of files in `dir` durable. On
/// Windows it does nothing: see `fs/windows.rs`.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    os::sync_dir(dir)
}

#[cfg(test)]
mod tests;
