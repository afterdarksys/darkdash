//! Private-file checks.
//!
//! Threats: a symlink, a group-readable file, or a file owned by another uid
//! must not be read as a pin, token, key, audit log, or status document.
//! The check is lstat, then open, then fstat, and the device and inode must
//! match. That closes a swap that lands between the two stats. It does not
//! close the later SQLite open of `signals.db`, which takes a path. That
//! remaining window is recorded in SECURITY.md.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use zeroize::Zeroize;

use crate::error::Error;

const MODE_FILE: u32 = 0o600;
const MODE_DIR: u32 = 0o700;

pub fn current_euid() -> Result<u32, Error> {
    let out = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map_err(|_| Error::Config("euid"))?;
    if !out.status.success() {
        return Err(Error::Config("euid"));
    }
    let text = std::str::from_utf8(&out.stdout)
        .map_err(|_| Error::Config("euid"))?
        .trim();
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
        return Err(Error::Config("euid"));
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Config("euid"));
    }
    text.parse().map_err(|_| Error::Config("euid"))
}

pub fn clean_abs(raw: &str) -> Result<PathBuf, Error> {
    if raw.is_empty() || raw.len() > 512 || raw.as_bytes().contains(&0) || !raw.starts_with('/') {
        return Err(Error::Config("path"));
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(Error::Config("path"));
    }
    let mut normals = 0u32;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => {
                if part.is_empty() || part.to_str().is_none() {
                    return Err(Error::Config("path"));
                }
                normals = normals.saturating_add(1);
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(Error::Config("path"));
            }
        }
    }
    if normals == 0 {
        return Err(Error::Config("path"));
    }
    Ok(path.to_path_buf())
}

pub fn is_inside(path: &Path, dir: &Path) -> bool {
    path.starts_with(dir)
}

fn perm_exact(mode: u32, expect: u32) -> bool {
    mode & 0o7777 == expect
}

fn file_meta_ok(meta: &fs::Metadata, euid: u32, max_len: u64) -> bool {
    meta.file_type().is_file()
        && !meta.file_type().is_symlink()
        && meta.uid() == euid
        && perm_exact(meta.mode(), MODE_FILE)
        && meta.len() <= max_len
}

fn same_inode(pre: &fs::Metadata, post: &fs::Metadata) -> bool {
    pre.dev() == post.dev() && pre.ino() == post.ino()
}

/// Confirm `path` is a regular 0600 file owned by the euid, then return an
/// open handle whose fstat matches the pre-open lstat.
pub fn open_private(path: &Path, max_len: u64) -> Result<File, Error> {
    let euid = current_euid()?;
    let pre = fs::symlink_metadata(path)?;
    if pre.file_type().is_symlink() || !file_meta_ok(&pre, euid, max_len) {
        return Err(Error::Config("mode"));
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let post = file.metadata()?;
    if !same_inode(&pre, &post) || !file_meta_ok(&post, euid, max_len) {
        return Err(Error::Config("mode"));
    }
    Ok(file)
}

pub fn read_private(path: &Path, max_len: u64) -> Result<Vec<u8>, Error> {
    let mut file = open_private(path, max_len)?;
    let stated = file.metadata()?.len();
    let mut buf = Vec::new();
    std::io::Read::take(&mut file, stated.saturating_add(1)).read_to_end(&mut buf)?;
    let got = u64::try_from(buf.len()).map_err(|_| Error::Config("size"))?;
    if got != stated {
        buf.zeroize();
        return Err(Error::Config("size"));
    }
    Ok(buf)
}

pub fn check_dir_0700(path: &Path) -> Result<(), Error> {
    let euid = current_euid()?;
    let pre = fs::symlink_metadata(path)?;
    if pre.file_type().is_symlink() || !pre.file_type().is_dir() {
        return Err(Error::Config("mode"));
    }
    if pre.uid() != euid || !perm_exact(pre.mode(), MODE_DIR) {
        return Err(Error::Config("mode"));
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let post = file.metadata()?;
    if !same_inode(&pre, &post)
        || !post.file_type().is_dir()
        || post.uid() != euid
        || !perm_exact(post.mode(), MODE_DIR)
    {
        return Err(Error::Config("mode"));
    }
    Ok(())
}

/// Create a new 0600 file. An existing path is refused, including a symlink.
pub fn write_private_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(Error::Config("exists"));
    }
    let euid = current_euid()?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(MODE_FILE)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(MODE_FILE))?;
    let post = file.metadata()?;
    if !post.file_type().is_file() || post.uid() != euid || !perm_exact(post.mode(), MODE_FILE) {
        return Err(Error::Config("mode"));
    }
    let pre = fs::symlink_metadata(path)?;
    if pre.file_type().is_symlink() || !same_inode(&pre, &post) {
        return Err(Error::Config("mode"));
    }
    Ok(())
}

/// Append one line to a 0600 audit file, creating it if needed.
pub fn append_private_line(path: &Path, line: &str, max_len: u64) -> Result<(), Error> {
    if line.contains('\n') || line.contains('\r') || line.len() > 2048 {
        return Err(Error::Config("audit"));
    }
    let euid = current_euid()?;
    match fs::symlink_metadata(path) {
        Ok(pre) => {
            if pre.file_type().is_symlink() || !file_meta_ok(&pre, euid, max_len) {
                return Err(Error::Config("mode"));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            write_private_new(path, b"")?;
        }
        Err(err) => return Err(err.into()),
    }
    let pre = fs::symlink_metadata(path)?;
    if pre.file_type().is_symlink() || !file_meta_ok(&pre, euid, max_len) {
        return Err(Error::Config("mode"));
    }
    let mut file = OpenOptions::new().append(true).open(path)?;
    let post = file.metadata()?;
    if !same_inode(&pre, &post) || !file_meta_ok(&post, euid, max_len) {
        return Err(Error::Config("mode"));
    }
    let extra = u64::try_from(line.len()).unwrap_or(u64::MAX);
    if post.len().saturating_add(extra).saturating_add(1) > max_len {
        return Err(Error::Config("audit"));
    }
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp")
    }

    #[test]
    fn rejects_a_symlink_and_a_group_readable_file() {
        let dir = scratch();
        let target = dir.path().join("target");
        fs::write(&target, b"secret").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();
        assert!(open_private(&link, 64).is_err());

        let loose = dir.path().join("loose");
        fs::write(&loose, b"secret").unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(open_private(&loose, 64).is_err());
    }

    #[test]
    fn open_matches_the_inode_it_stated() {
        let dir = scratch();
        let path = dir.path().join("pin");
        write_private_new(&path, b"abc").unwrap();
        let file = open_private(&path, 64).unwrap();
        let opened = file.metadata().unwrap();
        let stated = fs::symlink_metadata(&path).unwrap();
        assert!(same_inode(&stated, &opened));
        assert_eq!(opened.mode() & 0o777, 0o600);

        let other = dir.path().join("other");
        write_private_new(&other, b"xyz").unwrap();
        let other_meta = fs::symlink_metadata(&other).unwrap();
        assert!(!same_inode(&stated, &other_meta));
    }

    #[test]
    fn relative_and_parent_paths_are_refused() {
        assert!(clean_abs("relative").is_err());
        assert!(clean_abs("/tmp/../etc/passwd").is_err());
        assert!(clean_abs("/").is_err());
        assert!(clean_abs("/var/lib/darkdash").is_ok());
    }
}
