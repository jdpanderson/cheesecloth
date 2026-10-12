//! Unix groups, for the local API's operator check. Membership counts
//! supplementary groups: a macOS user's primary group is `staff`, and `admin`
//! is supplementary.

use std::{ffi::CString, io, mem::MaybeUninit, ptr};

use anyhow::{Context, Result, bail};

/// A group, looked up by name when the daemon starts.
#[derive(Debug)]
pub(crate) struct Group {
    pub(crate) name: String,
    pub(crate) gid: libc::gid_t,
}

impl Group {
    /// Looks up the group `name`. Fails if there is none.
    #[allow(unsafe_code, reason = "the standard library has no group lookup")]
    pub(crate) fn resolve(name: &str) -> Result<Self> {
        let c_name = CString::new(name).context("a group name can't hold a NUL byte")?;
        let mut buf = vec![0 as libc::c_char; 1024];
        loop {
            let mut group = MaybeUninit::<libc::group>::uninit();
            let mut found: *mut libc::group = ptr::null_mut();
            // SAFETY: c_name is NUL-terminated, group and found are valid
            // places to write, and buf is writable for buf.len() bytes.
            let err = unsafe {
                libc::getgrnam_r(
                    c_name.as_ptr(),
                    group.as_mut_ptr(),
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut found,
                )
            };
            match err {
                0 if found.is_null() => bail!("there is no group {name:?}"),
                // SAFETY: getgrnam_r found the group and filled in group.
                0 => {
                    return Ok(Self {
                        name: name.into(),
                        gid: unsafe { group.assume_init() }.gr_gid,
                    });
                }
                libc::ERANGE if buf.len() < MAX_BUF => buf.resize(buf.len() * 2, 0),
                err => {
                    return Err(io::Error::from_raw_os_error(err))
                        .with_context(|| format!("looking up the group {name:?}"));
                }
            }
        }
    }

    /// Whether the user `uid` is in this group. It may block: it can ask a
    /// directory service.
    pub(crate) fn has_member(&self, uid: libc::uid_t) -> io::Result<bool> {
        os::has_member(self.gid, uid)
    }
}

/// The largest buffer for a group or user record.
const MAX_BUF: usize = 1 << 20;

#[cfg(target_os = "macos")]
mod os {
    use std::{ffi::c_int, io};

    /// `uuid_t` from `<uuid/uuid.h>`.
    type Uuid = [u8; 16];

    // From `<membership.h>`, in libSystem.
    #[allow(unsafe_code, reason = "the libc crate does not declare these")]
    unsafe extern "C" {
        fn mbr_uid_to_uuid(uid: libc::uid_t, uu: *mut u8) -> c_int;
        fn mbr_gid_to_uuid(gid: libc::gid_t, uu: *mut u8) -> c_int;
        fn mbr_check_membership(user: *const u8, group: *const u8, ismember: *mut c_int) -> c_int;
    }

    /// Asks Directory Services, which knows nested and network groups and
    /// has no limit on the number of groups.
    #[allow(unsafe_code, reason = "the membership calls are C functions")]
    pub(super) fn has_member(gid: libc::gid_t, uid: libc::uid_t) -> io::Result<bool> {
        let check = |err: c_int| match err {
            0 => Ok(()),
            err => Err(io::Error::from_raw_os_error(err)),
        };
        let mut user: Uuid = [0; 16];
        let mut group: Uuid = [0; 16];
        let mut member: c_int = 0;
        // SAFETY: each pointer is to a live 16-byte array or a c_int, which
        // the calls write to or read from, and nothing more.
        unsafe {
            check(mbr_uid_to_uuid(uid, user.as_mut_ptr()))?;
            check(mbr_gid_to_uuid(gid, group.as_mut_ptr()))?;
            check(mbr_check_membership(
                user.as_ptr(),
                group.as_ptr(),
                &mut member,
            ))?;
        }
        Ok(member != 0)
    }
}

#[cfg(not(target_os = "macos"))]
mod os {
    use std::{io, mem::MaybeUninit, ptr};

    use super::MAX_BUF;

    /// Looks up the user's name and primary group, then the groups that list
    /// the user (`getgrouplist`).
    #[allow(
        unsafe_code,
        reason = "the standard library has no user or group lookup"
    )]
    pub(super) fn has_member(gid: libc::gid_t, uid: libc::uid_t) -> io::Result<bool> {
        let mut buf = vec![0 as libc::c_char; 1024];
        let mut user = MaybeUninit::<libc::passwd>::uninit();
        loop {
            let mut found: *mut libc::passwd = ptr::null_mut();
            // SAFETY: user and found are valid places to write, and buf is
            // writable for buf.len() bytes.
            let err = unsafe {
                libc::getpwuid_r(
                    uid,
                    user.as_mut_ptr(),
                    buf.as_mut_ptr(),
                    buf.len(),
                    &mut found,
                )
            };
            match err {
                // A uid with no user has no supplementary groups.
                0 if found.is_null() => return Ok(false),
                0 => break,
                libc::ERANGE if buf.len() < MAX_BUF => buf.resize(buf.len() * 2, 0),
                err => return Err(io::Error::from_raw_os_error(err)),
            }
        }
        // SAFETY: getpwuid_r found the user and filled in user. Its strings
        // point into buf, which lives until the end of this function.
        let user = unsafe { user.assume_init() };
        if user.pw_gid == gid {
            return Ok(true);
        }
        let mut groups: Vec<libc::gid_t> = vec![0; 64];
        loop {
            let mut count = groups.len() as libc::c_int;
            // SAFETY: pw_name is a NUL-terminated string in buf, groups is
            // writable for count entries, and count is a valid place to
            // write.
            let n = unsafe {
                libc::getgrouplist(user.pw_name, user.pw_gid, groups.as_mut_ptr(), &mut count)
            };
            if n >= 0 {
                groups.truncate(count as usize);
                return Ok(groups.contains(&gid));
            }
            // Too few entries. Linux sets count to the number needed; other
            // systems do not, so grow it at least twofold.
            let needed = (count as usize).max(groups.len() * 2);
            if needed > MAX_BUF {
                return Err(io::Error::other("the user is in too many groups"));
            }
            groups.resize(needed, 0);
        }
    }
}
