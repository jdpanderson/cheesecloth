use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::*;
use crate::testing::within;

#[tokio::test]
async fn a_client_and_the_server_exchange_lines() {
    let dir = tempfile::tempdir().unwrap();
    let addr = default_address(dir.path()).unwrap();
    let mut listener = Listener::bind(&addr).unwrap();
    let server = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let (read, mut write) = tokio::io::split(stream);
        let line = BufReader::new(read).lines().next_line().await.unwrap();
        write
            .write_all(format!("{}!\n", line.unwrap()).as_bytes())
            .await
            .unwrap();
    });
    let client = within(connect(&addr)).await.unwrap();
    let (read, mut write) = tokio::io::split(client);
    write.write_all(b"hello\n").await.unwrap();
    let mut lines = BufReader::new(read).lines();
    assert_eq!(
        within(lines.next_line()).await.unwrap().as_deref(),
        Some("hello!")
    );
    within(server).await.unwrap();
}

#[tokio::test]
async fn a_second_listener_on_a_live_address_fails() {
    let dir = tempfile::tempdir().unwrap();
    let addr = default_address(dir.path()).unwrap();
    let mut first = Listener::bind(&addr).unwrap();
    let err = Listener::bind(&addr).err().expect("a second bind fails");
    assert!(format!("{err:#}").contains("already listening"), "{err:#}");
    // The first listener still serves.
    let server = tokio::spawn(async move { first.accept().await.unwrap() });
    within(connect(&addr)).await.unwrap();
    within(server).await.unwrap();
}

#[test]
fn the_default_address_is_stable_for_one_directory() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        default_address(dir.path()).unwrap(),
        default_address(dir.path()).unwrap()
    );
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    use crate::{
        api::ErrorCode,
        ipc::unix::{Group, effective_uid},
    };

    #[tokio::test]
    async fn every_local_user_may_open_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let addr = default_address(dir.path()).unwrap();
        let _listener = Listener::bind(&addr).unwrap();
        let mode = std::fs::metadata(&addr).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o666);
    }

    #[allow(unsafe_code, reason = "the standard library has no getegid")]
    fn effective_gid() -> libc::gid_t {
        // SAFETY: getegid takes nothing and can't fail.
        unsafe { libc::getegid() }
    }

    /// What the gate allows this process, when the daemon runs as `me` with
    /// the API group `group`.
    async fn access_as(me: libc::uid_t, group: Option<Group>) -> Access {
        let gate = Gate {
            me,
            group: group.map(std::sync::Arc::new),
        };
        let (server, _client) = tokio::net::UnixStream::pair().unwrap();
        within(gate.access(&server)).await
    }

    /// A uid that is not this process's, for a daemon run by someone else.
    fn someone_else() -> libc::uid_t {
        // Root may do everything, so the refusals can't be seen as root.
        assert_ne!(
            effective_uid(),
            0,
            "these tests need a user other than root"
        );
        effective_uid() + 1
    }

    #[tokio::test]
    async fn the_daemons_own_user_may_do_everything() {
        assert_eq!(access_as(effective_uid(), None).await, Access::Full);
    }

    #[tokio::test]
    async fn without_a_group_others_are_refused() {
        let Access::Refused(why) = access_as(someone_else(), None).await else {
            panic!("allowed");
        };
        assert_eq!(why.code, ErrorCode::PermissionDenied);
    }

    /// This process's supplementary groups: not its primary group.
    #[allow(unsafe_code, reason = "the standard library has no getgroups")]
    fn supplementary_gids() -> Vec<libc::gid_t> {
        let mut gids: Vec<libc::gid_t> = vec![0; 1024];
        // SAFETY: gids is writable for its length.
        let n = unsafe { libc::getgroups(gids.len() as libc::c_int, gids.as_mut_ptr()) };
        assert!(n >= 0, "getgroups: {}", std::io::Error::last_os_error());
        gids.truncate(n as usize);
        gids.retain(|&g| g != effective_gid());
        gids
    }

    #[tokio::test]
    async fn members_of_a_supplementary_group_are_operators() {
        let gids = supplementary_gids();
        assert!(
            !gids.is_empty(),
            "these tests need a user with a supplementary group"
        );
        for gid in gids {
            let group = Group {
                name: "supplementary".into(),
                gid,
            };
            assert_eq!(
                access_as(someone_else(), Some(group)).await,
                Access::Operator,
                "gid {gid}"
            );
        }
    }

    #[tokio::test]
    async fn members_of_the_primary_group_are_operators() {
        let group = Group {
            name: "mine".into(),
            gid: effective_gid(),
        };
        assert_eq!(
            access_as(someone_else(), Some(group)).await,
            Access::Operator
        );
    }

    #[tokio::test]
    async fn others_are_refused_and_told_the_group() {
        // No user is in a group with this gid.
        let group = Group {
            name: "nobody-here".into(),
            gid: 3_999_999_999,
        };
        let Access::Refused(why) = access_as(someone_else(), Some(group)).await else {
            panic!("allowed");
        };
        assert_eq!(why.code, ErrorCode::PermissionDenied);
        // The message names the group, so a person knows what to ask for.
        assert!(why.message.contains("nobody-here"), "{why}");
    }

    #[test]
    fn a_group_is_found_by_name() {
        let root = if cfg!(target_os = "macos") {
            "wheel"
        } else {
            "root"
        };
        assert_eq!(Group::resolve(root).unwrap().gid, 0);
        let err = Group::resolve("no-such-group-cheesecloth").unwrap_err();
        assert!(err.to_string().contains("no group"), "{err}");
    }
}

#[cfg(windows)]
mod windows {
    #![allow(unsafe_code, reason = "the tests read access lists with windows-sys")]

    use std::{
        os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
        path::Path,
        ptr,
    };

    use cheesecloth_core::fs::windows::{
        Elevation, PIPE_CLIENT_ACCESS, SecurityDescriptor, TokenUser, administrators,
        current_token, take_local_string,
    };
    use windows_sys::Win32::{
        Foundation::{HANDLE, LocalFree},
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_KERNEL_OBJECT,
            },
            CheckTokenMembership, CreateRestrictedToken, CreateWellKnownSid,
            DACL_SECURITY_INFORMATION, EqualSid, ImpersonateLoggedOnUser, IsWellKnownSid,
            PSECURITY_DESCRIPTOR, RevertToSelf, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE,
            TOKEN_IMPERSONATE, TOKEN_QUERY, WinBuiltinAdministratorsSid, WinLocalServiceSid,
            WinLocalSystemSid,
        },
        Storage::FileSystem::FILE_APPEND_DATA,
    };

    use super::*;
    use crate::ipc::windows::{is_trusted, is_trusted_owner, pipe_name};

    #[test]
    fn the_pipe_name_comes_from_a_hash_of_the_directory() {
        let name = pipe_name(r"C:\PROGRAMDATA\CHEESECLOTH");
        let name = name.to_str().unwrap();
        let hex = name.strip_prefix(r"\\.\pipe\cheesecloth-").expect(name);
        assert_eq!(hex.len(), 32, "{name}");
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(
            pipe_name(r"C:\PROGRAMDATA\CHEESECLOTH"),
            pipe_name(r"C:\PROGRAMDATA\CHEESECLOTH2")
        );
    }

    // A client that is not elevated may not open the state directory, so
    // the address must not need to.
    #[test]
    fn the_default_address_does_not_open_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let expected = default_address(&missing).unwrap();
        std::fs::create_dir(&missing).unwrap();
        assert_eq!(default_address(&missing).unwrap(), expected);
    }

    #[test]
    fn one_directory_spelled_two_ways_has_one_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("State");
        std::fs::create_dir(&path).unwrap();
        let expected = default_address(&path).unwrap();
        assert_eq!(default_address(&path.join(".")).unwrap(), expected);
        let lower = dir.path().join("state");
        assert_eq!(default_address(&lower).unwrap(), expected);
        let other = tempfile::tempdir().unwrap();
        assert_ne!(default_address(other.path()).unwrap(), expected);
    }

    #[tokio::test]
    async fn an_address_that_is_not_a_pipe_is_refused() {
        for addr in [r"C:\ProgramData\cheesecloth\control.sock", r"\\.\pipe\"] {
            let err = Listener::bind(Path::new(addr)).err().expect(addr);
            assert!(
                format!("{err:#}").contains("must be a pipe name"),
                "{err:#}"
            );
            let err = connect(Path::new(addr)).await.unwrap_err();
            assert!(
                format!("{err:#}").contains("must be a pipe name"),
                "{err:#}"
            );
        }
    }

    /// The DACL of `sd` as an SDDL string.
    fn dacl(sd: PSECURITY_DESCRIPTOR) -> String {
        let mut s = ptr::null_mut();
        // SAFETY: sd is a valid descriptor and s is a valid place to write.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut s,
                ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        // SAFETY: the call allocated s with LocalAlloc, and only this code
        // uses it.
        unsafe { take_local_string(s) }.unwrap()
    }

    #[tokio::test]
    async fn a_pipe_prefix_in_upper_case_works() {
        let dir = tempfile::tempdir().unwrap();
        let addr = default_address(dir.path()).unwrap();
        let addr = addr.to_str().unwrap().replacen(r"\pipe\", r"\PIPE\", 1);
        let mut listener = Listener::bind(Path::new(&addr)).unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        within(connect(Path::new(&addr))).await.unwrap();
        within(server).await.unwrap();
    }

    #[tokio::test]
    async fn the_pipe_lets_in_interactive_users_but_not_as_servers() {
        let dir = tempfile::tempdir().unwrap();
        let addr = default_address(dir.path()).unwrap();
        let listener = Listener::bind(&addr).unwrap();
        let mut sd = ptr::null_mut();
        // SAFETY: the handle is open while listener lives, and sd is a valid
        // place to write; the other outputs are optional.
        let status = unsafe {
            GetSecurityInfo(
                listener.next.as_raw_handle(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            )
        };
        assert_eq!(status, 0, "{}", io::Error::from_raw_os_error(status as i32));
        let got = dacl(sd);
        // SAFETY: GetSecurityInfo allocated sd with LocalAlloc.
        unsafe { LocalFree(sd) };
        let expected = dacl(SecurityDescriptor::local_api_pipe().unwrap().as_ptr());
        assert!(
            expected.starts_with("D:P(A;;FA;;;SY)(A;;FA;;;BA)"),
            "{expected}"
        );
        // Interactive users may read and write data; FILE_APPEND_DATA, which
        // creates pipe instances, is not in their mask.
        assert!(expected.ends_with(";;;IU)"), "{expected}");
        assert_eq!(PIPE_CLIENT_ACCESS & FILE_APPEND_DATA, 0);
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn the_gate_lets_this_user_do_everything() {
        let dir = tempfile::tempdir().unwrap();
        let addr = default_address(dir.path()).unwrap();
        let mut listener = Listener::bind(&addr).unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        let _client = within(connect(&addr)).await.unwrap();
        let stream = within(server).await.unwrap();
        let gate =
            Gate::new(&crate::Options::new(dir.path().into(), Some("t".into())).unwrap()).unwrap();
        assert_eq!(within(gate.access(&stream)).await, Access::Full);
    }

    /// With Administrators made "deny only", a token looks like a
    /// non-elevated administrator's: an operator, but not trusted. GitHub's
    /// Windows runners are elevated, so there this tests that case.
    #[test]
    fn an_administrator_who_is_not_elevated_is_an_operator() {
        let token = current_token(TOKEN_DUPLICATE | TOKEN_QUERY).unwrap();
        let admin = administrators(token.as_handle()).unwrap().is_some();
        let restricted = without_administrators(&token);
        let expected = admin.then_some(Elevation::DenyOnly);
        assert_eq!(administrators(restricted.as_handle()).unwrap(), expected);
    }

    /// A client that is not elevated may open the pipe and read its owner.
    /// GitHub's Windows runners are elevated, so there this tests that case.
    /// The daemon here is this process, which such a client may open, so
    /// this does not test a daemon that runs as SYSTEM: the installer checks
    /// in cheesecloth-windows do.
    #[tokio::test]
    async fn a_client_that_is_not_elevated_may_connect() {
        let dir = tempfile::tempdir().unwrap();
        let addr = default_address(dir.path()).unwrap();
        let mut listener = Listener::bind(&addr).unwrap();
        let server = tokio::spawn(async move { listener.accept().await.unwrap() });
        let token = current_token(TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY).unwrap();
        let restricted = without_administrators(&token);
        // SAFETY: restricted is an open token. The test runs on one thread,
        // and connect does not wait between the two calls, so only connect
        // runs as the restricted token.
        let ok = unsafe { ImpersonateLoggedOnUser(restricted.as_raw_handle()) };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        let client = connect(&addr).await;
        // SAFETY: RevertToSelf takes nothing.
        assert_ne!(unsafe { RevertToSelf() }, 0);
        let _client = client.unwrap();
        within(server).await.unwrap();
    }

    /// A copy of `token` with the Administrators group for deny only.
    fn without_administrators(token: &OwnedHandle) -> OwnedHandle {
        let mut admins = well_known(WinBuiltinAdministratorsSid);
        let disable = SID_AND_ATTRIBUTES {
            Sid: admins.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let mut restricted: HANDLE = ptr::null_mut();
        // SAFETY: the token is open, disable points at one valid entry, and
        // restricted is a valid place to write.
        let ok = unsafe {
            CreateRestrictedToken(
                token.as_raw_handle(),
                0,
                1,
                &disable,
                0,
                ptr::null(),
                0,
                ptr::null(),
                &mut restricted,
            )
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        // SAFETY: the call succeeded, so restricted is an open handle we own.
        unsafe { OwnedHandle::from_raw_handle(restricted) }
    }

    /// A well-known SID.
    fn well_known(kind: i32) -> [u32; 17] {
        let mut sid = [0u32; 17];
        let mut size = size_of_val(&sid) as u32;
        // SAFETY: sid is valid for size bytes and aligned for a SID.
        let ok = unsafe {
            CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr().cast(), &mut size)
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        sid
    }

    #[test]
    fn a_token_of_this_user_is_trusted() {
        let me = TokenUser::current().unwrap();
        let token = current_token(TOKEN_QUERY).unwrap();
        assert!(is_trusted(token.as_handle(), me.sid()).unwrap());
    }

    /// The test runs as a user that is not LocalService, so only the
    /// Administrators group can make it trusted. GitHub's Windows runners are
    /// elevated, so there this tests the trusted case.
    #[test]
    fn a_token_with_administrators_enabled_is_trusted() {
        let mut admins = well_known(WinBuiltinAdministratorsSid);
        let mut is_admin = 0;
        // SAFETY: a null token means this thread's token, admins is a valid
        // SID, and is_admin is a valid place to write.
        let ok = unsafe {
            CheckTokenMembership(ptr::null_mut(), admins.as_mut_ptr().cast(), &mut is_admin)
        };
        assert_ne!(ok, 0, "{}", io::Error::last_os_error());
        let token = current_token(TOKEN_QUERY).unwrap();
        let mut other = well_known(WinLocalServiceSid);
        assert_eq!(
            is_trusted(token.as_handle(), other.as_mut_ptr().cast()).unwrap(),
            is_admin != 0
        );
    }

    #[test]
    fn a_token_of_another_user_without_administrators_is_refused() {
        let token = current_token(TOKEN_DUPLICATE | TOKEN_QUERY).unwrap();
        let restricted = without_administrators(&token);
        // The "user" `me` is LocalService, so only the Administrators group
        // could make the token trusted.
        let mut other = well_known(WinLocalServiceSid);
        assert!(!is_trusted(restricted.as_handle(), other.as_mut_ptr().cast()).unwrap());
    }

    #[test]
    fn only_system_administrators_and_this_user_are_trusted_owners() {
        let me = TokenUser::current().unwrap();
        let mut system = well_known(WinLocalSystemSid);
        let mut admins = well_known(WinBuiltinAdministratorsSid);
        let mut other = well_known(WinLocalServiceSid);
        assert!(is_trusted_owner(me.sid(), me.sid()));
        assert!(is_trusted_owner(system.as_mut_ptr().cast(), me.sid()));
        assert!(is_trusted_owner(admins.as_mut_ptr().cast(), me.sid()));
        assert!(!is_trusted_owner(other.as_mut_ptr().cast(), me.sid()));
    }

    /// An elevated daemon gives the pipe to Administrators, so that other
    /// administrators trust it. GitHub's Windows runners are elevated, so
    /// there this tests that case.
    #[tokio::test]
    async fn the_pipe_owner_is_administrators_when_elevated_or_else_this_user() {
        let dir = tempfile::tempdir().unwrap();
        let listener = Listener::bind(&default_address(dir.path()).unwrap()).unwrap();
        let sd = SecurityDescriptor::owner_of(listener.next.as_handle()).unwrap();
        let owner = sd.owner().unwrap();
        let token = current_token(TOKEN_QUERY).unwrap();
        let me = TokenUser::current().unwrap();
        // SAFETY: owner and me's SID are valid while sd and me live.
        let is_expected = unsafe {
            if administrators(token.as_handle()).unwrap() == Some(Elevation::Enabled) {
                IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
            } else {
                EqualSid(owner, me.sid()) != 0
            }
        };
        assert!(is_expected);
    }
}
