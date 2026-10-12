//! Windows: the local API on a named pipe. SYSTEM, Administrators, the
//! daemon's user and interactive users may open it; remote clients may not.
//! The daemon decides what each client may do from its token (`Gate`), and
//! the CLI checks who serves the pipe before it sends a request.

use std::{
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use cheesecloth_core::fs::windows::{
    PIPE_CLIENT_ACCESS, SecurityDescriptor, TokenUser, token_information,
};
use data_encoding::HEXLOWER;
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, ERROR_PIPE_BUSY, HANDLE, INVALID_HANDLE_VALUE},
    Security::{
        EqualSid, IsWellKnownSid, PSID, RevertToSelf, SID_AND_ATTRIBUTES, TOKEN_GROUPS,
        TOKEN_QUERY, TokenGroups, WinBuiltinAdministratorsSid,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    },
    System::{
        Pipes::{GetNamedPipeServerProcessId, ImpersonateNamedPipeClient},
        SystemServices::{SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY},
        Threading::{
            GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

pub(crate) type ServerStream = NamedPipeServer;
pub(crate) type ClientStream = NamedPipeClient;

/// Every pipe name starts with this, in any letter case.
const PIPE_PREFIX: &str = r"\\.\pipe\";

pub(super) fn default_address(state_dir: &Path) -> io::Result<PathBuf> {
    Ok(pipe_name(&std::fs::canonicalize(state_dir)?))
}

/// `\\.\pipe\cheesecloth-<hex>`, where hex is from a hash of `canonical`, so
/// that each state directory has its own pipe.
pub(super) fn pipe_name(canonical: &Path) -> PathBuf {
    let hash = blake3::hash(canonical.as_os_str().as_encoded_bytes());
    let hex = HEXLOWER.encode(&hash.as_bytes()[..16]);
    format!("{PIPE_PREFIX}cheesecloth-{hex}").into()
}

/// Refuses an address that is not a pipe name.
fn check_address(addr: &Path) -> Result<()> {
    let is_pipe = |name: &str| {
        name.len() > PIPE_PREFIX.len()
            && name
                .get(..PIPE_PREFIX.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PIPE_PREFIX))
    };
    if !addr.to_str().is_some_and(is_pipe) {
        bail!(
            "the local API address on Windows must be a pipe name that starts with {PIPE_PREFIX}, \
             not {}",
            addr.display()
        );
    }
    Ok(())
}

/// Decides what a client may do, from its token: SYSTEM, the daemon's user
/// and elevated administrators may do everything; administrators who are not
/// elevated may do all but `stop`.
pub(crate) struct Gate {
    /// The daemon's user.
    me: TokenUser,
}

impl Gate {
    pub(crate) fn new(_opts: &crate::Options) -> Result<Self> {
        Ok(Self {
            me: TokenUser::current().context("finding the daemon's user")?,
        })
    }

    pub(crate) async fn access(&self, stream: &ServerStream) -> super::Access {
        let access = client_token(stream).and_then(|token| {
            if is_trusted(token.as_handle(), self.me.sid())? {
                return Ok(super::Access::Full);
            }
            Ok(match administrators(token.as_handle())? {
                Some(_) => super::Access::Operator,
                None => super::Access::Refused(
                    "only administrators may use the cheesecloth daemon".into(),
                ),
            })
        });
        access.unwrap_or_else(|e| {
            super::Access::Refused(format!("can't tell who is connecting: {e}"))
        })
    }
}

/// The token of the client connected to `pipe`. The calling thread acts as
/// the client only between two calls, with nothing in between that can wait.
#[allow(unsafe_code, reason = "windows-sys has no safe impersonation calls")]
fn client_token(pipe: &NamedPipeServer) -> io::Result<OwnedHandle> {
    // SAFETY: the pipe handle is open while pipe lives.
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: token is a valid place to write. OpenAsSelf (1) checks access
    // as the daemon, not as the client.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    let error = io::Error::last_os_error();
    // SAFETY: RevertToSelf takes nothing.
    if unsafe { RevertToSelf() } == 0 {
        // The thread would go on as the client. Nothing safe can follow.
        std::process::abort();
    }
    if opened == 0 {
        return Err(error);
    }
    // SAFETY: the call succeeded, so token is an open handle we now own.
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

/// The server end of the pipe. It always holds one instance that waits for
/// the next client.
pub(crate) struct Listener {
    name: PathBuf,
    security: SecurityDescriptor,
    /// Visible to the tests, which read its access list.
    pub(super) next: NamedPipeServer,
}

impl Listener {
    /// Creates the pipe `name` as its first instance, so it fails if another
    /// process has the name.
    pub(crate) fn bind(name: &Path) -> Result<Self> {
        check_address(name)?;
        let security =
            SecurityDescriptor::local_api_pipe().context("building the pipe's access list")?;
        let next = create(name, &security, true).map_err(|e| {
            if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                anyhow!(
                    "another cheesecloth daemon is already listening on {}",
                    name.display()
                )
            } else {
                anyhow::Error::new(e).context(format!("creating the pipe {}", name.display()))
            }
        })?;
        Ok(Self {
            name: name.to_owned(),
            security,
            next,
        })
    }

    /// Waits for a client, then makes a new instance for the next one.
    pub(crate) async fn accept(&mut self) -> io::Result<ServerStream> {
        self.next.connect().await?;
        let next = create(&self.name, &self.security, false)?;
        Ok(std::mem::replace(&mut self.next, next))
    }
}

/// Creates one instance of the pipe `name`, with the access list of
/// `security`, for local clients only.
#[allow(
    unsafe_code,
    reason = "tokio takes the security attributes as a raw pointer"
)]
fn create(name: &Path, security: &SecurityDescriptor, first: bool) -> io::Result<NamedPipeServer> {
    let mut attributes = security.attributes();
    // SAFETY: attributes is a valid SECURITY_ATTRIBUTES, and its descriptor
    // lives as long as security; the call only reads them.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, (&raw mut attributes).cast())
    }
}

pub(super) async fn connect(name: &Path) -> Result<ClientStream> {
    check_address(name)?;
    let client = open(name).await.map_err(|e| {
        let message = if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            super::unreachable_message_with(
                name,
                "only interactive users, administrators and SYSTEM may open it",
            )
        } else {
            super::unreachable_message(name)
        };
        anyhow::Error::new(e).context(message)
    })?;
    check_server(&client, name)?;
    Ok(client)
}

/// Opens the pipe. While all instances are busy, it waits for a free one for
/// up to 2 s, as the named pipe protocol asks.
async fn open(name: &Path) -> io::Result<NamedPipeClient> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match open_once(name) {
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && Instant::now() < deadline => {}
            result => return result,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Opens the pipe with `PIPE_CLIENT_ACCESS` only. tokio's `ClientOptions`
/// asks for `GENERIC_WRITE`, which the access list does not give
/// interactive users. The daemon may identify the client, but not act as it.
#[allow(unsafe_code, reason = "windows-sys has no safe CreateFileW")]
fn open_once(name: &Path) -> io::Result<NamedPipeClient> {
    let wide: Vec<u16> = name.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: wide is NUL-terminated and lives across the call; the other
    // pointers are null, which CreateFileW allows.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            PIPE_CLIENT_ACCESS,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: handle is a new, open pipe handle in overlapped mode, which the
    // client now owns.
    unsafe { NamedPipeClient::from_raw_handle(handle) }
}

/// Refuses a pipe server that does not run as SYSTEM, an administrator or
/// this user. Another user could otherwise take the pipe name first and read
/// the requests.
#[allow(unsafe_code, reason = "windows-sys has no safe process or token calls")]
fn check_server(pipe: &NamedPipeClient, name: &Path) -> Result<()> {
    let finding = || format!("finding the process that serves {}", name.display());
    let mut pid = 0;
    // SAFETY: the pipe handle is open while pipe lives, and pid is a valid
    // place to write.
    if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error()).with_context(finding);
    }
    // SAFETY: OpenProcess takes no pointers.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error()).with_context(finding);
    }
    // SAFETY: the call succeeded, so process is an open handle we now own.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: process is an open handle and token is a valid place to write.
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error()).with_context(finding);
    }
    // SAFETY: the call succeeded, so token is an open handle we now own.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let me = TokenUser::current().context("finding this process's user")?;
    if !is_trusted(token.as_handle(), me.sid()).with_context(finding)? {
        bail!(
            "the process serving {} (pid {pid}) does not run as SYSTEM, an administrator or this \
             user; refusing to send the request",
            name.display()
        );
    }
    Ok(())
}

/// Whether the token is LocalSystem, the user `me`, or a member of
/// Administrators with that group enabled (elevated).
#[allow(unsafe_code, reason = "windows-sys has no safe SID calls")]
pub(super) fn is_trusted(token: BorrowedHandle<'_>, me: PSID) -> io::Result<bool> {
    let user = TokenUser::of(token)?;
    // SAFETY: both SIDs are valid while user and the caller's owner live.
    if user.is_system() || unsafe { EqualSid(user.sid(), me) } != 0 {
        return Ok(true);
    }
    Ok(administrators(token)? == Some(Elevation::Enabled))
}

/// How a token holds the Administrators group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Elevation {
    /// Enabled: an elevated administrator.
    Enabled,
    /// For deny only: an administrator who is not elevated (UAC).
    DenyOnly,
}

/// Whether the token holds the Administrators group, and how. None if it
/// does not.
#[allow(unsafe_code, reason = "windows-sys has no safe SID calls")]
pub(super) fn administrators(token: BorrowedHandle<'_>) -> io::Result<Option<Elevation>> {
    let buf = token_information(token, TokenGroups)?;
    let groups = buf.as_ptr().cast::<TOKEN_GROUPS>();
    // SAFETY: buf holds the TOKEN_GROUPS that GetTokenInformation wrote, with
    // GroupCount entries in a row from Groups, and is aligned for it.
    let groups = unsafe {
        std::slice::from_raw_parts(
            (&raw const (*groups).Groups).cast::<SID_AND_ATTRIBUTES>(),
            (*groups).GroupCount as usize,
        )
    };
    // SAFETY: g.Sid points into buf, which is alive.
    let admins = groups
        .iter()
        .find(|g| unsafe { IsWellKnownSid(g.Sid, WinBuiltinAdministratorsSid) } != 0);
    Ok(admins.and_then(|g| {
        if g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY as u32 != 0 {
            Some(Elevation::DenyOnly)
        } else if g.Attributes & SE_GROUP_ENABLED as u32 != 0 {
            Some(Elevation::Enabled)
        } else {
            None
        }
    }))
}
