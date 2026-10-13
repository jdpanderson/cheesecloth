//! Unix: the local API on a Unix domain socket that any local user may open
//! (0666). The daemon decides what each client may do from its peer
//! credentials (`Gate`).

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, bail};

use super::Access;
use crate::{
    Options,
    api::{ApiError, ErrorCode},
};

mod group;

pub(crate) use group::Group;

pub(crate) type ServerStream = tokio::net::UnixStream;
pub(crate) type ClientStream = tokio::net::UnixStream;

pub(super) fn default_address(state_dir: &Path) -> io::Result<PathBuf> {
    Ok(state_dir.join("control.sock"))
}

/// Decides what a client may do: root and the daemon's own user may do
/// everything, members of the API group may do all but `stop`.
pub(crate) struct Gate {
    /// The daemon's effective user.
    pub(super) me: libc::uid_t,
    pub(super) group: Option<Arc<Group>>,
}

impl Gate {
    /// Looks up the API group of `opts`. Fails if it does not exist.
    pub(crate) fn new(opts: &Options) -> Result<Self> {
        let group = match opts.api_group.as_deref() {
            Some(name) => Some(Arc::new(
                Group::resolve(name).context("the API group (--api-group)")?,
            )),
            None => None,
        };
        Ok(Self {
            me: effective_uid(),
            group,
        })
    }

    pub(crate) async fn access(&self, stream: &ServerStream) -> Access {
        let uid = match stream.peer_cred() {
            Ok(cred) => cred.uid(),
            Err(e) => {
                return Access::Refused(ApiError::new(
                    ErrorCode::AccessCheckFailed,
                    format!("can't tell who is connecting: {e}"),
                ));
            }
        };
        if uid == 0 || uid == self.me {
            return Access::Full;
        }
        let refused = || {
            Access::Refused(ApiError::new(
                ErrorCode::PermissionDenied,
                match &self.group {
                    Some(group) => format!(
                        "only root and members of the group {} may use the cheesecloth daemon",
                        group.name
                    ),
                    None => "only root may use the cheesecloth daemon".into(),
                },
            ))
        };
        let Some(group) = self.group.clone() else {
            return refused();
        };
        // The lookup may ask a directory service, so it runs off the
        // runtime's threads.
        let member = tokio::task::spawn_blocking(move || group.has_member(uid))
            .await
            .map_err(io::Error::other)
            .flatten();
        match member {
            Ok(true) => Access::Operator,
            Ok(false) => refused(),
            Err(e) => Access::Refused(ApiError::new(
                ErrorCode::AccessCheckFailed,
                format!("can't look up the groups of uid {uid}: {e}"),
            )),
        }
    }
}

#[allow(unsafe_code, reason = "the standard library has no geteuid")]
pub(super) fn effective_uid() -> libc::uid_t {
    // SAFETY: geteuid takes nothing and can't fail.
    unsafe { libc::geteuid() }
}

pub(crate) struct Listener(tokio::net::UnixListener);

impl Listener {
    /// Binds the local API socket at `path`, open to every local user
    /// (0666); `Gate` decides what each may do. The socket is created in a
    /// private staging directory and then moved into place, so it replaces a
    /// stale socket in one step. Refuses to replace the socket of a running
    /// daemon.
    pub(crate) fn bind(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            bail!(
                "another cheesecloth daemon is already listening on {}",
                path.display()
            );
        }
        let parent = path.parent().context("socket path has no directory")?;
        let staging = parent.join(format!(".cheesecloth-socket-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&staging);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&staging)
            .with_context(|| format!("creating {}", staging.display()))?;
        let result = (|| {
            let tmp = staging.join("control.sock");
            let listener = tokio::net::UnixListener::bind(&tmp)
                .with_context(|| format!("binding {}", tmp.display()))?;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666))?;
            std::fs::rename(&tmp, path)
                .with_context(|| format!("moving the socket to {}", path.display()))?;
            Ok(Self(listener))
        })();
        let _ = std::fs::remove_dir_all(&staging);
        result
    }

    pub(crate) async fn accept(&mut self) -> io::Result<ServerStream> {
        Ok(self.0.accept().await?.0)
    }
}

pub(super) async fn connect(socket: &Path) -> Result<ClientStream> {
    tokio::net::UnixStream::connect(socket)
        .await
        .with_context(|| super::unreachable_message(socket))
}
