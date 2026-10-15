//! The daemon's state directory.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use cheesecloth_core::{
    ClusterId,
    fs::{sync_dir, write_private},
    token::TokenPeer,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// A join waiting for approvals.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingJoin {
    pub proposal: cheesecloth_core::ProposalId,
    pub peers: Vec<TokenPeer>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterFile {
    pub cluster_id: ClusterId,
    #[serde(default)]
    pub pending: Option<PendingJoin>,
}

/// Durable local cleanup intent. It survives partial consensus-file deletion
/// and prevents restart from rejoining a cluster this process already left.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cleanup {
    pub cluster_id: ClusterId,
    pub interface: String,
    pub backend: Option<cheesecloth_wg::BackendKind>,
    pub remaining_members: usize,
    pub forget_cluster: bool,
}

#[derive(Clone, Debug)]
pub struct Files {
    pub dir: PathBuf,
}

impl Files {
    pub fn new(dir: &Path) -> Result<Self> {
        cheesecloth_core::fs::create_private_dir(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        // Other users may pass through (0711), but not list it, to reach the
        // local API socket inside. The keys and state files stay 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711))
                .with_context(|| format!("setting the permissions of {}", dir.display()))?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn identity(&self) -> PathBuf {
        self.dir.join("identity.key")
    }

    pub fn wg_key(&self) -> PathBuf {
        self.dir.join("wireguard.key")
    }

    pub fn cluster(&self) -> PathBuf {
        self.dir.join("cluster.json")
    }

    pub fn cleanup(&self) -> PathBuf {
        self.dir.join("cleanup.json")
    }

    pub fn load_cleanup(&self) -> Result<Option<Cleanup>> {
        load_json(&self.cleanup())
    }

    pub fn save_cleanup(&self, cleanup: &Cleanup) -> Result<()> {
        self.save_json(&self.cleanup(), cleanup)
    }

    pub fn finish_cleanup(&self, forget_cluster: bool) -> Result<()> {
        if forget_cluster {
            self.delete_cluster()?;
        }
        self.remove_files([self.cleanup()])?;
        sync_dir(&self.dir)?;
        Ok(())
    }

    /// This node's acceptor state (see `pnyx::store`), which holds the latest
    /// agreed state this node has learned. pnyx decides which files it uses.
    pub fn acceptor(&self) -> PathBuf {
        self.dir.join("acceptor")
    }

    /// The transitions this node has checked (see `node::proof`).
    pub fn transitions(&self) -> PathBuf {
        self.dir.join("transitions.bin")
    }

    pub fn load_cluster(&self) -> Result<Option<ClusterFile>> {
        load_json(&self.cluster())
    }

    pub fn save_cluster(&self, c: &ClusterFile) -> Result<()> {
        self.save_json(&self.cluster(), c)
    }

    /// Writes `value` to `path`, a JSON file in the state directory, as a
    /// private file, and syncs the directory.
    fn save_json<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        save_bytes(path, &serde_json::to_vec_pretty(value)?)?;
        Ok(())
    }

    /// Discards a partially prepared admission without removing its pending
    /// record. A failed join can still be retried or cancelled after restart.
    pub fn delete_consensus(&self) -> Result<()> {
        let acceptor = self.acceptor();
        pnyx::store::remove(&acceptor)
            .with_context(|| format!("removing the acceptor state {}", acceptor.display()))?;
        self.remove_files([self.transitions()])
    }

    /// Cancels a pending join durably. There is no running acceptor. Keep the
    /// pending record until other cleanup succeeds, and sync its deletion
    /// before the caller reports success.
    pub fn delete_pending(&self) -> Result<()> {
        self.delete_cluster()
    }

    /// Forgets the cluster (keeps this node's keys).
    pub fn delete_cluster(&self) -> Result<()> {
        self.delete_consensus()?;
        self.remove_files([self.cluster()])?;
        sync_dir(&self.dir)?;
        Ok(())
    }

    fn remove_files(&self, paths: impl IntoIterator<Item = PathBuf>) -> Result<()> {
        for p in paths {
            match fs::remove_file(&p) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("removing {}", p.display())),
            }
        }
        Ok(())
    }

    /// Loads the WireGuard private key, creating one if needed.
    pub fn load_or_create_wg_key(&self) -> Result<[u8; 32]> {
        let path = self.wg_key();
        match read_optional(&path)? {
            Some(b) => b
                .try_into()
                .map_err(|_| anyhow::anyhow!("{} must be 32 bytes", path.display())),
            None => {
                let (private, _) = cheesecloth_wg::generate_keypair();
                write_private(&path, &private)?;
                Ok(private)
            }
        }
    }
}

/// The contents of `path`, or `None` if there is no file.
fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Reads a JSON file, or `None` if there is no file.
fn load_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    read_optional(path)?
        .map(|b| serde_json::from_slice(&b))
        .transpose()
        .with_context(|| format!("reading {}", path.display()))
}

/// Writes `value` to `path` as a private file (see `write_private`), so that
/// a crash leaves either the old or the new contents.
pub fn save<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    save_bytes(path, &postcard::to_stdvec(value).map_err(io::Error::other)?)
}

/// Writes `bytes` to `path` as a private file, and syncs its directory.
fn save_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_private(path, bytes)?;
    // The rename is only durable once the directory is synced.
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    sync_dir(dir)
}

/// Reads a value written by [`save`], or `None` if there is no file.
pub fn load<T: DeserializeOwned>(path: &Path) -> io::Result<Option<T>> {
    read_optional(path)?
        .map(|bytes| postcard::from_bytes(&bytes))
        .transpose()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests;
