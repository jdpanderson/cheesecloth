//! The local API between the daemon and its clients (the `cheesecloth` CLI
//! and the desktop apps): one JSON request per line on a Unix domain socket,
//! or a named pipe on Windows, answered by one JSON response line.
//! `docs/LOCAL-API.md` describes it for clients.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};

use anyhow::{Result, anyhow, bail};
use cheesecloth_core::{
    NodeId, ProposalId, WgKey,
    state::{Outcome, SettingChange},
};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// The version of the local API that this daemon serves. Raise it for a
/// change that old clients would misread; see "Versions" in
/// `docs/LOCAL-API.md`.
pub const API_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ApiRequest {
    /// The API version and the daemon's version. Clients send it first.
    Hello,
    Status,
    Peers,
    Init {
        #[serde(default)]
        strict_security: bool,
        ipv4_range: Option<Ipv4Net>,
    },
    Invite,
    Join {
        token: String,
    },
    Remove {
        node: String,
    },
    Leave {
        /// Stop even if a step of leaving fails.
        #[serde(default)]
        force: bool,
    },
    Pending,
    Approve {
        proposal: cheesecloth_core::ProposalId,
    },
    Reject {
        proposal: cheesecloth_core::ProposalId,
    },
    ConfigGet,
    ConfigSet {
        key: String,
        value: String,
    },
    /// Stop the daemon. Answered once shutdown has finished.
    Stop,
}

/// Every response is `{"ok": ...}` or `{"err": "..."}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiResponse {
    Ok(serde_json::Value),
    Err(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusView {
    pub security: String,
    pub quorum: usize,
    pub reachable_voters: usize,
    pub changes_paused: bool,
    pub strict_security: bool,
    pub buffer_nodes: u8,
    pub node_id: NodeId,
    pub name: String,
    /// "none", "pending" or "member".
    pub phase: String,
    pub cluster_id: Option<String>,
    pub pending_proposal: Option<cheesecloth_core::ProposalId>,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub relay: bool,
    pub public: bool,
    pub keepalive: u16,
    /// The acceptors of the agreed state.
    pub acceptors: Vec<NodeId>,
    /// The acceptor configuration number.
    pub config: Option<u64>,
    /// The version of the agreed state this node holds.
    pub version: Option<u64>,
    pub members: usize,
    pub control_addr: Option<SocketAddr>,
    pub wg_backend: Option<String>,
    pub wg_interface: String,
    pub wg_port: u16,
    /// Router port mapping: `None` when it is off, else one entry per port.
    #[serde(default)]
    pub port_mapping: Option<Vec<PortMapView>>,
    pub warnings: Vec<String>,
}

/// The router port mapping of one local port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapView {
    /// "wireguard" or "control".
    pub port: String,
    pub local_port: u16,
    /// The mapping, once the router grants it.
    pub mapped: Option<PortMapGrant>,
    /// Why the last attempt to get or renew the mapping failed.
    pub error: Option<String>,
}

/// A mapping the router has granted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapGrant {
    /// The router's address and port.
    pub external: SocketAddr,
    /// The protocol it was granted with: "UPnP", "PCP" or "NAT-PMP".
    pub method: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerView {
    pub node_id: NodeId,
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
    pub relay: bool,
    pub acceptor: bool,
    pub this_node: bool,
    /// A live control-plane connection to this peer.
    pub connected: bool,
    /// Known to be alive: reached through live connections, directly or
    /// through other members. An acceptor that isn't present for 10 minutes
    /// is replaced.
    pub present: bool,
    pub wg_key: WgKey,
    /// How the WireGuard path is set up: lan, public, await, punch, or none.
    pub path: String,
    /// Detail such as "up", "punching", "quiet (retry in 20s)".
    pub path_state: String,
    pub wg_endpoint: Option<SocketAddr>,
    pub handshake_age_secs: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalView {
    pub id: cheesecloth_core::ProposalId,
    /// "join", "remove" or "setting".
    pub kind: String,
    /// The node joining or being removed; for joins, approve this key's fingerprint.
    pub node: Option<NodeId>,
    pub name: Option<String>,
    /// For a setting proposal: the setting and its new value, as
    /// `config set` takes them.
    pub setting: Option<SettingView>,
    pub proposer: NodeId,
    pub approvals: Vec<NodeId>,
    pub needed: u32,
    pub expires_in_secs: u64,
}

/// A setting and its value, such as `approvals_required` and `"1"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingView {
    pub key: String,
    pub value: String,
}

impl From<&SettingChange> for SettingView {
    fn from(change: &SettingChange) -> Self {
        let (key, value) = match change {
            SettingChange::ApprovalsRequired(n) => ("approvals_required", n.to_string()),
            SettingChange::Acceptors(n) => ("acceptors", n.to_string()),
            SettingChange::StrictSecurity(on) => ("strict_security", on.to_string()),
            SettingChange::BufferNodes(n) => ("buffer_nodes", n.to_string()),
            SettingChange::CatchUpDays(n) => ("catch_up_days", n.to_string()),
        };
        Self {
            key: key.into(),
            value,
        }
    }
}

/// The answer to `remove`, `approve`, `reject` and `config_set`: what the
/// change did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ChangeView {
    /// The change waits for approvals.
    Pending {
        proposal: ProposalId,
    },
    /// This approval counted; more are needed.
    Approved {
        proposal: ProposalId,
        remaining: u32,
    },
    Rejected {
        proposal: ProposalId,
    },
    /// A join was approved, and the node joined.
    Joined {
        node: NodeId,
        ipv4: Ipv4Addr,
    },
    Removed {
        node: NodeId,
    },
    SettingChanged,
}

impl TryFrom<Outcome> for ChangeView {
    type Error = anyhow::Error;

    fn try_from(outcome: Outcome) -> Result<Self> {
        Ok(match outcome {
            Outcome::Pending { proposal } => Self::Pending { proposal },
            Outcome::Approved {
                proposal,
                remaining,
            } => Self::Approved {
                proposal,
                remaining,
            },
            Outcome::Rejected { proposal } => Self::Rejected { proposal },
            Outcome::Joined { node, ipv4 } => Self::Joined { node, ipv4 },
            Outcome::Removed { node } => Self::Removed { node },
            Outcome::SettingChanged => Self::SettingChanged,
            other => bail!("unexpected result of a change: {other:?}"),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigView {
    pub approvals_required: u32,
    pub acceptors: u8,
    pub strict_security: bool,
    pub buffer_nodes: u8,
    pub catch_up_days: u32,
    pub ipv4_range: Ipv4Net,
    pub ipv6_prefix: String,
}

/// The answer to `hello`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HelloView {
    /// The daemon's `API_VERSION`.
    pub api: u32,
    /// The daemon's release, such as "0.5.0".
    pub daemon: String,
}

impl HelloView {
    pub(crate) fn new() -> Self {
        Self {
            api: API_VERSION,
            daemon: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

/// A connection to the daemon that has checked its API version.
pub struct Client {
    read: BufReader<tokio::io::ReadHalf<crate::ipc::ClientStream>>,
    write: tokio::io::WriteHalf<crate::ipc::ClientStream>,
}

impl Client {
    /// Connects, sends `hello`, and fails if the daemon serves another API
    /// version than this client.
    pub async fn connect(socket: &Path) -> Result<Self> {
        let (read, write) = tokio::io::split(crate::ipc::connect(socket).await?);
        let mut client = Self {
            read: BufReader::new(read),
            write,
        };
        let hello: HelloView = client.request(&ApiRequest::Hello).await?;
        if hello.api != API_VERSION {
            bail!(
                "the daemon (cheesecloth {}) serves local API version {}, but this \
                 cheesecloth ({}) needs version {API_VERSION}; use the same release of both",
                hello.daemon,
                hello.api,
                env!("CARGO_PKG_VERSION"),
            );
        }
        Ok(client)
    }

    /// Sends one request and returns its typed answer.
    pub async fn request<T: DeserializeOwned>(&mut self, req: &ApiRequest) -> Result<T> {
        let mut line = serde_json::to_string(req)?;
        line.push('\n');
        self.write.write_all(line.as_bytes()).await?;
        self.write.flush().await?;
        let mut resp = String::new();
        self.read.read_line(&mut resp).await?;
        if resp.is_empty() {
            return Err(anyhow!("the daemon closed the connection"));
        }
        match serde_json::from_str::<ApiResponse>(&resp)? {
            ApiResponse::Ok(v) => Ok(serde_json::from_value(v)?),
            ApiResponse::Err(e) => Err(anyhow!(e)),
        }
    }
}

/// Connects, checks the API version, sends one request and returns its
/// typed answer.
pub async fn call<T: DeserializeOwned>(socket: &Path, req: &ApiRequest) -> Result<T> {
    Client::connect(socket).await?.request(req).await
}

/// The answer to `init`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitView {
    pub cluster_id: String,
    pub ipv4_range: Ipv4Net,
}

/// The answer to `invite`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteView {
    pub token: String,
    pub expires_at_ms: u64,
}

/// The answer to `join`: joined, or waiting for approvals.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinView {
    pub joined: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,
    /// The proposal waiting for approvals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<cheesecloth_core::ProposalId>,
    /// This node's key, for approvers to check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<NodeId>,
}

/// The answer to `leave`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum LeaveView {
    Left {
        remaining_members: usize,
        /// With `force`: the steps of leaving that failed.
        problems: Vec<String>,
    },
    /// Local cancellation; the remote proposal or admission may still exist.
    JoinCancelled {
        cluster_id: String,
        proposal: cheesecloth_core::ProposalId,
    },
}

#[cfg(test)]
mod tests;
