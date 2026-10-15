//! The local API between the daemon and its clients (the `cheesecloth` CLI
//! and the desktop apps): one JSON request per line on a Unix domain socket,
//! or a named pipe on Windows, answered by one JSON response line.
//! `docs/LOCAL-API.md` describes it for clients.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};

use anyhow::Result;
use cheesecloth_core::{
    NodeId, ProposalId, WgKey,
    state::{Outcome, SettingChange},
};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

mod error;

pub use error::{ApiError, ErrorCode, ErrorDocument, with_code};

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
    Invite {
        /// The joiner becomes an unprivileged member.
        #[serde(default)]
        unprivileged: bool,
    },
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

/// Every response is `{"ok": ...}` or `{"err": {"code": ..., "message": ...}}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiResponse {
    Ok(serde_json::Value),
    Err(ApiError),
}

/// Where this node stands with a cluster: `"none"`, `"pending"` (a join
/// waiting for approval), `"member"` or `"stopping"` (left, local cleanup
/// pending).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodePhase {
    None,
    Pending,
    Member,
    Stopping,
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
    pub phase: NodePhase,
    pub cluster_id: Option<String>,
    pub pending_proposal: Option<cheesecloth_core::ProposalId>,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    /// Whether this node is a privileged member; `None` unless a member.
    pub privileged: Option<bool>,
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
    /// The member may change the cluster and vote.
    pub privileged: bool,
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
    /// How the WireGuard path is set up: self, lan, public, await, punch, or
    /// none.
    pub path: String,
    /// Where the path is, for programs.
    pub path_state: PathState,
    /// `path_state` for people, such as "no path; retry in 20s".
    pub path_detail: String,
    /// With `no_path`: when this node tries again.
    pub retry_in_secs: Option<u64>,
    pub wg_endpoint: Option<SocketAddr>,
    pub handshake_age_secs: Option<u64>,
}

/// Where the WireGuard path to a peer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathState {
    /// The row of this node.
    #[serde(rename = "self")]
    ThisNode,
    /// WireGuard has no peer for it yet.
    NotConfigured,
    /// A recent handshake: traffic flows.
    Up,
    /// The last handshake is too old.
    Stale,
    /// No handshake yet.
    NoHandshake,
    /// A hole punch is due, and waits for its turn.
    WaitingToPunch,
    /// This node offered a hole punch.
    OfferSent,
    /// Both sides are opening their NATs.
    Punching,
    /// The peer is being removed from WireGuard first.
    WaitingForRemoval,
    /// Hole punching failed; it is tried again after `retry_in_secs`.
    NoPath,
}

impl PathState {
    /// For people. `retry_in_secs` goes with `NoPath`.
    pub fn detail(self, retry_in_secs: Option<u64>) -> String {
        match self {
            PathState::ThisNode => "-".into(),
            PathState::NotConfigured => "not configured".into(),
            PathState::Up => "up".into(),
            PathState::Stale => "stale".into(),
            PathState::NoHandshake => "no handshake yet".into(),
            PathState::WaitingToPunch => "waiting to punch".into(),
            PathState::OfferSent => "offer sent".into(),
            PathState::Punching => "punching".into(),
            PathState::WaitingForRemoval => "waiting for peer removal".into(),
            PathState::NoPath => match retry_in_secs {
                Some(secs) => format!("no path; retry in {secs}s"),
                None => "no path".into(),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalView {
    pub id: cheesecloth_core::ProposalId,
    pub kind: ProposalKindView,
    /// The node joining or being removed; for joins, approve this key's fingerprint.
    pub node: Option<NodeId>,
    pub name: Option<String>,
    /// For a join: whether the joiner becomes a privileged member.
    pub privileged: Option<bool>,
    /// For a setting proposal: the setting and its new value, as
    /// `config set` takes them.
    pub setting: Option<SettingView>,
    pub proposer: NodeId,
    pub approvals: Vec<NodeId>,
    pub needed: u32,
    pub expires_in_secs: u64,
}

/// What a proposal does: `"join"`, `"remove"` or `"setting"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKindView {
    Join,
    Remove,
    Setting,
}

/// A setting and its value, such as `approvals_required` and `"1"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingView {
    pub key: String,
    pub value: String,
}

impl From<&SettingChange> for SettingView {
    fn from(change: &SettingChange) -> Self {
        Self {
            key: change.key().into(),
            value: change.value(),
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
    type Error = ApiError;

    fn try_from(outcome: Outcome) -> Result<Self, ApiError> {
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
            other => {
                return Err(ApiError::new(
                    ErrorCode::InternalError,
                    format!("unexpected result of a change: {other:?}"),
                ));
            }
        })
    }
}

/// The answer to `config get`: the settings (see `SettingChange::KEYS`) and
/// the overlay ranges, which are fixed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigView {
    #[serde(flatten)]
    pub settings: cheesecloth_core::state::Settings,
    pub ipv6_prefix: String,
}

impl ConfigView {
    /// Every key with its value, as text, in the order `config get` shows
    /// them: the changeable settings, then the fixed ranges.
    pub fn entries(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = SettingChange::KEYS
            .iter()
            .map(|k| (*k, self.settings.value(k).expect("a listed key")))
            .collect();
        out.push(("ipv4_range", self.settings.ipv4_range.to_string()));
        out.push(("ipv6_prefix", self.ipv6_prefix.clone()));
        out
    }
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

/// A connection to the daemon that has checked its API version. Each error
/// it returns is an `ApiError`: the daemon's own, or one with a client code
/// (`daemon_unavailable`, `api_version_mismatch`, `transport_error`,
/// `invalid_response`).
pub struct Client {
    read: BufReader<tokio::io::ReadHalf<crate::ipc::ClientStream>>,
    write: tokio::io::WriteHalf<crate::ipc::ClientStream>,
}

impl Client {
    /// Connects, sends `hello`, and fails if the daemon serves another API
    /// version than this client.
    pub async fn connect(socket: &Path) -> Result<Self, ApiError> {
        let stream = crate::ipc::connect(socket)
            .await
            .map_err(|e| ApiError::classify(&e, ErrorCode::DaemonUnavailable))?;
        let (read, write) = tokio::io::split(stream);
        let mut client = Self {
            read: BufReader::new(read),
            write,
        };
        let hello = match client.exchange(&ApiRequest::Hello).await? {
            Answer::Ok(value) => decode::<HelloView>(value)?,
            Answer::Err(e) => return Err(e),
            // A daemon from before `hello` answers it with an error, as
            // text. Its shape, not its words, says the daemon is older.
            Answer::Text(text) => {
                return Err(ApiError::new(
                    ErrorCode::ApiVersionMismatch,
                    format!(
                        "the daemon is older than this cheesecloth ({}), and doesn't \
                         know its local API ({text}); use the same release of both",
                        env!("CARGO_PKG_VERSION"),
                    ),
                ));
            }
        };
        if hello.api != API_VERSION {
            return Err(ApiError::new(
                ErrorCode::ApiVersionMismatch,
                format!(
                    "the daemon (cheesecloth {}) serves local API version {}, but this \
                     cheesecloth ({}) needs version {API_VERSION}; use the same release of both",
                    hello.daemon,
                    hello.api,
                    env!("CARGO_PKG_VERSION"),
                ),
            ));
        }
        Ok(client)
    }

    /// Sends one request and returns its typed answer.
    pub async fn request<T: DeserializeOwned>(&mut self, req: &ApiRequest) -> Result<T, ApiError> {
        match self.exchange(req).await? {
            Answer::Ok(value) => decode(value),
            Answer::Err(e) => Err(e),
            Answer::Text(text) => Err(ApiError::new(
                ErrorCode::InvalidResponse,
                format!("the daemon answered with an error in an old form: {text}"),
            )),
        }
    }

    async fn exchange(&mut self, req: &ApiRequest) -> Result<Answer, ApiError> {
        let transport = |e: std::io::Error| {
            ApiError::new(
                ErrorCode::TransportError,
                format!("talking to the daemon: {e}"),
            )
        };
        self.write
            .write_all(json_line(req).as_bytes())
            .await
            .map_err(transport)?;
        self.write.flush().await.map_err(transport)?;
        let mut resp = String::new();
        self.read.read_line(&mut resp).await.map_err(transport)?;
        if resp.is_empty() {
            return Err(ApiError::new(
                ErrorCode::TransportError,
                "the daemon closed the connection",
            ));
        }
        let invalid = invalid_response;
        Ok(
            match serde_json::from_str::<serde_json::Value>(&resp).map_err(invalid)? {
                serde_json::Value::Object(mut answer) if answer.len() == 1 => {
                    match (answer.remove("ok"), answer.remove("err")) {
                        (Some(value), _) => Answer::Ok(value),
                        (_, Some(serde_json::Value::String(text))) => Answer::Text(text),
                        (_, Some(err)) => {
                            Answer::Err(serde_json::from_value(err).map_err(invalid)?)
                        }
                        _ => return Err(invalid(serde::de::Error::custom("no ok or err"))),
                    }
                }
                _ => return Err(invalid(serde::de::Error::custom("not an answer"))),
            },
        )
    }
}

/// One answer, as `Client::exchange` reads it.
enum Answer {
    Ok(serde_json::Value),
    Err(ApiError),
    /// `{"err": "<text>"}`: an error from a daemon from before error codes.
    Text(String),
}

/// The daemon's answer, as a `T`.
pub fn decode<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, ApiError> {
    serde_json::from_value(value).map_err(invalid_response)
}

/// The error for an answer this client can't read.
fn invalid_response(e: serde_json::Error) -> ApiError {
    ApiError::new(
        ErrorCode::InvalidResponse,
        format!("reading the daemon's answer: {e}"),
    )
}

/// `value` as one line of the local API's protocol: JSON, then a newline.
pub(crate) fn json_line<T: Serialize>(value: &T) -> String {
    let mut line = serde_json::to_string(value).expect("serializable");
    line.push('\n');
    line
}

/// Connects, checks the API version, sends one request and returns its
/// typed answer.
pub async fn call<T: DeserializeOwned>(socket: &Path, req: &ApiRequest) -> Result<T, ApiError> {
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
