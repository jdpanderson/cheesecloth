//! Errors of the local API and the CLI: a stable `code` for programs, and a
//! `message` for people. See "Errors" in `docs/LOCAL-API.md`.
//!
//! The daemon gives an error its code where the cause is known: it returns
//! an `ApiError`, or adds one as context, and `classify` finds it in the
//! error chain. It never reads the words of a message to choose a code.

use std::fmt;

use cheesecloth_core::state::CommandError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Lists the codes once, for the enum, its strings, and `ErrorCode::KNOWN`.
macro_rules! codes {
    ($($(#[$doc:meta])* $variant:ident = $name:literal,)*) => {
        /// What went wrong, for programs. A code keeps its meaning across
        /// releases; new codes may be added within an API version.
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub enum ErrorCode {
            $($(#[$doc])* $variant,)*
            /// A code this program doesn't know, from a newer daemon. Treat it
            /// as a failure without more detail, and show the message.
            Other(String),
        }

        impl ErrorCode {
            /// Every code this release knows.
            pub const KNOWN: &[ErrorCode] = &[$(ErrorCode::$variant,)*];

            pub fn as_str(&self) -> &str {
                match self {
                    $(ErrorCode::$variant => $name,)*
                    ErrorCode::Other(code) => code,
                }
            }

            fn parse(code: &str) -> Self {
                match code {
                    $($name => ErrorCode::$variant,)*
                    other => ErrorCode::Other(other.into()),
                }
            }
        }
    };
}

codes! {
    // Access and requests.
    /// The caller may not use the daemon, or may not make this request.
    PermissionDenied = "permission_denied",
    /// The daemon can't tell who is connecting, or can't look up their groups.
    AccessCheckFailed = "access_check_failed",
    /// The line is not a request this daemon knows.
    InvalidRequest = "invalid_request",
    /// The daemon is stopping, and answers no more requests.
    ShuttingDown = "shutting_down",
    /// The node is stopping, for example while it leaves its cluster.
    NodeStopping = "node_stopping",
    /// The node stopped, but removing its interface or files failed.
    CleanupPending = "cleanup_pending",

    // The node's place in a cluster.
    /// The request needs a cluster, and this node is in none.
    NotInCluster = "not_in_cluster",
    /// The node is already in a cluster, or waiting to join one.
    AlreadyInCluster = "already_in_cluster",
    /// No free /24 is left in 100.64.0.0/10 for a new cluster.
    NoFreeRange = "no_free_range",

    // Joining.
    /// The invite token can't be read.
    InvalidToken = "invalid_token",
    /// No member listed in the token could be reached.
    MembersUnreachable = "members_unreachable",
    /// A member got the join request, but its answer was lost. The invite
    /// may have been used.
    JoinUnconfirmed = "join_unconfirmed",
    /// The members rejected the join, or its proposal expired.
    JoinRejected = "join_rejected",
    /// A member refused the join for a reason without a code.
    JoinRefused = "join_refused",

    // Selectors and settings.
    /// A node selector matches several members.
    AmbiguousNode = "ambiguous_node",
    /// `remove` names this node; it leaves with `leave`.
    RemoveSelf = "remove_self",

    // Agreement.
    /// Too few acceptors could be reached to agree on the change. It may
    /// still be agreed later.
    NoQuorum = "no_quorum",
    /// The change breaks the cluster's security policy.
    SecurityPolicy = "security_policy",
    /// The change would remove an acceptor that no other member can replace.
    NoReplacement = "no_replacement",
    /// This node is an acceptor; it gives up the role before it leaves.
    IsAcceptor = "is_acceptor",
    /// The change would make the agreed state too large.
    StateTooLarge = "state_too_large",
    /// Leaving stopped part way; this node still runs.
    LeaveIncomplete = "leave_incomplete",

    // The cluster's own refusals (`CommandError`).
    /// The command belongs to another cluster.
    WrongCluster = "wrong_cluster",
    /// A signature didn't verify.
    BadSignature = "bad_signature",
    /// The command is too old, or the clocks differ too much.
    StaleCommand = "stale_command",
    /// The command was already applied.
    AlreadyApplied = "already_applied",
    /// The cluster has already been created.
    AlreadyInitialized = "already_initialized",
    /// The cluster doesn't exist yet.
    NotInitialized = "not_initialized",
    /// The node that signed the command is not a member.
    NotMember = "not_member",
    /// The node that signed the command is an unprivileged member, which
    /// can't change the cluster.
    Unprivileged = "unprivileged",
    /// The last privileged member can't leave while other members remain.
    LastPrivileged = "last_privileged",
    /// The invite is unknown, expired or already used.
    InviteUnknown = "invite_unknown",
    /// The node is already a member.
    AlreadyMember = "already_member",
    /// A join for the node already waits for approval.
    AlreadyPending = "already_pending",
    /// No member matches.
    NoSuchMember = "no_such_member",
    /// No proposal has this ID.
    NoSuchProposal = "no_such_proposal",
    /// A proposer can't approve its own proposal.
    OwnProposal = "own_proposal",
    /// A member can't approve or reject its own removal.
    OwnRemoval = "own_removal",
    /// This member already approved the proposal.
    AlreadyApproved = "already_approved",
    /// No overlay IPv4 address is left in the cluster's range.
    RangeFull = "range_full",
    /// A setting name or value is not valid.
    InvalidSetting = "invalid_setting",
    /// A member record is not valid.
    InvalidMember = "invalid_member",

    // The CLI and other clients, before or outside an answer.
    /// The daemon's socket or pipe can't be reached.
    DaemonUnavailable = "daemon_unavailable",
    /// The daemon serves another API version, or predates `hello`.
    ApiVersionMismatch = "api_version_mismatch",
    /// The connection failed, or closed before the answer.
    TransportError = "transport_error",
    /// The daemon's answer can't be read.
    InvalidResponse = "invalid_response",
    /// The command line is not valid.
    InvalidArgument = "invalid_argument",

    // Anything else.
    /// An operation failed, such as a network, disk or interface step. The
    /// message says what.
    OperationFailed = "operation_failed",
    /// A fault in the daemon.
    InternalError = "internal_error",
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(ErrorCode::parse(&String::deserialize(d)?))
    }
}

impl From<&CommandError> for ErrorCode {
    fn from(e: &CommandError) -> Self {
        match e {
            CommandError::WrongCluster => ErrorCode::WrongCluster,
            CommandError::BadSignature => ErrorCode::BadSignature,
            CommandError::Stale => ErrorCode::StaleCommand,
            CommandError::Replay => ErrorCode::AlreadyApplied,
            CommandError::AlreadyInitialized => ErrorCode::AlreadyInitialized,
            CommandError::NotInitialized => ErrorCode::NotInitialized,
            CommandError::NotMember => ErrorCode::NotMember,
            CommandError::Unprivileged => ErrorCode::Unprivileged,
            CommandError::LastPrivileged => ErrorCode::LastPrivileged,
            CommandError::InviteUnknown => ErrorCode::InviteUnknown,
            CommandError::AlreadyMember => ErrorCode::AlreadyMember,
            CommandError::AlreadyPending => ErrorCode::AlreadyPending,
            CommandError::NoSuchMember => ErrorCode::NoSuchMember,
            CommandError::NoSuchProposal => ErrorCode::NoSuchProposal,
            CommandError::OwnProposal => ErrorCode::OwnProposal,
            CommandError::OwnRemoval => ErrorCode::OwnRemoval,
            CommandError::AlreadyApproved => ErrorCode::AlreadyApproved,
            CommandError::RangeFull(_) => ErrorCode::RangeFull,
            CommandError::InvalidSetting(_) => ErrorCode::InvalidSetting,
            CommandError::InvalidMember(_) => ErrorCode::InvalidMember,
        }
    }
}

/// An error with its code: `{"code": ..., "message": ...}` on the wire, and
/// in the daemon an error (or context) that gives a failure its code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct ApiError {
    pub code: ErrorCode,
    /// For people. Its words may change; programs use `code`.
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// `error` with its code, and its whole chain of causes as the message.
    /// The code is the one given where the cause was known, else `default`.
    pub fn classify(error: &anyhow::Error, default: ErrorCode) -> Self {
        let code = if let Some(e) = error.downcast_ref::<ApiError>() {
            e.code.clone()
        } else if let Some(e) = error.downcast_ref::<CommandError>() {
            e.into()
        } else {
            default
        };
        Self::new(code, format!("{error:#}"))
    }
}

/// What `cheesecloth --json` prints on stdout when it fails.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDocument {
    pub error: ApiError,
}

/// Gives `error` the code `code`, unless it already has one. Its message
/// stays the same.
pub fn with_code(error: anyhow::Error, code: ErrorCode) -> anyhow::Error {
    if error.downcast_ref::<ApiError>().is_some() {
        error
    } else {
        ApiError::new(code, format!("{error:#}")).into()
    }
}
