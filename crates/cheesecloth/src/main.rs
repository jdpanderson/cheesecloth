//! `cheesecloth`: the daemon and the command-line interface to it.

use std::{net::IpAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use cheesecloth_core::{
    MAPPED_KEEPALIVE_SECS, NAT_KEEPALIVE_SECS, now_ms,
    state::{INVITE_TTL, SettingChange},
};
use cheesecloth_daemon::{
    Options, RelayMode,
    api::{
        self, ApiError, ApiRequest, ChangeView, ConfigView, ErrorCode, ErrorDocument, InitView,
        InviteView, JoinView, LeaveView, NodePhase, PeerView, PortMapView, ProposalKindView,
        ProposalView, StatusView,
    },
};
use cheesecloth_wg::BackendKind;
use clap::{Parser, Subcommand};
use ipnet::Ipv4Net;
use serde_json::Value;

/// Help texts that quote limits and defaults: written from the constants,
/// so they can't go stale.
fn set_help() -> String {
    format!(
        "Change a setting: {}. Needs the current number of approvals.",
        SettingChange::KEYS.join(", ")
    )
}

fn invite_help() -> String {
    format!(
        "Create a single-use invite token (valid for {} minutes).",
        INVITE_TTL.as_secs() / 60
    )
}

fn keepalive_help() -> String {
    format!(
        "WireGuard persistent keepalive in seconds (default: {NAT_KEEPALIVE_SECS} behind NAT, \
         {MAPPED_KEEPALIVE_SECS} when the router maps the WireGuard port, off when public). The \
         control plane's QUIC keep-alive is always {NAT_KEEPALIVE_SECS} s."
    )
}

fn default_state_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        "/Library/Application Support/cheesecloth".into()
    } else if cfg!(windows) {
        r"C:\ProgramData\cheesecloth".into()
    } else {
        "/var/lib/cheesecloth".into()
    }
}

#[derive(Parser)]
#[command(
    name = "cheesecloth",
    version,
    about = "A lightweight, loose mesh: a peer-to-peer WireGuard cluster"
)]
struct Cli {
    /// The daemon's state directory. Run separate instances with separate
    /// directories (and ports and interfaces) to be in several clusters.
    #[arg(long, global = true, env = "CHEESECLOTH_STATE_DIR", default_value_os_t = default_state_dir())]
    state_dir: PathBuf,
    /// The daemon's local API address: a socket path, or a pipe name
    /// (\\.\pipe\...) on Windows. Default: control.sock in the state
    /// directory, or a pipe named after it on Windows.
    #[arg(long, global = true, env = "CHEESECLOTH_SOCKET")]
    socket: Option<PathBuf>,
    /// Print raw JSON. A failure prints {"error": {"code": ..., "message":
    /// ...}} instead, and exits nonzero.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon.
    Daemon {
        /// Act as a relay: auto (when publicly reachable), always or never.
        #[arg(long, default_value = "auto")]
        relay: RelayMode,
        /// WireGuard persistent keepalive in seconds.
        #[arg(long, long_help = keepalive_help())]
        keepalive: Option<u16>,
        /// Control-plane (QUIC) UDP port.
        #[arg(long, default_value_t = cheesecloth_core::DEFAULT_CONTROL_PORT)]
        listen_port: u16,
        /// WireGuard UDP port.
        #[arg(long, default_value_t = cheesecloth_core::DEFAULT_WG_PORT)]
        wg_port: u16,
        /// An address this node is reachable at (e.g. behind 1:1 NAT). Repeatable.
        #[arg(long)]
        advertise: Vec<IpAddr>,
        /// WireGuard interface name.
        #[arg(long, default_value = cheesecloth_wg::default_interface_name())]
        interface: String,
        /// WireGuard implementation: auto, kernel, userspace (or mock, for testing).
        #[arg(long, default_value = "auto")]
        wireguard: BackendKind,
        /// Bind the control plane to this address only.
        #[arg(long, default_value = "::")]
        bind: IpAddr,
        /// Don't ask the router for port mappings (UPnP, PCP).
        #[arg(long)]
        no_port_mapping: bool,
        /// This node's name, at most 32 bytes (default: the host name, cut to
        /// 32 bytes).
        #[arg(long)]
        name: Option<String>,
        /// Log filter, e.g. "info" or "cheesecloth_daemon=debug".
        #[arg(long, env = "RUST_LOG", default_value = "info")]
        log: String,
        /// The group whose members may use the local API without root:
        /// every command but `stop`. Default: admin on macOS, none elsewhere.
        /// An empty name turns it off.
        #[cfg(unix)]
        #[arg(long)]
        api_group: Option<String>,
    },
    /// Create a new cluster with this node as its first member.
    Init {
        /// Keep Byzantine protection after bootstrap, pausing instead of downgrading.
        #[arg(long)]
        strict_security: bool,
        /// Overlay IPv4 range (default: a random /24 inside 100.64.0.0/10).
        #[arg(long)]
        ipv4_range: Option<Ipv4Net>,
    },
    /// Create a single-use invite token.
    #[command(long_about = invite_help())]
    Invite {
        /// The new member can't invite, remove, change settings, approve,
        /// reject, vote or relay. It can still use the mesh, and leave.
        #[arg(long)]
        unprivileged: bool,
    },
    /// Join a cluster with an invite token.
    Join { token: String },
    /// This node: role, reachability, warnings.
    Status,
    /// Members and their WireGuard paths.
    Peers,
    /// Remove a member (by node ID prefix or name).
    Remove { node: String },
    /// Leave the cluster or cancel a pending join. Never needs approvals.
    Leave {
        /// Leave even if a step fails, such as handing the acceptor role or
        /// the agreed state to other members. The cluster may then need
        /// repair.
        #[arg(long)]
        force: bool,
    },
    /// Stop the daemon and wait until it has removed the WireGuard interface
    /// and released router port mappings. Unlike `leave`, this node stays in
    /// its cluster. Stop a system service with its service manager instead
    /// (e.g. `systemctl stop cheesecloth`, or `Stop-Service cheesecloth` on
    /// Windows).
    Stop,
    /// Proposals waiting for approvals.
    Pending,
    /// Approve a proposal.
    Approve {
        proposal: cheesecloth_core::ProposalId,
    },
    /// Reject a proposal.
    Reject {
        proposal: cheesecloth_core::ProposalId,
    },
    /// Cluster settings.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Show the settings (or one of them).
    Get { key: Option<String> },
    /// Change a setting. Needs the current number of approvals.
    #[command(long_about = set_help())]
    Set { key: String, value: String },
}

#[tokio::main]
async fn main() {
    // Read before parsing, so that a bad command line is reported in JSON too.
    let json = std::env::args_os().skip(1).any(|arg| arg == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        // --help and --version.
        Err(e) if !e.use_stderr() => e.exit(),
        Err(e) => {
            let text = e.render().to_string();
            let message = text.strip_prefix("error: ").unwrap_or(&text).trim_end();
            fail(
                json,
                &ApiError::new(ErrorCode::InvalidArgument, message),
                e.exit_code(),
            );
        }
    };
    if let Err(e) = run(cli).await {
        fail(json, &ApiError::classify(&e, ErrorCode::OperationFailed), 1);
    }
}

/// Reports `error` and exits with `status`: `error[<code>]: <message>` on
/// stderr, or with `--json` the document `{"error": {"code": ..., "message":
/// ...}}` on stdout. See "Errors" in docs/LOCAL-API.md.
fn fail(json: bool, error: &ApiError, status: i32) -> ! {
    if json {
        let doc = ErrorDocument {
            error: error.clone(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).expect("serializable")
        );
    } else {
        eprintln!("error[{}]: {}", error.code, error.message);
    }
    std::process::exit(status)
}

/// The daemon's answer as a `T`.
fn typed<T: serde::de::DeserializeOwned>(value: Value) -> Result<T> {
    Ok(api::decode(value)?)
}

async fn run(cli: Cli) -> Result<()> {
    let json_out = cli.json;
    let config_key = match &cli.command {
        Cmd::Config {
            action: ConfigCmd::Get { key },
        } => key.clone(),
        _ => None,
    };
    let req = match cli.command {
        Cmd::Daemon {
            relay,
            keepalive,
            listen_port,
            wg_port,
            advertise,
            interface,
            wireguard,
            bind,
            no_port_mapping,
            name,
            log,
            #[cfg(unix)]
            api_group,
        } => {
            let filter: tracing_subscriber::filter::Targets = log.parse().map_err(|e| {
                ApiError::new(
                    ErrorCode::InvalidArgument,
                    format!("invalid --log filter {log:?}: {e}"),
                )
            })?;
            let mut opts = Options::new(cli.state_dir, name)
                .context("reading the host name; use --name to supply a node name")?;
            opts.socket = cli.socket;
            opts.relay = relay;
            opts.keepalive = keepalive;
            opts.listen_port = listen_port;
            opts.wg_port = wg_port;
            opts.advertise = advertise;
            opts.interface = interface;
            opts.backend = wireguard;
            opts.bind_ip = bind;
            opts.port_mapping = !no_port_mapping;
            #[cfg(unix)]
            if let Some(group) = api_group {
                opts.api_group = (!group.is_empty()).then_some(group);
            }
            return cheesecloth_daemon::run(opts, filter).await;
        }
        Cmd::Init {
            ipv4_range,
            strict_security,
        } => ApiRequest::Init {
            ipv4_range,
            strict_security,
        },
        Cmd::Invite { unprivileged } => ApiRequest::Invite { unprivileged },
        Cmd::Join { token } => ApiRequest::Join { token },
        Cmd::Status => ApiRequest::Status,
        Cmd::Peers => ApiRequest::Peers,
        Cmd::Remove { node } => ApiRequest::Remove { node },
        Cmd::Leave { force } => ApiRequest::Leave { force },
        Cmd::Stop => ApiRequest::Stop,
        Cmd::Pending => ApiRequest::Pending,
        Cmd::Approve { proposal } => ApiRequest::Approve { proposal },
        Cmd::Reject { proposal } => ApiRequest::Reject { proposal },
        Cmd::Config { action } => match action {
            ConfigCmd::Get { .. } => ApiRequest::ConfigGet,
            ConfigCmd::Set { key, value } => ApiRequest::ConfigSet { key, value },
        },
    };
    // After the daemon case: on Windows the default address needs an
    // existing state directory, which the daemon creates. So no daemon runs
    // on a directory where this fails.
    let socket = cheesecloth_daemon::socket_path(&cli.state_dir, cli.socket.as_deref())
        .with_context(|| cheesecloth_daemon::unreachable_message(&cli.state_dir))
        .map_err(|e| api::with_code(e, ErrorCode::DaemonUnavailable))?;
    let value: Value = api::call(&socket, &req).await?;
    if json_out {
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    match req {
        ApiRequest::Status => print_status(&typed::<StatusView>(value)?),
        ApiRequest::Peers => print_peers(&typed::<Vec<PeerView>>(value)?),
        ApiRequest::Pending => print_pending(&typed::<Vec<ProposalView>>(value)?),
        ApiRequest::ConfigGet => print_config(&typed::<ConfigView>(value)?, config_key.as_deref())?,
        ApiRequest::Init { .. } => {
            let v: InitView = typed(value)?;
            println!("Created cluster {}", v.cluster_id);
            println!("Overlay IPv4 range: {}", v.ipv4_range);
            println!("Add members with `cheesecloth invite`.");
        }
        ApiRequest::Invite { .. } => {
            let v: InviteView = typed(value)?;
            println!("{}", v.token);
            let left = Duration::from_millis(v.expires_at_ms.saturating_sub(now_ms()));
            eprintln!(
                "Single use; expires in {}. On the new node: cheesecloth join <token>",
                humantime(left)
            );
        }
        ApiRequest::Join { .. } => {
            let v: JoinView = typed(value)?;
            if v.joined {
                let ip = v.ipv4.map_or_else(|| "?".into(), |ip| ip.to_string());
                println!("Joined; this node's overlay address is {ip}");
            } else {
                let proposal = v.proposal.unwrap_or_default();
                let key = v.node_id.map_or_else(|| "?".into(), |n| n.to_string());
                println!(
                    "Waiting for approvals (proposal {proposal}). Members approve with:\n  \
                     cheesecloth approve {proposal}\nThis node's key: {key}"
                );
            }
        }
        ApiRequest::Leave { .. } => match typed::<LeaveView>(value)? {
            LeaveView::JoinCancelled { proposal, .. } => {
                println!("Pending join cancelled.");
                println!(
                    "This is local cancellation. A cluster member may still need to reject proposal {proposal} or remove this node if it was admitted."
                );
            }
            LeaveView::Left { problems, .. } if problems.is_empty() => {
                println!("Left the cluster.");
            }
            LeaveView::Left { problems, .. } => {
                println!("Left the cluster, but some steps failed:");
                for p in &problems {
                    println!("  - {p}");
                }
                println!("The other members may need repair.");
            }
        },
        ApiRequest::Stop => println!("Stopped."),
        ApiRequest::Hello => unreachable!("no command sends hello; api::call does"),
        ApiRequest::Remove { .. }
        | ApiRequest::Approve { .. }
        | ApiRequest::Reject { .. }
        | ApiRequest::ConfigSet { .. } => print_change(&typed::<ChangeView>(value)?),
    }
    Ok(())
}

fn print_change(c: &ChangeView) {
    match c {
        ChangeView::Pending { proposal } => {
            println!("Proposal {proposal} is waiting for approvals.")
        }
        ChangeView::Removed { node } => println!("Removed {node}."),
        ChangeView::Approved {
            remaining,
            proposal: _,
        } => println!("Approved; {remaining} more approval(s) needed."),
        ChangeView::Rejected { proposal } => println!("Rejected proposal {proposal}."),
        ChangeView::Joined { node, .. } => println!("Approved: {node} joined."),
        ChangeView::SettingChanged => println!("Setting changed."),
    }
}

fn age(secs: Option<u64>) -> String {
    match secs {
        None => "-".into(),
        Some(s) if s < 120 => format!("{s}s ago"),
        Some(s) => format!("{}m ago", s / 60),
    }
}

/// One port's router mapping, e.g. "wireguard 51820 -> 203.0.113.5:51820 (UPnP)".
fn port_map_line(m: &PortMapView) -> String {
    let what = format!("{} {}", m.port, m.local_port);
    match (&m.mapped, &m.error) {
        (Some(g), None) => format!("{what} -> {} ({})", g.external, g.method),
        (Some(g), Some(e)) => format!(
            "{what} -> {} ({}), renewal failed: {e}",
            g.external, g.method
        ),
        (None, Some(e)) => format!("{what} not mapped: {e}"),
        (None, None) => format!("{what} asking the router"),
    }
}

fn print_status(s: &StatusView) {
    println!("node      {} ({})", s.node_id, s.name);
    match s.phase {
        NodePhase::None => {
            println!("cluster   none (run `cheesecloth init` or `cheesecloth join <token>`)");
            return;
        }
        NodePhase::Pending => {
            println!(
                "cluster   {} (join waiting for approval, proposal {})",
                s.cluster_id.as_deref().unwrap_or("?"),
                s.pending_proposal.unwrap_or_default()
            );
            return;
        }
        NodePhase::Stopping => {
            println!(
                "cluster   {} (stopping; local cleanup pending)",
                s.cluster_id.as_deref().unwrap_or("?")
            );
            for warning in &s.warnings {
                println!("warning   {warning}");
            }
            return;
        }
        NodePhase::Member => {}
    }
    println!(
        "cluster   {} ({} members)",
        s.cluster_id.as_deref().unwrap_or("?"),
        s.members
    );
    if let Some(ip) = s.ipv4 {
        println!(
            "overlay   {ip}  {}",
            s.ipv6.map(|i| i.to_string()).unwrap_or_default()
        );
    }
    let role = if s.relay { "relay" } else { "member" };
    let privilege = if s.privileged == Some(false) {
        "unprivileged "
    } else {
        ""
    };
    let reach = if s.public {
        "publicly reachable"
    } else {
        "behind NAT"
    };
    println!(
        "role      {privilege}{role}, {reach}, keepalive {}",
        if s.keepalive == 0 {
            "off".into()
        } else {
            format!("{}s", s.keepalive)
        }
    );
    println!(
        "consensus state version {}, {} acceptors (configuration {})",
        s.version.map_or_else(|| "-".into(), |v| v.to_string()),
        s.acceptors.len(),
        s.config.map_or_else(|| "-".into(), |c| c.to_string())
    );
    println!(
        "security  {}, quorum {}, {} reachable, strict {}, buffer {}{}",
        s.security,
        s.quorum,
        s.reachable_voters,
        s.strict_security,
        s.buffer_nodes,
        if s.changes_paused {
            ", changes paused"
        } else {
            ""
        }
    );
    println!(
        "wireguard {} on {} port {}",
        s.wg_backend.as_deref().unwrap_or("down"),
        s.wg_interface,
        s.wg_port
    );
    if let Some(a) = s.control_addr {
        println!("control   {a}");
    }
    match &s.port_mapping {
        None => println!("portmap   off"),
        Some(maps) => {
            for m in maps {
                println!("portmap   {}", port_map_line(m));
            }
        }
    }
    for w in &s.warnings {
        println!("warning   {w}");
    }
}

fn print_peers(peers: &[PeerView]) {
    println!(
        "{:<14} {:<16} {:<15} {:<7} {:<4} {:<5} {:<7} {:<24} {:<22} HANDSHAKE",
        "NODE", "NAME", "IPV4", "ROLE", "PRIV", "CTRL", "PATH", "STATE", "ENDPOINT"
    );
    for p in peers {
        let role = match (p.relay, p.acceptor) {
            (true, true) => "relay*",
            (true, false) => "relay",
            (false, true) => "member*",
            (false, false) => "member",
        };
        let name = if p.this_node {
            format!("{} (this)", p.name)
        } else {
            p.name.clone()
        };
        println!(
            "{:<14} {:<16} {:<15} {:<7} {:<4} {:<5} {:<7} {:<24} {:<22} {}",
            p.node_id.short(),
            name,
            p.ipv4,
            role,
            if p.privileged { "yes" } else { "no" },
            if p.this_node {
                "-"
            } else if p.connected {
                "yes"
            } else if p.present {
                "relay"
            } else {
                "no"
            },
            p.path,
            p.path_detail,
            p.wg_endpoint
                .map(|e| e.to_string())
                .unwrap_or_else(|| "-".into()),
            age(p.handshake_age_secs),
        );
    }
    println!("(* = acceptor)");
    println!("(CTRL relay = reached through other members)");
}

fn print_pending(ps: &[ProposalView]) {
    if ps.is_empty() {
        println!("No proposals waiting.");
        return;
    }
    for p in ps {
        let what = match p.kind {
            ProposalKindView::Join => format!(
                "join of {}{} ({})",
                if p.privileged == Some(false) {
                    "unprivileged "
                } else {
                    ""
                },
                p.name.as_deref().unwrap_or("?"),
                p.node.map(|n| n.to_string()).unwrap_or_default()
            ),
            ProposalKindView::Remove => format!(
                "removal of {} ({})",
                p.name.as_deref().unwrap_or("?"),
                p.node.map(|n| n.short()).unwrap_or_default()
            ),
            ProposalKindView::Setting => match &p.setting {
                Some(s) => format!("setting {} = {}", s.key, s.value),
                None => "setting ?".into(),
            },
        };
        println!(
            "{}: {what}; proposed by {}; {}/{} approvals; expires in {}",
            p.id,
            p.proposer.short(),
            p.approvals.len(),
            p.needed,
            humantime(Duration::from_secs(p.expires_in_secs)),
        );
    }
}

fn humantime(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h{}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}m", s / 60)
    }
}

fn print_config(c: &ConfigView, key: Option<&str>) -> Result<()> {
    let all = c.entries();
    match key {
        Some(k) => match all.iter().find(|(n, _)| *n == k) {
            Some((_, v)) => println!("{v}"),
            None => anyhow::bail!(ApiError::new(
                ErrorCode::InvalidArgument,
                format!("unknown setting {k:?}"),
            )),
        },
        None => {
            for (k, v) in all {
                println!("{k} = {v}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use cheesecloth_daemon::api::PortMapGrant;

    use super::*;

    #[test]
    fn port_map_lines_show_the_method_or_the_failure() {
        let m = |mapped: Option<(&str, &str)>, error: Option<&str>| PortMapView {
            port: "wireguard".into(),
            local_port: 51820,
            mapped: mapped.map(|(external, method)| PortMapGrant {
                external: external.parse().unwrap(),
                method: method.into(),
            }),
            error: error.map(Into::into),
        };
        assert_eq!(
            port_map_line(&m(None, None)),
            "wireguard 51820 asking the router"
        );
        assert_eq!(
            port_map_line(&m(Some(("203.0.113.5:40123", "UPnP")), None)),
            "wireguard 51820 -> 203.0.113.5:40123 (UPnP)"
        );
        assert_eq!(
            port_map_line(&m(None, Some("UPnP: no gateway; PCP: timed out"))),
            "wireguard 51820 not mapped: UPnP: no gateway; PCP: timed out"
        );
        assert_eq!(
            port_map_line(&m(
                Some(("203.0.113.5:40123", "PCP")),
                Some("PCP: timed out")
            )),
            "wireguard 51820 -> 203.0.113.5:40123 (PCP), renewal failed: PCP: timed out"
        );
    }
}
