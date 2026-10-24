# Design

This describes how Cheesecloth works now. To run it, see the
[quick start](QUICKSTART.md). For the fault model, see
[consensus safety](CONSENSUS-SAFETY.md).

Each daemon serves one cluster. There is no central server and no fixed
leader.

## Components

| Crate | Does |
| --- | --- |
| `cheesecloth-core` | identity, signed commands, invites, cluster state |
| `cheesecloth-net` | QUIC connections, authentication, relaying, reachability checks |
| `cheesecloth-wg` | WireGuard backends, path planning, NAT openers |
| `cheesecloth-daemon` | consensus rounds, membership, discovery, the local API |
| `cheesecloth` | the CLI and the daemon entry point |

The consensus engine and its storage are a separate crate,
[`pnyx`](https://crates.io/crates/pnyx).

The CLI and desktop apps talk to the daemon through the
[local API](LOCAL-API.md). It is a Unix socket, normally
`<state-dir>/control.sock`, or a named pipe on Windows.

## Identity and state

At first start, a node makes an Ed25519 identity and a WireGuard key. Its node
ID is its Ed25519 public key. Its signed member record ties that ID to its
WireGuard key, name and addresses. Keys are kept after leaving, and are never
rotated.

The cluster ID is a hash of the first signed command. Every later command
signs it.

There are two kinds of state:
- **Agreed state**: members, IPv4 addresses, settings, invites, pending
  proposals and recent results. Consensus decides it.
- **Soft state**: signed hints such as addresses, relay role and WireGuard
  endpoints. It guides routing, but can't change membership.

There is no full history of changes. Each member record says who admitted it.

## Control plane

Each node has one UDP socket for QUIC. A node checks each peer's Ed25519 key,
and only members may use member services. Non-members may only redeem an
invite or ask about their own join.

Every member connects to every relay. Other members connect directly only on
the same LAN, or when there is no relay. Relayed messages are signed end to
end. A relay can drop or delay them, but not change them.

### Relays

With `--relay auto`, a node relays when others can reach it from the
internet. To check, another member connects back to it from a new socket,
which the node's firewall sees as unrequested. The check runs every ten
minutes, and when the node's addresses change. A founder alone counts as
reachable if it has a public address.

Members on the same network as the node can't do this check, because their
connection does not cross the router. When only those are connected, the
check waits and `status` warns.

The check tests only the control port. The WireGuard port is assumed to
behave the same, because it is behind the same router.

Only members with the `relay` permission relay. Others never treat a member
without it as a relay, whatever it says. Only the WireGuard endpoints seen by
public relays are trusted.

### Protocol

The ALPN is `cheesecloth/2`, and messages use Postcard. Each stream starts
with its kind, the cluster ID and the sender's clock.

| Stream | Use |
| --- | --- |
| `direct` | consensus, state transfer and punch coordination |
| `state` | soft-state updates |
| `forward`, `deliver` | relayed messages |
| `join` | joining; the only stream for non-members |
| `probe` | reachability checks |

A request is retried on another route only if it can't have arrived. If the
reply is lost after it arrived, the result is reported as unknown.

## Membership and approvals

`init` makes a one-member cluster. The founder has no special power after
that. An invite holds a secret, the cluster ID, and the keys and addresses of
voters. A joiner trusts the voter it contacts, and the state it gets from it.

An invite expires after 30 minutes. It is used up as soon as it is redeemed,
even if the join then fails or waits for approval.

Permissions are described in [trust](TRUST.md#permissions). The CLI
gives every permission unless told not to. The local API gives only the ones
a request asks for. An admin may give a permission it doesn't have itself.

With `approvals_required = N`, a join, removal or setting change needs N
approvals from admins other than the one who proposed it. A member can't vote
on its own removal. One rejection from any admin ends a proposal. Proposals
expire after 24 hours.

`approvals_required` can't be more than the number of admins minus one.
Removing an admin needs N + 2 admins, because the target can't vote. If
admins leave, N may become too high to meet. It is never lowered for you. If
nobody can approve any more, rebuild the cluster.

The last admin or voter may leave:
- With no admin, the cluster works, but nobody can invite, remove or change
  settings. `status` warns.
- With no voter, nothing can change, not even a member leaving. The last
  voter's `leave` stops with `no_replacement`; `leave --force` goes on.

## Consensus

Any member may propose a change it has permission for. The daemon adds
signed evidence to each round. See
[the authenticated round](CONSENSUS-SAFETY.md#authenticated-round).

Voters come only from members with `vote`. Selection keeps current voters,
prefers reachable ones, and adds only reachable members, relays first. The
reachable voter with the lowest ID checks the selection every ten seconds. A
voter that is gone for ten minutes may be replaced, within the buffer and
strict rules. Each voter checks the new group with what it sees itself, so
they may disagree for a while.

A node accepts a new state only with its certificate and the chain of
configurations from the state it trusts. It saves both before it reports
progress.

Voters hear of each commit. Other members fetch a new state when soft state
shows one. A source that fails is retried after 2 seconds, doubling up to 256.

While too few voters are reachable, changes fail at once with `no_quorum`.
WireGuard keeps working with the last known members. There is no automatic
reset, and no merging of split histories. If the quorum is lost for good,
rebuild the cluster.

Proofs of configuration changes are kept for `catch_up_days`. A node that
returns after they expire can't catch up. Remove it and invite it again.

## Settings

Read settings with `cheesecloth config get [key]`. Change them with
`cheesecloth config set <key> <value>`; this follows the approval rules.
Daemon options, such as ports, are local and are not settings.

| Setting | Default | Meaning |
| --- | --- | --- |
| `approvals_required` | `0` | Approvals from other admins for joins, removals and setting changes. |
| `acceptors` | `7` | Most voters, from 1 to 7. |
| `strict_security` | `false` | Once protected, never move to relaxed mode. |
| `buffer_nodes` | `0` | Voters that may be offline while changes still work, from 0 to 3. |
| `catch_up_days` | `30` | Days to keep configuration proofs, from 1 to 3650. |

`ipv4_range` and `ipv6_prefix` can be read, but not changed.

## WireGuard and NAT traversal

IPv6 overlay addresses come from the cluster and node IDs. IPv4 addresses are
agreed through consensus. `init` picks a random /24 in `100.64.0.0/10` that
does not clash with the founder's routes. Use `init --ipv4-range CIDR` to pick
one yourself.

Every second, and on each change, the daemon works out the peers and routes
it wants and applies them. It owns its interface: it removes unknown peers,
and retries failed removals. A removed member keeps access until a removal
succeeds. There are no per-peer rules; use a host firewall to limit traffic.

A path uses a LAN address, a public endpoint, or NAT hole punching. For two
peers behind NAT, a relay shares the endpoints it sees and tells both to send
packets from their WireGuard ports. The lower ID then starts the handshake.
This works for IPv4 only.

A failed path is removed, and the daemon waits 35 seconds so the old NAT
mapping expires. Repeated failures back off to five minutes. WireGuard traffic
is never relayed. Some NATs need a port mapping, a forwarded port or a public
address.

The daemon asks the router for IPv4 port mappings with UPnP or PCP, and
releases them on shutdown. `--no-port-mapping` turns this off. `status` shows
each mapping, or its error.

WireGuard keepalive is 25 seconds behind NAT, 300 seconds with a router
mapping, and off when public. `--keepalive` overrides it. Punched paths
always keep a keepalive. QUIC keepalive is always 25 seconds.

The default backend is kernel WireGuard, then userspace. macOS, Windows and
FreeBSD use userspace: GotaTun inside the daemon, with a TUN device. Windows
uses Wintun, and needs `wintun.dll` beside the program.

## Lifecycle and recovery

`leave` never needs approval. A leaving voter hands its role to another, waits
for the new voters to save the state, then removes itself. If too few new
voters are reachable, it stops at once. If a step fails, the daemon keeps
running, and `leave` can be retried. `leave --force` goes on to local cleanup
anyway, which may leave the others without a quorum.

`leave` during a pending join cancels it locally. The invite stays used, and
the proposal stays until it is rejected or expires.

Members stop talking to a removed node, and revoke its WireGuard key. A
removed node that is online is told, so it can clean up. One that was offline
may never learn it; run `leave --force` on it.

Cleanup is saved to disk before the interface and files are removed. If it
fails, `status` shows `stopping` and the error, and normal work stops until
`leave` finishes it, also after a restart. A normal shutdown uses the same
cleanup, but keeps the cluster files.

| State file | Holds |
| --- | --- |
| `identity.key`, `wireguard.key` | the node's keys; kept after leaving |
| `cluster.json` | the cluster ID, and any pending join |
| `acceptor.0`, `acceptor.1` | voting records and the latest state with its proof, in two copies |
| `transitions.bin` | configuration change proofs |
| `cleanup.json` | unfinished cleanup |

Files are replaced atomically and synced to disk. On start, the daemon checks
that they agree.

## Clocks and retries

Keep clocks in sync with NTP. A new state's time may be at most 30 seconds
ahead of the voter's clock, or of the last state's time if that is later. A
signed command must be within ten minutes of that time. `status` warns when
peers' clocks are more than 30 seconds apart. Cheesecloth never sets the
clock.

Results are kept for 20 minutes, so a retry of the same command gets the
same result. Running a CLI command again sends a new command. After a
timeout, the first one may or may not have happened.

## Discovery and resource bounds

Nodes send soft state only when it changes. It spreads through existing
connections.

| Resource | Limit |
| --- | --- |
| Agreed state | 320 KiB |
| Request or response | 1 MiB |
| Join request | 64 KiB |
| Proofs per fetch | 256 KiB |
| Soft state per node | 128 KiB, 32 addresses per list, 1,024 connections or observations |
| Soft-state batch | 256 KiB |
| Soft state from unknown members | 256 entries |
| Member name | 32 bytes |
| Member addresses | 16 |

Non-members get at most 64 connections per node, and eight per IPv4 address
or IPv6 /64. Each has two streams, 30 seconds to send a request, and two
minutes in all. A wrong invite secret never starts a consensus round.

A ballot hint from a peer can raise the counter by at most `2^20`, so one bad
hint can't use up the counter.

## Windows

Some parts are weaker on Windows, such as disk sync and NAT openers. See
[the Windows weak points](WINDOWS.md#weak-points).
