# The local API

The daemon serves a local API. The `cheesecloth` CLI uses it, and so do the
desktop apps in the OS repositories (see [REPOSITORIES.md](REPOSITORIES.md)).
This document is the contract between them: a client may rely on what it
says, and on nothing else.

## Transport

- **Unix (macOS, Linux, FreeBSD):** a Unix domain socket, by default
  `<state-dir>/control.sock`. The default state directory is
  `/Library/Application Support/cheesecloth` on macOS and
  `/var/lib/cheesecloth` elsewhere.
- **Windows:** a named pipe, `\\.\pipe\cheesecloth-<hex>`, where `<hex>` is
  32 lowercase hex digits from a hash of the canonical state directory
  (`C:\ProgramData\cheesecloth` by default). Open it with read access and
  `FILE_WRITE_DATA` only (`FILE_GENERIC_READ | FILE_WRITE_DATA`), not
  `GENERIC_WRITE`: the pipe does not give other users the right to create
  instances, which `GENERIC_WRITE` includes. Before sending a request, check
  that the pipe's server process runs as SYSTEM, an administrator or the
  client's own user (`GetNamedPipeServerProcessId`), so that another user
  can't serve the pipe in the daemon's place.

`daemon --socket` and `--state-dir` choose another address. Separate daemons
have separate addresses.

On a connection, the client sends one request per line, and the daemon
answers each with one line, in order. Lines are UTF-8 JSON objects ending in
`\n`. A connection may carry any number of requests. Clients ask when they
need an answer; the daemon does not send anything unasked.

## Access

The daemon decides what each connection may do, from who opened it:

| Who | May |
| --- | --- |
| root; SYSTEM; an elevated administrator on Windows; the daemon's own user | send every request |
| an operator | send every request except `stop` |
| anyone else | nothing |

An operator is:
- on macOS, a member of `admin`;
- on Linux and FreeBSD, a member of the group named by `daemon --api-group`
  (none by default);
- on Windows, an administrator who is not elevated.

`daemon --api-group` also sets the group on macOS; an empty name turns it
off. A refused connection gets one error line, `permission_denied` (or
`access_check_failed` when the daemon can't tell who connected), before any
request, then the daemon closes it. An operator who sends `stop` gets
`permission_denied`; the service manager (launchd, systemd, the Windows
service manager) stops the daemon instead.

## Messages

A request is an object whose `cmd` names it, with its arguments beside it:

```json request
{"cmd":"approve","proposal":"6a1f0e2c9d3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f"}
```

An answer is `{"ok": <value>}` or `{"err": {"code": "<code>", "message":
"<text>"}}`:

```json response
{"ok":null}
```

```json response
{"err":{"code":"no_such_member","message":"no member matches \"zz\""}}
```

`code` says what went wrong, for programs; [Errors](#errors) lists the
codes. `message` is for people: show it as it is, and never read it to
decide what to do.

Values:
- Node, cluster and proposal IDs are 64 lowercase hex digits.
- WireGuard keys are base64, as WireGuard tools show them.
- Addresses are strings: `"100.80.11.5"`, `"[::]:51821"`.
- A field shown as `null` may also have a value, and the other way round,
  where the tables say so.

## Requests

### `hello`

Send it first. Its answer names the API version and the daemon's release.
Stop if you don't know the `api` number (see [Versions](#versions)).

```json request
{"cmd":"hello"}
```

```json hello
{"api":1,"daemon":"0.5.0"}
```

### `status`

This node.

```json request
{"cmd":"status"}
```

```json status
{
  "security": "protected",
  "quorum": 3,
  "reachable_voters": 4,
  "changes_paused": false,
  "strict_security": false,
  "buffer_nodes": 0,
  "node_id": "74b239929045c3f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a567",
  "name": "artemis.local",
  "phase": "member",
  "cluster_id": "7bcff0eaa871d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d1b09",
  "pending_proposal": null,
  "ipv4": "100.80.11.5",
  "ipv6": "fdcc:61c2:cb8b:0:561:bb3c:e9bd:32b9",
  "privileged": true,
  "relay": false,
  "public": false,
  "keepalive": 25,
  "acceptors": [
    "74b239929045c3f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a567"
  ],
  "config": 12,
  "version": 2119,
  "members": 7,
  "control_addr": "[::]:51821",
  "wg_backend": "userspace",
  "wg_interface": "utun7",
  "wg_port": 51820,
  "port_mapping": [
    {
      "port": "wireguard",
      "local_port": 51820,
      "mapped": {"external": "203.0.113.7:51820", "method": "UPnP"},
      "error": null
    },
    {
      "port": "control",
      "local_port": 51821,
      "mapped": null,
      "error": "no router answered"
    }
  ],
  "warnings": []
}
```

| Field | Meaning |
| --- | --- |
| `phase` | `none` (no cluster), `pending` (a join waits for approvals), `member`, or `stopping` (leaving has not finished; `warnings` says why). |
| `security` | `uninitialized` (not a member), `relaxed`, or `protected`. See [CONSENSUS-SAFETY.md](CONSENSUS-SAFETY.md). |
| `quorum`, `reachable_voters` | Votes needed, and voters this node can reach. 0 when not a member. |
| `changes_paused` | True when `reachable_voters` is below `quorum`, or while stopping. |
| `strict_security`, `buffer_nodes` | Cluster settings; see `config_get`. |
| `node_id`, `name` | This node. |
| `cluster_id` | Null in phase `none`. |
| `pending_proposal` | The join waiting for approvals, in phase `pending`; else null. |
| `ipv4`, `ipv6` | This node's overlay addresses; null unless a member. |
| `privileged` | This node may change the cluster and vote (see `peers`); null unless a member. |
| `relay` | This node relays control messages for others. |
| `public` | This node is reachable from the internet. |
| `keepalive` | WireGuard keepalive in seconds; 0 is off. |
| `acceptors` | The voters of the agreed state. |
| `config`, `version` | The acceptor configuration number and the version of the agreed state this node holds; null unless a member. |
| `members` | The number of members; 0 unless a member. |
| `control_addr` | The control plane's local address. |
| `wg_backend` | `kernel`, `userspace`, or null while there is no interface. Other values may come. |
| `wg_interface`, `wg_port` | The WireGuard interface name and port. |
| `port_mapping` | Null when port mapping is off. Else one entry for each port (`wireguard`, `control`): `mapped` once the router grants it (`method` is `UPnP`, `PCP` or `NAT-PMP`), and `error` from the last attempt that failed. Both null while it is still asking. |
| `warnings` | Sentences for people, one each. |

### `peers`

The members, this node among them. Fails if this node is not a member.

```json request
{"cmd":"peers"}
```

```json peers
[
  {
    "node_id": "9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d",
    "name": "hephaestus",
    "ipv4": "100.80.11.7",
    "ipv6": "fdcc:61c2:cb8b:0:9c0d:1e2f:3a4b:5c6d",
    "privileged": true,
    "relay": false,
    "acceptor": true,
    "this_node": false,
    "connected": true,
    "present": true,
    "wg_key": "Zq3cR8pY0v4u9dW2n1mK7jH6gF5eD4cB3aZ2yX1wV0s=",
    "path": "lan",
    "path_state": "up",
    "path_detail": "up",
    "retry_in_secs": null,
    "wg_endpoint": "10.0.0.64:51820",
    "handshake_age_secs": 16
  },
  {
    "node_id": "2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e",
    "name": "hypnos",
    "ipv4": "100.80.11.9",
    "ipv6": "fdcc:61c2:cb8b:0:2d3e:4f5a:6b7c:8d9e",
    "privileged": false,
    "relay": false,
    "acceptor": false,
    "this_node": false,
    "connected": false,
    "present": true,
    "wg_key": "Mb7cT2rX9q4n8eV1k5jL3hG6fD0aS2wQ7zY4uP9oI1E=",
    "path": "punch",
    "path_state": "no_path",
    "path_detail": "no path; retry in 20s",
    "retry_in_secs": 20,
    "wg_endpoint": null,
    "handshake_age_secs": null
  }
]
```

| Field | Meaning |
| --- | --- |
| `privileged` | The member may invite, remove, change settings, approve, reject, vote and relay. An unprivileged member has the same mesh access, but may only update itself and leave. |
| `relay` | The member relays control messages. Never true for an unprivileged member. |
| `acceptor` | The member votes. Only privileged members vote. |
| `this_node` | This entry is this node. |
| `connected` | This node has a direct control connection to it. |
| `present` | It is known to be alive, directly or through other members. Present but not connected means reached through other members. |
| `path` | How WireGuard reaches it: `self` (this node), `lan`, `public`, `await` (it will connect to us), `punch` (NAT hole punching), or `none`. |
| `path_state` | Where the path is: `self` (this node), `up` (a recent handshake), `stale` (the last handshake is old), `no_handshake`, `waiting_to_punch`, `offer_sent`, `punching`, `waiting_for_removal`, `no_path` (hole punching failed; it is tried again after `retry_in_secs`), or `not_configured`. Other values may come; show `path_detail` for them. |
| `path_detail` | `path_state` for people, such as `no path; retry in 20s`. Don't parse it. |
| `retry_in_secs` | With `no_path`: seconds until this node tries again; else null. |
| `wg_endpoint` | The address WireGuard sends to; null if none. |
| `handshake_age_secs` | Seconds since the last WireGuard handshake; null if none. |

### `init`

Create a cluster with this node as its first member. Both arguments may be
left out.

```json request
{"cmd":"init","strict_security":false,"ipv4_range":"100.80.11.0/24"}
```

```json init
{"cluster_id":"7bcff0eaa871d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d1b09","ipv4_range":"100.80.11.0/24"}
```

### `invite`

An invite token. It works once, and until `expires_at_ms` (milliseconds
since 1970), 30 minutes after it was made. It starts with `cc1`. With
`unprivileged` (may be left out), the new member is unprivileged (see
`peers`). The member's privilege never changes; to change it, the member
leaves or is removed, and joins again.

```json request
{"cmd":"invite","unprivileged":false}
```

```json invite
{"token":"cc1AAAA...","expires_at_ms":1760281200000}
```

### `join`

Join a cluster with a token from `invite`. The answer is either joined, or
waiting for approvals; then `node_id` is this node's key, for the approvers
to check.

```json request
{"cmd":"join","token":"cc1AAAA..."}
```

```json join
{"joined":true,"cluster_id":"7bcff0eaa871d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d1b09","ipv4":"100.80.11.8"}
```

```json join
{"joined":false,"proposal":"6a1f0e2c9d3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f","node_id":"74b239929045c3f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a567"}
```

### `leave`

Leave the cluster, or cancel a join that waits for approvals. `force` (may
be left out) goes on past steps that fail.

```json request
{"cmd":"leave","force":false}
```

```json leave
{"outcome":"left","remaining_members":6,"problems":[]}
```

```json leave
{"outcome":"join_cancelled","cluster_id":"7bcff0eaa871d2c3b4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d1b09","proposal":"6a1f0e2c9d3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f"}
```

`problems` lists the steps that failed, with `force`. A cancelled join is
cancelled on this node only: members may still need to reject the proposal.

### `remove`, `approve`, `reject`, `config_set`

These change the cluster. `remove` takes a node ID, a unique prefix of one,
or a name. `approve` and `reject` take a proposal ID from `pending`.
`config_set` takes a setting from `config_get` (not `ipv4_range` or
`ipv6_prefix`) and its value as a string.

```json request
{"cmd":"remove","node":"hypnos"}
```

```json request
{"cmd":"reject","proposal":"6a1f0e2c9d3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f"}
```

```json request
{"cmd":"config_set","key":"approvals_required","value":"1"}
```

The answer says what happened:

| `outcome` | Meaning |
| --- | --- |
| `pending` | The change waits for approvals, as `proposal`. |
| `approved` | The approval counted; `remaining` more are needed. |
| `rejected` | The proposal is rejected. |
| `joined` | The last approval admitted `node`, at `ipv4`. |
| `removed` | `node` is no longer a member. |
| `setting_changed` | The setting has its new value. |

```json change
{"outcome":"pending","proposal":"6a1f0e2c9d3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f"}
```

```json change
{"outcome":"approved","proposal":"6a1f0e2c9d3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f","remaining":1}
```

```json change
{"outcome":"joined","node":"9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d","ipv4":"100.80.11.8"}
```

```json change
{"outcome":"removed","node":"9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d"}
```

```json change
{"outcome":"setting_changed"}
```

### `pending`

The proposals that wait for approvals.

```json request
{"cmd":"pending"}
```

```json pending
[
  {
    "id": "6a1f0e2c9d3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f",
    "kind": "join",
    "node": "9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d",
    "name": "hypnos",
    "privileged": false,
    "setting": null,
    "proposer": "74b239929045c3f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a567",
    "approvals": [],
    "needed": 1,
    "expires_in_secs": 720
  },
  {
    "id": "1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c",
    "kind": "setting",
    "node": null,
    "name": null,
    "privileged": null,
    "setting": {"key": "approvals_required", "value": "2"},
    "proposer": "74b239929045c3f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a567",
    "approvals": [],
    "needed": 1,
    "expires_in_secs": 3000
  }
]
```

`kind` is `join`, `remove` or `setting`. For a join, `node` is the joining
node's key: approvers check it against the key the joining node shows. For
a removal it is the member to remove. `name` is null if unknown.
`privileged` says, for a join, whether the new member will be privileged;
it is null for other kinds.

### `config_get`

The cluster settings.

```json request
{"cmd":"config_get"}
```

```json config
{"approvals_required":0,"acceptors":5,"strict_security":false,"buffer_nodes":0,"catch_up_days":7,"ipv4_range":"100.80.11.0/24","ipv6_prefix":"fdcc:61c2:cb8b::/48"}
```

### `stop`

Stop the daemon. Root and the daemon's own user only (see [Access](#access)).
The answer, `{"ok":null}`, comes once shutdown has finished, and then the
daemon closes the connection. The error `cleanup_pending` means that the
daemon stopped, but removing its interface or files failed.

```json request
{"cmd":"stop"}
```

## Errors

Every error has a `code` and a `message`. Choose what to do from `code`
only. Show `message`, the full text for people, as the detail; its words may
change in any release.

A code keeps its meaning. New codes may come in the same API version
(see [Versions](#versions)): treat a code you don't know as a failure
without more detail, and show its message. A daemon from before error codes
(cheesecloth 0.4.0 and older) answers `hello` with `{"err": "<text>"}`, a
string: that shape, not its words, means `api_version_mismatch`.

Codes from the daemon:

| Code | Meaning |
| --- | --- |
| `permission_denied` | The caller may not use the daemon, or may not make this request (see [Access](#access)). |
| `access_check_failed` | The daemon can't tell who connected, or can't look up their groups. |
| `invalid_request` | The line is not a request this daemon knows: bad JSON, an unknown `cmd`, or a missing or wrong argument. |
| `shutting_down` | The daemon is stopping, and answers no more requests. |
| `node_stopping` | The node is stopping, for example while it leaves its cluster. |
| `cleanup_pending` | The node stopped, but removing its interface or files failed. `leave` again, or restart the daemon. |
| `not_in_cluster` | The request needs a cluster, and this node is in none. |
| `already_in_cluster` | `init` or `join`, but this node is in a cluster or waits to join one. |
| `no_free_range` | `init` found no free /24 in 100.64.0.0/10. |
| `invalid_token` | `join` can't read the invite token. |
| `members_unreachable` | `join` reached no member listed in the token. |
| `join_unconfirmed` | A member got the join request, but its answer was lost. The invite may have been used: check with a member before asking for another. |
| `join_rejected` | The members rejected the join, or its proposal expired. |
| `join_refused` | A member refused the join for a reason without a code. |
| `ambiguous_node` | `remove` names several members; give more of the node ID. |
| `remove_self` | `remove` names this node; use `leave`. |
| `no_quorum` | Too few acceptors could be reached to agree on the change. It may still be agreed later: read the state again before you retry. |
| `security_policy` | The change breaks the cluster's security policy (see [CONSENSUS-SAFETY.md](CONSENSUS-SAFETY.md)). |
| `no_replacement` | The change would remove an acceptor that no other member can replace. |
| `is_acceptor` | This node is an acceptor, and gives up the role before it leaves. |
| `state_too_large` | The change would make the agreed state too large. |
| `leave_incomplete` | Leaving stopped part way, and this node still runs. `leave` again, or `leave` with `force`. |
| `wrong_cluster` | The command belongs to another cluster. |
| `bad_signature` | A signature didn't verify. |
| `stale_command` | The command is too old, or the clocks differ too much. |
| `already_applied` | The command was already applied. |
| `already_initialized` | The cluster has already been created. |
| `not_initialized` | The cluster doesn't exist yet. |
| `not_member` | The node that signed the command is not a member. |
| `unprivileged` | This node is an unprivileged member, which can't change the cluster. |
| `last_privileged` | `leave` from the last privileged member while other members remain. Remove the unprivileged members first. |
| `invite_unknown` | The invite is unknown, expired or already used. |
| `already_member` | The node is already a member. |
| `already_pending` | A join for the node already waits for approval. |
| `no_such_member` | No member matches. |
| `no_such_proposal` | No proposal has this ID. |
| `own_proposal` | A proposer can't approve its own proposal. |
| `own_removal` | A member can't approve or reject its own removal. |
| `already_approved` | This member already approved the proposal. |
| `range_full` | No overlay IPv4 address is left in the cluster's range. |
| `invalid_setting` | A setting name or value is not valid. |
| `invalid_member` | A member record is not valid. |
| `operation_failed` | An operation failed, such as a network, disk or interface step, and has no more precise code. The message says what. |
| `internal_error` | A fault in the daemon. |

Codes from clients, for failures before or outside an answer:

| Code | Meaning |
| --- | --- |
| `daemon_unavailable` | The socket or pipe can't be reached. |
| `api_version_mismatch` | The daemon serves another API version, or is older than `hello`. |
| `transport_error` | The connection failed, or closed before the answer. |
| `invalid_response` | The daemon's answer can't be read. |
| `invalid_argument` | The command line is not valid. |

### The CLI

The `cheesecloth` CLI reports a failure with the same codes. It copies a
daemon's code and message as they are, and exits nonzero. Without `--json`
it writes one line to stderr, `error[<code>]: <message>`:

```
error[permission_denied]: only root and members of the group admin may use the cheesecloth daemon
```

A program can read the code with `^error\[([a-z_]+)\]: `, and must not
read the rest. With `--json` (even when the command line is not valid), a
success writes the answer's value to stdout, as before, and a failure
writes one JSON document to stdout instead:

```json cli_error
{"error":{"code":"daemon_unavailable","message":"can't reach the cheesecloth daemon at /var/lib/cheesecloth/control.sock (is it running, and do you have permission?): No such file or directory (os error 2)"}}
```

The exit status tells the two apart. A desktop app that runs the CLI should
use `--json`. If the CLI can't be started, or prints no valid document, that
is the app's own failure to report.

## Versions

`hello` answers `api`, one integer, now `1`. The daemon serves one API
version. A client checks it first, and stops if it does not know the
number.

These changes keep the number:
- a new request;
- a new field in an answer;
- a new error code;
- a new value of a string that this document lists as open (such as
  `wg_backend` and `path_state`).

Clients ignore fields they don't know.

These changes raise it:
- removing or renaming a request or a field;
- a change to a field's type or meaning;
- a new value of a string that this document lists as closed (such as
  `phase`, `security`, `path` and `outcome`);
- a new field that a request must have.

The desktop apps ship with their daemon, so a client and daemon of the same
release always match.
