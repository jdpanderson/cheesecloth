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
off. A refused connection gets one error line, then the daemon closes it.
An operator who sends `stop` gets an error; the service manager (launchd,
systemd, the Windows service manager) stops the daemon instead.

## Messages

A request is an object whose `cmd` names it, with its arguments beside it:

```json request
{"cmd":"approve","proposal":"6a1f0e2c9d3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f"}
```

An answer is `{"ok": <value>}` or `{"err": "<text>"}`:

```json response
{"ok":null}
```

```json response
{"err":"no member matches \"zz\""}
```

The error text is for people. Show it as it is; don't parse it.

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
    "relay": false,
    "acceptor": true,
    "this_node": false,
    "connected": true,
    "present": true,
    "wg_key": "Zq3cR8pY0v4u9dW2n1mK7jH6gF5eD4cB3aZ2yX1wV0s=",
    "path": "lan",
    "path_state": "up",
    "wg_endpoint": "10.0.0.64:51820",
    "handshake_age_secs": 16
  }
]
```

| Field | Meaning |
| --- | --- |
| `relay` | The member relays control messages. |
| `acceptor` | The member votes. |
| `this_node` | This entry is this node. |
| `connected` | This node has a direct control connection to it. |
| `present` | It is known to be alive, directly or through other members. Present but not connected means reached through other members. |
| `path` | How WireGuard reaches it: `self` (this node), `lan`, `public`, `await` (it will connect to us), `punch` (NAT hole punching), or `none`. |
| `path_state` | A short phrase for people, such as `up`, `stale`, `no handshake yet`, `punching` or `no path; retry in 20s`; `-` for this node. Don't parse it, except that `up` means a recent handshake. |
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
since 1970), 30 minutes after it was made. It starts with `cc1`.

```json request
{"cmd":"invite"}
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
daemon closes the connection. An error means that local cleanup is still
pending.

```json request
{"cmd":"stop"}
```

## Versions

`hello` answers `api`, one integer, now `1`. The daemon serves one API
version. A client checks it first, and stops if it does not know the
number.

These changes keep the number:
- a new request;
- a new field in an answer;
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
