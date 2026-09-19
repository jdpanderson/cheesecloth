# Configuration

Every option, and where each value comes from. [Commands](commands.md) says what
the commands that read them do.

Options come from command-line flags or from a YAML configuration file,
`/etc/cheesecloth/config.yaml` by default (on Windows
`%ProgramData%\cheesecloth\config.yaml`) or the file named by `--config`. The
file holds one interface's settings, keyed by the flag names without the leading
dashes:

```yaml
interface: wgcloth
bind-addr: "::"
overlay-net: 10.42.0.0/24
```

A flag given on the command line overrides the file. Unknown keys in the file
are an error, as is `join-key`, a one-time secret that stays on the command
line. Environment variables are not read. An annotated example is in
[`dist/config.yaml`](../dist/config.yaml), and `cheesecloth config` prints or
writes the file for you — see
[`cheesecloth config`](commands.md#cheesecloth-config).

One file describes one interface. A host running a second cluster gives it its
own file and names it with `--config`, which that agent has to be told anyway:
one process serves one interface, so a file that held several only ever meant
"find the part of this that applies to me".

## Options

| Option | Config key | Description | Default |
|---|---|---|---|
| `--join HOST[:PORT],...` | `join` | comma separated list of hostnames or IP addresses of existing cluster members, with the cluster port unless given; if not provided, will attempt resuming any known state or otherwise wait for further members |  |
| `--join-key TOKEN` | command line only | invitation token from `cheesecloth invite` on a member; needed only the first time this node joins, ignored afterwards |  |
| `--control-socket PATH` | `control-socket` | unix socket used by the commands that talk to the agent | `/run/cheesecloth/<interface>.sock` on Linux, see [Platforms](operations.md#platforms) |
| `--bind-addr ADDR` | `bind-addr` | address to bind for cluster membership; `0.0.0.0` or `::` binds every interface of that family and advertises one of its addresses (public preferred). The family decides whether the cluster runs over IPv4 or IPv6, see [IPv4 and IPv6](#ipv4-and-ipv6) | `0.0.0.0` |
| `--cluster-port PORT` | `cluster-port` | UDP port this node listens on for membership gossip and enrolment (QUIC); peers learn it and remember it, so it need not be the same on every node, but a member listening on another port must be given as `host:port` in `--join` | `7946` |
| `--wireguard-port PORT` | `wireguard-port` | port used for wireguard traffic (UDP); must be the same across the cluster | `51820` |
| `--overlay-net ADDR/MASK` | `overlay-net` | the network in which to allocate addresses for the overlay mesh network (CIDR), see [Overlay addresses](#overlay-addresses); the same on every node of a cluster | the cluster's, learned at enrolment and kept; a new cluster must be given one |
| `--quorum RULE` | `quorum` | how many members must agree before a membership takes effect: `majority` (N/2+1), `half` (N/2), or a count. Read only when this node starts a cluster: it is settled then and carried in the cluster's records, so every node uses the same rule. `majority` is the only value that cannot fork, and is relaxed at two members so one node being down cannot freeze the other, see [Quorum](membership.md#quorum) | `majority` |
| `--confirmations N` | `confirmations` | how many members besides its signer must confirm an admission or a revocation before it counts. `0` is a cluster one person runs; `1` asks a second node to agree before anything changes. Clamped to one short of the membership. Read only when this node starts a cluster, and carried in its records thereafter, see [Confirmations](membership.md#confirmations) | `0` |
| `--allowed-ips NET/MASK,...` | `allowed-ips` | extra networks reachable through this node, see [Routing networks through a node](#routing-networks-through-a-node); must not overlap `--overlay-net` |  |
| `--interface DEV` | `interface` | name of the wireguard interface to create and manage. At most 15 characters of letters, digits, dots, dashes and underscores, starting with a letter or a digit: the name is the device's, and also names this node's state file and its control socket | `wgcloth` |
| `--mtu MTU` | `mtu` | MTU of the wireguard interface | `1420` |
| `--persistent-keepalive DURATION` | `persistent-keepalive` | interval at which peers send keepalives, to keep NAT mappings open (e.g. `25s`); `0` disables | `0` |
| `--sync-interval DURATION` | `sync-interval` | how often this node reconciles its whole membership with one other member, which is what catches anything gossip missed, see [How often a node reconciles](#how-often-a-node-reconciles). Between `5s` and `1h`; this node's own, and need not match its peers | `90s` |
| `--no-etc-hosts` | `no-etc-hosts` | skip writing hosts entries for each node in the mesh | `false` |
| `--userspace` | `userspace` | run WireGuard inside the agent instead of the kernel module (Linux); the default wherever the kernel has none, see [Which WireGuard is running](operations.md#which-wireguard-is-running) | `false` |
| `--log-level LEVEL` | `log-level` | verbosity: `debug`, `info`, `warn` or `error` | `warn` |
| `--config PATH` | command line only | configuration file to read | `/etc/cheesecloth/config.yaml` on Linux and macOS, see [Platforms](operations.md#platforms) |

`--interface` is local to a node: each names its interface what it likes, but
that name has to be given to the commands that talk to its agent, since they
find it by interface. `--wireguard-port` must be the same across the cluster.
`--cluster-port` need not be.

What the agent does with these on start — resume, enrol, found a cluster, or
wait — is in [`cheesecloth`](commands.md#cheesecloth).

## Overlay addresses

The overlay IP address of each node is allocated out of a private network, which
must not overlap the network the nodes use to reach each other. The node that
starts the cluster takes the first address; each node enrolled afterwards is
assigned the lowest free address by the member that admitted it, and that
assignment is part of its signed admission record. Addresses are therefore
stable across restarts, allocated from the start of the network, and agreed on
by every member. A node claiming an address other than its assigned one is
ignored.

The overlay network must be the same on every node, and a node is not expected to
be told it twice: the member that admits a node states the network in the
welcome, and the node keeps it in its state file. So only the node that starts a
cluster needs `--overlay-net`; everything after that, enrolment and restarts
alike, takes it from the cluster.

Where the value comes from, in order: the command line, then the configuration
file, then the cluster (the welcome for a node being enrolled, the state file for
one that is already a member). A value given here wins, so a whole cluster can be
renumbered by giving every node the new network — each node keeps its slot
number, so every address changes and no node has to enrol again. Until every node
has the new value, a node that has it stands alone: it derives different
addresses from the same records and every peer's metadata fails to verify, which
is logged as a warning on both sides.

Because a configured network only starts a cluster on a node with no state, the
setting is safe to leave in the file: a node that is already a member reads it as
the network it allocates addresses in, not as an instruction to start over. To
make a node forget the cluster it is in, use
[`cheesecloth leave`](commands.md#cheesecloth-leave).

A node's name — the first label of its hostname — identifies it in the cluster
and must be unique; enrolment refuses a name another member already holds.

## IPv4 and IPv6

Any address option accepts either family. Two independent choices are made per
cluster:

- **Underlay** (cluster gossip and wireguard endpoints): set by the family of
  `--bind-addr`. `0.0.0.0` (the default) or a specific IPv4 address makes an
  IPv4 cluster; `::` or a specific IPv6 address makes an IPv6 cluster. Every node
  of a cluster must use the same family, since an IPv4-only node cannot reach an
  IPv6-only one. Dual-stack hosts can join either kind of cluster.
- **Overlay** (the mesh addresses): the family of `--overlay-net`, independent of
  the underlay. An IPv6 overlay such as `fd00:10::/64` over an IPv4 underlay
  works, and so does the reverse.

With a wildcard bind address, cheesecloth advertises one of the host's addresses
of that family to the cluster, preferring a public one, then any global unicast
address (RFC 1918 and unique local addresses included). Link-local addresses and
addresses on the cheesecloth interface itself are never chosen. Set a specific
`--bind-addr` to control it.

## Routing networks through a node

A node can advertise networks behind it with `--allowed-ips` (for example a LAN,
or a cloud VPC's private range). Every peer adds them to that node's wireguard
allowed IPs and routes them over the overlay interface, so hosts on those
networks are reachable from the whole mesh through the advertising node. The
advertising node must have IP forwarding enabled (`sysctl net.ipv4.ip_forward=1`
or the IPv6 equivalent) and the hosts behind it need a way back, typically a
route for the overlay network via that node or masquerading on it.

Advertised networks are signed with the rest of the node's metadata. They must
not overlap the overlay network, and a network advertised by two nodes is routed
via the first by name; both cases are logged and otherwise ignored. There is
room for about sixty IPv4 prefixes and a node asked to advertise more than fits
does not start — see [how many a node can
advertise](limitations.md#a-node-can-advertise-only-so-many-networks).

Routes on the overlay interface are managed by cheesecloth: anything added by
hand is removed on the next membership change. A route the operating system
refuses — most often a network this host already routes somewhere else — is
logged as an error naming the destination and the node that advertised it, and
skipped. Only that destination is unreachable over the mesh: the peers whose
routes were installed keep working, and the next membership change tries again.
The same goes for a stale route that cannot be removed, which is logged and left
in place.

## How often a node reconciles

Records do not wait for this. An admission, a revocation or a confirmation is
sent to every member the moment it is signed — gossiped if it fits a datagram,
handed over a stream if not — so the cluster learns of a change in well under a
second. `--sync-interval` is the backstop: every so often a node reconciles its
whole membership with one other member, which is what catches a record that
reached nobody because the member was unreachable exactly then, or a node whose
state has drifted for a reason nothing announced.

So the setting trades how long a node can hold a membership the cluster has
moved past against how much it says while nothing is happening. A sync carries
both the node table and this node's records — a few kilobytes on a cluster of
twenty-five — and at the default each node exchanges one roughly every ninety
seconds. Halving the interval halves the reconciliation window and doubles that
traffic; doubling it does the reverse.

Enrolling a node is measured against it. A joiner waits for the cluster to
agree a membership holding it, and a member that never heard the admission
takes it at its next sync — so the admitting node waits one interval and a
margin before it gives up and tells the operator to invite the node again. A
node told to reconcile seldom therefore admits others slowly. A cluster still
being built is the case for a short interval; a large settled one, where the
traffic is what costs and nothing is joining, is the case for a long one, and
the interval can be raised again once it has settled.

It is this node's own. A node on a metered link can be turned up without
touching the rest of the cluster, because each node initiates on its own
schedule and its peer simply answers.

## /etc/hosts

cheesecloth adds an entry to `/etc/hosts` for each peer, so the nodes' hostnames
resolve to their overlay addresses (assuming `files` comes first for `hosts` in
`/etc/nsswitch.conf`). `--no-etc-hosts` disables this. On Windows the file is
`%SystemRoot%\System32\drivers\etc\hosts`.

Each agent rewrites the file whole, keeping the lines it does not manage, so a
host running several clusters has several agents writing it. They take a lock on
`/etc/hosts.lock` first, since otherwise one could write back what it read before
another's entries were added, and drop them. The lock file is created beside the
file it protects, is empty, and is left in place between writes.

The agent finds its own lines by a banner comment naming the interface; a
hand-written line ending in exactly that text is treated as one of ours, which is
in [limitations](limitations.md#a-hosts-file-line-ending-in-our-banner-is-treated-as-ours).

## Running multiple clusters

To make a node a member of several clusters, start one cheesecloth instance per
cluster. Each instance must have different values for:

- `--interface`
- either `--cluster-port` or `--bind-addr`
- `--wireguard-port`

`--overlay-net` need not differ but should, so a host in both clusters does not
see the same addresses twice.

Each gets its own configuration file, named with `--config`:

```yaml
# /etc/cheesecloth/wg1.yaml
interface: wg1
cluster-port: 7946
wireguard-port: 51820
overlay-net: 10.10.0.0/16
```

```yaml
# /etc/cheesecloth/wg2.yaml
interface: wg2
cluster-port: 7947
wireguard-port: 51821
overlay-net: 10.11.0.0/16
```

Every command then names the file it acts under — the agent, and `status`,
`invite`, `confirm`, `revoke` and `leave` alike:

```
# cheesecloth --config /etc/cheesecloth/wg2.yaml status
```
