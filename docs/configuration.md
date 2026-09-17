# Configuration

Options come from command-line flags or from a YAML configuration file,
`/etc/cheesecloth/config.yaml` by default (on Windows
`%ProgramData%\cheesecloth\config.yaml`) or the file named by `--config`. The
file holds one interface's settings, keyed by the flag names without the
leading dashes:

```yaml
interface: wgcloth
bind-addr: "::"
overlay-net: 10.42.0.0/24
```

A flag given on the command line overrides the file. Unknown keys in the file
are an error, as is `join-key`, a one-time secret that stays on the command
line. Environment variables are not read. An annotated example is in
[`dist/config.yaml`](../dist/config.yaml).

One file describes one interface. A host running a second cluster gives it its
own file and names it with `--config`, which that agent has to be told anyway:
one process serves one interface, so a file that held several only ever meant
"find the part of this that applies to me".

| Option | Config key | Description | Default |
|---|---|---|---|
| `--join HOST[:PORT],...` | `join` | comma separated list of hostnames or IP addresses of existing cluster members, with the cluster port unless given; if not provided, will attempt resuming any known state or otherwise wait for further members |  |
| `--join-key TOKEN` | command line only | invitation token from `cheesecloth invite` on a member; needed only the first time this node joins, ignored afterwards |  |
| `--control-socket PATH` | `control-socket` | unix socket used by `cheesecloth invite`, `cheesecloth revoke` and `cheesecloth leave` | `/run/cheesecloth/<interface>.sock` on Linux, see [Platforms](operations.md#platforms) |
| `--bind-addr ADDR` | `bind-addr` | address to bind for cluster membership; `0.0.0.0` or `::` binds every interface of that family and advertises one of its addresses (public preferred). The family decides whether the cluster runs over IPv4 or IPv6, see [IPv4 and IPv6](#ipv4-and-ipv6) | `0.0.0.0` |
| `--cluster-port PORT` | `cluster-port` | UDP port this node listens on for membership gossip and enrolment (QUIC); peers learn it and remember it, so it need not be the same on every node, but a member listening on another port must be given as `host:port` in `--join` | `7946` |
| `--wireguard-port PORT` | `wireguard-port` | port used for wireguard traffic (UDP); must be the same across cluster | `51820` |
| `--overlay-net ADDR/MASK` | `overlay-net` | the network in which to allocate addresses for the overlay mesh network (CIDR format), see [Overlay addresses](#overlay-addresses); the same on every node of a cluster | the cluster's, learned at enrolment and kept; a new cluster must be given one |
| `--quorum RULE` | `quorum` | how many members must agree before a membership takes effect: `majority` (N/2+1), `half` (N/2), or a count. Read only when this node starts a cluster: it is settled then and carried in the cluster's records, so every node uses the same rule. `majority` is the only value that cannot fork, and is relaxed at two members so one node being down cannot freeze the other, see [Quorum](membership.md#quorum) | `majority` |
| `--allowed-ips NET/MASK,...` | `allowed-ips` | extra networks reachable through this node, see [Routing networks through a node](#routing-networks-through-a-node); must not overlap `--overlay-net` |  |
| `--interface DEV` | `interface` | name of the wireguard interface to create and manage | `wgcloth` |
| `--mtu MTU` | `mtu` | MTU of the wireguard interface | `1420` |
| `--persistent-keepalive DURATION` | `persistent-keepalive` | interval at which peers send keepalives, to keep NAT mappings open (e.g. `25s`); `0` disables | `0` |
| `--no-etc-hosts` | `no-etc-hosts` | whether to skip writing hosts entries for each node in mesh | `false` |
| `--userspace` | `userspace` | run WireGuard inside the agent instead of the kernel module (Linux); the default wherever the kernel has none, see [Platforms](operations.md#platforms) | `false` |
| `--log-level LEVEL` | `log-level` | set the verbosity (one of debug/info/warn/error) | `warn` |
| `--config PATH` | command line only | configuration file to read | `/etc/cheesecloth/config.yaml` on Linux and macOS, see [Platforms](operations.md#platforms) |

## What the agent does on start

The agent settles its membership before it configures anything, from its state
and what it was given:

- **Already a member**: it resumes from its state file and rejoins. This is the
  usual case, and needs neither `--overlay-net` nor `--join-key`. A stale
  `--join-key` left on the command line is ignored.
- **Not a member, `--join-key` given**: it enrols with one of the `--join`
  members, which tells it the cluster's overlay network.
- **Not a member, an overlay network configured**: it starts a new cluster with
  itself as the root. Configuring a network for a node that has no state is
  what starts a cluster; there is no separate flag for it.
- **Not a member, neither given**: it waits. Nothing is configured and no
  interface is created, but the node's identity is generated and kept, so it is
  the same node when it is finally given something to act on. The control socket
  is opened and every command refused with what would give it a cluster, since
  an agent that is running should say so rather than look absent. Waiting rather than exiting means a node can be installed and its
  service enabled before anyone has decided what it joins, and means a service
  manager is not left restarting an agent that is only unconfigured.

Because a configured network only starts a cluster on a node with no state, the
setting is safe to leave in the file: a node that is already a member reads it
as the network it allocates addresses in, not as an instruction to start over.
To make a node forget the cluster it is in, use `cheesecloth leave` (or `leave
--force` when its agent is not running), which is described in
[operations](operations.md#decommissioning-a-node).

## Reading and writing the configuration

`cheesecloth config` prints the settings as a config file, so that what a node
runs with can be captured into one rather than reconstructed by hand. It prints
the effective settings — the command line, then the file, then what the cluster
told the node, then the defaults — leaving out anything that matches its
default, so the result is as short as what has to be maintained:

```
# cheesecloth config --interface wgmesh
interface: wgmesh
overlay-net: 10.42.0.0/24
```

That is the form to redirect somewhere as a whole:

```
# cheesecloth config > /etc/cheesecloth/config.yaml
```

`cheesecloth config --init` writes the file instead of printing it, which is how
a node is set up before its agent first runs. A file that is already there is
left alone rather than written over — edit it, print the settings and redirect
them yourself, or name another file with `--config`. Creating the file is the
whole of the write, so two of these racing need no lock: one creates it and the
other is told it is there.

## Overlay addresses

The overlay IP address of each node is allocated out of a private network,
which must not overlap the network the nodes use to reach each other. The node that starts the cluster takes the first address;
each node enrolled afterwards is assigned the lowest free address by the member
that admitted it, and that assignment is part of its signed admission record.
Addresses are therefore stable across restarts, allocated from the start of
the network, and agreed on by every member. A node claiming an address other
than its assigned one is ignored.

The overlay network must be the same on every node, and a node is not expected
to be told it twice: the member that admits a node states the network in the
welcome, and the node keeps it in its state file. So only the node that starts
a cluster needs `--overlay-net`; everything after that, enrolment and restarts
alike, takes it from the cluster.

Where the value comes from, in order: the command line, then the configuration
file, then the cluster (the welcome for a node being enrolled, the state file
for one that is already a member). A value given here wins,
so a whole cluster can be renumbered by giving every node the new network —
each node keeps its slot number, so every address changes and no node has to
enrol again. Until every node has the new value, a node that has it stands
alone: it derives different addresses from the same records and every peer's
metadata fails to verify, which is logged as a warning on both sides.

A node's name — the first label of its hostname — identifies it in the cluster
and must be unique; enrolment refuses a name another member already holds.

## IPv4 and IPv6

Any address option accepts either family. Two independent choices are made per
cluster:

- **Underlay** (cluster gossip and wireguard endpoints): set by the family of
  `--bind-addr`. `0.0.0.0` (the default) or a specific IPv4 address makes
  an IPv4 cluster; `::` or a specific IPv6 address makes an IPv6 cluster. Every
  node of a cluster must use the same family, since an IPv4-only node cannot
  reach an IPv6-only one. Dual-stack hosts can join either kind of cluster.
- **Overlay** (the mesh addresses): the family of `--overlay-net`, independent
  of the underlay. An IPv6 overlay such as `fd00:10::/64` over an IPv4 underlay
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
room for about fifteen IPv4 prefixes, fewer for IPv6: the metadata gossiped
about a node is 512 bytes, and its key, address, identity and signature take
229 of them. A node asked to advertise more than fits does not start, and says
how many it was given. Routes on the overlay interface are managed by
cheesecloth: anything added by hand is removed on the next membership change.

A route the operating system refuses — most often a network this host already
routes somewhere else — is logged as an error naming the destination and the
node that advertised it, and skipped. Only that destination is unreachable over
the mesh: the peers whose routes were installed keep working, and the next
membership change tries again. The same goes for a stale route that cannot be
removed, which is logged and left in place.

## /etc/hosts

cheesecloth adds an entry to `/etc/hosts` for each peer, so the nodes' hostnames
resolve to their overlay addresses (assuming `files` comes first for `hosts` in
`/etc/nsswitch.conf`). `--no-etc-hosts` disables this. On Windows the file is
`%SystemRoot%\System32\drivers\etc\hosts`.

Each agent rewrites the file whole, keeping the lines it does not manage, so a
host running several clusters has several agents writing it. They take a lock
on `/etc/hosts.lock` first, since otherwise one could write back what it read
before another's entries were added, and drop them. The lock file is created
beside the file it protects, is empty, and is left in place between writes.

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
`invite`, `revoke` and `leave` alike:

```
# cheesecloth --config /etc/cheesecloth/wg2.yaml status
```
