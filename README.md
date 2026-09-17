[![Build Status](https://github.com/jdpanderson/cheesecloth/actions/workflows/main.yaml/badge.svg)](https://github.com/jdpanderson/cheesecloth/actions/workflows/main.yaml)

# cheesecloth

cheesecloth builds a private mesh network between a small number of machines using
[WireGuard](https://www.wireguard.com/). It is meant for people who run a few servers or home machines and want them
to reach each other securely without much setup. Every node connects directly to every other node over an encrypted
tunnel. Each node gets a fixed private address and a hostname entry. Nodes find each other again after a restart
without any intervention. There is no central server and no shared password. A new machine is added with an
invitation token and removed with a single command.

Someone observing can see that you run cheesecloth and which nodes are talking to each other. The public addresses,
the ports, the timing of packets and the protocol names in the connection setup are all visible. Everything else is
encrypted: node names, identities, keys, the invitation exchange, and all traffic between the nodes.

## Quickstart

cheesecloth runs on Linux, macOS and Windows. On Linux it uses the kernel's WireGuard, which is in Linux 5.6 and
later, and runs WireGuard itself where the kernel has none. On macOS and Windows it always runs WireGuard itself.
Two UDP ports must be open between the nodes: 51820 for WireGuard and 7946 for cheesecloth. The commands below are
for Linux; the other platforms are described in [operations](docs/operations.md#platforms).

1. Download the binary on every node:

   ```
   $ wget -O cheesecloth https://github.com/jdpanderson/cheesecloth/releases/latest/download/cheesecloth-$(go env GOOS)-$(go env GOARCH)
   $ chmod a+x cheesecloth
   ```

2. On the first node, write a configuration and start the agent. A node with an overlay network configured and no
   state to go with it starts a cluster holding itself alone, so nothing else is needed the first time:

   ```
   ./cheesecloth config --init --overlay-net 10.0.0.0/8
   ./cheesecloth

   # Or customize the interface name, and the overlay network the cluster allocates addresses in
   # ./cheesecloth config --init --interface wghomelab --overlay-net 10.42.0.0/24
   ```

3. On the same node, create an invitation for the next node:

   ```
   ./cheesecloth invite
   7xk3...
   valid for 10m0s, and admits one node. On the new node:
     cheesecloth --join <this host> --join-key 7xk3...
   ```

4. On the new node, run the command from the invitation:

   ```
   ./cheesecloth --join first.example.net --join-key 7xk3...

   # If you customize the interface name, you might want to use it on the joined hosts
   # ./cheesecloth --join first.example.net --join-key 7xk3... --interface wghomelab
   ```

The two nodes are now connected. Repeat steps 3 and 4 for each additional node — an invitation admits one node, so
each one gets its own; it can be created on any node that is already a member. After the first start, a node needs neither `--join` nor `--join-key`: it resumes
from what it saved, which is what makes the agent something a service manager can start on every boot.

`cheesecloth status` lists the peers, `cheesecloth revoke NAME` removes another node and `cheesecloth leave` removes
the node it runs on. Both removals take effect once most of the members agree, so they need the cluster reachable.
[Commands](docs/commands.md) describes each one; running cheesecloth as a system service is in
[operations](docs/operations.md).

An agent that is not a member of any cluster and has been given nothing to act on — no overlay network to start one
with, no `--join-key` to enrol with — waits rather than failing, so a node can be installed and enabled before anyone
decides what it joins.

A node does still need the settings it runs with, on every start, with one exception: `--overlay-net` comes from the
cluster. The member that admits a node tells it which network the cluster allocates addresses in, and the node keeps
it, so only the node that starts a cluster is given one. Rather than repeat the rest on every command, most setups
put them in `/etc/cheesecloth/config.yaml` once, after which every command runs with no arguments:

```yaml
interface: wgmesh
overlay-net: 10.42.0.0/24
```

`cheesecloth config` prints what a node runs with, ready to be redirected into that file, and `cheesecloth config
--init` writes it. [`dist/config.yaml`](dist/config.yaml) is an annotated example, and
[configuration](docs/configuration.md) describes every option.

## How it works

Each node has a permanent identity, which is an Ed25519 key pair generated on its first start. Membership is a signed
statement of who the members are, carrying the signatures of the members that agreed to it. To admit a new node, an
existing member signs a record for it; to remove one, any member signs a revocation. Neither changes anything on its
own: every node works out the membership that would follow and signs it, and once enough of them have signed the same
one, that becomes the membership and the records that led to it are discarded — so a node holds who the members are
now, not everything that ever happened. Changing the membership therefore needs most of the nodes reachable; a cluster
of two is special-cased, so that one node being down cannot freeze the other.

There is no cluster-wide key, so there is no single secret to steal. A member is trusted, though: a node whose key is
compromised is a member and can act as one, which is the trade that buys a cluster with no shared secret and no central
authority. `cheesecloth revoke` is for removing a node that has gone, not for recovering from that — see
[the threat model](docs/design.md#the-threat-model-a-member-is-trusted). A cluster that wants a second pair of eyes on
every change can ask for one with `--confirmations`.

New nodes are admitted with an invitation. `cheesecloth invite` creates a random token that is kept in memory on the
inviting node until it is used or expires. The new node and the inviting node each prove to the other that they know
the token. The inviting node then signs the admission record and both nodes discard the token. The admission record
also assigns the new node the lowest unused address in the overlay network, so every node computes the same address
for every member and the address does not change across restarts.

Nodes communicate over QUIC on a single UDP port and use [memberlist](https://github.com/hashicorp/memberlist) to
track membership and detect failed nodes. Each connection is a TLS 1.3 session in which both sides present a
certificate for their identity, and a connection is accepted only if the peer is a current member. Over these
connections each node announces its WireGuard public key, which is regenerated on every start, its overlay address,
and any networks it routes. The announcement is signed with the node's identity. Peers check it against the membership
and then configure the WireGuard interface: peer keys, endpoints, allowed IPs, routes and `/etc/hosts` entries are
updated whenever the membership changes.

## Further reading

- [Commands](docs/commands.md): every command, what it prints and what it refuses.
- [Configuration](docs/configuration.md): all options, the configuration file, IPv6, routing networks through a
  node, and running several clusters on one host.
- [Operations](docs/operations.md): permissions, service managers, platforms, packages, what to watch in the log,
  and recovery.
- [Design](docs/design.md): why it is built this way — the trust model, the threat model, the two planes, and how
  membership becomes an interface configuration.
- [Membership](docs/membership.md): the protocol specification — identities, records, how a membership is agreed and
  discarded, the enrolment exchange and the transport.
- [Limitations](docs/limitations.md): what cheesecloth deliberately does not do, and any open defects.
- [wesher](https://github.com/costela/wesher): the project cheesecloth was forked from. cheesecloth follows the same
  approach of a WireGuard mesh configured by gossip, but its protocol, state and key model are all different.

## Credits

This project is co-developed with Claude Opus 5 / Claude Fable 5.1.
