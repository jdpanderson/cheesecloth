# Operations

## Permissions

wireguard, and therefore cheesecloth, needs root to work properly. The binary
can instead be given the capability to manage the wireguard interface:

```
# setcap cap_net_admin=eip cheesecloth
```

This allows running as an unprivileged user, but writing `/etc/hosts` will not
work (see `--no-etc-hosts` in [configuration](configuration.md)).

## systemd

A unit file is provided under `dist` and can be copied to `/etc/systemd/system`:

```
# wget -O /etc/systemd/system/cheesecloth.service https://raw.githubusercontent.com/jdpanderson/cheesecloth/main/dist/cheesecloth.service
# systemctl daemon-reload
# systemctl enable cheesecloth
```

It assumes cheesecloth is installed to `/usr/local/sbin`. It is a `Type=notify`
service: cheesecloth tells systemd it is ready once it has joined the cluster
and configured the interface, so a unit with `After=cheesecloth.service` and
`Requires=cheesecloth.service` starts with the overlay in place. `systemctl
status` shows the current peer count.

Put the node's settings in `/etc/cheesecloth/config.yaml`, which
`cheesecloth config --init` writes:

```
# cheesecloth config --init --overlay-net 10.42.0.0/24
```

On the node that starts the cluster, that is all the unit needs: the agent finds
a configured network and no state, and roots a cluster on its first start. The
join key never goes in the file, so a node that joins an existing cluster is
enrolled once by hand, or from a provisioning step, with `cheesecloth --join-key
TOKEN` (the `join` hosts can come from the file), after which the unit starts it
on every boot from what it saved.

The unit can also be enabled before either has happened: an agent that is not a
member and has been given nothing to act on waits instead of failing, so
`systemctl enable --now cheesecloth` does not leave systemd restarting it.

## Checking on a node

`cheesecloth status` shows the wireguard interface and its peers, with the last
handshake age, traffic counters and advertised routes, naming peers from the
persisted cluster state. Add `--json` for machine-readable output and
`--interface` if not using the default. It needs the same privileges as the agent.

```
# cheesecloth status
interface: wgcloth
address:   10.0.0.1/32
port:      51820
pubkey:    gm/3EV7bl46Z2QPUa5CppLUjwoL45BwHO1nrEgIFsFA=
identity:  KE9rn7ryXPCL+A1uHT1Or7tnBG/eheIihMPaYcN9EME=
peers:     2

NAME     IDENTITY  OVERLAY   ENDPOINT              HANDSHAKE  RX     TX     ROUTES
linode2  mFrk3G+0  10.0.0.2  178.79.147.187:51820  2s ago     348 B  404 B  -
linode3  kwvzJSL2  10.0.0.3  172.105.13.112:51820  1s ago     348 B  404 B  -
```

`cheesecloth invite [--ttl 10m] [--uses 1]` creates an invitation token on a
running member. `cheesecloth revoke NAME|IDENTITY` removes a member. Every
peer stops talking to the revoked node; the revoked node is not notified.
`cheesecloth leave` removes the node it runs on, see [Decommissioning a
node](#decommissioning-a-node).

## Decommissioning a node

`cheesecloth leave` takes the node it runs on out of the cluster for good. The
agent revokes this node's own identity, hands the revocation to each member it
can still reach, tears the interface down, removes its hosts entries and
deletes its state file, then stops. Every peer drops the node; the node keeps
nothing of the cluster.

```
# cheesecloth leave
left the cluster: revoked KE9rn7ryXPCL+A1uHT1Or7tnBG/eheIihMPaYcN9EME=, 2 member(s) told
the agent has stopped and its state for wgcloth is gone
```

The agent exits, so a service that starts it at boot should be disabled as
well (`systemctl disable cheesecloth`). Starting it again without a fresh
invitation fails: the node is no longer a member and has no state.

Any node may leave this way, the node that started the cluster included. The root is
a peer: revoking it takes it out of the mesh and leaves every node it admitted
where it is, because records are judged as of the moment they were signed. The
cluster carries on without it, and still admits new nodes.

One case cannot tell the cluster anything, and needs `--force`: the node's
agent is not running, so nothing can sign or send a revocation. `--force`
removes the interface, the hosts entries and the state file only. The command
then prints the node's identity, and the cluster keeps trusting it until a
member revokes it:

```
# cheesecloth leave --force
removed this node's state for wgcloth
the cluster still trusts this node: run 'cheesecloth revoke KE9r...' on a member
```

Removing a node that cannot be reached at all is the same operation seen from
the other side: run `cheesecloth revoke NAME|IDENTITY` on any member.

## Restarts and recovery

A restarted node rejoins the last known peers using its persisted identity in
`/var/lib/cheesecloth/<interface>.json`. No token is needed, even if every node
restarts at once. A node that loses that file has lost its identity: enrol it
again with a fresh invitation and revoke the old identity.

To make a node start over deliberately — to root a new cluster on a host that is
already a member, or to recover one whose state file cannot be read — take it
out first with `cheesecloth leave` (`--force` when its agent is not running),
which removes the interface, the hosts entries and the state file. The next
start then finds no state, and roots a cluster or enrols as its configuration
says. Nothing starts over by accident: with the state file in place, a
configured overlay network is read as the network to allocate addresses in, not
as an instruction to abandon the cluster.

## Installing from source

```
$ git clone https://github.com/jdpanderson/cheesecloth.git
$ cd cheesecloth
$ make
```

This builds a bit-by-bit identical binary to the released ones, given the same
Go version as the tag. Without a checkout (`--version` will then report `dev`):

```
$ go install github.com/jdpanderson/cheesecloth/cmd/cheesecloth@latest
```

## Platforms

cheesecloth runs on Linux, macOS and Windows. Membership, enrolment and gossip
are the same code everywhere. What differs is where the WireGuard interface
comes from, how the service is run, and where the files are.

| | Linux | macOS | Windows |
|---|---|---|---|
| WireGuard | the kernel module when the kernel has it, otherwise inside the agent | inside the agent, on a `utun` interface | inside the agent, on a Wintun adapter; `wintun.dll` must sit next to the binary |
| Runs as | root, or with `cap_net_admin` (see [Permissions](#permissions)) | root | Administrator |
| Service manager | systemd, `dist/cheesecloth.service` | launchd, `dist/io.github.jdpanderson.cheesecloth.plist` | Service Control Manager, `cheesecloth service install` |
| State | `/var/lib/cheesecloth/` | `/var/db/cheesecloth/` | `%ProgramData%\cheesecloth\` |
| Configuration | `/etc/cheesecloth/config.yaml` | `/etc/cheesecloth/config.yaml` | `%ProgramData%\cheesecloth\config.yaml` |
| Control socket | `/run/cheesecloth/<interface>.sock` | `/var/run/cheesecloth/<interface>.sock` | `%ProgramData%\cheesecloth\<interface>.sock` |
| Hosts file | `/etc/hosts` | `/etc/hosts` | `%SystemRoot%\System32\drivers\etc\hosts` |

### Which WireGuard is running

When the interface comes up the agent logs one line saying so, at level
`info`:

```
wireguard interface iface=wgcloth os=wgcloth device=kernel
```

`device=kernel` is the Linux kernel module. `device=userspace` is WireGuard
running inside the agent (the wireguard-go implementation, built into the
binary). On Linux the module is used whenever the kernel has it; when the
kernel refuses to create a WireGuard interface the agent says so and runs the
device itself, which needs `/dev/net/tun`. `--userspace` asks for that
regardless. The userspace device moves packets through the tun device and
back, so it is slower than the module; on a Linux host, load the module.

`os=` is the interface's name in the operating system. On Linux and Windows
it is the `--interface` name. On macOS the system names tun interfaces
itself (`utun4`, say); `--interface` then names the WireGuard control socket,
and `cheesecloth status` and `wg show` find the utun through the record the
agent keeps in `/var/run/wireguard/<interface>.name`.

### macOS

Take `cheesecloth-darwin-amd64` or `cheesecloth-darwin-arm64` from a release,
or build it (`GOOS=darwin go build ./cmd/cheesecloth`), and put it in
`/usr/local/sbin/` as `cheesecloth`. The release binaries are not signed or
notarised: download them with `curl` or `wget`, which do not mark the file as
quarantined. A binary downloaded with a browser is refused by Gatekeeper until
`xattr -d com.apple.quarantine cheesecloth` clears the mark or it is approved
under Privacy & Security in System Settings. Put the node's settings in
`/etc/cheesecloth/config.yaml`. Initialise or enrol the node once by hand, as
root, the same way as on Linux. Then install the launchd job:

```
# cp dist/io.github.jdpanderson.cheesecloth.plist /Library/LaunchDaemons/
# launchctl bootstrap system /Library/LaunchDaemons/io.github.jdpanderson.cheesecloth.plist
```

The agent logs to `/var/log/cheesecloth.log`; launchd restarts it if it
exits. `launchctl bootout system/io.github.jdpanderson.cheesecloth` stops and
unloads it. launchd has no readiness protocol, so the job is up as soon as the
process runs.

### Windows

Take `cheesecloth-windows-amd64.exe` or `cheesecloth-windows-arm64.exe` from a
release, or build it (`GOOS=windows go build ./cmd/cheesecloth`). Put it and
`wintun.dll` (from [wintun.net](https://www.wintun.net/), the architecture of
the binary) in one directory, with the binary renamed to `cheesecloth.exe`.
Wintun is not shipped in the release; without it the agent cannot create its
interface. Put the node's settings in `%ProgramData%\cheesecloth\config.yaml`,
which `cheesecloth.exe config --init` writes. From an administrator console,
start or enrol the node once by hand (bare `cheesecloth.exe` with an overlay
network configured, or `cheesecloth.exe --join HOST --join-key TOKEN`, stopping
it with Ctrl-C once it is a member), then register and start the service:

```
> cheesecloth.exe service install
> sc start cheesecloth
```

The service starts at boot, reports its state to the Service Control Manager
and logs to `%ProgramData%\cheesecloth\agent.log`. `sc stop cheesecloth` stops
it and `cheesecloth.exe service uninstall` removes it. Windows support is
newer than Linux and macOS and has had less use; the TODO lists what is known
to be missing.

## Packages

Each GitHub release carries a binary per platform, named
`cheesecloth-<os>-<arch>`, with `.exe` on Windows: Linux on amd64, arm, arm64,
mipsle and riscv64, macOS on amd64 and arm64, and Windows on amd64 and arm64.
`cheesecloth.sha256sums` lists their checksums. Next to them are a `.deb` for
amd64 and arm64 and an Arch Linux package for x86_64. Install those with
`dpkg -i` or `pacman -U`. Both install the binary, the systemd unit and
`/etc/cheesecloth/config.yaml` as a configuration file, and leave the service
disabled: initialise or enrol the node once by hand, edit the configuration,
then `systemctl enable --now cheesecloth`.

The `.deb` is built on Debian trixie with a current Go toolchain. The binary
is static, so the same package installs on Debian trixie and on Ubuntu 26.04.
The binary is installed as `/usr/sbin/cheesecloth`.

To build the packages yourself:

- Debian and Ubuntu: `debian/`. Run `dpkg-buildpackage -us -uc -b` from a
  checkout; see `debian/README.source`. Cross builds with `-a<arch>` work and
  skip the tests.
- Arch Linux: `arch/PKGBUILD` builds the `cheesecloth-git` package from the
  repository with `makepkg`. `arch/release/PKGBUILD` is the versioned package
  CI builds from an archive of the tagged checkout. The binary is installed as
  `/usr/bin/cheesecloth`.

## Security considerations

There is no cluster-wide secret. Each node has a persisted identity (an Ed25519
key), and membership is a set of signed admission records rooted at the node
that started the cluster. A new node is admitted when it and an existing member prove
to each other that they know an invitation token; the token exists only during
that exchange. Cluster gossip runs over QUIC, inside a TLS 1.3 session per pair
of nodes authenticated by their identity keys (self-signed certificates, no CA),
and a node installs a peer's wireguard key only if the peer's identity is a valid
member and signed its metadata. The design is described in
[membership.md](membership.md).

An attacker who compromises a node obtains that node's identity, which any
member can revoke with `cheesecloth revoke`. Until it is revoked, the attacker
can:

- access services exposed on the overlay network
- impersonate that node and disrupt traffic to and from it
- attract traffic for any network outside the overlay by advertising it with
  `--allowed-ips`, since every member trusts every other member's advertisements

It cannot decrypt traffic between other nodes, and it cannot admit new nodes
without also minting a token on a member.

Nodes are expected to keep their clocks synchronised; records are ordered by the
issuer's clock (see [membership.md](membership.md#clocks)).

## Known limitations

What follows are consequences of how cheesecloth is designed, and are not
expected to change. Defects that should eventually be fixed are kept apart, in
[known issues](known-issues.md).

### Name and overlay address collisions

Two nodes can be assigned the same overlay address, or the same name, only if
two different members admit new nodes at the same moment, before either
admission has reached the other. The signed records still decide, the same way
for both: the earlier admission keeps the address or the name and every node
ignores the later one, logging the collision. The losing node keeps running
without peers until it is enrolled again: stop it, delete
`/var/lib/cheesecloth/<interface>.json`, and start it with a fresh invitation.
A node that lost a name has to be renamed first, since the name it had now
belongs to the node that kept it.

### A host's name has to be usable as a node name

A node is known to the cluster by one hostname label: lowercase letters,
digits and hyphens, at most 63 of them. A node takes the first label of its
hostname when it enrols, so `web1.example.com` enrols as `web1`, but a host
whose name has nothing usable in it — one named `Server_01`, say — stops with
an error rather than enrolling under a name the other nodes cannot resolve.
Rename the host, or set its hostname to a plain name, and start it again.

The name is fixed at enrolment. Renaming a host afterwards does not rename the
node: it goes on using the name in its admission record, which is what its
peers resolve and what `cheesecloth revoke` takes. To change it, revoke the
node and enrol it again.

### A revoked node can cut off the nodes it admitted

A node keeps its key when it is revoked, and every record it signed while it
was a member still stands, which is what keeps the nodes it admitted in the
cluster. It can sign a second record under the number one of those records
took. The two cannot be told apart — both carry its signature, and the
sequence number is the only thing that says which was signed while it was
still trusted — so neither counts, and a node whose only admission was that
record is no longer a member. Nothing else is affected, and the revoked node
cannot get itself or anyone else back in this way; the cost is availability,
not trust.

It is a deliberate choice of the lesser harm. The alternative, taking both
records at face value, would let a revoked node admit nodes of its own under a
number from before its revocation, which is the thing the revocation exists to
stop. Telling the two apart needs evidence the records do not carry today.

Every member logs the reuse when it sees it, naming the node that signed twice
and the number; the node that lost its place logs that its peers will drop it,
and refuses to start the next time. Enrol it again: `cheesecloth leave --force`
on it, then a fresh invitation from any member. It takes a new identity, and
with it a new overlay address.

### Enrolment can be crowded out

Enrolment shares the cluster port and accepts a connection from anyone, since
a joiner is not a member yet and only the token exchange decides. At most
eight exchanges run at once, so anyone who can reach the port can hold those
slots and stop new nodes enrolling for as long as they keep it up. Gossip
between the nodes already in the cluster is unaffected, and nothing is
admitted that could not be admitted anyway: the cost is that `cheesecloth
invite` may have to be retried. Where that matters, reach the cluster port
with a firewall rule rather than leaving it open to everyone, and open it
while a node is being added.

### Split-brain

cheesecloth does not distinguish a failed node from one that was removed on
purpose. This is intentional, so that a cluster can grow and shrink without
configuration changes. A long connection loss between two parts of the cluster
(for example across a WAN link between providers) therefore causes each side to
treat the other as failed. A workaround is to restart cheesecloth periodically
on one node of each side with `--join` pointing at the other side. Static seed
nodes are a candidate for future work.
