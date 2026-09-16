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
`--interface` if not using the default. It needs the same privileges as the
agent.

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
running member. `cheesecloth revoke NAME|IDENTITY` removes a member: the command
signs the record, and the node is out once a quorum of the members has agreed a
membership without it, which takes a moment while they are reachable and does
not happen at all while too few of them are. Every peer then stops talking to
the revoked node; the revoked node is not notified. `cheesecloth leave` removes
the node it runs on, see [Decommissioning a node](#decommissioning-a-node).

**A revoked identity cannot rejoin while the cluster remembers it**, which it
does for the next 64 membership changes. Enrolment refuses it, so a node that
was just revoked cannot walk back in. To bring the host back before then, give
it a fresh identity (`cheesecloth leave --force`, then join again with a new
invitation).

A revocation is worth something only from a member. A node that has been revoked
cannot revoke anybody, and neither can one that has been admitted but is not yet
a member — which lasts until the cluster agrees the membership holding it, a
moment while the members are reachable.

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

Any node may leave this way, the node that founded the cluster included. It is a
peer like any other: taking it out leaves every node it admitted where it is,
since the cluster had agreed on them, and the mesh carries on without it and
still admits new nodes.

Two cases cannot tell the cluster anything, and need `--force`: the node's agent
is not running, so nothing can sign or send a revocation, and the node is a
member of nothing, so there is nobody to tell. `--force` removes the interface,
the hosts entries and the state file only, whether the agent refused or never
answered. The command then prints the node's identity, and the cluster keeps
trusting it until a member revokes it:

```
# cheesecloth leave --force
removed this node's state for wgcloth
the cluster still trusts this node: run 'cheesecloth revoke KE9r...' on a member
```

Removing a node that cannot be reached at all is the same operation seen from
the other side: run `cheesecloth revoke NAME|IDENTITY` on any member.

## What the records cost

Admissions and revocations do not accumulate: once the cluster has agreed a
membership that accounts for a record, the record is discarded. What a node
keeps is the membership itself, the deeper ones its peers are still signing,
and whatever has been signed since. There is no history behind it: a node that
has been away takes the membership the cluster is on now in one step.

What a membership carries besides its members is the identities removed in the
last 64 agreements, so that a record from before one of them cannot put an
identity back. That list is bounded by recent churn rather than by the age of
the cluster: a node that left long ago costs nothing.

Records about anybody else do not pile up either. A record asking for a name or
an overlay address a member holds is not taken at all, since the membership
settled that; one nobody who is or is about to be a member vouches for is
discarded at the next agreement. A cluster of fifty carries about 7 KB in
total, and that is what goes out in a state sync and in an enrolment.

### Check the cluster before you change it

A revocation is decided from the membership the node running it holds. It takes
out the node it names and nothing else, so the nodes that node admitted keep
their place; removing them is a separate decision, and the operator's. It cannot
be undone: the members it took out are out everywhere, and they have to enrol
again.

`--disown NAME...` names nodes to go with the subject. That is how a member that
was signing records nobody asked for is undone: the nodes named, and the node
that admitted them, are all taken out on every node that takes the record. Name
the nodes you do not recognise — `cheesecloth status` on a member lists them.
`--disown-all` takes no names and disowns every node the agent still holds a
record of the subject admitting. The command says which members the record takes
out before it returns:

```
# cheesecloth revoke linode2 --disown minted-a --disown minted-b --disown minted-c
revoked linode2 (mFrk3G+0...)
3 node(s) it admitted are withdrawn with it and have to enrol again:
  minted-a (Dz4W1m8t...)
  minted-b (9rkLm2Qx...)
  minted-c (Q0x8sVbb...)
```

Three things are refused rather than reported afterwards, since a revocation
cannot be taken back once it is signed:

- A revocation that would take the node you are running on out with its subject,
  which happens when this node is a member only through the one being revoked.
  Run it from a node the subject did not admit.
- A node named with `--disown` that this agent holds no record of the subject
  admitting. Once the cluster has agreed a membership, the records that said who
  admitted whom are discarded, so there is nothing left to disown by; revoke
  that node in its own right instead.
- A revocation with no effect at all, which means this node is no longer one of
  the members the cluster has agreed on.

Nothing is signed in any of those cases.

Everything else is your judgement, and `cheesecloth revoke` says nothing about
whether this node can see the cluster. The node being revoked is usually the one
that has gone, so a reachability check would fire on almost every legitimate
revocation and be learned as noise. Check with `cheesecloth status` before
revoking instead.

The command returns once the revocation is signed and saved, which is the point
after which it cannot be lost — not once the cluster has agreed the membership
without its subject, which follows when the members have seen it. Giving it to
the members happens after the command returns and is best-effort, so a record
too large for a gossip datagram — one that names many nodes, or the membership
that follows it in a cluster past about ten — goes to each member over a stream
and can leave somebody out. Only the node that first states a record does that;
the others send a signature, which always fits a datagram. The agent names who
it missed:

```
could not hand the revocation to every member. They take it at the next full
state sync; if they still do not have it after a few minutes, the cluster is
partitioned. told=5 missed="[gamma delta]"
```

Nothing needs doing about that on its own: the record is on disk and the state
sync carries it, once a minute by default. It is worth looking at if the same
members keep missing records, which says they are unreachable from here rather
than merely slow. If the agent is stopping the wording differs, because it will
not sync again: the record goes out when it starts again, and if the node is
leaving the cluster for good, run the command from another member instead.

Three things in the log are worth wiring an alert to:

- *"node revoked"* that nobody ran. A revocation is a deliberate act, and a node
  reports one only where it actually put somebody out, so a line naming a member
  nobody meant to remove means a key is being used by somebody who should not
  have it.
- *"this node is too far behind the cluster to catch up"*. This node was away
  while the cluster's membership turned over, so nobody who signed the
  membership it is being offered is a member as far as it knows. It goes
  on configuring peers from a membership the cluster has left behind — trusting
  nodes since revoked, and refusing nodes since admitted — until it is enrolled
  again. It says so at `error`, and the service manager's status line says it
  too, so `systemctl status` shows it without being asked.
- *"a member's records are too far behind to be taken"*. The same thing seen
  from the other side: that member is the one to enrol again.

A node that cannot take a record a peer offers says so too, counted rather than
one line per record, since a peer that re-offers one sends it at every state
sync. That is worth reading but rarely urgent: the commonest cause is a peer
that has not discarded records this node already has.

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

Either way the binary is left where it was built. Put it where the unit above
expects it, which is also where the packages would not collide with it:

```
# install -m 0755 cheesecloth /usr/local/sbin/cheesecloth
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
key), and membership is a signed statement of who the members
are, carrying the signatures of the members that agreed to it. A new node is admitted when it and an existing member
prove to each other that they know an invitation token; the token exists only
during that exchange. Cluster gossip runs over QUIC, inside a TLS 1.3 session
per pair of nodes authenticated by their identity keys (self-signed
certificates, no CA), and a node installs a peer's wireguard key only if the
peer's identity is a valid member and signed its metadata. The design is
described in [membership.md](membership.md).

An attacker who compromises a node obtains that node's identity, which any
member can revoke with `cheesecloth revoke`. Until it is revoked, the attacker
can:

- access services exposed on the overlay network
- impersonate that node and disrupt traffic to and from it
- attract traffic for any network outside the overlay by advertising it with
  `--allowed-ips`, since every member trusts every other member's advertisements
- admit nodes of its own, since a member mints its invitation tokens itself and
  signs the admission with its own identity; membership is the only unit of
  access control cheesecloth has. The quorum does not stop this: it decides that
  every node reaches the same membership, and the honest members attest to
  whatever the records propose, since an admission from a member is well formed
  whoever holds the key

It cannot decrypt traffic between other nodes, and nothing it signs once it has
been revoked counts for anything.

Revoking it does not revoke what it admitted: those are ordinarily nodes
somebody invited on purpose, and removing them automatically would remove nodes
the operator did not ask to remove. After a compromise that is not what is
wanted, so check `cheesecloth status` on a member for nodes that appeared while
the attacker held the key, and name them to `cheesecloth revoke --disown`, which
takes them out with the compromised node in one record.

Do it before the cluster agrees a membership including them and discards the
records that say who admitted whom; after that they are revoked in their own
right instead, which is one record each.

Nothing in cheesecloth reads a clock to decide membership, so a node with a
wrong clock is a full member of a cluster that works. Enrolment tokens have a
real lifetime, so a badly wrong clock shortens or extends an invitation.

## Known limitations

What follows are consequences of how cheesecloth is designed, and are not
expected to change. Defects that should eventually be fixed are kept apart, in
[known issues](known-issues.md). This is the whole list; the other documents
point here rather than keeping one of their own.

### A change needs a quorum of the members

Nothing changes the membership until a quorum of the current members has
attested to the one that follows. On the default `majority` that is more than
half of them, so while too few are reachable the cluster goes on running exactly
as it is: existing members keep their peers, their addresses and their hosts
entries, and nothing is added or removed until enough of them are back. A node
enrolling waits for that agreement and gives up after 30 seconds, telling the
operator how many members had to attest.

A cluster of **three** therefore keeps working with any one node down, of four
with one down, of five with two. A cluster of **two** is special-cased, since a
majority of two is everybody and the rule taken literally would let a single
stopped node freeze the survivor for good: at two members either node may agree
on its own. The cost is that two nodes which both change the membership while
partitioned from each other can end up with two different memberships and stay
that way — it takes an operator at each end to do, and rebuilding one node from
the other to undo. See [Quorum](membership.md#quorum).

### A node can advertise only so many networks

What a node announces about itself travels in the gossip protocol's per-node
metadata, which is 512 bytes. The overlay address, the wireguard key, the
identity and the signature take 229 of them, so about fifteen IPv4
`--allowed-ips` prefixes fit alongside; fewer if they are IPv6, which are
longer. A node given more than fit refuses to start and says how many it was
given, rather than starting and being ignored by every peer for metadata they
cannot read. Advertise a shorter prefix that covers them, or spread the
networks over more than one node.

### The control socket is protected by file permissions

Inviting, revoking and leaving go through a unix socket that the agent
creates owner-only, so the ability to run those commands is the ability to read
that file. That is the whole of the protection, and it holds on Linux and
macOS. On Windows the directory the socket sits in does not carry the same
permissions, so a Windows node's control socket is less protected than the
model assumes. Treat an account on a Windows node as equivalent to membership
of the cluster until that is fixed.

### Two joiners can contest one name or address, and one of them loses

Two members admitting new nodes at the same moment, before either admission has
reached the other, can give two joiners the same name or the same overlay
address. Neither is a member yet, and a membership naming both could never be
agreed, so the cluster settles it before either becomes anything: it agrees a
membership holding one of them, decided the same way on every node, and the
other is left out.

The joiner that loses is told so — its `--join` fails saying another node took
the name or the address at the same moment — and nothing about it is left in the
cluster. Run the join again and it takes the next free slot. A joiner that lost
a *name* has to be given a different one, since the name now belongs to the node
that kept it.

### A hosts-file line ending in our banner is treated as ours

The agent marks the lines it manages in the hosts file with a banner comment
naming the interface, and finds them again by looking for that banner at the
end of a line. A line somebody wrote by hand that happens to end with exactly
the same text is therefore read as one of ours: it is rewritten if its address
belongs to a member, and removed if it does not.

Nothing in normal use produces such a line. The banner carries the interface
name, and no interface's banner can be a suffix of another's, since a name
cannot contain the banner's fixed part. It matters only if you write hosts
entries that copy the banner text, which is how the agent tells its own lines
from yours.

### A host's name has to be usable as a node name

A node is known to the cluster by one hostname label: lowercase letters,
digits and hyphens, at most 63 of them. A node takes the first label of its
hostname when it enrols, so `web1.example.com` enrols as `web1`, but a host
whose name has nothing usable in it — one named `Server_01`, say — stops with
an error rather than enrolling under a name the other nodes cannot resolve.
Rename the host, or set its hostname to a plain name, and start it again.

The name is fixed at enrolment. Renaming a host afterwards does not rename the
node: it goes on using the name the membership gives it, which is what its
peers resolve and what `cheesecloth revoke` takes. To change it, revoke the
node and enrol it again.

### Revoking a node can fail an enrolment that is in progress

A node becomes a member when the cluster agrees a membership naming it, and its
`--join` waits for that. Revoking the member that admitted it inside that
window leaves the admission signed by nobody who is still a member, so the
membership is never agreed and the enrolment fails rather than half succeeding.

The window is one agreement wide and the joiner is told: `--join` reports that
the cluster did not agree a membership holding it. Run the join again, from a
member that is staying. Where the timing is foreseeable, wait for the new node
to appear in `cheesecloth status` before revoking the node that admitted it.

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

A connection that opens no stream holds its slot for two seconds, which is a
round trip's work: a joiner opens its stream as soon as the handshake is done.
Holding a slot for longer than that means running the exchange itself, which
needs the connection kept open and answered.

What such a peer cannot do is fill the log. Everything that fails before the
joiner has proved the token — an unreadable hello, a name that is not the
connection's, an unknown token, a proof that does not check — is counted rather
than written out one line each, and reported at most once a minute:

```
enrolment attempts by peers that proved nothing; a member reports these at its
own rate, since anyone who can reach the port can make them count=1184
since=37 recent="unproven: joiner could not prove knowledge of the token"
from=203.0.113.9:51242
```

A large count with `could not prove knowledge of the token` is someone guessing
at invitations. A failure after the proof is a peer that held a valid one, so
there can only be as many as the token had uses, and those are logged as they
happen under `enrolment failed`.

### Split-brain

cheesecloth does not distinguish a failed node from one that was removed on
purpose. This is intentional, so that a cluster can grow and shrink without
configuration changes. A long connection loss between two parts of the cluster
(for example across a WAN link between providers) therefore causes each side to
treat the other as failed. A workaround is to restart cheesecloth periodically
on one node of each side with `--join` pointing at the other side. Static seed
nodes are a candidate for future work.
