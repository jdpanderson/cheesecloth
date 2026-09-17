# Operations

Installing cheesecloth, running it as a service, and what to do when something
looks wrong. [Commands](commands.md) says what each command does;
[configuration](configuration.md) describes every option;
[limitations](limitations.md) collects what is deliberately not possible.

## Permissions

WireGuard, and therefore cheesecloth, needs root to work properly. The binary
can instead be given the capability to manage the WireGuard interface:

```
# setcap cap_net_admin=eip cheesecloth
```

This allows running as an unprivileged user, but writing `/etc/hosts` will not
work; see `--no-etc-hosts` in [configuration](configuration.md).

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

Put the node's settings in `/etc/cheesecloth/config.yaml`, which `cheesecloth
config --init` writes:

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

`cheesecloth status` shows the interface and its peers, and reads the state file
rather than the control socket, so it answers even when the agent is stopped.
Add `--json` for machine-readable output, and `--interface` if not using the
default. The output is in [commands](commands.md#cheesecloth-status).

Everything else — adding a node, removing one, confirming a record, taking this
node out — is in [commands](commands.md).

## After a record is signed

`cheesecloth revoke` and `cheesecloth invite` return once the record is signed
and saved, which is the point after which it cannot be lost. The cluster agreeing
a membership follows when the members have seen it.

Handing the record to the members happens after the command returns and is
best-effort. Single records always fit a gossip datagram, but the membership that
follows one does not past about five members, so the node that first states it
hands it to each member over a stream and can leave somebody out. Only that node
does this; the others send a signature. The agent names who it missed:

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

## What to watch

Three lines in the log are worth wiring an alert to.

- **`node revoked`** that nobody ran. A revocation is a deliberate act, and a
  node reports one only where it actually put somebody out, so a line naming a
  member nobody meant to remove means a key is being used by somebody who should
  not have it. Logged at `warn`.
- **`offered a membership deeper than its own that none of its members signed`.**
  Either this node was away while the cluster's membership turned over — so it
  is configuring peers from a membership that has been left behind, trusting
  nodes since revoked and refusing nodes since admitted, and has to be enrolled
  again — or a member is sending records it should not be. **A node cannot tell
  those apart**, because the only evidence either way is a membership it has no
  way to verify. Check `cheesecloth status` on another member before removing
  anything here. Logged at `error`, and the service manager's status line points
  at the log, so `systemctl status` shows something is wrong without being
  asked.
- **`a member's records are too far behind to be taken`.** The same thing seen
  from the other side: that member is the one to enrol again.

One more is worth reading but is rarely urgent: a node that cannot take a record
a peer offers says so, counted rather than one line per record, since a peer that
re-offers one sends it at every state sync. The commonest cause is a peer that
has not discarded records this node already has.

**`node admitted`** is the line that catches a stolen key. A node reports one for
every member that joins, naming who admitted it, so a line naming a node nobody
invited is the first sign. It is logged at `info`, below the default `warn`, so a
cluster that wants to alert on it has to run with `--log-level info`. See
[the threat model](design.md#the-threat-model-a-member-is-trusted).

## Restarts and recovery

A restarted node rejoins the last known peers using its persisted identity in
`/var/lib/cheesecloth/<interface>.json`. No token is needed, even if every node
restarts at once. A node that loses that file has lost its identity: enrol it
again with a fresh invitation and revoke the old identity.

To make a node start over deliberately — to root a new cluster on a host that is
already a member, or to recover one whose state file cannot be read — take it out
first with `cheesecloth leave` (`--force` when its agent is not running), which
removes the interface, the hosts entries and the state file. The next start then
finds no state, and roots a cluster or enrols as its configuration says.

Nothing starts over by accident: with the state file in place, a configured
overlay network is read as the network to allocate addresses in, not as an
instruction to abandon the cluster.

## Security considerations

There is no cluster-wide secret. Each node has a persisted identity (an Ed25519
key), and membership is a signed statement of who the members are, carrying the
signatures of the members that agreed to it. A new node is admitted when it and
an existing member prove to each other that they know an invitation token; the
token exists only during that exchange. Cluster gossip runs over QUIC, inside a
TLS 1.3 session per pair of nodes authenticated by their identity keys
(self-signed certificates, no CA), and a node installs a peer's WireGuard key
only if the peer's identity is a valid member and signed its metadata.

**The design assumes its members are not compromised.** A member is trusted, so
an attacker who compromises a node holds a member's identity and can act as one.
That is deliberate, and what it buys, what an attacker can then do, and why
`cheesecloth revoke` is not the answer to it are set out in [the threat
model](design.md#the-threat-model-a-member-is-trusted). The operator's response
to a compromised node is to rebuild the cluster, not to revoke: found a new one
on a node you trust and enrol the others with fresh identities.

`--confirmations 1` means an invitation or a revocation does nothing until a
second node confirms it, so one compromised key cannot add or remove members by
itself. It raises what an attacker needs from one key to two; it does not make a
compromised member safe. See [Confirmations](membership.md#confirmations).

Nothing in cheesecloth reads a clock to decide membership, so a node with a
wrong clock is a full member of a cluster that works. Enrolment tokens have a
real lifetime, so a badly wrong clock shortens or extends an invitation.

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

When the interface comes up the agent logs one line saying so, at level `info`:

```
wireguard interface iface=wgcloth os=wgcloth device=kernel
```

`device=kernel` is the Linux kernel module. `device=userspace` is WireGuard
running inside the agent (the wireguard-go implementation, built into the
binary). On Linux the module is used whenever the kernel has it; when the kernel
refuses to create a WireGuard interface the agent says so and runs the device
itself, which needs `/dev/net/tun`. `--userspace` asks for that regardless. The
userspace device moves packets through the tun device and back, so it is slower
than the module; on a Linux host, load the module.

`os=` is the interface's name in the operating system. On Linux and Windows it
is the `--interface` name. On macOS the system names tun interfaces itself
(`utun4`, say); `--interface` then names the WireGuard control socket, and
`cheesecloth status` and `wg show` find the utun through the record the agent
keeps in `/var/run/wireguard/<interface>.name`.

### macOS

Take `cheesecloth-darwin-amd64` or `cheesecloth-darwin-arm64` from a release, or
build it (`GOOS=darwin go build ./cmd/cheesecloth`), and put it in
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

The agent logs to `/var/log/cheesecloth.log`; launchd restarts it if it exits.
`launchctl bootout system/io.github.jdpanderson.cheesecloth` stops and unloads
it. launchd has no readiness protocol, so the job is up as soon as the process
runs.

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

The service starts at boot, reports its state to the Service Control Manager and
logs to `%ProgramData%\cheesecloth\agent.log`. `sc stop cheesecloth` stops it and
`cheesecloth.exe service uninstall` removes it. Windows support is newer than
Linux and macOS and has had less use; the control socket there is less protected
than the model assumes, which is in [limitations](limitations.md#the-control-socket-is-protected-by-file-permissions).

## Packages

Each GitHub release carries a binary per platform, named
`cheesecloth-<os>-<arch>`, with `.exe` on Windows: Linux on amd64, arm, arm64,
mipsle and riscv64, macOS on amd64 and arm64, and Windows on amd64 and arm64.
`cheesecloth.sha256sums` lists their checksums. Next to them are a `.deb` for
amd64 and arm64 and an Arch Linux package for x86_64. Install those with `dpkg
-i` or `pacman -U`. Both install the binary, the systemd unit and
`/etc/cheesecloth/config.yaml` as a configuration file, and leave the service
disabled: initialise or enrol the node once by hand, edit the configuration,
then `systemctl enable --now cheesecloth`.

The `.deb` is built on Debian trixie with a current Go toolchain. The binary is
static, so the same package installs on Debian trixie and on Ubuntu 26.04. The
binary is installed as `/usr/sbin/cheesecloth`.

To build the packages yourself:

- Debian and Ubuntu: `debian/`. Run `dpkg-buildpackage -us -uc -b` from a
  checkout; see `debian/README.source`. Cross builds with `-a<arch>` work and
  skip the tests.
- Arch Linux: `arch/PKGBUILD` builds the `cheesecloth-git` package from the
  repository with `makepkg`. `arch/release/PKGBUILD` is the versioned package CI
  builds from an archive of the tagged checkout. The binary is installed as
  `/usr/bin/cheesecloth`.
