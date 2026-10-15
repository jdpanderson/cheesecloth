# Cheesecloth

Cheesecloth builds a peer-to-peer WireGuard mesh without a central server.
Members agree on membership and settings through an authenticated, adaptive
CASPaxos protocol. Relays help control messages cross NAT; WireGuard traffic
always travels directly between peers.

**Pre-release.** Linux has end-to-end coverage with kernel WireGuard. macOS
CI tests userspace WireGuard; multi-machine and NAT operation remain unvalidated.
FreeBSD is unvalidated. Windows CI builds and tests the daemon and CLI on x64
and arm64. The daemon runs as a Windows service, but there is no installer
yet; multi-machine operation there remains unvalidated. Mobile is not
supported. See [Windows](docs/WINDOWS.md) for the service and what is weaker
there. The consensus
security layer has regression tests, but no independent audit or machine-checked
Byzantine proof.

## Quick start on Linux

Use Rust and Cargo 1.95 or later, synchronized clocks, and either running
`systemd-resolved` or a `resolvconf` implementation for interface cleanup.
The `resolvconf` from `systemd-resolvconf` calls `systemd-resolved`, so with it
`systemd-resolved` must be running. If cleanup fails, the daemon will not start
until the interface is gone; remove it with `sudo ip link delete cheesecloth0`.
The daemon needs root, or `CAP_NET_ADMIN` and `CAP_NET_RAW` with suitable file
permissions. These examples use root for the daemon and the CLI. With
`daemon --api-group <group>`, members of that group may run every CLI command
but `stop` without root; on macOS the group is `admin` by default. See
[the local API](docs/LOCAL-API.md#access).

Build and install from the repository root:

```sh
cargo build --release --locked
sudo install -m 755 target/release/cheesecloth /usr/local/bin/cheesecloth
```

Start the daemon on each machine and leave it running:

```sh
sudo cheesecloth daemon
```

In another terminal on the first machine:

```sh
sudo cheesecloth init
sudo cheesecloth invite
```

On the next machine, join using the token printed by `invite`:

```sh
sudo cheesecloth join '<token>'
sudo cheesecloth status
sudo cheesecloth peers
```

Invites are single-use and expire after 30 minutes. Create one for each join.
A committed redemption consumes the token even if admission fails.

A new member gets every permission: admin, vote and relay. To add a machine
that should use the mesh but not manage it, such as a friend's, take some
away, for example with `cheesecloth invite --no-admin --no-vote --no-relay`.
See below.

Defaults are UDP **51821** for control, UDP **51820** for WireGuard, and
`/var/lib/cheesecloth` for state on Linux. Allow both ports where direct
inbound access is intended. Keep the WireGuard interface dedicated to
Cheesecloth; manually added peers are removed.

## Membership and settings

```sh
sudo cheesecloth remove '<name-or-node-id-prefix>'
sudo cheesecloth leave
sudo cheesecloth config get
sudo cheesecloth config set approvals_required 1
sudo cheesecloth pending
sudo cheesecloth approve '<proposal-token>'
sudo cheesecloth reject '<proposal-token>'
```

By default, any admin can invite or remove another member and change
settings. `approvals_required` adds approvals from other admins for joins,
removals and setting changes. Use the complete proposal token shown by
`pending`; check the joining identity before approving. Leaving never needs
approvals.

Each member has three permissions, set by its invite:

| Permission | Allows | Take away with |
| --- | --- | --- |
| admin | invite, remove others, change settings, approve, reject | `invite --no-admin` |
| vote | be an acceptor, and take joins to the cluster | `invite --no-vote` |
| relay | relay for others; without it, `--relay` is ignored | `invite --no-relay` |

Every member has the same mesh access, and can leave. A typical home network
gives the owner's workstation all three, the owner's public servers `vote`
and `relay` only, and a friend's machine none. A member's permissions never
change: to change them, remove the member and invite it again.

The last admin and the last voter may leave. Without an admin, the network
keeps working, but nobody can invite, remove or change settings any more.
Without a voter, nothing in the network can change any more, not even a
member's leaving; the last voter's `leave` asks for `--force` first. See
[membership and approvals](docs/DESIGN.md#membership-and-approvals).

`leave` also cancels a pending join locally, even while offline. It does not
withdraw the remote proposal or restore the invite. A member may still need
to reject that proposal or remove the admitted identity.

If local cleanup fails, status shows `stopping`; fix the reported problem and
retry `leave`. `leave --force` continues past cluster handoff failures, but
cannot bypass unfinished local cleanup. See [lifecycle and recovery](docs/DESIGN.md#lifecycle-and-recovery).

`stop` stops a daemon that you started yourself, and returns when it has
removed the WireGuard interface and released router port mappings. The node
stays in its cluster. Stop the packaged service with
`sudo systemctl stop cheesecloth`, or on Windows with
`Stop-Service cheesecloth` in an elevated PowerShell.

## Security and availability

With default settings, three voters require two votes and have **no Byzantine
safety guarantee**. Four require three votes and activate protection intended
to tolerate one compromised voter. The installed quorum must approve every
voter change: four voters suddenly reduced to two pause changes. Existing
WireGuard paths continue using the last learned membership.

- `init --strict-security` allows bootstrap, then prevents automatic loss of
  protection. It can also be enabled with `config set strict_security true`.
- `buffer_nodes` reserves unavailable votes. With buffer two, five voters use
  three votes in relaxed mode; six use four in protected mode. All voters vote.
- `status` shows the installed mode, quorum, reachable voters and warnings.

Read [consensus safety](docs/CONSENSUS-SAFETY.md) for assumptions, transitions and
limits. Consensus protection does not restrict actions allowed by the approval
policy, and later protection cannot repair a fork created in relaxed mode.

## Network options

Use `cheesecloth daemon --help` for all options. The usual adjustments are:

| Option | Purpose |
| --- | --- |
| `--advertise IP` | Advertise a reachable address, such as a cloud VM's public IP. Repeatable. |
| `--relay MODE` | `auto` (default) checks reachability; `always` forces relaying; `never` disables it. |
| `--no-port-mapping` | Disable automatic UPnP and PCP router mappings. |
| `--wireguard MODE` | Select `auto` (default), `kernel` or `userspace`. |
| `--keepalive SECONDS` | Set WireGuard keepalive; QUIC keepalive remains 25 seconds. |

`status` shows whether the node is publicly reachable, its WireGuard keepalive,
and the state of each router port mapping.

Without a relay, separate NATs may prevent control-plane communication. If
WireGuard punching and port mapping fail, there is no data relay fallback;
provide a reachable endpoint or port forward. NAT openers and automatic port
mapping currently support IPv4 only.

Each daemon serves one cluster. Separate instances need distinct state
directories, interfaces, control ports and WireGuard ports. Use the same
`--state-dir` or `--socket` when calling that instance's CLI.

## Packages

Packages are built and released in their own repositories:

| Platform | Repository | Package |
| --- | --- | --- |
| Debian 13, amd64 and arm64 | [cheesecloth-linux](https://github.com/jdpanderson/cheesecloth-linux) | `.deb`, plus debugging symbols |
| Arch Linux, x86-64 | [cheesecloth-linux](https://github.com/jdpanderson/cheesecloth-linux) | `.pkg.tar.zst`, signed |
| macOS 14+, Apple Silicon or Intel | [cheesecloth-macos](https://github.com/jdpanderson/cheesecloth-macos) | `.pkg` installer |

Each release of this repository attaches a plain binary for each target,
with a `SHA256SUMS` file. The Linux binaries need glibc 2.39 or newer. CI runs
the workspace tests on every target before a release; both macOS binaries
must also pass the real userspace WireGuard tests.

Both Linux packages install a systemd service; start it with
`sudo systemctl enable --now cheesecloth` instead of running a second daemon.
Set daemon options in `/etc/default/cheesecloth` and restart the service. The
unit and the defaults file are in [packaging/](packaging) for other
packagers.

## Development

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
tests/e2e/run.sh
```

After a dependency change, regenerate `THIRD-PARTY-NOTICES.md` with
`cargo about generate --fail about.hbs -o THIRD-PARTY-NOTICES.md`
(`cargo install cargo-about --locked --features cli`); CI checks it.

To check the Windows code from Linux or macOS, install
[cargo-xwin](https://github.com/rust-cross/cargo-xwin), clang and the
`x86_64-pc-windows-msvc` target, then run:

```sh
cargo xwin clippy --locked --workspace --all-targets \
  --target x86_64-pc-windows-msvc -- -D warnings
```

Windows tests run in CI. Only the Windows arm64 CI job checks the
`aarch64-pc-windows-msvc` target, because ring and blake3 do not cross-build
for it with cargo-xwin.

The end-to-end lab needs Podman, or Docker with `ENGINE=docker`, and Linux
kernel WireGuard and container network privileges. It covers direct paths,
NAT, port mapping, restart and removal. `FIREWALL=0` tests routers without
inbound filtering; `SKIP_BUILD=1` reuses the image; `KEEP=1` keeps the lab for
inspection.

On Linux, test real kernel and userspace WireGuard in a new user and network
namespace, without root:

```sh
cargo test --locked -p cheesecloth-wg --features linux-integration \
  --test linux_tunnel \
  --config 'target."cfg(target_os = \"linux\")".runner = ["unshare", "-rn"]'
```

This needs the WireGuard kernel module, `/dev/net/tun`, `ip` and
unprivileged user namespaces.

On a disposable Mac, run the privileged userspace test with:

```sh
cargo test --release --locked -p cheesecloth-wg \
  --features macos-integration --test macos_userspace \
  --config 'target."cfg(target_os = \"macos\")".runner = ["sudo", "-n"]' \
  -- --nocapture
```

This requires passwordless sudo; only the test executable runs as root. It
creates a temporary `utun` interface and routes in reserved test address ranges.
It checks encrypted IPv4/IPv6 traffic, peer removal, NAT openers, cleanup and
recreation, and verifies that DNS settings stay unchanged. No remote host or
separate WireGuard installation is needed.

See [the design](docs/DESIGN.md) for architecture, settings and recovery, and
[consensus validation limits](docs/CONSENSUS-SAFETY.md#validation-and-limits) for
what the model checks establish.
