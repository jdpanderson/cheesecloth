# Development

How to build, test and change Cheesecloth. To make a release, see
[RELEASING.md](RELEASING.md).

## Repositories

This repository holds the daemon and CLI. Packages and desktop apps for each
OS are in their own repositories:
- [cheesecloth-linux](https://github.com/jdpanderson/cheesecloth-linux)
- [cheesecloth-macos](https://github.com/jdpanderson/cheesecloth-macos)
- [cheesecloth-windows](https://github.com/jdpanderson/cheesecloth-windows)

Each one documents how its packages are built, signed and released, and how
it picks the version of Cheesecloth to package.

Check them out side by side. There are no submodules:

```
~/git/cheesecloth/
  cheesecloth/
  cheesecloth-linux/
  cheesecloth-macos/
  cheesecloth-windows/
```

### What goes here

This repository holds everything about how Cheesecloth runs:
- the service code, logging, stopping, and the state directory and its access
  lists;
- the systemd unit and `/etc/default/cheesecloth`, which other packagers
  expect to get from here;
- the local API, its doc and its access rules;
- docs on running the daemon on each OS, such as [WINDOWS.md](WINDOWS.md).

### Contracts

The OS repositories use these files from here. Keep them stable, or change
the OS repositories to match.

**Release binaries.** Each release has one plain binary for each target, not
an archive, and a `SHA256SUMS` file:

```
cheesecloth-<version>-x86_64-unknown-linux-gnu
cheesecloth-<version>-aarch64-unknown-linux-gnu
cheesecloth-<version>-aarch64-apple-darwin
cheesecloth-<version>-x86_64-apple-darwin
cheesecloth-<version>-x86_64-pc-windows-msvc.exe
cheesecloth-<version>-aarch64-pc-windows-msvc.exe
SHA256SUMS
```

`<version>` is the tag without its `v`, such as `0.4.0` or `0.4.0-rc1`.

**The local API doc.** Desktop apps use only what
[LOCAL-API.md](LOCAL-API.md) describes.

**Shipped files.** The packages ship `README.md`, `LICENSE`,
`THIRD-PARTY-NOTICES.md` and `docs/*.md` from here.

### A change across repositories

1. Make and merge the change here first, such as an API change and its doc.
2. Make the matching change in the OS repository, against that commit.
3. Release this repository.
4. Move the OS repository to the release.

## Checks

Use Rust 1.95 or later. Before a pull request, run from the repository root:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
tests/e2e/run.sh
```

## Dependencies

To list newer versions of the direct dependencies, including breaking ones,
install [cargo-edit](https://github.com/killercup/cargo-edit) with
`cargo install cargo-edit --locked`, then run:

```sh
cargo upgrade --incompatible --dry-run
```

Without `--dry-run`, it updates the `Cargo.toml` files and `Cargo.lock`.
`cargo update` takes only compatible versions and changes only `Cargo.lock`.

After any change to `Cargo.lock`, run the checks and regenerate
`THIRD-PARTY-NOTICES.md` in the same pull request. It lists the licenses of
every crate, and the packages ship it. CI fails if it is out of date.

```sh
cargo install cargo-about --locked --features cli
cargo about generate --fail about.hbs -o THIRD-PARTY-NOTICES.md
```

## Platform tests

### End-to-end lab

`tests/e2e/run.sh` needs Podman (or Docker with `ENGINE=docker`), kernel
WireGuard and container network privileges. It tests direct paths, NAT, port
mapping, restart and removal. Options:
- `FIREWALL=0` tests routers that do not filter inbound traffic.
- `SKIP_BUILD=1` reuses the image.
- `KEEP=1` keeps the lab running afterwards.

### WireGuard on Linux

This tests kernel and userspace WireGuard in a new user and network
namespace, without root:

```sh
cargo test --locked -p cheesecloth-wg --features linux-integration \
  --test linux_tunnel \
  --config 'target."cfg(target_os = \"linux\")".runner = ["unshare", "-rn"]'
```

It needs the WireGuard kernel module, `/dev/net/tun`, `ip` and unprivileged
user namespaces.

### WireGuard on macOS

Run this on a Mac you don't mind changing. It needs passwordless sudo, and
only the test runs as root:

```sh
cargo test --release --locked -p cheesecloth-wg \
  --features macos-integration --test macos_userspace \
  --config 'target."cfg(target_os = \"macos\")".runner = ["sudo", "-n"]' \
  -- --nocapture
```

It makes a temporary `utun` interface with routes in reserved test ranges.
It tests encrypted IPv4 and IPv6 traffic, peer removal, NAT openers and
cleanup, and checks that DNS settings do not change. It needs no other host
and no WireGuard install.

### Windows

To check the Windows code from Linux or macOS, install
[cargo-xwin](https://github.com/rust-cross/cargo-xwin), clang and the
`x86_64-pc-windows-msvc` target, then run:

```sh
cargo xwin clippy --locked --workspace --all-targets \
  --target x86_64-pc-windows-msvc -- -D warnings
```

Windows tests run only in CI. The arm64 target is checked only by its CI job,
because ring and blake3 do not cross-build for it with cargo-xwin.

## Further reading

- [The design](DESIGN.md): architecture, settings and recovery.
- [Consensus safety](CONSENSUS-SAFETY.md#validation-and-limits): what the
  model checks show.
