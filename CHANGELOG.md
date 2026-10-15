# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Member permissions, for machines that should use the mesh without every
  role, such as a friend's, or a public server that routes and votes but
  doesn't manage. Each member has three, set by its invite:
  - `admin`: invite, remove others, change settings, approve and reject.
  - `vote`: be an acceptor, and take joins to the cluster.
  - `relay`: relay for others, and report WireGuard endpoints that others
    trust.

  `invite` gives all three, and `--no-admin`, `--no-vote` and `--no-relay`
  take them away. The local API is fail-safe: an `invite` request gives only
  the permissions it sets to true, and refuses an unknown one. Every member
  has full mesh access and can leave. A
  member's permissions never change. The last admin and the last voter may
  leave; DESIGN.md says what still works then. `status`, `peers` and
  `pending` show the permissions, and the local API has the error code
  `missing_permission`.

### Changed

- The agreed state has a new format. This release can't read the state of
  older releases, and can't work in a cluster with them: rebuild existing
  clusters. A node with old state stops at start, and says which files to
  delete.

### Removed

- The move of `acceptor.bin`, the state file of 0.1.0, to the newer files.
  The new state format can't read it.

## [0.5.0-beta.0] - 2026-10-13

### Added

- A `hello` request in the local API. It answers the API version and the
  daemon's release. The CLI sends it first, and stops with a clear error if
  the daemon serves another API version.
- On Unix, members of the API group may use the local API without root:
  every command but `stop`. Set it with `daemon --api-group`; it is `admin`
  on macOS, and none elsewhere. Others are refused with a message.
- On Windows, administrators may use the local API without elevation: every
  command but `stop`. Other users are refused with a message.
- `docs/LOCAL-API.md`: the local API protocol, its access rules and its
  versions, for the desktop apps. Tests check that its examples match what
  the daemon reads and writes.
- Error codes. A local API error is `{"err": {"code": ..., "message":
  ...}}`: programs choose what to do from `code`, and show `message` to
  people. `docs/LOCAL-API.md` lists the codes. The CLI reports the same
  codes: `error[<code>]: <message>` on stderr, or with `--json` a document
  `{"error": {"code": ..., "message": ...}}` on stdout, also for a bad command
  line.
- In `peers`, `path_state` is a code (`up`, `stale`, `no_path` and so on),
  `path_detail` is the text for people, and `retry_in_secs` says when a
  failed path is tried again.

### Changed

- On Unix the local API socket is `0666` and the state directory `0711`:
  the daemon decides what each client may do from its peer credentials. The
  keys and state files stay `0600`.
- On Windows interactive users may open the local API pipe, to read and
  write data only; the daemon decides what each may do from the client's
  token. The CLI opens the pipe without asking for `GENERIC_WRITE`.
- A member that refuses a join tells the joiner why with a typed reason, so
  `join` fails with a code such as `invite_unknown`. This changes the join
  messages between nodes: a refusal between this release and 0.4.0 or older
  is misread, so join through a member of the same release.
- In the local API, `remove`, `approve`, `reject` and `config_set` answer
  `{"outcome": "...", ...}` in snake case, as `leave` does, and a setting
  proposal in `pending` has `setting: {"key": ..., "value": ...}` in place of
  debugging text.

## [0.4.0] - 2026-10-11

### Changed

- The macOS installers moved to
  [cheesecloth-macos](https://github.com/jdpanderson/cheesecloth-macos).
  Releases here no longer attach them; they attach the macOS binaries.
- The Debian and Arch packages, and the Arch package signing, moved to
  [cheesecloth-linux](https://github.com/jdpanderson/cheesecloth-linux).
  Releases here no longer attach them; they attach the Linux binaries.

### Added

- Releases attach a plain binary for each target: Linux x86-64 and arm64,
  macOS arm64 and x86-64, Windows x64 and arm64. `SHA256SUMS` covers them.
  The Linux binaries need glibc 2.39 or newer.
- The Windows local API: a named pipe named after the state directory, open
  to SYSTEM, Administrators and the daemon's user only. The CLI checks who
  serves the pipe. `--socket` takes a full pipe name (`\\.\pipe\...`).
- On Windows the state directory, keys and state files allow only SYSTEM,
  Administrators and the daemon's user.
- On Windows the daemon stops cleanly on Ctrl-C or Ctrl-Break.
- A Windows CI job that runs the lints and tests, on x64 and arm64.
- The daemon runs as a Windows service. A stop or pre-shutdown request from
  the service manager shuts it down cleanly, as SIGTERM does on Unix.
- The Windows service logs to the Event Log, source `cheesecloth`, with
  error, warning and information levels. A console daemon still logs to
  stdout.
- `docs/WINDOWS.md`: setting up and running the service, logs, and the
  Windows weak points, which moved there from DESIGN.md.

### Fixed

- A key or state file written after a failed write no longer keeps the
  permissions of the temporary file that the failed write left.
- A `cheesecloth stop` sent while the daemon is already shutting down waits
  for the shutdown and gets its answer, in place of "can't reach the
  cheesecloth daemon". Other requests that shutdown cuts off get "the daemon
  is shutting down".

## [0.3.0] - 2026-10-09

### Changed

- Building needs Rust 1.95 or later, which GotaTun requires.
- WireGuard no longer uses the defguard libraries. Kernel WireGuard on Linux
  is configured over netlink directly. Userspace WireGuard is
  [GotaTun](https://github.com/mullvad/gotatun) running inside the daemon on
  every OS, so no `wireguard-go`, `boringtun` or `wg` program is needed.
- Userspace WireGuard changes a peer in place. It no longer removes and adds
  the peer, which reset its session.
- On FreeBSD the daemon uses userspace WireGuard; it no longer drives the
  kernel's `if_wg`.
- When an earlier run left a kernel WireGuard interface with the configured
  name, the daemon replaces it in place of reusing it. It refuses to touch
  an interface with that name that is not WireGuard.

### Added

- Windows userspace WireGuard, on a Wintun adapter. `wintun.dll` must be in
  the same directory as the executable.
- The packages include `THIRD-PARTY-NOTICES.md`: the licenses of the crates
  built into the binary, and where to get their source code. GotaTun is under
  MPL-2.0, and its older code under BoringTun's BSD-3-Clause license.

## [0.2.1] - 2026-10-08

### Fixed

- A node could fail to learn an agreed state with "this node's acceptor
  ignored the agreed state". This happened when an earlier attempt to learn
  the same state was stopped after it was saved, for example by a timeout
  during a slow disk sync. The node now takes in the saved state.

## [0.2.0] - 2026-10-08

### Changed

- The CASPaxos engine moved out of this repository, to the
  [pnyx](https://crates.io/crates/pnyx) crate.
- The acceptor state is now kept in two files with a checksum,
  `acceptor.0` and `acceptor.1`, in place of `acceptor.bin`. The daemon moves
  an existing `acceptor.bin` to the new files when it starts.
- An older version can't read the new files: after a downgrade, it reports
  that there is no cluster state. Putting back an old copy of `acceptor.bin`
  is not safe, because the acceptor would forget promises it made since. To
  downgrade a node, have it leave the cluster first, and join again after.
- If an agreed state can't be saved by this node's acceptor, learning it now
  fails, so the node never reports a state that isn't on disk.

### Fixed

- When a change can't be agreed, the error now gives the cause of each
  failed request to an acceptor, not only its outer message.
- Requests that arrived while the daemon was starting were refused with
  "not ready". The control plane now accepts connections only once it can
  answer them.
- The Debian package has the right version. The 0.1.0 package was labelled
  0.0.0.

## [0.1.0] - 2026-10-07

Initial Release

### Added

- First release: a peer-to-peer WireGuard mesh with membership agreed through
  authenticated CASPaxos, relays for control messages, and packages for
  macOS, Debian 13 and Arch Linux.
