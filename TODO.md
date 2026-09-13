# cheesecloth (formerly wesher) TODO

Working list for evaluating and adopting wesher. Ordered by priority; we work
through it top to bottom, one item at a time, and check items off as we go.
Items marked **DECISION** need a joint call before work starts.

Baseline (2026-09-07, upstream `main` @ 8887b51, last commit 2024-11-11):

| Metric | Value |
|---|---|
| Total statement coverage | 17.4% |
| `cluster` / `common` / `etchosts` / `wg` / `main` | 10.3% / 66.7% / 28.6% / 30.0% / 0.0% |
| `go.mod` Go directive | 1.18 (local toolchain is 1.27) |
| CI Go matrix | 1.18.x, 1.19.x (both EOL) |
| `go build`, `go vet`, `go test -race` | all pass |
| Direct deps with newer versions | 8 of 9 (see phase 2) |

## Phase 0: groundwork

- [x] **DECISION**: fork strategy. Keep module path `github.com/costela/wesher`
      until phase 5 so fixes stay easy to upstream; revisit then.
- [x] Add `make coverage` and `make test` targets.
- [x] Add `make vulncheck` and `make lint` (pinned via `go run pkg@version`) and a
      non-blocking CI job. Lint is non-blocking until its 7 findings are fixed:
      3 errcheck (phase 5) and 4 govet inline warnings that vanish with the Go
      directive bump (phase 2). govulncheck: 0 called vulnerabilities, 36 in
      required modules that are not reached (phase 2 motivation).
- [x] Baseline numbers recorded in the table above.

## Phase 1: pure-logic unit tests

Target: every function that does not require `NET_ADMIN` reaches near 100%.

Pure logic, no privileges needed (done 2026-09-07; total coverage 17.4% -> 41.1%):

- [x] `key.UnmarshalText` (key.go): valid key, bad base64, wrong length.
- [x] `AgentCmd.Validate` (agent.go): overlay mask not a
      multiple of 8, bind-addr + bind-iface conflict, bind-iface resolution
      (uses `lo`), autodetect. Remaining gaps are OS error branches.
- [x] `computeClusterKey` (cluster/cluster.go): provided key wins, state key
      used when none provided, random key generated and stored when both empty.
- [x] `loadState` (cluster/state.go): missing file, deprecated path fallback,
      malformed JSON, unreadable file. Tests use `t.TempDir()`;
      `deprecatedStatePath` became a var to allow overriding it.
- [x] `state.save`: unwritable directory error path.
- [x] `delegateNode` (cluster/delegate.go): `NodeMeta` success and over-limit,
      no-op methods.
- [x] `common.Node`: `String`, `EncodeMeta` over-limit, `DecodeMeta` garbage.
- [x] `etchosts.WriteEntries` end to end against a temp file: add, update,
      remove, preserve unmanaged lines, preserve mode, missing file, nil
      `Logger` happy path, no leftover temp files. The rename-fallback branch
      of `movePreservePerms` is still uncovered (needs a cross-device rename).
- [x] `wg.nodesToPeerConfigs` and `wg.addrToIPNet`: IPv4 and IPv6, bad key,
      empty list.
- [x] `wg.overlayAddr`: `/32` and non-byte-aligned mask cases.

## Phase 2: update dependencies with minimal code change

Done 2026-09-07, one commit per bump. Only code change: `io/ioutil` -> `os`
and dropping the `wg/netlink.go` shim.

- [x] Go directive 1.18 -> 1.26 (latest x/crypto requires 1.26). `io/ioutil`
      replaced with `os` equivalents.
- [x] `golang.org/x/crypto`, `x/net`, `x/sys`, `x/sync` -> latest. govulncheck:
      36 -> 1 unreached module vulnerabilities; the remaining one is the
      unmaintained `x/crypto/openpgp` package, not imported here, no fix.
- [x] `hashicorp/memberlist` 0.5.1 -> 0.6.0. Reviewed the source diff: atomics,
      keyring locking fix, push-pull size cap, lowercased errors. No API or
      wire change.
- [x] `wgctrl` 2022-05 -> 2024-12.
- [x] `vishvananda/netlink` 1.3.0 -> 1.3.1; `netlink.Wireguard` now exists, so
      `wg/netlink.go` is gone.
- [x] `kong` 1.4.0 -> 1.16.1. Verified `--version`, `--help`, `Validate` and
      `AfterApply` ordering behave identically by running both binaries.
- [x] `logrus`, `go-isatty`, `testify`, and all indirect deps of built
      packages (`go get -u ./...`). `backoff/v4` already latest; v5 skipped.
- [x] `go mod tidy`; unit and race tests pass; coverage unchanged at 41.1%.
      e2e not run here: it needs the test image fix, which is a phase 3 item.
- [x] CI: Go matrix 1.26.x/1.27.x; checkout v7, setup-go v7, upload-artifact
      v7, download-artifact v8, action-gh-release v3.

## Phase 3: tests that require root or a live cluster

Covers what phase 1 could not: memberlist integration and the netlink/wgctrl
code. Root-gated tests skip without `CAP_NET_ADMIN`; the docker e2e suite stays
as the end-to-end check.

- [x] `cluster.New` / `Join` / `Leave` / `Update` / `Members`: two in-process
      memberlists on loopback. Exposed two real data races on `state` (fixed
      in their own commit, see phase 5 list). Cluster coverage 36% -> 92%.
- [x] `wg.New`, `SetUpInterface`, `DownInterface`: netns-gated tests, skipped
      without `CAP_NET_ADMIN`. `make test-privileged` runs the suite under
      `unshare -r`, which is enough. wg coverage 39% -> 85% privileged;
      remaining lines are netlink error branches (phase 4 seams).
- [x] e2e suite builds its image from `tests/Dockerfile` (golang:1.27) and
      runs locally. All 5 original scenarios pass on the phase 2 dependencies.
- [x] e2e `test_node_leave`: clean SIGTERM leave removes the peer's hosts
      entry. `tests/e2e.sh <name>...` runs selected cases.
- [x] e2e runs under rootless podman (`docker` aliased to `podman`):
      containers get `--cap-add=NET_RAW`, `--device /dev/net/tun` and
      `--security-opt label=disable`; all no-ops under docker. Known gap:
      `test_multiple_clusters_restart` fails under podman because the
      restarted container gets a new IP and the non-PID-1 wesher instance is
      killed without leaving, so memberlist sees a name conflict. Passes
      under docker, where the IP is reused.

Privileged coverage after phase 3: 67.8% total (cluster 92%, common 92%,
etchosts 66%, wg 85%, main 25%).

## Phase 4: adapt the code for automated testing

Done 2026-09-07. Seams are unexported and injected; public API unchanged.

- [x] **DECISION** (taken as proposed, open to revision): `wg.State` holds the
      subsets of `*netlink.Handle` and `*wgctrl.Client` it uses as two small
      interfaces; `New` wires the real ones, `newState` takes fakes.
- [x] `AgentCmd.Run` returns errors; `loop` and `apply` take
      `clusterController`/`wgController`/`hostsWriter` interfaces and are
      driven by fakes. Termination returns nil instead of `os.Exit(0)`.
- [x] `cluster`: `Leave` closes a `done` channel that stops the `Members`
      goroutine and closes its channel; `Leave` is idempotent (memberlist
      panics on a second leave). `newMemberlistConfig` package var lets tests
      use fast timers; added a failed-node detection test.
- [x] `etchosts`: unexported `rename` hook; copy fallback now tested. Logging
      goes through a nil-safe helper (the fallback path dereferenced a nil
      `Logger`).
- [x] Netns-gated wg tests kept as integration checks; fakes cover the error
      branches unprivileged.
- [x] Coverage: 41.1% -> 79.7% privileged (main 50%, cluster 92%, common 92%,
      etchosts 80%, wg 95%). Unprivileged: wg 91%, rest identical.
      All 6 e2e scenarios pass.

Remaining uncovered lines: `AgentCmd.Run` wiring (needs a real cluster and
interface), `main`, kong hooks, and OS error branches in `Validate`,
`state.save`, `computeClusterKey`.

## Phase 5: review and update the codebase

Correctness issues found during the initial read (verify each, then fix):

- [x] `etchosts.movePreservePerms` nil `Logger` dereference in the rename
      fallback. Fixed in phase 4.
- [x] `etchosts.writeEntries` deletes from the caller's map as a side effect.
      Tracks written IPs in a local set instead; output now goes through a
      `bufio.Writer` so write errors are checked once on `Flush`.
- [x] `AgentCmd.Run` `Fatal`/`os.Exit` replaced with returned errors. Fixed in
      phase 4.
- [x] `Cluster.Update` installs the memberlist delegates after
      `memberlist.Create`; memberlist reads `Config.Delegate` during `Create`
      and on every gossip cycle, so this is a data race and the local node's
      metadata is only pushed by the `UpdateNode` call. Removed `Update`:
      the agent resolves the hostname, `wg.New` names the node, and
      `cluster.New` takes it and installs the delegates before `Create`.
      Local metadata never changes at runtime, so nothing needed re-announcing.
- [x] `Cluster.Name` dereferences `localNode`, nil until `Update` is called.
      Removed: it had no callers, and in production returned "" because
      `wg.New` never sets the node name.
- [x] `Cluster.Members` goroutine now stops on `Leave` (phase 4); data races
      with `Leave` on `state` and on the node slice fixed in phase 3. `Leave`
      now also waits for the goroutine to exit (it could still be mid-save).
- [x] The 100-slot events buffer remains a workaround for a memberlist
      deadlock (hashicorp/memberlist#23); check whether 0.6.0 still needs it.
      It did: memberlist 0.6.0 still calls the event delegate under its node
      write-lock, and `Members` took that lock via `ml.Members()`. Events now go
      to a forwarder that only logs and sets a one-slot "changed" signal;
      `Members` rebuilds the list from that signal. Buffer reduced to 16, only
      to absorb events in flight during shutdown.
- [x] `SetUpInterface` adds a route per peer but never removes routes for
      peers that left; stale `/32` routes accumulate until the interface goes
      down. `ReplacePeers: true` already handles the wireguard side. Now lists
      the main-table routes on the link and deletes host routes inside the
      overlay net that no current peer owns.
- [x] `--bind-iface` picks `addrs[0]` blindly, which may be IPv6 or link-local.
      Now prefers a global unicast IPv4, falls back to any IPv4 (loopback),
      and errors when the interface has none. The autodetect path uses the
      same helper with a public-address predicate, replacing
      `go-sockaddr.GetPublicIP` (direct dependency dropped; memberlist still
      pulls it in).
- [x] `computeClusterKey` prints the generated key only when stdout is a TTY,
      so a systemd-started first node never reveals its key (upstream TODO
      suggests a `showkey` subcommand). Minimal fix: off a terminal it now
      logs a warning naming the state file to grep. `showkey` stays a phase 6
      candidate; `computeClusterKey` is pure and reports whether it generated.
- [x] `common.Node.DecodeMeta` trusts peer metadata blindly (upstream TODO).
      `AgentCmd.validateNode` now rejects (log-and-skip) nodes with an empty
      name, an overlay address outside `--overlay-net`, or an unparseable
      public key. Validation lives in the agent, which knows the overlay net.
- [x] Join retry uses backoff defaults, which give up after 15 minutes. Decided
      2026-09-07: retry indefinitely (interval capped at 60s), SIGTERM/SIGINT
      is the way out. A node that gives up needs a manual restart, which is
      worse than a periodic error log.
- [x] `LogLevelFlag.AfterApply` calls `Fatal` instead of returning the error.
      Fixed as part of the logrus -> `log/slog` migration (2026-09-07); the
      level is parsed by `slog.Level.UnmarshalText`.

Hygiene:

- [x] Drop the pre-0.3 `/var/lib/wesher/state.json` read fallback
      (`deprecatedStatePath`); state has been keyed by interface name since
      2020-05. README pointed at the old path; now names the per-interface file.
- [x] logrus -> `log/slog` (logrus is in maintenance mode). memberlist logs
      through `slog.NewLogLogger` at debug; `etchosts.Logger` is a
      `*slog.Logger`; messages are structured key/value pairs.
- [x] Source layout (2026-09-08): the entry point is `cmd/cheesecloth/main.go`;
      the command implementations live in `internal/cli`, one file per purpose
      (root parser, config file, log level, agent command, agent loop,
      bind-address selection, control adapter, invite, revoke, status command,
      status rendering). Library packages stay at the top level.
- [x] Simplification pass (2026-09-07, one commit each): kong's built-in
      `VersionFlag`; `key` is a byte slice validated on parse;
      `wg.overlayAddr` is a pure function; `DownInterface` asks netlink only;
      `path` -> `path/filepath`; `Validate` bind selection as a switch;
      `loadState` returns the state.
- [x] Remove the hidden `--ip-as-name` flag (PoC-era local-testing aid that
      set the memberlist node name to the bind IP and broke `/etc/hosts`
      entries). The integration tests now name nodes via the
      `newMemberlistConfig` hook instead.
- [x] Replace `nolint: errcheck` sites with explicit logging where the error is
      useful (state save failures are worth a warning). Done: state save,
      memberlist leave/shutdown and the post-failure interface down all log a
      warning; test deferred closes use `_ =`.
- [x] Wire up `golangci-lint` with a modest config and fix what it reports.
      `.golangci.yml`: standard set plus misspell, unconvert, unparam,
      gocritic, govet shadow, gofmt. Nine findings fixed; the CI lint job is
      now blocking.
- [x] Update README: configuration table, CI badge, and the "future version"
      promises to reflect what we actually plan. Table and promises done; the
      badge and the release job's repository check follow the module-path
      DECISION below.
- [x] **DECISION**: module path rename and README ownership (deferred from
      phase 0). Decided 2026-09-08: the code has diverged too far for
      cherry-picking to upstream to matter. Module path is
      `github.com/jdpanderson/wesher`; imports, the `import` comment, the CI
      release gate and the README follow. `go install .../wesher@latest`
      works again. The README keeps the "fork of costela/wesher" line.

## Phase 6: features

Candidates, roughly by value-to-effort. Each is a **DECISION** to discuss
before starting; none are committed yet.

- [x] Configurable MTU (`--mtu`, default 1420). `wg.New` now takes a `wg.Config`.
- [x] `showkey` subcommand to print the persisted cluster key
      (`wesher showkey [--interface DEV]`, via `cluster.LoadKey`).
- [x] Persistent keepalive option for peers behind NAT
      (`--persistent-keepalive`, a duration in whole seconds, 0 = off).
- [x] Remove stale routes and hosts entries when a peer leaves (overlaps with
      the phase 5 route item; may fall out of that fix). It did: hosts entries
      were already rewritten on every update, routes are now pruned too.
- [x] Extra `AllowedIPs` per node so a node can route a subnet into the mesh
      (advertised via node metadata). 2026-09-09: `--allowed-ips`, signed
      with the metadata; peers add them to allowed IPs and route them over the
      interface. Overlaps with the overlay net are dropped, a network
      advertised twice goes to the first node by name. Route pruning now
      removes every route on the interface nobody advertises.
- [ ] Static / seed nodes to mitigate split-brain (upstream roadmap item):
      periodically re-join configured addresses.
- [x] Overlay IP collision detection: warn or refuse when two members hash to
      the same address (upstream roadmap item). 2026-09-09: hashing is gone.
      The admission record carries the node's slot in the overlay net; the
      admitter hands out the lowest free one, so addresses are dense, stable
      and agreed on by every member. Peers whose metadata claims a different
      address are ignored, as is the later of two admissions to one slot
      (a race between two admitters); the loser is logged and must re-enrol.
      `--overlay-net` no longer needs a /8-aligned mask.
- [x] Config file support. Decided 2026-09-08: YAML at
      `/etc/cheesecloth/config.yaml` or `--config`, keys are flag names,
      command line overrides the file, unknown keys are an error, `join-key`
      and `init` are refused in the file. Environment variables removed
      entirely; the systemd unit no longer loads an EnvironmentFile.
- [x] `status` subcommand listing peers, handshake age, and overlay addresses
      (`wesher status [--interface DEV] [--json]`; names come from the
      persisted cluster state). A health endpoint remains a separate candidate.
- [x] QUIC for all of cheesecloth's own traffic. Decided 2026-09-10: one
      UDP port carries memberlist gossip (QUIC datagrams), push/pull (streams)
      and enrolment (streams under a second ALPN), all inside per-pair TLS 1.3
      authenticated by the identity certificates. Replaces the hand-rolled
      AES-GCM packet layer, the address book and the enrolment TCP listener on
      the wireguard port. WireGuard keeps its own UDP port: the kernel owns it.
      Done the same day; the welcome message lost its own encryption since
      the stream carries it, and `--join` takes an optional port.
- [x] **DECISION** macOS and Windows support. Decided 2026-09-11: target
      both, kernel WireGuard stays the way on Linux. Plan in phase 8.
- [ ] Tool dependencies as `tool` directives in `go.mod` (Go 1.24+), run with
      `go tool golangci-lint` and `go tool govulncheck`, instead of
      `go run pkg@version` pinned in the Makefile; Dependabot then updates
      them like any dependency.
- [ ] **DECISION** Release pipeline with GoReleaser: one config for the
      cross-compiled binaries, checksums, SBOM, cosign signing and the
      GitHub release, with nfpm producing the .deb and Arch packages. Would
      replace the hand-written Makefile loop and the per-distribution
      container jobs; `debian/` and `arch/` could stay for local builds or go.
      Releases currently carry no signature or provenance.
- [x] `internal/wg/platform_other.go` deleted: its build tag covered every
      operating system but the three that are supported, and nothing there can
      ever be compiled, because `internal/paths` has no file for those systems
      and `wgctrl` does not build for them either. Done 2026-09-12. An
      unsupported platform is refused by the build, not at startup.
- [x] Unexport what never leaves its package: the token codec and the
      enrolment version in `enrol`, the banner and path defaults in
      `etchosts`, and `RootHost`, `SeedLen` and `ErrUntrustedRoot` in `trust`.
      Done 2026-09-12. The `hello` struct's `Version` field stays exported,
      since `encoding/json` only marshals exported fields.
- [x] Packaging tidy. Done 2026-09-12: `arch/release/cheesecloth.install` was
      a byte-identical copy of `arch/cheesecloth.install` and is now a symlink
      to it, verified by building the release package in an Arch container:
      makepkg reads it through the link and the package carries `.INSTALL`.
      `debian/changelog` claimed version 0.1.0, which matched no tag; it is now
      an honest 0.0.0 placeholder that says CI stamps the real version.
- [ ] Fuzz tests (native `go test -fuzz`) for the parsers: enrolment frames
      and messages, the token codec, node metadata JSON, records JSON and the
      config file.
- [ ] Fill `--version` from `debug.ReadBuildInfo` (commit and dirty flag) when
      no tag is stamped with `-X main.version`.
- [x] Drop the X25519 key from identities and admission records. Done
      2026-09-12. It fed the pairwise gossip keys, which QUIC replaced, and the
      enrolment MAC key, where the identity-to-TLS-peer binding does the same
      job: an intermediary cannot pass the MAC check with its own identity and
      cannot compute one without the token. An identity is now just the
      Ed25519 seed, the admission record loses a field, and the exchange loses
      two. The enrolment version goes to 4 and the admission domain to v2,
      both of which fail closed against anything older; nothing to migrate, so
      no fallback was written.
- [x] Packaging: `debian/` (dh 13, native source, unit installed disabled,
      config as conffile, cross builds from `DEB_HOST_ARCH`) and
      `arch/PKGBUILD` (`cheesecloth-git`). 2026-09-11.
- [x] Release packages: CI builds `.deb` for amd64 and arm64 in the
      `golang:1.27-trixie` image (installs on trixie and Ubuntu 26.04) and an
      x86_64 Arch package from `arch/release/PKGBUILD`, versions stamped by
      `dist/version.sh`; `v*` tags attach them to the release. 2026-09-11.
- [x] README stripped to pitch, quickstart, how it works and links; the
      option table, IPv6, routing, multiple clusters moved to
      `docs/configuration.md`, permissions/systemd/status/security/limitations
      to `docs/operations.md` (2026-09-11).
- [x] systemd `sd_notify` readiness and a `Type=notify` unit file. 2026-09-09:
      `internal/notify` (stdlib only) sends READY after the first snapshot
      is applied, STATUS with the peer count on every change and STOPPING on
      shutdown. `Members()` now emits a first snapshot at once, so a lone
      node brings its interface up without waiting for a peer.
- [x] Cluster key rotation (upstream roadmap item; largest effort, needs a
      protocol design). Superseded by phase 7: there is no cluster key to
      rotate.
- [x] IPv6 underlay support and verification (memberlist and endpoint
      handling are IPv4-assumed in places). 2026-09-08: `--bind-addr` is a
      `netip.Addr` defaulting to `0.0.0.0`; its family decides the cluster's
      family. For a wildcard (`0.0.0.0`/`::`) wesher picks the advertise address
      itself (public, then global unicast; never on the overlay interface)
      and sets memberlist's `AdvertiseAddr`, which memberlist only did for
      `0.0.0.0`. `--bind-iface` removed (breaking): it conflicted with
      `--bind-addr` and picked addresses awkwardly. e2e: `test_ipv6_cluster`
      (IPv6 underlay and overlay) and `test_ipv6_overlay` (IPv6 overlay over
      IPv4). The e2e IPv4 network is now pinned to 172.30.0.0/24 because
      podman's default 10.89.0.0/24 sits inside the default overlay net. Found
      and fixed on the way: stale-route pruning removed the kernel's route to
      our own IPv6 /128 address.
- [x] The invitation output printed `cheesecloth --join <host> --join-key
      TOKEN`, which enrolled the joiner onto the default overlay network: on a
      cluster that set `--overlay-net`, the joiner computed every address from
      the wrong network and the mesh did not work. Done in phase 11: the
      welcome carries the cluster's overlay network and the joiner adopts it,
      so the printed command is right for every cluster. The interface name
      was never part of this, being local to each node.
- [x] `--overlay-net` was not persisted, so a node restarted without it
      silently moved to the default network: a node on `10.42.0.0/24` came
      back as `10.0.0.1` with nothing in the log, and its peers then rejected
      its announcement, because the address no longer matched the one its
      admission assigns. Done in phase 11: the network is kept with the rest
      of the bootstrap state, an explicit flag still wins so a cluster can be
      renumbered, and a value that differs from the cluster's is logged as a
      warning rather than applied in silence.
- [x] The root is a peer, not a king: it can revoke itself, and any member can
      revoke it. Done 2026-09-12. Before this the root was valid
      unconditionally, so it could not leave its own cluster except with
      `leave --force`, which told the cluster nothing and left an identity
      nothing could ever retire. `leave` now works on the root like any other
      node. Nothing cascades: records are judged as of the moment they were
      signed, so the members a departed root admitted are unaffected and the
      cluster keeps admitting new ones with that key still pinned as the anchor.
      A revoked root admits nobody afterwards. This also retires the root key
      of a decommissioned machine, which used to be trusted for good.
- [x] A member cannot revoke the member that admitted it. `Set.validAt` guarded
      against cycles with a set keyed on identity alone, so judging the
      revoker's own admission re-entered that identity at an earlier time and
      the guard read it as a cycle: in a root -> a -> b chain, b revoking a left
      a a member, while the root revoking a worked. The record was stored and
      gossiped, so `cheesecloth revoke` reported success and nothing happened.
      Done 2026-09-12: the guard is keyed on identity and time. A record's time
      never changes, so the questions the recursion can ask stay finite and it
      still ends.
- [ ] A node that runs with no peers erases the addresses it needs to rejoin.
      The state file's peer list is written from the live membership, so a node
      left alone persists an empty list: verified 2026-09-12, a two-node
      cluster where one node was stopped left the survivor with no remembered
      peers within seconds. Any node that is ever the last one running forgets
      every address, and once that has happened to all of them a cluster-wide
      restart leaves every node running, a member, and unable to find the
      others without `--join`. Seen for real while renumbering: both nodes came
      up alone and neither could rejoin. This contradicts the goal that all
      nodes may restart at once unattended. Options: never persist an empty
      peer list; or keep the last known address of each member separately from
      the live membership, dropped only when the member is revoked.
- [ ] Rate limiting sensitive incoming requests; We don't want to allow brute-forcing joins or denial of service. We should have a mechanism of shutting down incoming requests if the rate is too high. This feels like something that must already exist as a package (or combination of packages). We could also just support dectection or logging such that an external piece of software would watch the logs and block hosts. This needs thought and design before we implement
- [ ] A switch that stops a node offering enrolment, held per node, so that a
      cluster whose nodes have all turned it off stonewalls every joiner. The
      node keeps its membership and gossips as before; it refuses the enrolment
      ALPN, mints no tokens, and says so rather than letting a joiner guess.
      Useful once a cluster is built and nobody should be joining it, and as
      something to turn off in a hurry while an incident is being worked out.

      What it does not do is stop a stolen member minting members, because that
      never uses enrolment: an attacker with the seed signs admissions itself
      and hands them over at the next push/pull (see "What a stolen member
      costs" in `docs/membership.md`). Closing that needs a rule on the
      receiving side, and it cannot be per node: two nodes running different
      rules about which admissions to accept would disagree about who is a
      member, and the union merge converges only because they cannot. So this
      is an operational control, not an answer to a compromised member; that is
      what cascading revocation would be for.

      Decide before any work starts: whether the switch is a flag alone or is
      also settable on a running agent through the control socket, and whether
      a node that has it off should say so in its metadata, so `status` can
      show the operator that the cluster is in fact sealed rather than leaving
      them to check every node.

## Phase 7: identity-based membership

Design: `docs/membership.md` (accepted 2026-09-08). Replaces the shared
cluster key with per-node identities, signed admission records, invitation
tokens that live only for the exchange, and an identity-authenticated gossip
transport. Not compatible with shared-key wesher.

- [x] `trust` package: identity from seed (Ed25519 + X25519), admission and
      revocation records, validity evaluation from a pinned root, signed node
      metadata. Validity is time-aware: an admission stands if its admitter
      was a member when it signed.
- [x] `cluster`: state carries seed, root, records and peer identities;
      memberlist transport with per-pair AES-GCM packets and mutual-TLS
      streams; metadata verification before a peer is reported. Records sync
      by push/pull and re-broadcast. A revoked node is cut off, not informed:
      it sees its peers fail and ends up alone.
- [x] Enrolment over TCP on the WireGuard port: token store, mutual HMAC
      exchange, encrypted hand-off of root, records and gossip address.
      Agent: `--init` roots a cluster, `--join HOST --join-key TOKEN` enrols,
      a bare start rejoins from state. `--cluster-key` and `showkey` removed.
- [x] Control socket (`/run/wesher/<iface>.sock`, owner-only, JSON request and
      response) and `invite` / `revoke` subcommands. `status` shows identities.
- [x] e2e: enrol via `invite`, restart without token, spent token rejected,
      simultaneous joiners on one multi-use token, revoke reaching a third node;
      README quickstart and security section rewritten.
- [x] **DECISION**: rename the project. It now forks the concept, not just
      the code: no compatibility with wesher's wire protocol, state, flags or
      key model remains. Decided 2026-09-08: **cheesecloth** (a mesh that
      strains). Renamed: module path `github.com/jdpanderson/cheesecloth`,
      binary, `CHEESECLOTH_*` env prefix, `/var/lib/cheesecloth`,
      `/run/cheesecloth`, crypto domain strings, systemd unit, e2e image and
      networks, README, docs. Kept: default interface `wgoverlay` (it names
      what the interface is, not who made it). Dropped the old logo and the
      upstream deepsource config. GitHub repository rename is the user's step;
      the old URL redirects.

## Phase 8: macOS and Windows

Decided 2026-09-11. Cross-building fails today in two places only: the `wg`
package (netlink throughout) and one chown in `etchosts`. The trust,
enrolment, gossip, cluster, control socket and sd_notify code already compiles
for both platforms. Principles: one interface per Linux-specific concern,
implementations selected by build tag, an implementation that refuses at
startup ("not supported on this platform") where nothing real exists, and a
no-op only where absence is legitimate (service readiness on macOS, hosts
entries when opted out). Tests keep recording fakes rather than nulls. On
Linux the kernel module is used whenever it is present; the userspace device
is a fallback, never a replacement.

- [x] Portability seams, Linux behaviour unchanged. Done 2026-09-11: `wg` has
      `device` and `linker` interfaces, `internal/paths`, `internal/notify`;
      the whole tree vets for darwin and windows and the suite runs on macOS. `wg.netlinker` becomes an
      OS-neutral link interface in `netip` terms: ensure interface, set
      address and MTU, up, replace routes, list addresses, delete. The
      netlink implementation moves behind `//go:build linux`; the fake becomes
      portable; an "unsupported" implementation covers other platforms. The
      hosts-file chown splits into a Unix file and a Windows no-op. The four
      default paths (state dir, control socket, config, hosts) get per-OS
      values, one file each. A service notifier interface fronts sd_notify.
      Gate: `GOOS=darwin` and `GOOS=windows` builds pass and join CI as
      compile checks; Linux e2e stays green.
- [x] Device provider. Done 2026-09-11 (`--userspace`; e2e image no longer
      installs wireguard-go; `test_userspace_device`). On Linux the kernel provider creates the link as
      today and is used whenever the module is present (probe: create the
      link; `EOPNOTSUPP`/`ENOTSUP` means no module). Only when that fails, or
      `--userspace` is given, the agent embeds wireguard-go as a library: the
      device runs in-process and exposes the standard userspace control
      socket under the interface name, so wgctrl configures it exactly like a
      kernel device and the peer configuration code does not change. The log
      says which one is in use. The e2e image drops the separate wireguard-go
      install; the container scenarios exercise the userspace path, the
      Linode hosts the kernel path.
- [x] macOS. Done 2026-09-11: ioctls for address, MTU and flags, the routing
      socket for routes; `dist/io.github.jdpanderson.cheesecloth.plist`; a
      `macos` CI job runs the suite and a live root test. Link implementation over the BSD routing socket for addresses
      and routes. The device is a `utun` the system names, so the user-facing
      interface name is the control socket name and `status` shows both. A
      launchd plist under `dist/`. GitHub's macOS runners allow sudo: unit
      tests and a one-node smoke test run there.
- [x] Windows. Done 2026-09-11: `winipcfg` linker, `notify.SCM`, the agent
      runs under the Service Control Manager when started by it and logs to
      `%ProgramData%\\cheesecloth\\agent.log`; `cheesecloth service install|uninstall`;
      a `windows` CI job runs the suite. Not yet verified on a real Windows
      machine: the CI job is the first run. Link implementation over the IP helper API (the
      wireguard-windows module wraps it in pure Go). `wintun.dll` ships next
      to the binary. The notifier reports to the Service Control Manager and a
      `service install` subcommand registers the agent. Paths move under
      `%ProgramData%\cheesecloth`; the hosts file is
      `%SystemRoot%\System32\drivers\etc\hosts`. Unit tests on a Windows
      runner. Packaging (zip or MSI) is a later item.
- [x] Docs for each platform once it runs: install, privileges (root or
      Administrator), which device is in use and how to tell. Done 2026-09-11:
      `docs/operations.md` Platforms section, README and configuration updated.
- [x] Releases carry macOS and Windows binaries. Done 2026-09-11: the Makefile
      builds `os/arch` pairs from `TARGETS` rather than architectures from
      `GOARCHES`, naming them `cheesecloth-<os>-<arch>` with `.exe` on
      Windows; CI builds nine of them on the Linux runner (CGO is off, so
      every platform cross-compiles) and the existing upload globs them.
      macOS binaries are unsigned, so the docs point at `curl`/`wget` rather
      than a browser download; Wintun is still not shipped with the exe.
- [ ] Windows follow-ups: the control socket relies on file permissions the
      hosts file directory does not give (an ACL on the socket, or a named
      pipe, would); wintun.dll is not shipped with the binary yet; service
      logs go to a file, not the event log.

## Phase 9: design documentation

- [x] `docs/design.md`: the critical design elements at a level above the
      code. Done 2026-09-12: goals and non-goals, the control and data planes
      and why the keys differ, trust and derived addressing, the whole-state
      agent loop, the portability seams, state, the operator interface,
      failure behaviour, testing and known limits. Points at
      `docs/membership.md` for the protocol rather than repeating it.
- [ ] **DECISION** whether to add a second layer of design documentation
      covering the code itself: package responsibilities, the main types and
      how a change moves through them.

## Phase 10: operator commands

Proposed 2026-09-12. The CLI has no way to take a node out of a cluster: a
member can `revoke` another node, but a node cannot remove itself, and nothing
deletes its state file, so a decommissioned node stays trusted and its
identity lingers in every peer's record set. `cheesecloth leave` fills that
gap. `--init` as an agent flag and changing settings on a running agent are
separate items, still to be designed. (Phase 14 took `--init` away; changing
settings on a running agent is still open.)

- [x] A member may revoke itself. Done 2026-09-12. `Set.validAt` only
      honoured a revocation whose revoker was valid, and the cycle guard made
      a self-revocation a no-op: the record was accepted and had no effect.
      Only the holder of that key can sign it and it removes nobody else, so
      it is honoured unconditionally. The root was still exempt at this point;
      phase 6 took that exemption away later the same day.
- [x] `cluster.RevokeSelf`: revoke this node's identity and push the record to
      each member over the stream transport, rather than only queueing it for
      gossip, because the node is about to stop. `cluster.Forget` deletes the
      state file. Done 2026-09-12.
- [x] `control`: a `leave` operation, and `Server.Close` waits for in-flight
      handlers so the reply outlives the agent's shutdown. Done 2026-09-12:
      the handler revokes this node, stops the agent as a signal would, waits
      for the usual teardown and for the state file to be deleted, and only
      then answers.
- [x] `wg.Remove`: delete an interface a stopped agent left behind. Only a
      kernel interface outlives its agent; elsewhere it is a no-op. Done
      2026-09-12.
- [x] `cheesecloth leave`: the agent revokes this node, tears the interface
      down and forgets the cluster. `--force` leaves without revoking, at this
      point for the root as well as for a node whose agent is not running; it
      says the cluster keeps trusting the identity until a member revokes it.
      The root stopped needing it in phase 6, where it became a peer.
      Done 2026-09-12, with the `test_leave_command` e2e scenario:
      the leaving node's peers drop it, including the one the operator never
      talked to, and its state file is gone.
- [x] A remembered peer is rejoined on its own gossip port. The peers in the
      state file kept an address and no port, and `Join` completed them with
      this node's `--cluster-port`, so a restart could only find peers that
      happened to share it. The port memberlist reached each peer at is now
      kept with the address; an address without one, from state written
      before this, still falls back to this node's port. The WireGuard port
      is a separate matter: peer endpoints are built from this node's
      `--wireguard-port`, which must still match across the cluster. Done
      2026-09-12.
- [x] Docs: decommissioning a node in `docs/operations.md`, the command list
      in `docs/membership.md`, the operator interface in `docs/design.md`,
      README. Done 2026-09-12.

## Phase 11: the overlay network comes from the cluster

Proposed 2026-09-12. `--overlay-net` is a cluster-wide value that only exists
on each node's command line, and nothing checks it against the cluster. A
joiner given a different one enrols, joins the gossip ring and is then ignored
by every peer, and ignores them, because each side derives a different address
from the same admission slot: two nodes, no peers, a warning in each log. Only
a prefix too small for the assigned slot is caught, at startup. The cluster
knows the answer, so it should say it.

Resolution order for the value the agent runs with: the command line, then the
config file (kong merges these two), then the welcome for a node being
enrolled, then the state file, then `10.0.0.0/8` for a brand new cluster. An
explicit value that differs from what the cluster uses wins and is stored, so
renumbering a whole cluster still works, but it is logged as the plain warning
that it is: this node will see no peers until every other node is given the
same value.

- [x] `enrol`: the welcome carries the cluster's overlay network, asserted by
      the admitting member alongside the slot it assigns and the record set.
      An old member sends none, which reads as "not known". Done 2026-09-12.
- [x] `cluster`: the overlay network is persisted with the rest of the
      bootstrap, so a restart needs no flag; the cluster stores the value it
      was created with. Done 2026-09-12.
- [x] `cli`: resolve the overlay network in that order, re-check it against
      `--allowed-ips` once resolved, and warn when an explicit value differs
      from the cluster's. Docs: `--overlay-net` is no longer needed to enrol
      or restart a node, in configuration, README and membership. Done
      2026-09-12, with the `test_overlay_net_from_cluster` e2e scenario: a
      joiner given no network takes the cluster's 10.77.0.0/16, at enrolment
      and on every later start. The flag lost its kong default, so an
      `--allowed-ips` overlap with the default network is now reported when
      the agent starts rather than when the flags are parsed.

## Phase 12: what a long-lived cluster costs

Measured 2026-09-12 on an M1, with throwaway benchmarks. `Set.Valid` walks the
admission chain to the root, so its cost follows the depth of that chain, not
the number of records: a flat set of 10,000 answers in 118 ns, the same as one
of 10 (101 ns), while a chain 1,000 deep takes 158 us (216 ns at depth 1). Depth only grows when
new nodes are admitted by recently admitted ones, so it is a pattern of use
rather than a matter of time. The call is on the hot path: the transport
checks it for every gossip datagram and every stream.

What does grow with time is the record set, at about 300 bytes per record,
which nothing prunes. The binding limit is the 1 MiB enrolment frame: 1,000
lifetime identities with half of them revoked make a 447 KB welcome, 2,000
make 896 KB, and at roughly 2,300 the welcome no longer fits. Verified: the
member logs `frame too large`, the joiner sees `EOF` with no explanation, and
the admission was signed and broadcast before the welcome was attempted, so
every failed attempt adds another record and makes the overflow worse. Other
costs are tolerable: rewriting the state file on each membership change is
850 us at 1,000 records and 9.4 ms at 10,000, `FreeHost` is 1.8 ms at 10,000,
and memberlist's own push/pull cap is 20 MiB.

- [x] A joiner that cannot be admitted is told why, and nothing is signed for
      it. The welcome carries a refusal instead of the cluster's state, so a
      name clash, a full overlay and a record set that has outgrown the frame
      all reach the operator running the join. Refusals before the token is
      proved stay silent. Done 2026-09-12.
- [x] `Set.Valid` caches its answer until the records change, so the walk is
      not repeated for every packet. Done 2026-09-12: a cached answer costs
      about 15 ns whatever the depth, against 216 ns at depth 1, 22 us at
      depth 100 and 158 us at depth 1,000. Only valid identities are cached, since anything that can
      open a connection is asked about and an unknown identity is decided in
      one lookup anyway. The map is taken before the answer is computed, so an
      answer from before a record change can only land in the map that change
      discarded.
- [x] `cheesecloth prune` removes the records of identities that are no longer
      members and that nothing still standing runs through, which is the
      largest set closed under "everyone this identity signed about goes too".
      Done 2026-09-12. A signed prune record carries the request; each node
      derives the same set from its own records and removes only what it can
      confirm, and remembers what it removed so a peer that has not pruned
      cannot hand the records back at the next push/pull. `--dry-run` reports
      without signing, and nothing prunes on its own. Still open: pruning the
      superseded admissions of members who are still here, a root-signed
      checkpoint that re-anchors the whole membership, and any way to undo a
      prune.

## Phase 13: BSD, iOS and Android

Proposed 2026-09-12. What stands in the way today, checked from the macOS
host:

- `GOOS=android GOARCH=arm64 go build ./...` already succeeds, and
  `GOOS=ios CGO_ENABLED=1 go vet ./...` is clean: android satisfies the
  `linux` build tag and ios the `darwin` one, so both pick up implementations
  written for a privileged host. Compiling is not the problem there; what the
  code does is. Neither platform lets a process create its own tunnel, write
  `/etc/hosts` or keep state in `/var/lib`.
- `GOOS=freebsd` and `GOOS=openbsd` do not build, because `internal/paths` has
  one file per operating system and no fallback, so `stateDir`, `configFile`,
  `runDir` and `hostsFile` are undefined.
- The in-process device would run on both. Verified with `CGO_ENABLED=0`:
  `golang.zx2c4.com/wireguard/device`, `tun` and `ipc` all build for freebsd
  and openbsd. wireguard-go has `tun_freebsd.go` and `tun_openbsd.go`, and its
  `ipc` package is tagged `darwin || freebsd || openbsd`.
- OpenBSD needs no cgo anywhere: wgctrl builds for it with cgo off. Its kernel
  client's cgo file is `//go:build ignore`, a `cgo -godefs` input, with
  generated definitions checked in for 386, amd64, arm and arm64. Both the
  kernel and the userspace path are available in a cross-compiled release.
- FreeBSD is blocked by a compile-time import rather than by a runtime choice.
  wgctrl's `os_freebsd.go` calls `wgfreebsd.New` unconditionally, and that
  client really is cgo (`import "C"` in `client_freebsd.go`), so with cgo off
  the file is dropped, the symbol is undefined and the package fails to build.
  `internal/wg` imports wgctrl in `wireguard.go` and `status.go`, so
  `--userspace` cannot get around it: the binary would not link. Its kernel
  definitions also exist only for 386 and amd64, so freebsd/arm64 has no
  kernel client even with cgo, and userspace is the only path there.
- `GOOS=netbsd` cannot run the in-process device at all: wireguard-go has
  `tun_` implementations for darwin, freebsd, openbsd, linux and windows, and
  its `ipc` package covers darwin, freebsd and openbsd. wgctrl has kernel
  clients for linux, freebsd, openbsd and windows.
- The BSD work is mostly done already without being called that: `bsdLinker`
  in `link_darwin.go` drives addresses with `SIOCAIFADDR` ioctls and routes
  over the routing socket, which is how FreeBSD and OpenBSD work too.

- [ ] `internal/paths` for the BSDs: `/var/db/cheesecloth`,
      `/usr/local/etc/cheesecloth/config.yaml`, `/var/run/cheesecloth`,
      `/etc/hosts`. That is the whole of what stops openbsd building, so
      `GOOS=openbsd go vet ./...` joins the cross-compile gate with it;
      freebsd joins once the UAPI client below removes the wgctrl import.
- [ ] A UAPI client of our own, behind the existing `wgClient` interface
      (`Device`, `ConfigureDevice`). The in-process device already publishes
      the socket wgctrl and `wg(8)` look for (`uapi_unix.go`), and the
      protocol is a short text exchange: `get=1`, or `set=1` and key=value
      lines, terminated by a blank line. Roughly 150 lines and its own tests.
      It is what makes FreeBSD buildable with cgo off, since nothing then has
      to import wgctrl where the device runs in this process, and it keeps
      `cheesecloth status` working from a separate process, which configuring
      the device in-process with `device.IpcSet` would not. It is also most of
      what iOS and Android need, where the same client talks to the device
      directly instead of over a socket. Which client a platform uses belongs
      in the `platform` file next to the device and the linker.
- [ ] FreeBSD and OpenBSD device and link. Both have kernel WireGuard
      (`wg(4)`) and a wgctrl client for it, so the shape is the Linux one:
      create the interface, fall back to the in-process device when the kernel
      refuses. On FreeBSD that fallback is the only path until the cgo
      question below is settled, and the only path on arm64 regardless. Widen
      `bsdLinker` past `//go:build darwin` and check the ioctl struct layouts
      per operating system rather than assuming Darwin's. The interface is
      named by the agent on the BSDs, not by the system as on macOS, so
      `tunname` becomes a no-op there.
- [ ] **DECISION** kernel WireGuard on FreeBSD, which is the only thing cgo is
      needed for once the UAPI client exists. Reaching it means either
      building FreeBSD binaries natively with a C toolchain, and giving up the
      cross-compiled release for that one target, or a wgctrl that does not
      need cgo. Shipping FreeBSD with the in-process device only is a
      supportable answer: it is what macOS and Windows already do, and what
      freebsd/arm64 has to do in any case.
- [ ] NetBSD is out of reach until wireguard-go grows a tun and uapi
      implementation for it. Record it as unsupported rather than pretending.
- [ ] Verification. GitHub-hosted runners have no BSD, so the gate is
      cross-compilation plus vet in CI, and a manual run on a FreeBSD VM
      before claiming support, in the way the Linode cluster proved Linux.
- [ ] **DECISION** iOS and Android are a different deliverable, not another
      `GOOS`. The platform owns the tunnel: an app gets a file descriptor from
      `VpnService.Builder.establish` or `NEPacketTunnelProvider` and hands it
      to wireguard-go (`tun.CreateTUNFromFile`), sets addresses and routes
      through the platform API rather than a linker, and has no hosts file, no
      service manager, no root and no `/var`. The device would also be
      configured in process (`device.IpcSet`) instead of through the UAPI
      socket wgctrl talks to, which an app sandbox cannot open, though the
      UAPI client above is the same seam. Membership, trust, enrolment and the
      agent loop are already portable; what changes is the device and linker
      seam, the paths, and the operator interface, which becomes a Go API the
      app calls rather than a command and a unix socket. The call to make is whether cheesecloth ships a library target
      (gomobile AAR, c-archive framework) at all, since that is a second
      product surface to keep working, not a port.

## Phase 14: configuring a node

Proposed 2026-09-12. `--init` was an agent flag, so the documented way to start
a cluster was `cheesecloth --init`, a command that blocks a terminal and does
three unrelated things at once: write no configuration, root a cluster, and run
the agent. That is not how a node is actually set up. An operator wants a
configuration file and a service unit, and the agent to work out the rest on
every start. The flag was also the only destructive one in the CLI, and the
only one that had to be remembered exactly once and never again.

Splitting it: configuring a node is `cheesecloth config`, and rooting a cluster
is what the agent does when it finds a network configured and no state to go
with it. Nothing then has to be run by hand at the right moment, and the same
unit file works on the node that starts the cluster and on every node that
joins it.

- [x] Agent: `--init` is gone. Membership is settled from state and settings —
      already a member, `--join-key` to enrol, an overlay network with no state
      to root a cluster, or none of these, which waits. Done 2026-09-12. The
      waiting case replaces an error that made a service manager restart an
      agent that was merely unconfigured; it configures nothing and opens no
      control socket, but generates and keeps the identity, so the node is the
      same one when it is finally given something to act on. `cluster.Load`
      lost its `init` parameter with the flag; starting over is `cheesecloth
      leave --force`, which already removed the state file.
- [x] Config file: keyed by interface name, one section each, so a host running
      several clusters has one file rather than one per interface. `interface`
      is no longer a key, since the section name is the interface and the two
      could otherwise disagree. A command takes the section named by
      `--interface`, or the only one there is; several sections and no flag is
      an error rather than a guess. Done 2026-09-12. Kong traces the command
      path before it resolves flags, so `ctx.Selected()` exempts `config` from
      that error; the section itself is chosen from a small scan of the
      arguments, because the file is loaded before kong has parsed anything.
- [x] `cheesecloth config`: prints an interface's effective settings, or every
      section with no `--interface`, and writes them with `--init`. Done
      2026-09-12. Settings equal to their default are left out, read from the
      kong tags rather than a second copy, so what it writes cannot drift from
      what the agent defaults to. `--init` appends, so the comments of the
      shipped file survive, and refuses an interface the file already has.
- [x] The shipped `dist/config.yaml` is commented out entirely, including the
      keys that were previously active. Done 2026-09-12. A fresh install now
      has no effective settings at all, which is what makes the waiting case
      the default: the package can be installed and the unit enabled before
      anyone has decided what the node joins.
- [x] Default interface renamed from `wgoverlay` to `wgcloth`, reversing the
      Phase 7 decision to keep the name inherited from wesher. Done 2026-09-12.
      It now names the project rather than the topology, and a host still
      running wesher no longer has the two defaults collide. The custom names
      in the documentation and the e2e tests are untouched: they illustrate
      calling an interface something else, which is the point of them.
- [ ] Changing settings on a running agent, still to be designed. `cheesecloth
      config` reads the state and the file but cannot ask the agent what it is
      actually running with, and nothing rereads the file without a restart.

## Phase 15: what the records cost on the wire

- [ ] **DECISION** A binary encoding for the record set, in place of JSON, to
      raise the cluster ceiling. A welcome carries the whole set in one 1 MiB
      frame, which is about 3,500 records at roughly 300 bytes each, and that
      is what bounds how many nodes a cluster can hold. Two things are paid for
      twice there: base64, which costs a third of every key and signature, and
      the admitter, whose 44 characters repeat in every admission a node signed
      — in the ordinary cluster, where the root admits everyone, that is one
      constant stored 3,500 times. The fields themselves are small: identity
      32, admitter 32, signature 64, name about 10, the three numbers 24, so
      about 162 bytes packed against roughly 300 as JSON. Grouping admissions
      by admitter would save most of the repetition on top of that. Together
      they should roughly double the ceiling.

      What it touches: `trust.Records` is the form used for the state file, the
      push/pull state sync and the enrolment welcome alike, so one encoding
      change moves all three. `wire.Canonical` is unaffected — what a record
      signs is already a packed encoding and does not change. Protocol version
      stays 1; there are no users to keep compatible with.

      Worth weighing against leaving it: the ceiling is reached only by a
      cluster of a few thousand nodes, and pruning already buys some of it
      back. Decide whether the ceiling is worth a hand-written codec and the
      tests to go with it before any work starts.
