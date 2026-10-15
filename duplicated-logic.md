# Duplicated logic

A survey of places where the same logic is written more than once, so that one
fix would have to be made in several places, or the copies could drift apart.

No code was changed. Line numbers are for the working tree on 2026-10-15,
branch `unprivileged-members`, with its uncommitted edits. Paths are relative
to the repo root; `daemon/` means `crates/cheesecloth-daemon/src/`, `core/`
means `crates/cheesecloth-core/src/`, `net/` means `crates/cheesecloth-net/src/`.

Things checked and found to be fine: quorum arithmetic always goes through
`pnyx::quorum` / `Config::quorum()`; the CLI reuses `socket_path`,
`Options::new` and `PathState::detail` from the daemon; `Member::may_relay`
and `soft::relay_role` are used as the single rule for other nodes' relay role.

## Severity key

- **A**: the copies already behave differently, or the rule is security
  or consensus relevant.
- **B**: the copies agree today, but a change needs edits in several places.
- **C**: small or local; worth fixing when nearby.

---

## A. Copies that already differ, or that guard consensus

### A1. Extending `Trusted` with transitions: three copies, two rules

- `daemon/node/consensus.rs:618-630` (`learn`): sorts the transitions by
  config number, then silently skips any from another cluster.
- `daemon/node/round.rs:118-125` (`verify_round_inner`): no sort, and a
  foreign transition is an error (`ensure!(..., "foreign transition")`).
- `daemon/node/consensus.rs:725-727` (`frontier`): the `Trusted::new` +
  `extend` prefix only.

The difference in sort and in foreign handling is a real behavioral split
in proof-checking code. Suggested home: one
`Trusted::from(current, stored, extra) -> Result<Trusted>` in `proof.rs`.

### A2. Checking a received (state, certificate) pair: four copies, four sets of checks

- `daemon/node/mod.rs:177-183` (`Node::start`): cluster id, `proves`,
  `check_config`. No `verify_members`.
- `daemon/membership.rs:335-351` (`finish_join`): cluster id, `verify_members`,
  `check_config`, `proves`.
- `daemon/node/consensus.rs:604-636` (`learn`): cluster id, `trusted.check`,
  `proves`, `verify_members`.
- `daemon/node/round.rs:583-586` (stale reply): `check_config`, cluster id,
  `proves`; then `learn` repeats the checks.

Each site decides on its own which checks to run. Suggested home: a
`Proven::check(cluster_id, trust)` in `proof.rs`, where `trust` is either a
`Trusted` or "self-certified".

### A3. A node's public IP: two copies, plus the "best observation" rule written twice

- `daemon/node/view.rs:85-101` (`public_ip_of`): own facts if public, else
  the peer's announced `public_ip` if public, else
  `observed_by_public`, else the announced `public_ip`.
- `daemon/wgrec.rs:486-497` (closure in `Inputs::gather`): the same four
  steps, but step three reads `observations()` instead.
- The ranking `(!via_mapping, seq)` is written in both
  `daemon/soft.rs:316-327` (`observed_by_public`, `max_by_key`) and
  `daemon/soft.rs:331-350` (`observations`, manual `rank >= old`).

`status` / dialing and WireGuard planning can disagree about a node's address
if either copy is edited alone. Suggested home: one
`SoftTable::public_ip(node, members, my_facts)` built on one ranking function;
`observed_by_public` becomes a lookup in `observations`.

### A4. "Is this IP on one of our networks?": two copies, one canonicalises

- `daemon/node/reach.rs:280-285` (`on_our_network`): `ip.to_canonical()`
  before testing `facts.ifaces.nets`.
- `daemon/node/view.rs:170` (`local_addrs` / same-site filter): no
  `to_canonical()`.

An IPv4-mapped IPv6 address answers differently in the two places.
Suggested home: `Interfaces::contains(ip)` in `local.rs` that canonicalises.

### A5. "Log a failure only when it changes": four copies, two comparisons

- `daemon/node/problem.rs:30-47` (`Problem::record`): compares the summary
  (`e.to_string()`) only. The doc comment says this is on purpose, because
  causes vary between runs.
- `daemon/wgrec.rs:179-196` (`note_status`), `daemon/wgrec.rs:199-217`
  (`note_peer`) and `daemon/wgrec.rs:395-399` (revoke): compare the full
  `{e:#}` chain.

The WireGuard copies re-log whenever only a cause changes, which is what
`Problem` was written to prevent. Suggested home: use `Problem`, or a
per-key map built on it.

### A6. "How many other members?": two formulas

- `daemon/membership.rs:90-96`: `members.keys().filter(id != me).count()`.
- `daemon/membership.rs:542`: `members.len().saturating_sub(1)`.

They differ when this node is not itself in `members`. Suggested home:
`ClusterState::others(&me)` in core.

### A7. Settings `buffer_nodes` maximum written by hand

- `core/state/mod.rs:819-821`: `if *n > 3` with the comment "the reserve of
  seven relaxed voters", i.e. `MAX_ACCEPTORS - pnyx::quorum(7, false)`.
- `daemon/node/acceptors.rs:55`: compares the buffer with the *protected*
  quorum, `n - pnyx::quorum(n, true) >= buffer_nodes`, which is 2 for seven.

A buffer of 3 passes validation but can never give a protected configuration.
May be intended; the rule should be derived in one place in core.

### A8. `approvals_required` limit written twice in `ClusterState`

- `core/state/mod.rs:467` (`warnings`): `approvals_required + 1 > n`.
- `core/state/mod.rs:801-803` (`validate_setting`):
  `possible = privileged - 1; n > possible`.

Equivalent today. Suggested home: `ClusterState::max_approvals()`.

---

## B. Copies that agree today but must be edited together

### B1. The setting-name table: five copies across three crates

- `daemon/commands.rs:191-200` (`config_set` match on the key strings).
- `daemon/commands.rs:207-209`: a hand-written "known: ..." list in the error.
- `daemon/api.rs:247-253` (`SettingView::from`): `SettingChange` back to the
  same strings.
- `crates/cheesecloth/src/main.rs:584-592` (`print_config`): the same names,
  plus read-only `ipv4_range` and `ipv6_prefix`.
- `crates/cheesecloth/src/main.rs:158`: the names again in help text.
- `core/state/mod.rs:797-833` (`validate_setting`): the names in messages.

Adding a setting needs six edits, and the two free-text lists are the ones
most likely to be missed. Suggested home: a key table on `SettingChange` in
core (`KEYS`, `key()`, `parse(key, value)`).

### B2. The acceptor-change sequence `choose` -> `configuration` -> `present_quorum` -> `Change::Close`: four copies

- `daemon/node/consensus.rs:193-205` (`change_to`).
- `daemon/node/consensus.rs:315-329` (`give_up_round`).
- `daemon/node/acceptors.rs:232-243` (`check_acceptors`, pre-check).
- `daemon/node/acceptors.rs:245-261` (`check_acceptors`, closure).

Same shape; they differ in the candidate state, in error mapping
(`Refused::Security` vs `anyhow::Error::msg`) and in whether `protected` is
compared. Suggested home: one `plan_config(agreed, state, facts)` in
`acceptors.rs`.

### B3. "A quorum of acceptors is reachable": three copies

- `daemon/node/acceptors.rs:142` (`present_quorum`): `filter(present).count() >= quorum`.
- `daemon/node/acceptors.rs:174`: `intersection(&live).count() >= quorum`.
- `daemon/views.rs:90-91`: `reachable_voters = intersection(&live).count(); changes_paused = reachable < quorum`.

Same result because `present` is `live.contains`. Suggested home: one
`reachable(config, live) -> usize` plus `has_reachable_quorum` in
`acceptors.rs`.

### B4. Sealing a command and stepping the state

Sealing `CommandBody` with `Domain::Command`:

- `daemon/node/consensus.rs:109-116` (`submit`).
- `daemon/node/consensus.rs:296-303` (`give_up_round`).
- `daemon/membership.rs:206-210` (genesis).
- `daemon/testing.rs:216-225` (`signed`), `daemon/node/tests.rs:1034-1041`
  (inline, same file already imports `signed`), `core/state/tests.rs:35-47`
  (`Node::cmd`).

Building the `Request` and applying it, then `record_step`:

- `daemon/node/consensus.rs:149-161` and `304-312` use
  `at_ms: now_ms().max(state.now_ms)`.
- `daemon/membership.rs:225-228` uses plain `now_ms()`.
- `daemon/node/acceptors.rs:258-261`.
- Test copies: `daemon/node/tests.rs:375-382`, `1046-1055` (a line-for-line
  copy of `write_round` without the replay check), `1367-1372`, `1578-1584`,
  `1606-1612`; `core/state/tests.rs:884-892` (`stepped`);
  `daemon/node/round/tests.rs:182`, `213`.

A change to `write_round` (for example the `at_ms` clamp) would not be seen
by the tests that copy it. Suggested home: `SignedCommand::new(...)` and
`ClusterState::step(base, Option<Request>)` in core, used by production and
tests.

### B5. Wire framing built in `wire.rs` but parsed and answered by hand elsewhere

- Header build: `net/wire.rs:22-28` (offsets 0, 1..33, 33..41).
- Header parse: `net/conn.rs:365-370` repeats the offsets.
- Response encode: `net/conn.rs:396-403` (8-byte clock then body).
- Response decode: `net/rpc.rs:59-68` (`buf[..8]`, `buf[8..]`).
- Test copies: `crates/cheesecloth-net/tests/net.rs:789-799` (`raw_request`)
  and `net.rs:440-444`, with stream kinds as bare numbers.

Suggested home: `wire.rs` owns `parse_header`, `encode_response`,
`decode_response`, and exposes them to the tests.

### B6. Per-kind message size limit chosen twice

- `net/conn.rs:376-381`: `if kind == Kind::Join { MAX_JOIN_MESSAGE } else { MAX_MESSAGE }` plus a membership check.
- `net/rpc.rs:38-42`: the same choice.

Suggested home: `Kind::max_message()` in `wire.rs`.

### B7. Which configuration to trust for an accept: copied verbatim

- `daemon/node/consensus.rs:494-498`.
- `daemon/node/round.rs:145-149`.

Suggested home: `trusted_config_for(&learned, number)`.

### B8. Voter-configuration shape check: twice in `proof.rs`

- `daemon/node/proof.rs:129-132` (`check_config`).
- `daemon/node/proof.rs:241-244` (`Trusted::follow`).

Suggested home: `fn valid_config(&Config) -> bool`.

### B9. `MemberInfo` built from two sources

- `daemon/membership.rs:156-178` (`initial_info`): key from
  `cheesecloth_wg::public_key(&wg_private)`, own `relay` rule.
- `daemon/node/reach.rs:289-299` (`my_info`): key from `node.wg_public`,
  `relay` from facts.
- Advertised IPs to `SocketAddr`: `daemon/membership.rs:157-162` and
  `daemon/node/reach.rs:113-116`.

Suggested home: one `my_info(opts, facts, key)` used by both.

### B10. Own `may_relay` and own `is_relay` re-derived

- `daemon/node/view.rs:63-67` and `daemon/node/reach.rs:119-124`:
  `members.get(&me).is_some_and(|m| m.may_relay())`, while core already has
  `ClusterState::is_privileged`.
- `daemon/wgrec.rs:502-508` (`have_relays` closure) re-implements
  `Node::is_relay` / `have_relays` (`daemon/node/view.rs:27-51`).
- Mixed access paths to the same state: `.value.value.members` at
  `daemon/node/view.rs:38`, `daemon/node/mod.rs:230`,
  `daemon/node/round.rs:155-197`, `daemon/wgrec.rs:820-829`, `894-903`, while
  most code uses the `.state()` accessor.

### B11. WireGuard key decoding outside core

- `core/id.rs:122-129` (`de_wg`).
- `crates/cheesecloth-wg/src/sys/linux/kernel.rs:130-140` (`decode_key`).

`WgKey` has `Display` but no `FromStr`. Suggested home: `impl FromStr for WgKey`.

### B12. Member-name length rule in two crates

- `core/state/mod.rs:921-925`.
- `daemon/options.rs:106-110`.

Same constant, different messages. Suggested home: `state::check_name`.

### B13. CLI repeats the daemon's response decoding

- `crates/cheesecloth/src/main.rs:205-213` (`typed`).
- `daemon/api.rs:463-470` (`decode`) and `daemon/api.rs:431-436`.

Identical bodies and messages. Suggested home: make `api::decode` public.

### B14. Strings shared between daemon and CLI by convention

- Phase names `"none" | "pending" | "stopping" | "member"`: set in
  `daemon/views.rs:31,63,69,80`, matched in `crates/cheesecloth/src/main.rs:395-418`.
- Proposal kinds `"join" | "remove" | "setting"`: set in
  `daemon/commands.rs:119,127,134`, matched in `main.rs:542-558`.
- Invite lifetime: `core/state/mod.rs:19` (`INVITE_TTL`) versus "30 minutes"
  in `main.rs:108` and `main.rs:309-311`, while `InviteView.expires_at_ms`
  is already returned.
- Keepalive defaults 25 and 300: `main.rs:59-61` and `daemon/options.rs:50-52`
  repeat `NAT_KEEPALIVE_SECS` / `MAPPED_KEEPALIVE_SECS` in text.

Suggested home: serde enums in `api.rs` for the first two; format the
constants for the rest.

### B15. `hand_off` re-implements `transitions_for`

- `daemon/node/consensus.rs:347-348` builds
  `config.number.saturating_sub(MAX_CONFIGS_AHEAD)` itself.
- `daemon/node/consensus.rs:717-720` (`transitions_for`) is the helper.
- The "encode once, request each peer, `join_all`" loop is at
  `consensus.rs:353-369`, `802-811`, `830-849`.

### B16. Platform `Platform` impls in cheesecloth-wg

- `crates/cheesecloth-wg/src/sys/macos.rs:27-35` and `sys/freebsd.rs:26-33`:
  the same `tun_builder(...).with(associate_route).build_async()`.
- `interface_exists` / `send_raw_udp` passthroughs repeated in
  `sys/linux.rs:29-36`, `sys/macos.rs:37-43`, `sys/freebsd.rs:35-41`.

Suggested home: a shared unix helper or default trait methods.

---

## C. Small or local repeats

- **Pending join lookup** written twice in `daemon/node/join.rs:67-69` and
  `92-97`; suggested `ClusterState::pending_join(node)`.
- **Ballot-owner check** `ballot.node == from` at
  `daemon/node/consensus.rs:472`, `857`, `daemon/node/round.rs:110`, with
  three messages.
- **Postcard batch sizing** starts at the magic `10` in both
  `daemon/soft.rs:280-291` (`seed`) and `daemon/soft.rs:355-374` (`batches`).
- **`encode` / `decode` helpers** in `daemon/node/mod.rs:367-374` are
  bypassed by direct `postcard` calls in `consensus.rs:348,760,802,830`,
  `round.rs:400,506`, `membership.rs:268,420`, `wgrec.rs:811,861`.
- **JSON file load/save and "missing means None"** repeated in
  `daemon/files.rs:79-93`, `115-129`, `169-181`, `199-207`.
- **Abort-and-await a task**: `daemon/membership.rs:62-72` and `477-487`.
- **Peer key and allowed IPs lookup**: `daemon/wgrec.rs:820-829` and `894-903`.
- **Interface prefix lengths**: `daemon/wgrec.rs:648-664` hard-codes `/64`
  and `/24` instead of using `ula_prefix(..).prefix_len()` and the range in
  `core/addr.rs:23`.
- **Seq clock packing** `<< 16` / `>> 16` at `net/rpc.rs:73,291,314,321`;
  suggested `seq_from_ms` / `seq_ms` in `wire.rs`.
- **Payload budget check** identical at `net/rpc.rs:108-111` and `331-334`.
- **Unspecified address of the same family**: `net/lib.rs:264` and
  `net/probe.rs:470-474`.
- **Timed dial with error mapping**: `net/conn.rs:179-182` and
  `net/probe.rs:477-489`.
- **JSON line framing**: `daemon/local_api.rs:40-43` and `daemon/api.rs:416-421`
  (the two ends of one protocol).
- **Ten-minute windows**: `FORWARD_WINDOW_MS` at `net/rpc.rs:20` and
  `REPLAY_WINDOW` at `core/state/mod.rs:24`. Possibly a coincidence; a
  comment should say whether they must match.

---

## D. Test code

`daemon/lib.rs:29-30` has `#[cfg(test)] mod testing;`, so the integration
tests (`tests/cluster.rs`, net tests, CLI tests) cannot use it. A shared home
for them needs a `test-util` feature or a dev-only crate.

The worst cases, where tests re-implement production logic so a production
bug would be mirrored, are in B4 (command sealing and stepping) and B5 (wire
framing). The rest are copied fixtures:

- **Multi-signer certificate builder**, five copies: `daemon/testing.rs:167-182`
  (`Harness::certify`), `daemon/node/proof/tests.rs:41-49`,
  `daemon/node/round/tests.rs:237-249`, `daemon/membership/tests.rs:209-215`,
  `daemon/node/tests.rs:1414-1423`. They differ in `sign` vs `sign_verified`.
- **Polling loops instead of one `eventually`**: `daemon/node/tests.rs:942-947`,
  `971-976`, `1026-1031`, `1143-1148` (none assert after the loop, so a
  timeout passes silently), `1068-1073`, `1495-1500`;
  `crates/cheesecloth-daemon/tests/cluster.rs:87-99` (`eventually`, the right
  shape) and `397-406`; `crates/cheesecloth/tests/cli.rs:180-186`
  (`wait_until`); `daemon/testing.rs:282-293`;
  `daemon/node/lifecycle_tests.rs:151-157`;
  `crates/cheesecloth-net/tests/net.rs:303-309`.
- **Daemon `Options` fixture and `free_port`**: `daemon/testing.rs:243-264`
  and `63-71`, `tests/cluster.rs:15-21` and `52-69`,
  `crates/cheesecloth/tests/cli.rs:13-19` and `33-40`.
- **Restart a daemon from its options**: `daemon/membership/tests.rs:245-256`,
  `daemon/wgrec/tests.rs:274-276`, `314-318`.
- **Restart a `Node` on harness state**: `daemon/testing.rs:153-162`,
  `daemon/node/lifecycle_tests.rs:40-50`, `91-98`.
- **Read the saved acceptor store**: `daemon/testing.rs:234-238`
  (`has_acceptor`), `daemon/node/lifecycle_tests.rs:55-61`,
  `daemon/node/tests.rs:455-457`, `958-960` (these last two use `open`, which
  may create, instead of `open_existing`).
- **Signed soft-state entry**: `daemon/testing.rs:200-212`,
  `daemon/soft/tests.rs:15-24` and seven variants in the same file,
  `daemon/node/tests.rs:184-216`, `1515-1527`,
  `daemon/node/lifecycle_tests.rs:107-115`, `143-152`.
- **`MemberInfo` fixture** (`WgKey(node_id.0)`, port 51820, `relay: false`):
  `daemon/testing.rs:99-106`, `301-308`, `daemon/node/tests.rs:619-628`,
  `core/state/tests.rs:21-33`. The genesis/invite/redeem sequence also:
  `daemon/testing.rs:113-137`, `core/state/tests.rs:50-91`, `447-455`.
- **WireGuard tunnel test body across platforms**:
  `crates/cheesecloth-wg/tests/linux_tunnel.rs` vs `tests/macos_userspace.rs`,
  about 50 near-identical lines plus a byte-identical drop guard and
  `command()`. `tests/common/mod.rs` already exists as the home.
- **`within` timeout wrapper**: `daemon/api/tests.rs:9-13` and
  `daemon/ipc/tests.rs:8-12` are identical; inline at
  `daemon/wgrec/tests.rs:293-296`, `daemon/node/lifecycle_tests.rs:151-157`.
- **Fetch agreed state over `SVC_FETCH`**: `daemon/node/tests.rs:250-252`,
  `579-581`, `daemon/membership/tests.rs:25-34`,
  `daemon/node/lifecycle_tests.rs:21`; `Node::proven(0)` already does this.
- **Unix mode checks**: `core/fs/tests.rs:45-47` has `mode()`;
  `daemon/files/tests.rs:70-79` repeats `.mode() & 0o777` three times.
- **Windows SDDL conversion**: `daemon/ipc/tests.rs:266-281` and
  `core/fs/tests.rs` (`Security::of`).

---

## Noticed on the way (not duplication)

`crates/cheesecloth/src/main.rs:289` passes the state directory to
`unreachable_message`, which expects a socket address. The error text then
names the directory as the address.

## Suggested order of work

1. A1, A2 (proof checking), then B4 (command sealing / stepping): these touch
   consensus safety and the tests copy them.
2. A3, A4, A5, A6 (daemon behaviour already split).
3. B1 (settings table) and B14 (shared strings): the easiest to drift.
4. B5 / B6 (wire framing) and the rest of B.
5. Test helpers in D, starting with `eventually` and the certificate builder.
