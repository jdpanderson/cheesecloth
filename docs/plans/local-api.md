# Plan: local API access and versioning

Phase 1, items 3 and 4 of [the packaging plan](packaging.md). They block the
desktop components, which run as the logged-in user and speak the local API.

## Goal

- A desktop app, running as the logged-in user without elevation, can use
  the local API on every OS: macOS, Windows, Linux and FreeBSD. Desktop apps
  for each OS live in their own repositories (see
  [REPOSITORIES.md](../REPOSITORIES.md)), so the API is the same everywhere.
- The protocol is written down, has a version that clients check, and has
  rules for changing it. The OS repositories use only what the doc says.

## Who may do what

On every OS, the transport lets local users connect, and the daemon decides
by who is on the other end. One rule, one place:

| Caller | Allowed |
| --- | --- |
| root, SYSTEM, an elevated administrator, or the daemon's own user | every request |
| an operator (see below) | every request except `stop` |
| anyone else | nothing; the connection gets one error line and is closed |

An operator is:
- macOS: a member of `admin`.
- Windows: a member of Administrators who is not elevated.
- Linux and FreeBSD: a member of the API group, if one is set.

Why operators may do almost everything: the network has one operator (a
homelab). On macOS and Windows, operators are the users who can already
become root or SYSTEM, so this gives them nothing new. `stop` stays with
root because a service manager owns the daemon's life: launchd, the Windows
service manager, or systemd.

### Windows

No new groups. A non-elevated process of an administrator has the
Administrators group in its token, but only as "deny only", so a pipe access
list can't let it in by that group. So:
- The pipe's access list also lets interactive users (`INTERACTIVE`) read
  and write data, but not create pipe instances. The pipe already rejects
  remote clients. Clients open it without `GENERIC_WRITE`, which includes
  creating instances.
- The daemon reads the client's token: it impersonates the client only long
  enough to open the thread token, so there is no process ID that could be
  reused. Administrators enabled (elevated) means full access; deny only
  means an operator.

Today the CLI must run elevated. After this change it need not.

### The group on Linux and FreeBSD

- `cheesecloth daemon --api-group <name>`, also in `/etc/default/cheesecloth`.
- Default: none, so nothing changes. The Linux packages are expected to create
  a `cheesecloth` group and set it, when the Linux desktop work starts.
- macOS takes the same option, with `admin` as its default.
- `--api-group ''` turns it off.
- The daemon resolves the group name once at start, and fails to start if the
  group does not exist.

Membership includes supplementary groups. A macOS user's primary group is
`staff`, and `admin` is supplementary, so the primary gid from the peer
credentials is not enough:
- macOS: `mbr_check_membership` (asks Directory Services, so it also knows
  network accounts, and has no 16-group limit).
- Linux and FreeBSD: `getpwuid_r` for the user name, then `getgrouplist`.

These are libc calls, so they need `#[allow(unsafe_code, reason = ...)]`, as
`if_nametoindex` already has. They live in `ipc/unix.rs`, behind one safe
function `fn may_connect(cred) -> Access`.

The check runs once per connection, when it is accepted. A user added to the
group later needs a new connection, and nothing more.

## Where the socket lives

Today: `<state-dir>/control.sock`, mode `0600`, in a `0700` state directory.
A non-root user can't reach it.

Change:
- The socket becomes `0666`. The peer-credential check is now the access
  control, not the file mode.
- The state directory becomes `0711`: others may pass through it to the
  socket, but can't list it. Keys and state files stay `0600`, owned by
  root.
- The socket keeps its place, so separate instances still get separate
  sockets with no new option.

Other choice: a runtime directory (`/var/run/cheesecloth/`) that holds only
the socket, with the state directory left at `0700`. It keeps the state
directory private, but each instance would then need a second directory,
named after the first. Its only gain is that others can't pass through the
state directory, and the `0600` key files already block them. I suggest
`0711`.

Side effect: a user in the group can run `cheesecloth status` without `sudo`.
The CLI's "do you have permission?" hint should name the group.

## Versioning

A new request, `{"cmd":"hello"}`, answered with:

```json
{"ok":{"api":1,"daemon":"0.5.0"}}
```

- `api` is one integer. A client checks it first, and refuses to go on if it
  does not know that number.
- Changes that keep `api`: new requests; new fields in answers; new values in
  string fields that the doc lists as open (such as `path`). Clients ignore
  fields they don't know.
- Changes that raise `api`: removing or renaming a request or a field,
  changing a field's type or meaning, a new required field in a request.
- A daemon serves one `api` number. With one operator and the app shipped
  with its daemon (see the macOS plan), we don't serve two versions at once.

The CLI also calls `hello` and checks `api`, so a CLI and daemon that don't
match say so plainly.

## The protocol doc

`docs/LOCAL-API.md`:
- transport: the socket or pipe address, one JSON object per line each way,
  one answer per request, in order, on one connection;
- access: the table above, and the Windows access list;
- every request and its answer, with field types, which fields may be null,
  and the closed sets of string values (`phase`: `none`, `pending`,
  `member`, `stopping`; `security`: ...);
- errors: `{"err":"..."}` text is for people, and clients must not parse it;
- the versioning rules above;
- how `stop` is answered (after shutdown).

Tests that keep it true:
- each JSON example in the doc is parsed as an `ApiRequest` or the answer type
  it names (a test reads the doc and finds the fenced blocks by a tag);
- a test that a non-group, non-root caller is refused, and a group caller is
  allowed (on Unix CI, as a normal user, with the group set to one of the
  test user's groups);
- a test that the group may not `stop`.

## Polling

No push channel. Clients ask when they need an answer: the desktop apps ask
when the user opens their menu or window, and not in the background. A
`watch` request can be added later without raising `api`.

## Client crate

Not now. The macOS app is Swift and the OS repositories don't build Rust. The
doc is the contract. If the Windows tray app is written in Rust, we move
`api.rs` into a client crate then.

## Steps

1. `hello`, the `api` number, and the CLI check.
2. Peer-credential check and `--api-group`, socket `0666`, state directory
   `0711`. Tests.
3. Windows: `INTERACTIVE` on the pipe, and the client token check. Tests in
   the Windows CI job. WINDOWS.md: the CLI no longer needs elevation.
4. `docs/LOCAL-API.md` and its tests. DESIGN.md points to it.
5. CHANGELOG, README (status without sudo), and close items 3 and 4 in
   [packaging.md](packaging.md).

One branch, one PR. The macOS repository then pins its commit.

## Open questions

- Summary states. The macOS mockups show badges such as "Healthy", "Online",
  "Synced" and "Protected". If each app derives these from raw fields, three
  apps will derive them three ways. The daemon could answer them in
  `status`, each as a level (`ok`, `warning`, `error`) and a short reason.
