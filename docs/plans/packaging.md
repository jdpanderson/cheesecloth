# Plan: split packaging and desktop components into OS repositories

A high-level plan. Each phase becomes its own workflow with a detailed plan.

## Goal

The main repository holds the app and its support for each OS. Each OS gets
one repository for its packages and its desktop component:

| Repository | Packages | Component |
| --- | --- | --- |
| `cheesecloth` | none (plain binaries for each target) | the daemon and CLI |
| `cheesecloth-linux` | Debian, Arch | GNOME Shell extension |
| `cheesecloth-windows` | Inno Setup installer | tray app |
| `cheesecloth-macos` | `.pkg` or app bundle | menu-bar app |

## Where the line goes

Stays in `cheesecloth` (how the app runs on each OS):
- the service code, the Event Log logging and its message table, the stop
  handling, the state directory and its access lists;
- the systemd unit and `/etc/default/cheesecloth`: other packagers expect
  upstream to ship these;
- FreeBSD support (WireGuard through `wg(4)`, routes, rc.d stop), when it comes;
- the local API, its documentation and its access rules;
- docs on running the daemon on each OS (`docs/WINDOWS.md` and the like).

Moves out (how a package is built and shipped):
- `debian/`, the PKGBUILD, `packaging/macos/`, `packaging/windows/`;
- third-party files shipped with a package (Wintun) and their pins;
- package signing and its secrets;
- the package jobs of `packages.yml` and their release uploads.

## Phase 0: done

1. Branch `windows-service` (the service, Event Log, arm64 CI, docs) is
   merged.
2. Branch `windows-installer` (the installer commits, on top of
   `windows-service`) stays unmerged. It becomes the start of
   `cheesecloth-windows`.

## Phase 1: what `cheesecloth` needs first

1. **Release binaries.** Each tagged release attaches the plain binary for
   each target (Linux x86-64 and arm64, macOS arm64 and x86-64, Windows x64
   and arm64) with a SHA-256 file. The Windows and macOS repos package these
   and do not build Rust. The Linux repo builds from source, as Debian and
   Arch expect. See [REPOSITORIES.md](../REPOSITORIES.md) for the names.
2. **OS-support tests that stay.** The installer checks are where the Windows
   service is tested today. Before they move, the main CI gets its own tests:
   on Windows, register the built binary with `sc create`, start it, stop it,
   read its events, check a restart after a kill; on Linux, run the systemd
   unit in a container or VM.
3. **Non-admin access to the local API.** Desktop components run as a normal
   user, but the local API allows only root, SYSTEM or Administrators. Decide
   for each OS how a desktop user gets access (for example a read-only status
   channel, or a `cheesecloth` group that may connect), and what they may do.
   This is a security decision; it needs its own plan.
4. **A stable, versioned local API.** Today it is internal to the CLI. Write
   down the protocol, add a version that clients check, and set rules for
   changing it. Optionally a small Rust client crate.

Items 3 and 4 block the desktop components. Items 1 and 2 block the split.

## Phase 2: the split

For each OS repository:
1. Create it, moving the files with their history (`git filter-repo` on a
   copy of `cheesecloth`, keeping only that OS's paths).
2. Pin the main release it packages in one file (version and SHA-256 of each
   binary). CI downloads and checks them.
3. CI: build and check the packages on every push; on a schedule, also
   against the main repository's `main`, so breakage shows early.
4. Releases: a package release names the main version it packages, plus a
   package revision (`0.4.0-2`, as Debian and Arch already do). Packages go
   on the OS repository's own releases. Uploading to the main repository's
   release would need a token with write access there, which weakens the
   separation of secrets.
5. Remove the moved files and jobs from `cheesecloth`, and point its README
   at the new repositories.

Suggested order: Windows (the branch is ready), then macOS, then Linux.

## Phase 3: desktop components

One plan each, after phase 1 items 3 and 4:
- Windows tray app: status, start and stop, open the logs. The installer
  installs it.
- GNOME Shell extension (GJS): status in the top bar. Works on Linux and
  FreeBSD.
- macOS menu-bar app (Swift). It may carry the daemon and register it with
  launchd, which would replace the `.pkg`.

## How to develop across the repositories

**Sibling checkouts and explicit pins, no submodules.**

```
~/git/cheesecloth/
  cheesecloth/
  cheesecloth-linux/
  cheesecloth-windows/
  cheesecloth-macos/
```

- Each OS repository pins the main release in one file. For work that spans
  repositories, the pin may name a commit of `cheesecloth` in place of a
  release; CI then builds the binaries from source at that commit. Before a
  release, the pin must name a release again.
- Local builds take a path to a local binary (as `build.ps1 -Exe` does
  today).
- A Rust component uses the client crate as a git dependency with a tag. For
  local work, an untracked `.cargo/config.toml` patches it to the sibling
  checkout.
- One agent session per repository, started in that repository. Add the
  siblings as working directories to read them. Worktrees work in each
  repository as they do now.

Why not submodules:
- **Packaging repos as submodules of `cheesecloth`:** the dependency goes
  the wrong way. The app would know about its packages, every clone and CI run
  of the app would see them, and each packaging change would need a pointer
  commit in the app.
- **`cheesecloth` as a submodule of each OS repository:** the direction is
  right, and it pins an exact commit. But the OS repositories use release
  binaries, not source, and Cargo already pins git dependencies. It would be a
  second pin mechanism.
- **An umbrella repository with all four as submodules:** one clone gets
  everything, and it records snapshots. But every change needs a pointer
  commit, submodules sit on detached HEADs, and it is easy to forget a pointer
  update. The OS repositories already pin what they need, so the snapshots
  add little.

Submodules fit when one repository builds another's source at an exact commit
and that never changes. Here the repositories meet at release binaries and a
versioned API, so pins in each repository are simpler.

## Open questions

- The tray app's language: Rust (shares the client crate) or C#.
- The macOS app: decided. It carries the daemon, registers it with
  `SMAppService`, and replaces the `.pkg`. If that needs a Developer ID, we
  get one. See cheesecloth-macos's `docs/plans/menu-bar-app.md`.
- The settings of the new GitHub repositories (branch protection, secrets).
