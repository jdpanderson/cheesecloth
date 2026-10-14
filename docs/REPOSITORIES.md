# Repositories

Cheesecloth is split across four repositories. This one holds the app. Each
OS has one more for its packages and its desktop component.

| Repository | Owns |
| --- | --- |
| [`cheesecloth`](https://github.com/jdpanderson/cheesecloth) | the daemon and CLI, plain release binaries |
| [`cheesecloth-linux`](https://github.com/jdpanderson/cheesecloth-linux) | Debian and Arch packages; GNOME Shell extension |
| [`cheesecloth-windows`](https://github.com/jdpanderson/cheesecloth-windows) | Inno Setup installer; tray app |
| [`cheesecloth-macos`](https://github.com/jdpanderson/cheesecloth-macos) | app bundle in a disk image; menu-bar app |

No packages are built here any more. Some work in this repository is still to
come. See [the plan](plans/packaging.md).

## Where the line goes

This repository holds how the app runs on each OS:
- the service code, logging, stop handling, and the state directory with its
  access lists;
- the systemd unit and `/etc/default/cheesecloth`, which other packagers
  expect upstream to ship;
- the local API, its protocol doc and its access rules;
- docs on running the daemon on each OS, such as [WINDOWS.md](WINDOWS.md).

An OS repository holds how a package is built and shipped:
- package scripts, their CI jobs and their releases;
- third-party files shipped with a package (such as Wintun) and their pins;
- package signing and its secrets.

## Contracts

The repositories depend on each other only through files:
- **Release binaries.** Each release here attaches one plain binary (not an
  archive) for each target, named with its Rust target triple, and a
  `SHA256SUMS` file:

  ```
  cheesecloth-<version>-x86_64-unknown-linux-gnu
  cheesecloth-<version>-aarch64-unknown-linux-gnu
  cheesecloth-<version>-aarch64-apple-darwin
  cheesecloth-<version>-x86_64-apple-darwin
  cheesecloth-<version>-x86_64-pc-windows-msvc.exe
  cheesecloth-<version>-aarch64-pc-windows-msvc.exe
  SHA256SUMS
  ```

  `<version>` is the release tag without its `v`, such as `0.4.0` or
  `0.4.0-rc1`.

  The Windows and macOS repositories package these binaries and do not build
  Rust. The Linux repository builds from source at the pinned version, as
  Debian and Arch packages are expected to. The binaries are also there for
  anyone who wants them on their own.
- **The local API protocol doc** (in this repository). Desktop components
  use only what it describes.
- **The pin file** (`cheesecloth.pin` in each OS repository). It names what
  the packages hold. It is TOML, in one of two forms:

  ```toml
  # A release of this repository (its <version>), with the SHA-256 of each
  # binary the repository uses. The Linux repository lists no binaries.
  release = "0.4.0"
  [sha256]
  x86_64-pc-windows-msvc = "<sha-256>"
  aarch64-pc-windows-msvc = "<sha-256>"
  ```

  ```toml
  # A commit of this repository, for work that spans repositories. CI builds
  # the binaries from source at that commit.
  commit = "<40-character commit id>"
  ```

  Before a package release, it must name a release again.

A package release names the version it packages plus a package revision,
such as `0.4.0-2`. Packages are published on the OS repository's own
releases.

## A change across repositories

1. Change this repository first (for example an API change and its doc), and
   merge it.
2. In the OS repository, pin that commit and make the matching change.
3. Release this repository.
4. Move the pin to the release.

## Local layout

Sibling checkouts, no submodules:

```
~/git/cheesecloth/
  cheesecloth/
  cheesecloth-linux/
  cheesecloth-windows/
  cheesecloth-macos/
```
