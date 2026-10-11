# Repositories

Cheesecloth is split across four repositories. This one holds the app. Each
OS has one more for its packages and, later, its desktop component.

| Repository | Owns |
| --- | --- |
| [`cheesecloth`](https://github.com/jdpanderson/cheesecloth) | the daemon and CLI, plain release binaries |
| [`cheesecloth-linux`](https://github.com/jdpanderson/cheesecloth-linux) | Debian and Arch packages; GNOME Shell extension (later) |
| [`cheesecloth-windows`](https://github.com/jdpanderson/cheesecloth-windows) | Inno Setup installer; tray app (later) |
| [`cheesecloth-macos`](https://github.com/jdpanderson/cheesecloth-macos) | `.pkg` or app bundle; menu-bar app (later) |

The move is in progress. Until it is done, some packaging is still here. See
[the plan](plans/packaging.md).

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
- **Release binaries.** Each release here attaches the binary for each target
  with a SHA-256 file. OS repositories package these and do not build Rust.
- **The local API protocol doc** (in this repository). Desktop components
  use only what it describes.
- **The pin file** (in each OS repository). It names the release of this
  repository that the packages hold, with the SHA-256 of each binary. For
  work that spans repositories, it may name a commit in place of a release;
  CI then builds the binaries from source at that commit. Before a package
  release, it must name a release again.

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
