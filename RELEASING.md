# Releasing

1. Set the version in `Cargo.toml` (`[workspace.package]`), then run
   `cargo check` to update `Cargo.lock`.
2. In `CHANGELOG.md`, add `## [X.Y.Z] - YYYY-MM-DD` below `## [Unreleased]`.
3. In `debian/changelog`, add an entry for `X.Y.Z` at the top. The Debian
   package takes its version from there.
4. Check:
   ```sh
   cargo fmt --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo deny check
   cargo xwin clippy --locked --workspace --all-targets \
     --target x86_64-pc-windows-msvc -- -D warnings
   ```
   The `aarch64-pc-windows-msvc` target is checked only by the Windows arm64
   CI job.
5. Commit as `vX.Y.Z`, and push `main`.
6. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.

The tag starts `.github/workflows/packages.yml`. It checks that the tag
matches the version, builds the plain binaries for each target and the Debian
and Arch packages, and makes the GitHub release. The binaries are named with
the tag (see `docs/REPOSITORIES.md`). A tag with a suffix (`vX.Y.Zpre0`,
`vX.Y.Z-rc1`) makes a pre-release.

The Arch package reads the version from `Cargo.toml`; it needs no change.

The macOS installers are released from
[cheesecloth-macos](https://github.com/jdpanderson/cheesecloth-macos). After
this release is published, move the pin there to it.
