# Releasing

1. Set the version in `Cargo.toml` (`[workspace.package]`), then run
   `cargo check` to update `Cargo.lock`. For a beta, use a Cargo pre-release
   version such as `0.5.0-beta.0` and the matching tag `v0.5.0-beta.0`.
2. In `CHANGELOG.md`, add a heading with the full version and date below
   `## [Unreleased]`.
3. Check:
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
4. Commit as `vX.Y.Z`, and push `main`.
5. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.

The tag starts `.github/workflows/packages.yml`. It checks that the tag
matches the version, builds the plain binaries for each target, and makes the
GitHub release. The binaries are named with the tag (see
`docs/REPOSITORIES.md`). A tag with a suffix (`vX.Y.Zpre0`, `vX.Y.Z-rc1`)
makes a pre-release. For a Cargo pre-release, the tag must match the full
version in `Cargo.toml`.

The packages are released from
[cheesecloth-linux](https://github.com/jdpanderson/cheesecloth-linux) and
[cheesecloth-macos](https://github.com/jdpanderson/cheesecloth-macos). After
this release is published, move the pin in each of them to it.
