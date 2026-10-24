# Releasing

Use semver versions `X.Y.Z`, with tags `vX.Y.Z`. For a beta, use a Cargo
pre-release version such as `0.5.0-beta.0`, with the tag `v0.5.0-beta.0`.

## Steps

1. Set the version in `Cargo.toml`, under `[workspace.package]`. Run
   `cargo check` to update `Cargo.lock`.
2. In `CHANGELOG.md`, add a heading with the version and date below
   `## [Unreleased]`.
3. Run the [checks](DEVELOPMENT.md#checks), the
   [Windows check](DEVELOPMENT.md#windows) and `cargo deny check`. The
   end-to-end lab (`tests/e2e/run.sh`) is optional.
4. Commit as `vX.Y.Z`, and push `main`.
5. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.

## What the tag does

The tag starts `.github/workflows/packages.yml`. It checks that the tag
matches the version, builds a plain binary for each target, and makes the
GitHub release. The binaries are named as in
[contracts](DEVELOPMENT.md#contracts). A tag with a suffix, such as
`v0.5.0-beta.0`, makes a pre-release.

## Packages

After the release is published, release the packages from
[cheesecloth-linux](https://github.com/jdpanderson/cheesecloth-linux),
[cheesecloth-macos](https://github.com/jdpanderson/cheesecloth-macos) and
[cheesecloth-windows](https://github.com/jdpanderson/cheesecloth-windows), as
each one's README describes.
