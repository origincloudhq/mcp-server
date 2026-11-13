# Releasing

Every push to `main` publishes `ghcr.io/origincloudhq/mcp-server:main` and
`:sha-<commit>`. A release is a version of the image that a deployment
pins: `ghcr.io/origincloudhq/mcp-server:X.Y.Z`.

## Making a release

1. **Bump the version** in a pull request, unless `main` is at it already:

   ```sh
   git switch -c release/v0.2.0 origin/main
   sed -i 's/^version = ".*"/version = "0.2.0"/' Cargo.toml   # the [package] version
   cargo update --workspace                                  # its entry in Cargo.lock, nothing else
   git commit -am "Release v0.2.0"
   ```

   Merge it once CI is green.

2. **Tag** the merge on `main`, and push the tag:

   ```sh
   git switch main && git pull
   git tag v0.2.0 && git push origin v0.2.0
   ```

   The Release workflow (`.github/workflows/release.yml`) refuses a tag
   that isn't `Cargo.toml`'s version, runs the tests, publishes the image
   as `0.2.0`, `0.2`, and `latest` unless the tag is a prerelease
   (`v0.2.0-rc.1`), and creates the GitHub release with the image's digest.

A published version is immutable: a fix is a new version.
