# XR Release Workflows

Public, credential-free reusable workflows for releasing XR Linux Debian
packages from private product repositories. This repository owns the common
release state machine and validation contract. It does not own any product's
Debian contents, build dependencies, system services, device policy, or
hardware acceptance.

The v1 candidate supports exactly two binary architectures: `amd64` on
`ubuntu-24.04` and `arm64` on `ubuntu-24.04-arm`. Each product chooses its own
digest-pinned build container and repository-local build/test entrypoint.

## Security boundary

This repository stores no credentials. A public release repository calls the
reusable workflow at a full commit SHA and passes exactly three named secrets:

- `XR_PRIVATE_SOURCE_TOKEN`: Contents-read access to one private source repo;
- `XR_APT_REPO_USER`: upload identity supplied by the caller;
- `XR_APT_REPO_PASS`: upload credential supplied by the caller.

The APT URL, distribution, and component are non-sensitive caller inputs,
normally sourced from selected Organization Variables. Secret inheritance is
not part of the contract.

Build jobs receive a read-only `GITHUB_TOKEN`. Only the final publish job asks
the caller for `contents: write`. The private source token is used only by
`actions/checkout` with `persist-credentials: false`; it is not placed in a Git
remote URL or exported to product build scripts. APT credentials exist only in
the strict publication step.

## Private source manifest

Each product tag must contain a manifest such as
`packaging/release-manifest.json`:

```json
{
  "schema": "xr-linux-deb-release-manifest/1",
  "packages": ["example-runtime", "example-audio-defaults"],
  "build_script": "packaging/release-build.sh",
  "release_notes_path": "CHANGELOG.md",
  "architectures": {
    "amd64": {
      "runner": "ubuntu-24.04",
      "container": "registry.example/debian:12@sha256:<64-lowercase-hex>"
    },
    "arm64": {
      "runner": "ubuntu-24.04-arm",
      "container": "registry.example/debian:12@sha256:<64-lowercase-hex>"
    }
  }
}
```

The checked-in [JSON schema](schema/release-manifest.schema.json) documents the
format. Runtime products can select a Debian 12/Bookworm image; ROS products
can select a suitable Ubuntu/ROS image. The central workflow does not substitute
one product baseline for another.

The product build entrypoint runs inside the declared container with:

- `XR_RELEASE_ARCH`: `amd64` or `arm64`;
- `XR_RELEASE_VERSION`: exact source tag without the leading `v`;
- `XR_RELEASE_OUTPUT_DIR`: absolute path to the fixed `release-out` directory.

It must install or verify its own dependencies, build, run product tests, and
put exactly one DEB per declared package in that output directory. v1 does not
support `Architecture: all`; each declared package must be present once for
each binary architecture.

## Public caller example

Production callers reference an immutable 40-character workflow commit. The
comment records the human version; it does not control execution.

```yaml
name: Release private source

on:
  workflow_dispatch:
    inputs:
      source_tag:
        required: true
        type: string
      source_commit:
        required: true
        type: string

permissions:
  contents: read

jobs:
  release:
    permissions:
      contents: write
    # xr-release-workflows v1.0.0 candidate
    uses: xr-esp-private/xr-release-workflows/.github/workflows/linux-deb-release.yml@0123456789abcdef0123456789abcdef01234567
    with:
      source_repository: xr-esp-private/example-private-source
      source_tag: ${{ inputs.source_tag }}
      source_commit: ${{ inputs.source_commit }}
      source_manifest_path: packaging/release-manifest.json
      apt_repository_url: ${{ vars.XR_APT_REPO_URL }}
      apt_distribution: ${{ vars.XR_APT_DISTRIBUTION }}
      apt_component: ${{ vars.XR_APT_COMPONENT }}
      prerelease: false
    secrets:
      XR_PRIVATE_SOURCE_TOKEN: ${{ secrets.XR_PRIVATE_SOURCE_TOKEN }}
      XR_APT_REPO_USER: ${{ secrets.XR_APT_REPO_USER }}
      XR_APT_REPO_PASS: ${{ secrets.XR_APT_REPO_PASS }}
```

The private source dispatcher separately holds a repository-scoped
`XR_RELEASE_DISPATCH_TOKEN` with Actions-write permission only on its paired
public release repository. That token is never passed into this reusable
workflow.

## Release state machine

The workflow rejects caller inputs before private checkout, resolves the exact
tag and commit to the same Git object, validates the manifest, builds both
architectures, and verifies package count, Package, Version, Architecture, and
SHA-256.

Publication is deliberately recoverable:

1. create or reuse a draft GitHub Release;
2. refuse an existing asset with different bytes;
3. upload only missing byte-identified assets;
4. preflight the APT index and refuse same package/version with another hash;
5. upload through HTTPS and poll both architecture indexes;
6. require exact APT SHA-256 matches and a clearsigned `InRelease`;
7. publish the GitHub Release only after APT verification.

Missing inputs or secrets fail before publication. There is no non-blocking APT
mode. The adapter refuses plaintext HTTP and authenticated redirects. A failed
APT operation leaves the GitHub Release as a draft and preserves existing APT
versions.

## Local checks

The validation code uses Python's standard library and Debian's `dpkg-deb`.
On a Debian/Ubuntu host:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/audit_repository.py
python3 scripts/build_fixture_deb.py --architecture amd64 --output /tmp/xr-fixture
python3 scripts/validate_debs.py \
  --directory /tmp/xr-fixture \
  --packages-json '["xr-release-fixture"]' \
  --version 1.2.3 \
  --architecture amd64 \
  --checksums-out /tmp/xr-fixture/SHA256SUMS.amd64
```

Credential-free CI repeats fixture generation on native amd64 and arm64
runners, tests required failure cases, merges the artifacts, and verifies the
complete checksum set. It never invokes the publication workflow or any real
APT endpoint.

See [VERSIONING.md](VERSIONING.md) for caller upgrades and rollback and
[SECURITY.md](SECURITY.md) for credential handling and incident response.
