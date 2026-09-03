# XR Release Workflows

Public, credential-free reusable workflows for releasing XR Linux Debian
packages from private product repositories. This repository owns the common
release state machine and validation contract. It does not own any product's
Debian contents, build dependencies, system services, device policy, or
hardware acceptance.

The current candidate supports exactly two binary architectures: `amd64` on
`ubuntu-24.04` and `arm64` on `ubuntu-24.04-arm`. Each product chooses its own
digest-pinned build container and repository-local build/test entrypoint.

## Security boundary

This repository stores no credentials. A public release repository calls the
publication workflow at a full commit SHA and provides exactly one of these two
private-source credentials:

- `XR_PRIVATE_SOURCE_SSH_KEY`: read-only Deploy Key for one private source repo
  (recommended for the first XR Audio Runtime caller); or
- `XR_PRIVATE_SOURCE_TOKEN`: Contents-read token for one private source repo
  (backward-compatible option).

Publication additionally requires:

- `XR_APT_REPO_USER`: upload identity supplied by the caller;
- `XR_APT_REPO_PASS`: upload credential supplied by the caller.

The APT URL, distribution, and component are non-sensitive caller inputs,
normally sourced from selected Organization Variables. Secret inheritance is
not part of the contract.

The independent validation workflow accepts the same exclusive choice between
the Deploy Key and token. Supplying neither or both fails before every private
checkout. It binds the exact source tag and commit, builds and validates
`amd64` and `arm64`, and validates the merged artifact set. It has read-only
repository permissions, accepts no APT inputs or secrets, performs no upload,
and cannot create or publish a GitHub Release.

Build jobs receive a read-only `GITHUB_TOKEN`. Only the final publish job asks
the caller for `contents: write`. The selected private source credential is
passed directly to the pinned `actions/checkout` input with
`persist-credentials: false`; it is not placed in a Git remote URL, shell
command, artifact, log, or product build environment. Deploy Key checkout also
sets `ssh-strict: true`. APT credentials exist only in the strict publication
step.

The pinned checkout action still parses its default caller `github.token` when
`ssh-key` is provided, but its source selects an SSH fetch URL whenever the SSH
key is non-empty. The public caller token therefore is not selected to fetch the
private repository. The action manages the key in a mode-0600 runner temporary
file and removes both SSH and token authentication configuration because
credential persistence is disabled.

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

Before private source checkout, the shared workflow bootstraps
`ca-certificates`, `git`, `openssh-client`, and `python3` inside the product
container. Product containers must therefore be Debian/Ubuntu-compatible and
provide `apt-get`; product-specific build dependencies remain owned by the
repository build entrypoint.

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
    # Replace both occurrences with the same reviewed immutable workflow commit.
    uses: xr-esp-private/xr-release-workflows/.github/workflows/linux-deb-release.yml@0123456789abcdef0123456789abcdef01234567
    with:
      workflow_implementation_commit: 0123456789abcdef0123456789abcdef01234567
      source_repository: xr-esp-private/example-private-source
      source_tag: ${{ inputs.source_tag }}
      source_commit: ${{ inputs.source_commit }}
      source_manifest_path: packaging/release-manifest.json
      apt_repository_url: ${{ vars.XR_APT_REPO_URL }}
      # Required only for the explicitly accepted legacy HTTP endpoint.
      apt_allow_plain_http: true
      apt_distribution: ${{ vars.XR_APT_DISTRIBUTION }}
      apt_component: ${{ vars.XR_APT_COMPONENT }}
      apt_signing_key_url: ${{ vars.XR_APT_SIGNING_KEY_URL }}
      apt_signing_key_fingerprint: ${{ vars.XR_APT_SIGNING_KEY_FINGERPRINT }}
      prerelease: false
    secrets:
      XR_PRIVATE_SOURCE_SSH_KEY: ${{ secrets.XR_PRIVATE_SOURCE_SSH_KEY }}
      XR_APT_REPO_USER: ${{ secrets.XR_APT_REPO_USER }}
      XR_APT_REPO_PASS: ${{ secrets.XR_APT_REPO_PASS }}
```

The private source dispatcher separately holds a repository-scoped
`XR_RELEASE_DISPATCH_TOKEN` with Actions-write permission only on its paired
public release repository. That token is never passed into this reusable
workflow.

For an HTTPS APT repository, omit `apt_allow_plain_http` or leave it `false`.
The default is deliberately fail closed. Setting it to `true` permits only an
otherwise valid `http://` base URL; it does not permit credentials in the URL,
redirects, endpoint-specific paths, query strings, fragments, or other URL
schemes.

## Validation-only caller example

Use the separate workflow before publication credentials or APT connectivity
are ready. This is a build-and-contract check, not a release mode:

```yaml
name: Validate private source release

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
  validate:
    # Replace both occurrences with the same reviewed immutable workflow commit.
    uses: xr-esp-private/xr-release-workflows/.github/workflows/linux-deb-validate.yml@0123456789abcdef0123456789abcdef01234567
    with:
      workflow_implementation_commit: 0123456789abcdef0123456789abcdef01234567
      source_repository: xr-esp-private/example-private-source
      source_tag: ${{ inputs.source_tag }}
      source_commit: ${{ inputs.source_commit }}
      source_manifest_path: packaging/release-manifest.json
    secrets:
      XR_PRIVATE_SOURCE_SSH_KEY: ${{ secrets.XR_PRIVATE_SOURCE_SSH_KEY }}
```

Use `XR_PRIVATE_SOURCE_TOKEN` in place of `XR_PRIVATE_SOURCE_SSH_KEY` only for
an existing token-based caller. Never map both. A Deploy Key is repository
specific and can be read-only, but it does not expire automatically. Record its
owner and rotation date, keep the private half only in the paired public caller
Secret, and revoke/replace it when access changes or exposure is suspected.

## Release state machine

The workflow rejects caller inputs before private checkout, resolves the exact
tag and commit to the same Git object, validates the manifest, builds both
architectures, and verifies package count, Package, Version, Architecture, and
SHA-256.

Publication is deliberately recoverable:

1. create or reuse a draft GitHub Release;
2. refuse an existing asset with different bytes;
3. upload only missing byte-identified assets;
4. verify `InRelease` cryptographically with the fingerprint-pinned key;
5. require the raw amd64 and arm64 `Packages` bytes to match the verified
   Release SHA-256 and size entries;
6. preflight the authenticated APT indexes and refuse same package/version with
   another hash;
7. upload through HTTPS, or explicitly opted-in HTTP, and poll both
   architecture indexes;
8. repeat signature, signed-index, and exact DEB SHA-256 verification;
9. publish the GitHub Release only after APT verification.

Missing inputs or secrets fail before publication. There is no non-blocking APT
mode. Plaintext HTTP is rejected before private checkout unless the typed
`apt_allow_plain_http` input is explicitly true. All APT redirects are rejected,
so Basic credentials cannot be forwarded to a redirect target. A failed APT
operation leaves the GitHub Release as a draft and preserves existing APT
versions.

## Plaintext HTTP risk acceptance and client bootstrap

The simple DEB repository selected for the first product currently uses HTTP.
The opt-in records that operational choice; it does not make the transport
confidential. HTTP Basic upload credentials and package request metadata can be
observed or modified in transit. Use a low-privilege upload account restricted
to the exact repository and path, keep rapid revocation and rotation available,
and migrate to HTTPS or a controlled private network when possible.

APT package authenticity over HTTP depends on cryptographic verification of
`InRelease`; HTTP provides no confidentiality. The publication workflow
requires two non-secret caller inputs:

- `apt_signing_key_url`: exactly
  `https://raw.githubusercontent.com/OWNER/REPOSITORY/<40-char-commit>/PATH`;
- `apt_signing_key_fingerprint`: the complete canonical uppercase primary-key
  fingerprint (40 or 64 hexadecimal characters).

The key URL must pin an immutable Git commit. Branches, tags, redirects,
userinfo, query strings, fragments, other hosts, and non-HTTPS transports are
rejected. Before private source checkout, the workflow downloads the public key
without redirects and confirms its sole primary-key fingerprint. Before any APT
upload, it repeats that bootstrap, uses an isolated temporary keyring and real
`gpgv` verification to extract the authenticated Release payload, and verifies
the exact SHA-256 and length of both raw `Packages` files against that signed
payload before parsing package records.

Do not download both a setup script and its first-trust key from the HTTP APT
origin. Check the public key into the public release repository, bind
`XR_APT_SIGNING_KEY_URL` to its GitHub raw URL at an immutable commit, and set
`XR_APT_SIGNING_KEY_FINGERPRINT` from an independently reviewed full
fingerprint. A `signed-by` client source entry is useful only after this same
independent key verification. Key rotation requires a reviewed new key commit
and fingerprint update; neither value is a Secret.

## Local checks

Local framework validation is deliberately limited to dependency-free Python,
static audit, and actionlint checks:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/audit_repository.py
actionlint -color
```

Do not start Docker on a developer Mac to perform product dual-architecture
builds. The digest-pinned build containers belong on GitHub-hosted runners.
Credential-free CI builds framework fixtures on native amd64 and arm64 runners,
tests required failure cases, merges the artifacts, and verifies the complete
checksum set. Real product amd64/arm64 builds and merged package validation must
run through `linux-deb-validate.yml` on GitHub Actions before publication. These
validation paths never invoke the publication workflow or a real APT endpoint.

See [VERSIONING.md](VERSIONING.md) for caller upgrades and rollback and
[SECURITY.md](SECURITY.md) for credential handling and incident response.
