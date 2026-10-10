# Security policy

## No-secret repository

This public repository must never contain a token, password, private key,
credential file, private product source, internal absolute path, or production
APT endpoint. Examples and fixtures use reserved or invalid names only.

Reusable workflows declare each accepted secret by name. Callers must map
those secrets explicitly. Broad secret inheritance is forbidden. Product build
jobs do not receive APT credentials or a repository-write `GITHUB_TOKEN`.

## Credential scope

- The source-dispatch credential belongs to the private source repository and
  can trigger only its paired public release repository.
- The source-read credential belongs to the public release repository and has
  read access to only its paired private source repository. The preferred first
  XR Audio Runtime mechanism is a read-only, single-repository Deploy Key stored
  as `XR_PRIVATE_SOURCE_SSH_KEY`. The compatible token alternative is
  `XR_PRIVATE_SOURCE_TOKEN`; callers must provide exactly one.
- Shared APT credentials may be Organization Secrets selected only for public
  release repositories that publish packages.
- Non-sensitive APT routing data should be selected Organization Variables.
  A caller may instead explicitly map optional `XR_APT_REPO_URL` from an
  Organization Secret; it must still contain only a public base URL with no
  embedded credentials. That Secret overrides the compatible URL input and
  is resolved directly inside the prepare/publish jobs, not exported through
  job outputs. Organization access policy must include the public caller.
- The reusable workflow repository has none of these credentials.

Fine-grained, expiring personal access tokens remain the compatible alternative
when centralized expiry is required. A GitHub App installation token is
preferred for future multi-repository automation once app ownership and
rotation are operationally supported.

A Deploy Key has no automatic expiration. Give it no write access, document its
owner and planned rotation date without recording the private key, and revoke it
immediately when the paired repository is retired or the key may be exposed.
The private key is passed only to the pinned checkout action. With strict host
checking and `persist-credentials: false`, checkout uses an SSH fetch URL,
stores the key only in its mode-0600 runner temporary file, and removes its
authentication configuration after the checkout step.

## Transport and publication

HTTPS is the default APT transport. Plaintext HTTP is accepted only when the
caller explicitly sets the typed `apt_allow_plain_http` input to `true`; its
default is `false`. The adapter rejects URL userinfo, non-HTTP(S) schemes,
suspicious or endpoint-specific base paths, query strings, fragments, and every
redirect. A redirect therefore cannot receive the Basic Authorization header.

This opt-in records a bounded risk acceptance for the current simple DEB
product; it does not make plaintext transport safe. HTTP Basic credentials can
be sniffed or altered in transit. The upload identity must be low privilege,
restricted to the exact repository/path, and ready for rapid revocation and
rotation. HTTPS or a controlled private network remains the preferred target.

HTTP APT download authenticity depends on actual `gpgv` verification of
`InRelease`; there is no confidentiality. The signing key is downloaded without
redirects only from a GitHub HTTPS raw URL containing a full commit SHA. Its
sole primary-key fingerprint must exactly match the caller's complete uppercase
fingerprint. Both are public configuration, not Secrets.

The verified Release payload must cover the exact raw amd64 and arm64
`Packages` paths. Their downloaded bytes must match both the signed SHA-256 and
signed length before package records are parsed. Missing coverage, bad
signature, wrong key, wrong fingerprint, hash mismatch, length mismatch, or an
unavailable `gpg`/`gpgv` executable fails before upload. A clearsigned text
header alone is never accepted as evidence.

Never bootstrap first trust by fetching both a setup script and the signing key
from the same HTTP origin. Keep the public key in the paired public release
repository, pin its GitHub raw URL to an immutable commit, and independently
review the full fingerprint. Rotation requires a new reviewed key commit and
fingerprint; do not silently replace bytes behind an existing URL.

The release remains a GitHub draft until both APT architecture indexes contain
the exact DEB SHA-256 values. Same package/version with different bytes is an
incident, not an overwrite operation.

The validation-only reusable workflow has no APT inputs or secrets, no
repository write permission, and no release or upload step. It is the supported
way to validate an exact source tag/commit and merged two-architecture package
set before publication access is available. Product build containers run on
GitHub-hosted amd64/arm64 runners; developers must not start local Docker on a
Mac to reproduce those product builds.

Reusable callers must pass the same reviewed full commit in both the job
`uses` reference and `workflow_implementation_commit`. The explicit input is
needed because `github.workflow_sha` belongs to the caller workflow during a
reusable-workflow run and therefore cannot identify this repository's scripts.

## Reporting and response

Report a suspected vulnerability privately to an Organization owner. Do not
open a public issue containing credentials, private repository names beyond the
documented examples, runner logs with sensitive data, or unpublished package
contents.

If a credential may be exposed:

1. revoke it before investigating workflow behavior;
2. inspect public workflow commits and Actions logs without printing values;
3. create a new least-privilege credential;
4. update the caller Secret through GitHub's protected input path;
5. verify exact tag/commit binding and a credential-free dry run;
6. record scope and rotation date, never the value.

Published workflow tags are planned to be immutable. Callers execute a full
commit SHA, so a central regression is rolled back by restoring the previous
reviewed SHA in the caller.
