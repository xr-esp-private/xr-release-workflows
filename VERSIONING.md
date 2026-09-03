# Versioning and compatibility

## Version model

The reusable workflow contract follows Semantic Versioning:

- major: manifest, required input/secret, artifact, or publication behavior is
  incompatible;
- minor: backward-compatible validation or release capability;
- patch: backward-compatible defect or documentation fix.

The original HTTPS-only implementation was the `v1.0.0` candidate. Controlled
HTTP opt-in, validation-only, and Deploy Key support were backward-compatible
additions. Cryptographic APT bootstrap adds two required publication inputs and
therefore makes `v2.0.0` the recommended current candidate. This repository
does not create that tag or a GitHub Release until the candidate commit and
native two-architecture CI have been reviewed.

Existing source-token and Deploy Key choices remain compatible, and
`apt_allow_plain_http` remains optional with a default of `false`. Publication
callers must add the immutable `apt_signing_key_url` and complete
`apt_signing_key_fingerprint`; validation-only callers do not receive either
input and remain compatible.

## Immutable execution reference

Release callers must use the full commit SHA corresponding to an accepted
version. Floating branches and movable major tags are not production execution
references. A nearby comment may record the matching SemVer release.

Third-party GitHub Actions in this repository are also pinned to full commit
SHAs. Updates are reviewed as ordinary commits and must pass the credential-free
contract suite before callers adopt the new workflow SHA.

## Upgrade

1. Review the central diff, compatibility notes, permissions, and secret list.
2. Require the native amd64 and arm64 fixture checks and static contract check.
3. Update a single non-production caller to the new full SHA.
4. Exercise exact tag/commit and product dual-architecture validation through
   the validation-only workflow on GitHub-hosted runners, without APT secrets.
5. Run a controlled end-to-end product release only after transport and package
   acceptance are ready.
6. Update remaining callers through separate reviewed changes.

## Rollback

Restore the caller's previous full workflow SHA. Do not move or rewrite the
central version tag. If publication failed after draft creation, keep the draft
and retry the same byte-identical assets after correcting the cause. Never
replace an existing package/version with different bytes; publish a new package
version instead.

The caller owns product rollback instructions. This repository only guarantees
that old APT versions are not deliberately deleted by the release workflow.
