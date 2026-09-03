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
  Contents-read access to only its paired private source repository.
- Shared APT credentials may be Organization Secrets selected only for public
  release repositories that publish packages.
- Non-sensitive APT routing data should be selected Organization Variables.
- The reusable workflow repository has none of these credentials.

Fine-grained, expiring personal access tokens are the short-term mechanism.
A GitHub App installation token is preferred once app ownership and rotation
are operationally supported.

## Transport and publication

The APT adapter requires HTTPS and refuses redirects on authenticated uploads.
Enabling this workflow does not make an existing plaintext upload endpoint
safe. TLS or a controlled private network and an upload-credential rotation are
release prerequisites.

The release remains a GitHub draft until both APT architecture indexes contain
the exact DEB SHA-256 values. Same package/version with different bytes is an
incident, not an overwrite operation.

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
