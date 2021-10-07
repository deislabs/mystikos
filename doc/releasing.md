# Mystikos Release Management

This document describes the versioning scheme and release processes for
Mystikos.

## Versioning

The Mystikos project follows [standard SemVer versioning](https://semver.org/),
beginning with `v0.1.0`.

While traditional SemVer does not mandate that pre-1.0 releases do not
introduce breaking changes, we will strive to minimize impact to early adopters
and always document breaking changes in patch and release notes. A point
release should never introduce a breaking change, *even before v1.0*.

The primary development branch of Mystikos is `main`.
The initial announcement of the upcoming release will be a PR to the `main` branch with the commit to bump the [VERSION
file](../VERSION) to _next_ pre-release, e.g. `v0.5.0`

## Source Tracking via Release Branches

The documentation below follows the pattern followed for `v0.5.0`.

All versions will be worked on in a branch named after the release. For example:
- `v0.5.0` is a branch for the `v0.5.0` release.
- `v0.2.0` is a branch for the `v0.2.0` release.
- Starting with  `v0.6.0`, the release branch will be named `v.<major>.<minor>.x`.

The release branch is created from the last commit in `main` before the version is bumped.
As an example, just before VERSION is bumped to v0.5.0 in `main`, the `v0.5.0` branch is created.
Since we want a release candidate before every release, the first commit to the release branch is
to change the VERSION to `v0.5.0-rc1`.

As release candidates are created, the suffix is incremented, e.g. `v0.5.0-rc2`.

When the release is finalized, the branch is once again bumped to the final
version number without the suffix, e.g. `v0.5.0`.

Hotfix releases are made from this branch, following a similar process, but with
the patch version incremented to `v0.5.1`.

All normal development continues to happen on the `main` branch. As PRs are
opened against `main`, the PR will be merged into `main` as we do normally.
If the PR fixes a bug in the release and is deemed necessary for the release by
 the PR issues and reviewers, the fix can be cherry-picked into the release branch
 but only after it has been merged into `main`. All major feature work should be merged
 to `main` before the release branch is created.
 Cherry-picks into the release branch should be reserved for critical fixes and release-specific changes.

# Versioning of the Open Enclave SDK Branch Used by Mystikos

Mystikos uses a branch of Open Enclave SDK since some of the required changes are still
 in the process of being upstreamed to the master branch.
 The branch used by Mystikos used can be found in the [Open Enclave SDK Makefile]
(../third_partyopenenclave/Makefile). When Mystikos is released, 
the version in the Open Enclave SDK branch is updated to track the state of the branch when
 Mystikos was released.
As an example, when Mystikos v.5.0 was released, it used [mystikos.v5 branch](https://github.com/openenclave/openenclave/tree/mystikos.v5). 
The [VERSION](https://github.com/openenclave/openenclave/blob/mystikos.v5/VERSION) 
file in this branch was updated to indicate that this branch was used for the v0.5.0 release of Mystikos.
For the v0.6.0 release of Mystikos, a new Open Enclave SDK will be created (`mystikos.v6`).

## Tagging

Code which corresponds to a binary release shall be tracked with project
*tags*, visible on GitHub and in the Git repo. Tags should be considered an immutable artifact
and never updated, except in exceptional circumstances, and then clearly
communicated.

Tags match VERSION in the release branch at the time the release was created.
As an example, `v0.5.0-rc1` is the tag for the `v0.5.0-rc1` release.

## Publishing a release

After packages have been generated and tested for the release, a release will be drafted [GitHub
Release](https://help.github.com/articles/creating-releases/).

The release notes will be added to the description field (which supports
Markdown), and the packages will be uploaded as binaries.

Until version `v1.0.0`, the checkbox "This is a pre-release" _will_ be checked.

**When the release is drafted, the packages' commit hash must match the
head of the release branch, at which the tag will point.**

## Binary releasing

Pre-built binaries will be uploaded and made available as part of each tagged
release in the form of a .tar.gz file. Binary tarballs should be named:
`mystikos-<major>-<minor>-<point>-<ARCH>.tar.gz`

If, in the future, we release installable packages, they should be named:
`mystikos-<major>.<minor>.<point>-<ARCH>.<deb|rpm>.gz`

## Examples

 - `mystikos-0.1.0-x86_64.tar.gz`
 - `mystikos-0.1.0-x86_64.rpm.gz`
