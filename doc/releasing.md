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

## Tagging and Branching

The primary development branch of Mystikos is `main`.

Pre-release versions may be worked on in a branch with the suffix `-pre`, and
recent releases may be tracked on a branch without this suffix. For example:
- `pre_0.1.2` indicates a branch that is under active use, while preparing to
  release version `v0.1.2`. This branch should be deleted after the release is
  tagged.
- `release_0.1.2` indicates a branch that matches the `release-0.1.2` tagged
  release.

Code which corresponds to a binary release shall be tracked with project
*tags*, visible on GitHub and in the Git repo. Tags must be signed by a member
of the project release team. Tags should be considered an immutable artifact
and never updated, except in exceptional circumstances, and then clearly
communicated.


## Source tracking

The naming convention for these branches should be:
`release_<major>.<minor>.<point>`

When a branch is ready to release, the final commit should be tagged with the
same name as the branch name:

Tags should be named:
`release-<major>.<minor>.<point>`

## Binary releasing

Pre-built binaries will be uploaded and made available as part of each tagged
release in the form of a .tar.gz file. Binary tarballs should be named:
`mystikos-<major>-<minor>-<point>-<ARCH>.tar.gz`

If, in the future, we release installable packages, they should be named:
`mystikos-<major>.<minor>.<point>-<ARCH>.<deb|rpm>.gz`

## Examples
 - `mystikos-0.1.0-x86_64.tar.gz`
 - `mystikos-0.1.0-x86_64.rpm.gz`
