# Mystikos Contributor's Guide

This document describes the requirements and best-practices for contributing to
this repository.

If you just want to start using Mystikos, see the [jumpstart
guide](doc/dev-jumpstart.md) first.

## Contributor License Agreement

This repository is governed under a [Contributor License
Agreement](https://cla.opensource.microsoft.com/deislabs/mystikos). All PR
submitters must accept the CLA before their contributions can be merged.

## Coding Standards

**TODO**

- Wrap all lines at 80 chars, where practical.
- Squash and rebase on `main` 

## Pull Request Management

All code that is contributed to Mystikos must go through a GitHub-based PR
process. To contribute a PR, you should:
- fork this project into your own GitHub account;
- create a new branch in your own repo, with a descriptive short-name;
- make changes on that branch and upload to GitHub;
- use GitHub to open a pull request with your changes.

If your PR is not ready to merge (for example, because it is a work-in-progress
that you'd like early feedback on), please prefix your PR with "[WIP]".

The primary "upstream" branch name is `main`. Branches are to be used for
releases, and for back-porting fixes to previous releases (if needed).

When you are preparing to open a PR, please ensure that your branch name is
descriptive and your commit message is clearly written, wrapped at 80
characters, describes all meaningful changes within the PR.

You should *squash* your local commits into meaningful groups (probably just a
single commit per PR, but there could be exceptions), and you must rebase onto
the current `main` branch. Additional rebases may be needed during the review
process. This allows the history to be cleaner once your PR is merged.

All PRs must be tested. A PR from a non-core developer will not trigger our
automatic tests. Instead, please run regression tests locally:

```
cd tests; make tests; cd ..
cd solutions; make tests; cd ..
```

After a core developer determines the validity of a PR, the core developer can
trigger our CI pipeline with the comment `/AzurePipelines run`.

Every PR must be reviewed by at least one core developer of the Project before
it can be merged. Once a PR has been marked "Approved" (and as long as no core
devs have "Rejected" it), then the PR must be tested by our CI pipeline, and
finally it may be merged (assuming it passed the automated tests).

While everyone is welcome (and encouraged) to review and discuss code, only
reviews from Core Devs count towards the above requirement.

## Code of Conduct

This project has adopted the [Microsoft Code of
Conduct](https://opensource.microsoft.com/codeofconduct/). All participants are
expected to abide by these basic tenets to ensure that the community is a
welcoming place for everyone.
