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

## Pull Request Management

All code that is contributed to Mystikos must go through a GitHub-based Pull
Request & Review process. To contribute a PR, you should:
- fork this project into your own GitHub account;
- create a new branch in your own repo, with a descriptive short-name;
- make changes on that branch, squashing local changes to a single commit, and upload to GitHub;
- use GitHub's UI to open a pull request back to the deislabs/mystikos repo.


If your PR is not ready to merge, perhaps because it is a work-in-progres for
which you'd like to request feedback, prefix your Pull Request with `[WIP]`.

When you are preparing to open a Pull Request, please ensure that your branch
name is descriptive and your commit message is clearly written, wrapped at 80
characters, describes all meaningful changes within the PR.

You should *squash* your local commits into meaningful groups (probably just a
single commit per PR, but there could be exceptions), and you must rebase onto
the current `main` branch before opening a PR. See below for an example of doing this.
Note that additional rebases may be needed during the review process. This allows the
history to be cleaner once your PR is merged.

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

### Working in a Fork

You can use the GitHub UI to fork into your own project. After that, you might
set up your local environment like this:

```
cd <workdir>
git clone git@github.com:deislabs/mystikos.git
cd mystikos
git remote rename origin upstream
git remote add git@github.com:<YOURUSERNAME>/mystikos.git origin
git checkout <WORKBRANCH>
```

Now, you can work on your local copy and push to your own fork:
```
git commit ...
git push origin <WORKBRANCH>
```

If you need to do a squash-rebase before opening a PR:
```
git checkout <WORKBRANCH>
git remote update
git rebase -i upstream/main
```

You can keep your fork up to date from the main repo like this:
```
git checkout main
git remote update

# watch for any errors with this command, as it could indicate you accidentally
# committed something to your local main branch and de-sync'd
git pull upstream main
git push origin main
```

## Code of Conduct

This project has adopted the [Microsoft Code of
Conduct](https://opensource.microsoft.com/codeofconduct/). All participants are
expected to abide by these basic tenets to ensure that the community is a
welcoming place for everyone.
