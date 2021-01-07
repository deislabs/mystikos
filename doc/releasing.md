# Mystikos Release Management

This document describes the process of releasing the Mystikos binaries and the tagging of the source.

## Problem area

When a release or pre-release of Mystikos is done we need to make sure that a release can be patched and re-released with an incremental versioning update.

Customers tend to do a test of a specific release of a product and if they find a bug they don't want to have to move to the next major or minor  version that pulls in lots of new features. Rather they prefer to have an incrementally patched version based on what they are are already using with only important fixes that are required. Forcing a customer to move to the next release, or even going against daily builds just to pull in a fix is not acceptable as they would need to do a full test pass of the complete codebase.

The issues would need to be big or security related to do this kind of release as maintaining many releases is expensive.

## Versioning

Products often have multiple major releases over many years. The releases often enable many new features. Major releases _may_ have breaking changes. These breaking changes do need to be kept to a minimum if at all possible because big breaking changes ofter require changes in command line tools, major configuration changes, and even major paradigm changes. Having many of these can deter customers from moving to newer versions making the support of older versions more difficult.

Minor release numbers are for incremental releases with no breaking changes although they may bring in some new features. Customers may be more willing to move forwards with these releases due to the no-breaking-change policy, however some customers may not want to move forwards just to pick up a major fix that solves a specific problem.

Point releases allow security fixes and serious bug fixes to be released from existing major and minor releases. Bug fixes would generally be issues that are reported from customers where the severity may be enough to block them. Security fixes also fall into this category and may require releases to be made on disclosure dates.

The first pre-release should start with 0.1.0, where the minor release is updated for each customer drop we deliver.

## Source tracking

In order to apply fixes to a specific version, let's say a customer has 0.3.5, we would need to be able to get to the version of source for that release, add bug fixes, build and test it, then re-release as a point release. That re-release will again need to be used to apply further fixes going forwards and should automatically be added to the master branch. The complex part is the number of minor releases that have been released and are still supported, as those supported releases will need to be patched also.

Source tagging in the master branch in GitHub can be used to achieve this but doing point releases is harder to achieve.

Creating release branches are a common solution to this whereby each release that is made gets a new branch. This makes it easier to cherry pick fixes from master into a specific version and create a new release branch based on that updated version.

The naming convention for these branches should be: **release_\<major\>.\<minor\>.\<point\>**

When a branch is ready to release, the final commit should be tagged with the same name as the branch name:

Tags should be named: **release-\<major\>-\<minor\>-\<point\>**

## Binary releasing

Sources are only part of what is needed, but once the code is open sourced we need to have a way for customers to just download a specific version of the binaries.

GitHub allows releases to be created which are made against specific code tags. Once a versioned branch is complete and tagged, a release is then made, using the release tag created against the head of the release branch, and that tag can then be used within the GitHub release page where a binary tarball can be dropped and tarballs of the source are made available based on that source tag automatically by GitHub.

Compressed binary tarballs should be named: **mystikos-\<major\>-\<minor\>-\<point\>-\<OS\>.tar.gz*

If DEB or RPM packages are released: **mystikos-\<major\>-\<minor\>-\<point\>-\<deb|rpm\>.gz**

Examples:
    mystikos-0.1.0-x86_64.tar.gz
    mystikos-0.1.0-x86_64.rpm.gz
