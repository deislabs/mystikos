The Mystikos build cache
========================

To enable the Mystikos build cache, define the following environment variable
before building.

```
export MYST_USE_BUILD_CACHE=1
```

When enabled, the build scripts cache various build artifacts under the
following directory.

```
~/.mystikos/cache
```

Subsequent builds of the current tree or freshly cloned trees use this cache
to avoid downloading and rebuilding these artifacts again and again.

When caching the build output from submodules, the build scripts use commit
hashes to determine whether cache is out of date.

To remove the cache, simply remove the ~/.mystikos/cache directory.
