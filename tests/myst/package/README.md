package test
============

Test the "myst package" command with various options. For example, cover the
following cases.

```
myst package <appdir> ...
myst package --roothash=<filename> ...
myst package --pubkey=<pemfile> ...
```

Also perform negative testing where packaging or running the package is
expected to fail.
