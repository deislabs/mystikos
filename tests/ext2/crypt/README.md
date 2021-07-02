tests/ext2/crypt
================

The app mounts an encrypted file system. This requires adding a roothash to the
app image (--roothash=filename) and passing the encryption key to the mount()
function.
