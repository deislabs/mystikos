LTP tests
=========

running tests
-------------

To run the LTP tests against the ext2fs, do this:

```
$ make tests FS=ext2fs
```

To run the LTP tests against the hostfs, do this:

```
$ make tests FS=hostfs
```

broken tests
------------

/ltp/testcases/kernel/syscalls/lseek/lseek02:
    - mknod (pipe) not implemented

/ltp/testcases/kernel/syscalls/lseek/lseek11:
    - added support for fsync syscall
    - lseek(..., SEEK_DATA) not supported

/ltp/testcases/kernel/syscalls/fcntl/fcntl10:
    - fcntl(..., F_SETLKW, ...) not supported
