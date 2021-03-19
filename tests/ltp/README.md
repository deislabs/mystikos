# LTP tests

This suite contains LTP tests that do not use filesystem syscalls. The other tests are located [here](../ltp_fs)

## running tests

To run the LTP tests against the ext2fs, do this:

```bash
make alltests FS=ext2fs
```

To run the LTP tests against the hostfs, do this:

```bash
make alltests FS=hostfs
```

To run the LTP tests against the ramfs, do this:

```bash
make alltests FS=ramfs
```

The tests have been segregated into files based on their state (running/failing/how are they failing). The following key applies -

ALL TESTS

1. [all_ltp.txt](all_ltp.txt): All the tests in ltp that we have (pass + fail)
2. [all_without_fstests](all_without_fstests.txt): All the tests (pass + fail) that do not include the ones in the [ltp_fs](../ltp_fs) suite.

PASSING

1. [<fs-type>\_tests_passed.txt](ext2fs_tests_passed.txt): All tests that pass

FAILING

1. [<fs-type>\_tests_unhandled_syscalls.txt](ext2fs_tests_unhandled_syscalls.txt): Tests that fail due to an unimplemented syscall in mystikos.
2. [<fs-type>\_tests_other_errors.txt](ext2fs_tests_other_errors.txt): Tests that fail due to errors like invalid return value, etc.

## broken tests

/ltp/testcases/kernel/syscalls/lseek/lseek02: - mknod (pipe) not implemented

/ltp/testcases/kernel/syscalls/lseek/lseek11: - added support for fsync syscall - lseek(..., SEEK_DATA) not supported

/ltp/testcases/kernel/syscalls/fcntl/fcntl10: - fcntl(..., F_SETLKW, ...) not supported
