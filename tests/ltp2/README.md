LTP tests
=========

broken tests
------------

/ltp/testcases/kernel/syscalls/lseek/lseek02:
    - mknod (pipe) not implemented

/ltp/testcases/kernel/syscalls/lseek/lseek11:
    - added support for fsync syscall
    - lseek(..., SEEK_DATA) not supported
