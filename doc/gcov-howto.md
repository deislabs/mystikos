How to use gcov in openlibos
============================

Instrumenting
=============

To enable **gcov** define the **LIBOS_ENABLE_GCOV** environment variable and
rebuild openlibos. For example:

```
$ export LIBOS_ENABLE_GCOV=1
$ make clean
$ make
```

This instruments **liboskernel.so** with **gcov** by compiling sources with
the following options:

```
-fprofile-arcs
-ftest-coverage
```

Additionally it links with:

```
libgcov_musl.a
```

The **libgcov_musl.a** library was extended to support libc by adding one
public function:

```
void gcov_init_libc(libc_t* libc, FILE* stream);
```

Any module that links **libgcov_musl.a** must invoke this function with a
function table that provides various C functions and **stderr**. The following
file (added to **libgcov_musl.a**) defines hidden standard C wrapper functions.
These call into the libc function table.

```
gcov_libc.c
```

The kernel calls **gcov_init_libc()** this during initialization. Other modules
will have to invoke it as well, possibly by using a global constructor. For
example:

```
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <libos/gcov.h>

__attribute__((constructor))
void initialize_gcov(void)
{
    static libc_t _libc =
    {
        fopen, fdopen, fread, fwrite, fseek, ftell, fclose, setbuf, open, close,
        fcntl, getenv, __errno_location, getpid, strtol, access, mkdir, abort,
        vfprintf, atoi, malloc, free, memset, memcpy, strcpy, strlen,
    };

    gcov_init_libc(&_libc, stderr);
}
```

Running
=======

Running with **gcov** instrumentation creates **.gcda** files under the RAM
file system (**ramfs**). These are exported with the **--export-ramfs**
option. For example:

```
$ libos exec --export-ramfs rootfs /bin/hello
```

This creates a directory called **ramfs** under the current directory.
