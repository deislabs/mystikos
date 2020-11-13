// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libos/defs.h>
#include <libos/gcov.h>

static libc_t _libc;

LIBOS_WEAK
FILE* const stderr;

int gcov_init_libc(libc_t* libc, FILE* stderr_stream)
{
    if (!libc && !stderr_stream)
        return -EINVAL;

    _libc = *libc;
    *(FILE**)&stderr = stderr_stream;

    return 0;
}

LIBOS_WEAK
FILE* fopen(const char* pathname, const char* mode)
{
    return _libc.fopen(pathname, mode);
}

LIBOS_WEAK
FILE* fdopen(int fd, const char* mode)
{
    return _libc.fdopen(fd, mode);
}

LIBOS_WEAK
size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return _libc.fread(ptr, size, nmemb, stream);
}

LIBOS_WEAK
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return _libc.fwrite(ptr, size, nmemb, stream);
}

LIBOS_WEAK
int fseek(FILE* stream, long offset, int whence)
{
    return _libc.fseek(stream, offset, whence);
}

LIBOS_WEAK
long ftell(FILE* stream)
{
    return _libc.ftell(stream);
}

LIBOS_WEAK
int fclose(FILE* stream)
{
    return _libc.fclose(stream);
}

LIBOS_WEAK
void setbuf(FILE* stream, char* buf)
{
    return _libc.setbuf(stream, buf);
}

LIBOS_WEAK
int open(const char* pathname, int flags, ...)
{
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);

    return _libc.open(pathname, flags, mode);
}

LIBOS_WEAK
int close(int fd)
{
    return _libc.close(fd);
}

LIBOS_WEAK
int fcntl(int fd, int cmd, ... /* arg */)
{
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);

    return _libc.fcntl(fd, cmd, arg);
}

LIBOS_WEAK
char* getenv(const char* name)
{
    return _libc.getenv(name);
}

LIBOS_WEAK
int* __errno_location(void)
{
    return _libc.__errno_location();
}

LIBOS_WEAK
pid_t getpid(void)
{
    return _libc.getpid();
}

LIBOS_WEAK
long int strtol(const char* nptr, char** endptr, int base)
{
    return _libc.strtol(nptr, endptr, base);
}

LIBOS_WEAK
int access(const char* pathname, int mode)
{
    return _libc.access(pathname, mode);
}

LIBOS_WEAK
int mkdir(const char* pathname, mode_t mode)
{
    return _libc.mkdir(pathname, mode);
}

LIBOS_WEAK
_Noreturn void abort(void)
{
    _libc.abort();

    for (;;)
        ;
}

LIBOS_WEAK
int vfprintf(FILE* stream, const char* format, va_list ap)
{
    return _libc.vfprintf(stream, format, ap);
}

LIBOS_WEAK
int fprintf(FILE* stream, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int r = vfprintf(stream, format, ap);
    va_end(ap);
    return r;
}

LIBOS_WEAK
int __popcountdi2(unsigned long a)
{
    size_t nbits = 0;

    /* Count the number of bits that are set */
    for (unsigned long i = 0; i < 64; i++)
    {
        if ((a & (1LU << i)))
            nbits++;
    }

    /* Return 1 if the nbits is odd; return 0 if nbits is event */
    return (nbits % 2) ? 1 : 0;
}
