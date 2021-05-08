// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MYST_GCOV_STDERR ((FILE*)0x67001b41aafb4224)

FILE* const myst_gcov_stderr = MYST_GCOV_STDERR;

_Noreturn void myst_gcov_abort(void)
{
    abort();

    for (;;)
        ;
}

FILE* myst_gcov_fopen(const char* pathname, const char* mode)
{
    return fopen(pathname, mode);
}

FILE* myst_gcov_fdopen(int fd, const char* mode)
{
    return fdopen(fd, mode);
}

size_t myst_gcov_fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    if (stream == MYST_GCOV_STDERR)
        stream = stderr;

    return fread(ptr, size, nmemb, stream);
}

size_t myst_gcov_fwrite(
    const void* ptr,
    size_t size,
    size_t nmemb,
    FILE* stream)
{
    if (stream == MYST_GCOV_STDERR)
        stream = stderr;

    return fwrite(ptr, size, nmemb, stream);
}

int myst_gcov_fseek(FILE* stream, long offset, int whence)
{
    if (stream == MYST_GCOV_STDERR)
        stream = stderr;

    return fseek(stream, offset, whence);
}

long myst_gcov_ftell(FILE* stream)
{
    if (stream == MYST_GCOV_STDERR)
        stream = stderr;

    return ftell(stream);
}

int myst_gcov_fclose(FILE* stream)
{
    if (stream == MYST_GCOV_STDERR)
        stream = stderr;

    return fclose(stream);
}

void myst_gcov_setbuf(FILE* stream, char* buf)
{
    if (stream == MYST_GCOV_STDERR)
        stream = stderr;

    return setbuf(stream, buf);
}

int myst_gcov_open(const char* pathname, int flags, ...)
{
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);

    return open(pathname, flags, mode);
}

int myst_gcov_close(int fd)
{
    return close(fd);
}

int myst_gcov_fcntl(int fd, int cmd, ... /* arg */)
{
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);

    return fcntl(fd, cmd, arg);
}

char* myst_gcov_getenv(const char* name)
{
    /* called to get GCOV_PREFIX and GCOV_PREFIX_STRIP */
    return getenv(name);
}

int* myst_gcov___errno_location(void)
{
    return __errno_location();
}

pid_t myst_gcov_getpid(void)
{
    return getpid();
}

long int myst_gcov_strtol(const char* nptr, char** endptr, int base)
{
    return strtol(nptr, endptr, base);
}

int myst_gcov_access(const char* pathname, int mode)
{
    return access(pathname, mode);
}

int myst_gcov_mkdir(const char* pathname, mode_t mode)
{
    return mkdir(pathname, mode);
}

int myst_gcov_vfprintf(FILE* stream, const char* format, va_list ap)
{
    if (stream == MYST_GCOV_STDERR)
        stream = stderr;

    return vfprintf(stream, format, ap);
}

int myst_gcov_fprintf(FILE* stream, const char* format, ...)
{
    if (stream == MYST_GCOV_STDERR)
        stream = stderr;

    va_list ap;
    va_start(ap, format);
    int r = vfprintf(stream, format, ap);
    va_end(ap);
    return r;
}

int myst_gcov___popcountdi2(unsigned long a)
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

int myst_gcov___vfprintf_chk(
    FILE* stream,
    int flag,
    const char* format,
    va_list ap)
{
    (void)flag;

    if (stream == MYST_GCOV_STDERR)
        stream = myst_gcov_stderr;

    return vfprintf(stream, format, ap);
}

int myst_gcov___fprintf_chk(FILE* stream, int flag, const char* format, ...)
{
    va_list ap;
    (void)flag;

    if (stream == MYST_GCOV_STDERR)
        stream = stderr;

    va_start(ap, format);
    int n = vfprintf(stream, format, ap);
    va_end(ap);

    return n;
}
