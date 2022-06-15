// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <myst/gcov.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

FILE* const myst_gcov_stderr = MYST_GCOV_STDERR;

long myst_gcov(const char* func, long params[6]);

int myst_gcov_fprintf(FILE* stream, const char* format, ...);

void* myst_gcov_malloc(size_t size)
{
    long params[6] = {(long)size};
    return (void*)myst_gcov(__FUNCTION__, params);
}

void myst_gcov_free(void* ptr)
{
    long params[6] = {(long)ptr};
    myst_gcov(__FUNCTION__, params);
}

_Noreturn void myst_gcov_abort(void)
{
    myst_gcov(__FUNCTION__, NULL);

    for (;;)
        ;
}

FILE* myst_gcov_fopen(const char* pathname, const char* mode)
{
    long params[6] = {(long)pathname, (long)mode};
    return (FILE*)myst_gcov(__FUNCTION__, params);
}

FILE* myst_gcov_fdopen(int fd, const char* mode)
{
    long params[6] = {(long)fd, (long)mode};
    return (FILE*)myst_gcov(__FUNCTION__, params);
}

size_t myst_gcov_fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    long params[6] = {(long)ptr, (long)size, (long)nmemb, (long)stream};
    return (size_t)myst_gcov(__FUNCTION__, params);
}

size_t myst_gcov_fwrite(
    const void* ptr,
    size_t size,
    size_t nmemb,
    FILE* stream)
{
    long params[6] = {(long)ptr, (long)size, (long)nmemb, (long)stream};
    return (size_t)myst_gcov(__FUNCTION__, params);
}

int myst_gcov_fseek(FILE* stream, long offset, int whence)
{
    long params[6] = {(long)stream, (long)offset, (long)whence};
    return (int)myst_gcov(__FUNCTION__, params);
}

long myst_gcov_ftell(FILE* stream)
{
    long params[6] = {(long)stream};
    return (size_t)myst_gcov(__FUNCTION__, params);
}

int myst_gcov_fclose(FILE* stream)
{
    long params[6] = {(long)stream};
    return (int)myst_gcov(__FUNCTION__, params);
}

void myst_gcov_setbuf(FILE* stream, char* buf)
{
    long params[6] = {(long)stream, (long)buf};
    myst_gcov(__FUNCTION__, params);
}

int myst_gcov_open(const char* pathname, int flags, ...)
{
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);

    long params[6] = {(long)pathname, (long)flags, (long)mode};
    return (int)myst_gcov(__FUNCTION__, params);
}

int myst_gcov_close(int fd)
{
    long params[6] = {(long)fd};
    return (int)myst_gcov(__FUNCTION__, params);
}

int myst_gcov_fcntl(int fd, int cmd, ... /* arg */)
{
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);

    long params[6] = {(long)fd, (long)cmd, (long)arg};
    return (int)myst_gcov(__FUNCTION__, params);
}

char* myst_gcov_getenv(const char* name)
{
    long params[6] = {(long)name};
    return (char*)myst_gcov(__FUNCTION__, params);
}

int* myst_gcov___errno_location(void)
{
    return (int*)myst_gcov(__FUNCTION__, NULL);
}

pid_t myst_gcov_getpid(void)
{
    return (pid_t)myst_gcov(__FUNCTION__, NULL);
}

long int myst_gcov_strtol(const char* nptr, char** endptr, int base)
{
    long params[6] = {(long)nptr, (long)endptr, (long)base};
    return (long int)myst_gcov(__FUNCTION__, params);
}

int myst_gcov_access(const char* pathname, int mode)
{
    long params[6] = {(long)pathname, (long)mode};
    return (int)myst_gcov(__FUNCTION__, params);
}

int myst_gcov_mkdir(const char* pathname, mode_t mode)
{
    long params[6] = {(long)pathname, (long)mode};
    return (int)myst_gcov(__FUNCTION__, params);
}

int myst_gcov_vfprintf(FILE* stream, const char* format, va_list ap)
{
    int ret = -1;
    char* str = NULL;
    int len;

    /* determine the number of characters that will be formatted */
    {
        va_list ap_copy;
        char buf[1];

        va_copy(ap_copy, ap);
        len = vsnprintf(buf, sizeof(buf), format, ap_copy);
        va_end(ap_copy);

        if (len < 0)
            goto done;
    }

    if (len == 0)
    {
        ret = 0;
        goto done;
    }

    if (!(str = myst_gcov_malloc(len + 1)))
        goto done;

    if ((len = vsnprintf(str, len + 1, format, ap)) < 0)
        goto done;

    if (myst_gcov_fwrite(str, 1, len, stream) != len)
        goto done;

    ret = len;

done:

    if (str)
        myst_gcov_free(str);

    return ret;
}

int myst_gcov_fprintf(FILE* stream, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = myst_gcov_vfprintf(stream, format, ap);
    va_end(ap);
    return n;
}

int myst_gcov___popcountdi2(unsigned long a)
{
    long params[6] = {(long)a};
    return (int)myst_gcov(__FUNCTION__, params);
}

int myst_gcov___vfprintf_chk(
    FILE* stream,
    int flag,
    const char* format,
    va_list ap)
{
    (void)flag;
    return myst_gcov_vfprintf(stream, format, ap);
}

int myst_gcov___fprintf_chk(FILE* stream, int flag, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = myst_gcov_vfprintf(stream, format, ap);
    va_end(ap);
    return n;
}

int myst_gcov___sprintf_chk(
    char* s,
    int flag,
    size_t slen,
    const char* format,
    ...)
{
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(s, INT_MAX, format, ap);
    va_end(ap);
    return n;
}

_Noreturn void myst_gcov_exit(int status)
{
    myst_gcov(__FUNCTION__, NULL);

    for (;;)
        ;
}

char* myst_gcov_strcat(char* dest, const char* src)
{
    char* dest_copy = dest;

    while (*dest)
        dest++;

    while (*src)
    {
        *dest = *src;
        dest++;
        src++;
    }

    *dest = '\0';

    return dest_copy;
}
