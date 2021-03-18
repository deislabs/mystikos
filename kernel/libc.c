// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <myst/backtrace.h>
#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/kernel.h>
#include <myst/list.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/spinlock.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/tcall.h>

/*
**==============================================================================
**
** <string.h>
**
**==============================================================================
*/

#define USE_BUILTIN_MEMSET
#define USE_BUILTIN_MEMCPY
#define USE_LOOP_UNROLLING

char* strdup(const char* s)
{
    char* p;
    size_t len;

    len = strlen(s);

    if (!(p = malloc(len + 1)))
        return NULL;

    memcpy(p, s, len + 1);

    return p;
}

char* strcpy(char* dest, const char* src)
{
    char* p = dest;

    while (*src)
        *p++ = *src++;

    return dest;
}

char* strncpy(char* dest, const char* src, size_t n)
{
    size_t i;

    for (i = 0; i < n && src[i]; i++)
        dest[i] = src[i];

    for (; i < n; i++)
        dest[i] = '\0';

    return dest;
}

void* memset(void* s, int c, size_t n)
{
#ifdef USE_BUILTIN_MEMSET

    unsigned char* p = (unsigned char*)s;

    while (n >= 1024)
    {
        __builtin_memset(p, c, 1024);
        n -= 1024;
        p += 1024;
    }

    while (n >= 256)
    {
        __builtin_memset(p, c, 256);
        n -= 256;
        p += 256;
    }

    while (n >= 64)
    {
        __builtin_memset(p, c, 64);
        n -= 64;
        p += 64;
    }

    while (n >= 16)
    {
        __builtin_memset(p, c, 16);
        n -= 16;
        p += 16;
    }

    while (n--)
        *p++ = (uint8_t)c;

    return s;

#else /* USE_BUILTIN_MEMSET */

    unsigned char* p = (unsigned char*)s;

    while (n--)
        *p++ = (unsigned char)c;

    return s;

#endif /* !USE_BUILTIN_MEMSET */
}

void* memcpy(void* dest, const void* src, size_t n)
{
#ifdef USE_BUILTIN_MEMCPY

    unsigned char* p = (unsigned char*)dest;
    const unsigned char* q = (const unsigned char*)src;

    while (n >= 1024)
    {
        __builtin_memcpy(p, q, 1024);
        n -= 1024;
        p += 1024;
        q += 1024;
    }

    while (n >= 256)
    {
        __builtin_memcpy(p, q, 256);
        n -= 256;
        p += 256;
        q += 256;
    }

    while (n >= 64)
    {
        __builtin_memcpy(p, q, 64);
        n -= 64;
        p += 64;
        q += 64;
    }

    while (n >= 16)
    {
        __builtin_memcpy(p, q, 16);
        n -= 16;
        p += 16;
        q += 16;
    }

    while (n--)
        *p++ = *q++;

    return dest;

#else /* USE_BUILTIN_MEMCPY */

    unsigned char* p = (unsigned char*)dest;
    unsigned char* q = (unsigned char*)src;

    while (n--)
        *p++ = *q++;

    return dest;

#endif /* !USE_BUILTIN_MEMCPY */
}

int memcmp(const void* s1, const void* s2, size_t n)
{
    unsigned char* p = (unsigned char*)s1;
    unsigned char* q = (unsigned char*)s2;

    while (n--)
    {
        if (*p < *q)
            return -1;
        else if (*p > *q)
            return 1;

        p++;
        q++;
    }

    return 0;
}

void* memmove(void* dest_, const void* src_, size_t n)
{
    char* dest = (char*)dest_;
    const char* src = (const char*)src_;

    if (dest != src && n > 0)
    {
        if (dest <= src)
        {
            memcpy(dest, src, n);
        }
        else
        {
            for (src += n, dest += n; n--; dest--, src--)
                dest[-1] = src[-1];
        }
    }

    return dest;
}

size_t strlen(const char* s)
{
#ifdef USE_LOOP_UNROLLING

    const char* p = s;

    while (p[0] && p[1] && p[2] && p[3] && p[4] && p[5])
        p += 6;

    if (!p[0])
        return (size_t)(p - s);
    if (!p[1])
        return (size_t)(p - s + 1);
    if (!p[2])
        return (size_t)(p - s + 2);
    if (!p[3])
        return (size_t)(p - s + 3);
    if (!p[4])
        return (size_t)(p - s + 4);
    if (!p[5])
        return (size_t)(p - s + 5);

    /* Unreachable */
    return 0;

#else /* USE_LOOP_UNROLLING */

    size_t n = 0;

    while (*s++)
        n++;

    return n;

#endif /* USE_LOOP_UNROLLING */
}

int strcmp(const char* s1, const char* s2)
{
    while ((*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
    }

    return *s1 - *s2;
}

int strncmp(const char* s1, const char* s2, size_t n)
{
    /* Compare first n characters only */
    while (n && (*s1 && *s2) && (*s1 == *s2))
    {
        s1++;
        s2++;
        n--;
    }

    /* If first n characters matched */
    if (n == 0)
        return 0;

    /* Return difference of mismatching characters */
    return *s1 - *s2;
}

size_t strspn(const char* s, const char* accept)
{
    const char* p = s;

    while (*p)
    {
        if (!strchr(accept, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}

size_t strcspn(const char* s, const char* reject)
{
    const char* p = s;

    while (*p)
    {
        if (strchr(reject, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}

char* strtok_r(char* str, const char* delim, char** saveptr)
{
    char* p = str;
    char* end;

    if (str)
        p = str;
    else if (*saveptr)
        p = *saveptr;
    else
        return NULL;

    /* Find start of next token */
    while (*p && strchr(delim, *p))
        p++;

    /* Find the end of the next token */
    for (end = p; *end && !strchr(delim, *end); end++)
        ;

    if (p == end)
        return NULL;

    if (*end)
    {
        *end++ = '\0';
        *saveptr = end;
    }
    else
        *saveptr = NULL;

    return p;
}

char* strchr(const char* s, int c)
{
    while (*s && *s != c)
        s++;

    if (*s == c)
        return (char*)s;

    return NULL;
}

char* strrchr(const char* s, int c)
{
    char* p = (char*)s + strlen(s);

    if (c == '\0')
        return p;

    while (p != s)
    {
        if (*--p == c)
            return p;
    }

    return NULL;
}

/*
**==============================================================================
**
** <stdio.h>
**
**==============================================================================
*/

int vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return (int)myst_tcall_vsnprintf(str, size, format, ap);
}

int snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = vsnprintf(str, size, format, ap);
    va_end(ap);

    return ret;
}

int vprintf(const char* format, va_list ap)
{
    return myst_console_vprintf(STDOUT_FILENO, format, ap);
}

int printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = myst_console_vprintf(STDOUT_FILENO, format, ap);
    va_end(ap);

    return n;
}

int puts(const char* s)
{
    myst_console_printf(STDOUT_FILENO, "%s\n", s);
    return 0;
}

int putchar(int c)
{
    myst_console_printf(STDOUT_FILENO, "%c", c);
    return (int)c;
}

/*
**==============================================================================
**
** <fcntl.h>
**
**==============================================================================
*/

int creat(const char* pathname, mode_t mode)
{
    return (int)myst_syscall_ret(myst_syscall_creat(pathname, mode));
}

int open(const char* pathname, int flags, ...)
{
    va_list ap;

    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);

    return (int)myst_syscall_ret(myst_syscall_open(pathname, flags, mode));
}

off_t lseek(int fd, off_t offset, int whence)
{
    return (off_t)myst_syscall_ret(myst_syscall_lseek(fd, offset, whence));
}

ssize_t read(int fd, void* buf, size_t count)
{
    return (ssize_t)myst_syscall_ret(myst_syscall_read(fd, buf, count));
}

ssize_t write(int fd, const void* buf, size_t count)
{
    return (ssize_t)myst_syscall_ret(myst_syscall_write(fd, buf, count));
}

ssize_t pread(int fd, void* buf, size_t count, off_t offset)
{
    return myst_syscall_ret(myst_syscall_pread(fd, buf, count, offset));
}

ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset)
{
    return myst_syscall_ret(myst_syscall_pwrite(fd, buf, count, offset));
}

ssize_t readv(int fd, const struct iovec* iov, int iovcnt)
{
    return (ssize_t)myst_syscall_ret(myst_syscall_readv(fd, iov, iovcnt));
}

ssize_t writev(int fd, const struct iovec* iov, int iovcnt)
{
    return (ssize_t)myst_syscall_ret(myst_syscall_writev(fd, iov, iovcnt));
}

int stat(const char* pathname, struct stat* statbuf)
{
    return (int)myst_syscall_ret(myst_syscall_stat(pathname, statbuf));
}

int lstat(const char* pathname, struct stat* statbuf)
{
    return (int)myst_syscall_ret(myst_syscall_lstat(pathname, statbuf));
}

int fstat(int fd, struct stat* statbuf)
{
    return (int)myst_syscall_ret(myst_syscall_fstat(fd, statbuf));
}

int mkdir(const char* pathname, mode_t mode)
{
    return (int)myst_syscall_ret(myst_syscall_mkdir(pathname, mode));
}

int rmdir(const char* pathname)
{
    return (int)myst_syscall_ret(myst_syscall_rmdir(pathname));
}

int link(const char* oldpath, const char* newpath)
{
    return (int)myst_syscall_ret(myst_syscall_link(oldpath, newpath));
}

int unlink(const char* pathname)
{
    return (int)myst_syscall_ret(myst_syscall_unlink(pathname));
}

int access(const char* pathname, int mode)
{
    return (int)myst_syscall_ret(myst_syscall_access(pathname, mode));
}

int rename(const char* oldpath, const char* newpath)
{
    return (int)myst_syscall_ret(myst_syscall_rename(oldpath, newpath));
}

int truncate(const char* path, off_t length)
{
    return (int)myst_syscall_ret(myst_syscall_truncate(path, length));
}

int ftruncate(int fd, off_t length)
{
    return (int)myst_syscall_ret(myst_syscall_ftruncate(fd, length));
}

ssize_t readlink(const char* pathname, char* buf, size_t bufsiz)
{
    return (int)myst_syscall_ret(myst_syscall_readlink(pathname, buf, bufsiz));
}

int symlink(const char* target, const char* linkpath)
{
    return (int)myst_syscall_ret(myst_syscall_symlink(target, linkpath));
}

/*
**==============================================================================
**
** <unistd.h>
**
**==============================================================================
*/

int close(int fd)
{
    return (int)myst_syscall_ret(myst_syscall_close(fd));
}

/*
**==============================================================================
**
** <dirent.h>
**
**==============================================================================
*/
#define DIRENT_BUF_SIZE 14

struct __dirstream
{
    int fd;
    uint8_t* ptr;
    uint8_t* end;
    off_t tell;
    uint8_t buf[4096];
};

DIR* opendir(const char* name)
{
    DIR* ret = NULL;
    DIR* dir = NULL;
    int fd = -1;

    if (!name)
    {
        errno = EINVAL;
        goto done;
    }

    if ((fd = open(name, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)) < 0)
        goto done;

    if (!(dir = calloc(1, sizeof(DIR))))
    {
        errno = ENOMEM;
        goto done;
    }

    dir->fd = fd;
    fd = -1;

    ret = dir;
    dir = NULL;

done:

    if (fd >= 0)
        myst_syscall_close(fd);

    if (dir)
        free(dir);

    return ret;
}

int closedir(DIR* dir)
{
    int ret = -1;

    if (!dir)
    {
        errno = ENOMEM;
        goto done;
    }

    if (close(dir->fd) != 0)
        goto done;

    free(dir);
    ret = 0;

done:
    return ret;
}

struct dirent* readdir(DIR* dir)
{
    struct dirent* ret = NULL;
    struct dirent* ent = NULL;

    if (!dir)
    {
        errno = ENOMEM;
        goto done;
    }

    /* If the dirent buffer is exhausted, read more entries */
    if (dir->ptr >= dir->end)
    {
        long n = myst_syscall_getdents64(
            dir->fd, (struct dirent*)dir->buf, sizeof(dir->buf));

        if (n < 0)
        {
            errno = (int)-n;
            goto done;
        }

        if (n == 0)
        {
            /* end of file */
            goto done;
        }

        assert((size_t)n <= sizeof(dir->buf));
        dir->ptr = dir->buf;
        dir->end = dir->buf + n;
    }

    ent = (struct dirent*)(dir->ptr);

    /* Check for 8-byte alignement */
    assert(((uint64_t)ent % 8) == 0);

    dir->ptr += ent->d_reclen;
    dir->tell = ent->d_off;

    ret = ent;

done:
    return ret;
}
