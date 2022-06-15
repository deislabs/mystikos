#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <myst/gcov.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <myst/eraise.h>

#include "myst_t.h"

#ifdef MYST_ENABLE_GCOV

#define DEFAULT_GCOV_PID 101

extern int oe_host_printf(const char* format, ...);

#define oe_host_printf printf

long myst_handle_tcall(long n, long params[6]);

typedef struct file
{
    int fd;
} file_t;

static file_t _stderr = {.fd = STDERR_FILENO};

static file_t* _fileof(FILE* stream)
{
    if (stream == MYST_GCOV_STDERR)
        return &_stderr;
    else
        return (file_t*)stream;
}

static int _open(const char* pathname, int flags, mode_t mode)
{
    const uid_t uid = UINT_MAX;
    const gid_t gid = UINT_MAX;

    long params[6] = {
        (long)pathname, (long)flags, (long)mode, (long)uid, (long)gid};
    return (int)myst_handle_tcall(SYS_open, params);
}

static int _access(const char* pathname, int mode)
{
    long params[6] = {(long)pathname, (long)mode};
    return (int)myst_handle_tcall(SYS_access, params);
}

static int _fcntl(int fd, int cmd, long arg)
{
    long params[6] = {(long)fd, (long)cmd, (long)arg};
    return (int)myst_handle_tcall(SYS_fcntl, params);
}

static ssize_t _read(int fd, void* buf, size_t count)
{
    long params[6] = {(long)fd, (long)buf, (long)count};
    return (ssize_t)myst_handle_tcall(SYS_read, params);
}

static ssize_t _write(int fd, const void* buf, size_t count)
{
    long params[6] = {(long)fd, (long)buf, (long)count};
    return (ssize_t)myst_handle_tcall(SYS_write, params);
}

static long _lseek(int fd, off_t offset, int whence)
{
    long params[6] = {(long)fd, (long)offset, (long)whence};
    return myst_handle_tcall(SYS_lseek, params);
}

static int _close(int fd)
{
    long params[6] = {(long)fd};
    return (int)myst_handle_tcall(SYS_close, params);
}

static int _mkdir(const char* pathname, mode_t mode)
{
    long params[6] = {(long)pathname, (long)mode};
    return (int)myst_handle_tcall(SYS_mkdir, params);
}

static ssize_t _readn(int fd, void* data, size_t size)
{
    ssize_t ret = 0;
    unsigned char* p = (unsigned char*)data;
    size_t r = size;
    size_t bytes_read = 0;

    while (r)
    {
        ssize_t n = _read(fd, p, r);

        if (n > 0)
        {
            p += n;
            r -= (size_t)n;
            bytes_read += (size_t)n;
        }
        else if (n == 0)
        {
            if (bytes_read)
                break;

            ret = -EIO;
            goto done;
        }
        else
        {
            ret = n;
            goto done;
        }
    }

    ret = (ssize_t)bytes_read;

done:
    return ret;
}

ssize_t _writen(int fd, const void* data, size_t size)
{
    ssize_t ret = 0;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;
    size_t bytes_written = 0;

    while (r > 0)
    {
        ssize_t n = _write(fd, p, r);

        if (n == 0)
        {
            if (bytes_written)
                break;

            ret = -EIO;
            goto done;
        }
        else if (n < 0)
        {
            ret = n;
            goto done;
        }

        p += n;
        r -= (size_t)n;
        bytes_written += (size_t)n;
    }

    ret = (ssize_t)bytes_written;

done:

    return ret;
}

static int _fdopen(int fd, const char* mode, FILE** stream)
{
    int ret = -1;
    file_t* file = NULL;

    /* ATTN: ignore mode */

    if (stream)
        *stream = NULL;

    if (fd < 0 || !mode || !stream)
    {
        errno = EINVAL;
        goto done;
    }

    if (!(file = calloc(1, sizeof(file_t))))
    {
        errno = ENOMEM;
        goto done;
    }

    file->fd = fd;
    *stream = (FILE*)file;
    file = NULL;

    ret = 0;

done:

    if (file)
        free(file);

    return ret;
}

static size_t _fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    size_t ret = 0;
    file_t* file = _fileof(stream);
    size_t count;
    ssize_t n;

    if ((!ptr && size) || !file)
    {
        errno = EINVAL;
        goto done;
    }

    if (__builtin_mul_overflow(size, nmemb, &count))
    {
        errno = ERANGE;
        goto done;
    }

    n = _readn(file->fd, ptr, count);

    if (n < 0)
    {
        errno = (int)-n;
        goto done;
    }

    ret = (size_t)n / size;

done:
    return ret;
}

static size_t _fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    size_t ret = 0;
    file_t* file = _fileof(stream);
    size_t count;
    ssize_t n;

    if ((!ptr && size) || !file)
        goto done;

    if (__builtin_mul_overflow(size, nmemb, &count))
        goto done;

    n = _writen(file->fd, ptr, count);

    if (n < 0)
    {
        errno = (int)-n;
        goto done;
    }

    ret = (size_t)n / size;

done:
    return ret;
}

static int _fseek(FILE* stream, long offset, int whence)
{
    int ret = -1;
    file_t* file = _fileof(stream);
    long r;

    if (!file)
        goto done;

    if ((r = _lseek(file->fd, offset, whence)) < 0)
    {
        errno = (int)-r;
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static long _ftell(FILE* stream)
{
    long ret = -1;
    file_t* file = _fileof(stream);
    off_t off;

    if (!file)
    {
        errno = EINVAL;
        goto done;
    }

    if ((off = _lseek(file->fd, 0, SEEK_CUR)) < 0)
    {
        errno = (int)-off;
        goto done;
    }

    ret = (long)off;

done:
    return ret;
}

static int _fclose(FILE* stream)
{
    int ret = -1;
    file_t* file = _fileof(stream);
    int r;

    if (!file)
    {
        errno = EINVAL;
        goto done;
    }

    if ((r = _close(file->fd)) < 0)
    {
        errno = -r;
        goto done;
    }

    free(file);

    ret = 0;

done:
    return ret;
}

static int _popcountdi2(unsigned long a)
{
    unsigned long nbits = 0;

    for (unsigned long i = 0; i < 64; i++)
    {
        if ((a & (1LU << i)))
            nbits++;
    }

    return (int)nbits;
}

static void* _malloc(size_t size)
{
    return oe_host_malloc(size);
}

static void _free(void* ptr)
{
    oe_host_free(ptr);
}

long myst_gcov(const char* func, long params[6])
{
    if (strcmp(func, "myst_gcov_abort") == 0)
    {
        abort();
        /* never returns */
        return 0;
    }
    else if (strcmp(func, "myst_gcov_fopen") == 0)
    {
        /* ATTN: never called */
        assert(0);
        return (long)0;
    }
    else if (strcmp(func, "myst_gcov_fdopen") == 0)
    {
        int fd = (int)params[0];
        const char* mode = (const char*)params[1];
        FILE* stream;

        if (_fdopen(fd, mode, &stream) != 0)
            return (long)NULL;

        return (long)stream;
    }
    else if (strcmp(func, "myst_gcov_fread") == 0)
    {
        void* ptr = (void*)params[0];
        size_t size = (size_t)params[1];
        size_t nmemb = (size_t)params[2];
        FILE* stream = (FILE*)params[3];
        return (long)_fread(ptr, size, nmemb, stream);
    }
    else if (strcmp(func, "myst_gcov_fwrite") == 0)
    {
        const void* ptr = (const void*)params[0];
        size_t size = (size_t)params[1];
        size_t nmemb = (size_t)params[2];
        FILE* stream = (FILE*)params[3];
        return (long)_fwrite(ptr, size, nmemb, stream);
    }
    else if (strcmp(func, "myst_gcov_fseek") == 0)
    {
        FILE* stream = (FILE*)params[0];
        off_t offset = (off_t)params[1];
        int whence = (int)params[2];
        return (long)_fseek(stream, offset, whence);
    }
    else if (strcmp(func, "myst_gcov_ftell") == 0)
    {
        FILE* stream = (FILE*)params[0];
        return (long)_ftell(stream);
    }
    else if (strcmp(func, "myst_gcov_fclose") == 0)
    {
        FILE* stream = (FILE*)params[0];
        return (long)_fclose(stream);
    }
    else if (strcmp(func, "myst_gcov_setbuf") == 0)
    {
        /* ATTN: ignored */
        return 0;
    }
    else if (strcmp(func, "myst_gcov_open") == 0)
    {
        const char* pathname = (const char*)params[0];
        int flags = (int)params[1];
        mode_t mode = (mode_t)params[2];
        int fd;

        if ((fd = _open(pathname, flags, mode)) < 0)
        {
            errno = -fd;
            return -1;
        }

        return (long)fd;
    }
    else if (strcmp(func, "myst_gcov_close") == 0)
    {
        int fd = (int)params[0];
        int r;

        if ((r = _close(fd)) < 0)
        {
            errno = -r;
            return -1;
        }

        return 0;
    }
    else if (strcmp(func, "myst_gcov_fcntl") == 0)
    {
        int fd = (int)params[0];
        int cmd = (int)params[1];
        uint64_t arg = (uint64_t)params[2];
        int r;

        if ((r = _fcntl(fd, cmd, (long)arg)) < 0)
        {
            errno = -r;
            return -1;
        }

        return r;
    }
    else if (strcmp(func, "myst_gcov_getenv") == 0)
    {
        /* called for GCOV_PREFIX or GCOV_PREFIX_STRIP (so ignore) */
        return (long)NULL;
    }
    else if (strcmp(func, "myst_gcov___errno_location") == 0)
    {
        return (long)__errno_location();
    }
    else if (strcmp(func, "myst_gcov_getpid") == 0)
    {
        return DEFAULT_GCOV_PID;
    }
    else if (strcmp(func, "myst_gcov_strtol") == 0)
    {
        assert(0);
        return 0;
    }
    else if (strcmp(func, "myst_gcov_access") == 0)
    {
        const char* pathname = (const char*)params[0];
        int mode = (int)params[1];
        int r;

        if ((r = _access(pathname, mode)) < 0)
        {
            errno = -r;
            return -1;
        }

        return 0;
    }
    else if (strcmp(func, "myst_gcov_mkdir") == 0)
    {
        const char* pathname = (const char*)params[0];
        mode_t mode = (mode_t)params[1];
        int r;

        if ((r = _mkdir(pathname, mode)) < 0)
        {
            errno = -r;
            return -1;
        }

        return 0;
    }
    else if (strcmp(func, "myst_gcov___popcountdi2") == 0)
    {
        unsigned long a = (unsigned long)params[0];
        return (long)_popcountdi2(a);
    }
    else if (strcmp(func, "myst_gcov_malloc") == 0)
    {
        return (long)_malloc((size_t)params[0]);
    }
    else if (strcmp(func, "myst_gcov_free") == 0)
    {
        _free((void*)params[0]);
        return 0;
    }
    else
    {
        fprintf(stderr, "%s(%u): %s(): unhandled gcov function: %s\n",
            __FILE__, __LINE__, __FUNCTION__, func);
        fflush(stderr);
        abort();
    }

    return -1;
}

#endif /* MYST_ENABLE_GCOV */
