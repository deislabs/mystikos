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

static libc_t _libc;

FILE* const stderr;

int gcov_init_libc(libc_t* libc, FILE* stderr_stream)
{
    if (!libc && !stderr_stream)
        return -EINVAL;

    _libc = *libc;
    *(FILE**)&stderr = stderr_stream;

    return 0;
}

FILE* fopen(const char* pathname, const char* mode)
{
    return _libc.fopen(pathname, mode);
}

FILE* fdopen(int fd, const char* mode)
{
    return _libc.fdopen(fd, mode);
}

size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return _libc.fread(ptr, size, nmemb, stream);
}

size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return _libc.fwrite(ptr, size, nmemb, stream);
}

int fseek(FILE* stream, long offset, int whence)
{
    return _libc.fseek(stream, offset, whence);
}

long ftell(FILE* stream)
{
    return _libc.ftell(stream);
}

int fclose(FILE* stream)
{
    return _libc.fclose(stream);
}

void setbuf(FILE* stream, char* buf)
{
    return _libc.setbuf(stream, buf);
}

int open(const char* pathname, int flags, ...)
{
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);

    return _libc.open(pathname, flags, mode);
}

int close(int fd)
{
    return _libc.close(fd);
}

int fcntl(int fd, int cmd, ... /* arg */)
{
    va_list ap;
    va_start(ap, cmd);
    long arg = va_arg(ap, long);
    va_end(ap);

    return _libc.fcntl(fd, cmd, arg);
}

void* malloc(size_t size)
{
    return _libc.malloc(size);
}

void free(void* ptr)
{
    _libc.free(ptr);
}

void* memset(void* s, int c, size_t n)
{
    return _libc.memset(s, c, n);
}

void* memcpy(void* dest, const void* src, size_t n)
{
    return _libc.memcpy(dest, src, n);
}

size_t strlen(const char* s)
{
    return _libc.strlen(s);
}

char* strcpy(char* dest, const char* src)
{
    return _libc.strcpy(dest, src);
}

char* getenv(const char* name)
{
    return _libc.getenv(name);
}

int* __errno_location(void)
{
    return _libc.__errno_location();
}

pid_t getpid(void)
{
    return _libc.getpid();
}

long int strtol(const char* nptr, char** endptr, int base)
{
    return _libc.strtol(nptr, endptr, base);
}

int access(const char* pathname, int mode)
{
    return _libc.access(pathname, mode);
}

int mkdir(const char* pathname, mode_t mode)
{
    return _libc.mkdir(pathname, mode);
}

_Noreturn void abort(void)
{
    _libc.abort();

    for (;;)
        ;
}

int vfprintf(FILE* stream, const char* format, va_list ap)
{
    return _libc.vfprintf(stream, format, ap);
}

int fprintf(FILE* stream, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int r = vfprintf(stream, format, ap);
    va_end(ap);
    return r;
}

int atoi(const char* nptr)
{
    return _libc.atoi(nptr);
}

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
