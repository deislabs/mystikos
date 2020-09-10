#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <libos/syscallext.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

void _dlstart_c(size_t* sp, size_t* dynv);

typedef long (*syscall_callback_t)(long n, long params[6]);

static syscall_callback_t _syscall_callback;

void libos_trace_ptr(const char* msg, const void* ptr);

void libos_trace(const char* msg);

void libos_dump_argv(int argc, const char* argv[]);

long libos_syscall(long n, long params[6])
{
    return (*_syscall_callback)(n, params);
}

void libos_load_symbols(void)
{
    long params[6];
    libos_syscall(SYS_libos_load_symbols, params);
}

void libos_dump_argv(int argc, const char* argv[])
{
    long params[6];
    params[0] = (long)argc;
    params[1] = (long)argv;

    libos_syscall(SYS_libos_dump_argv, params);
}

void libos_trace(const char* msg)
{
    long params[6] = {0};
    params[0] = (long)msg;
    (*_syscall_callback)(SYS_libos_trace, params);
}

void libos_dump_stack(const void* stack)
{
    long params[6] = {0};
    params[0] = (long)stack;
    (*_syscall_callback)(SYS_libos_dump_stack, params);
}

void libos_trace_ptr(const char* msg, const void* ptr)
{
    long params[6] = {0};
    params[0] = (long)msg;
    params[1] = (long)ptr;
    (*_syscall_callback)(SYS_libos_trace_ptr, params);
}

long libos_add_symbol_file(const char* path, const void* text, size_t text_size)
{
    long params[6] = {0};
    params[0] = (long)path;
    params[1] = (long)text;
    params[2] = (long)text_size;
    return (*_syscall_callback)(SYS_libos_add_symbol_file, params);
}

/* Replacement for __clone() defined in clone.s */
int __clone(int (*fn)(void*), void* child_stack, int flags, void* arg, ...)
{
    va_list ap;
    va_start(ap, arg);
    pid_t* ptid = va_arg(ap, pid_t*);
    void* newtls = va_arg(ap, void*);
    pid_t* ctid = va_arg(ap, pid_t*);
    va_end(ap);

    libos_clone_syscall_args_t args = {
        .fn = fn,
        .child_stack = child_stack,
        .flags = flags,
        .arg = arg,
        .ptid = ptid,
        .newtls = newtls,
        .ctid = ctid,
    };

    long params[6] = {(long)&args};
    return libos_syscall(SYS_libos_clone, params);
}

void oelcrt_enter(void* stack, void* dynv, syscall_callback_t callback)
{
    _syscall_callback = callback;

#if 0
    /* Dump the arguments */
    {
        long argc = *(long*)stack;
        const char** argv = (const char**)(((long*)stack + 1));

        libos_trace_ptr("argc", (void*)argc);

        for (int i = 0; i < argc; i++)
            libos_trace(argv[i]);

        libos_dump_stack(stack);
    }
#endif

    _dlstart_c((size_t*)stack, (size_t*)dynv);
}

/*
**==============================================================================
**
** glibc compatibility functions:
**
** ATTN: add sanity checks to the functions below
**
**==============================================================================
*/

int __snprintf_chk(
    char* str,
    size_t size,
    int flags,
    size_t slen,
    const char* format,
    ...)
{
    va_list ap;

    va_start(ap, format);
    int r = vsnprintf(str, size, format, ap);
    va_end(ap);

    return r;
}

int __vfprintf_chk(FILE* fp, int flag, const char* format, va_list ap)
{
    return vfprintf(fp, format, ap);
}

char* __strcpy_chk(char* dest, const char* src, size_t destlen)
{
    return strcpy(dest, src);
}

int __printf_chk(int flag, const char* format, ...)
{
    va_list ap;

    va_start(ap, format);
    int r = vprintf(format, ap);
    va_end(ap);

    return r;
}

void* __memcpy_chk(void* dest, const void* src, size_t len, size_t destlen)
{
    return memcpy(dest, src, len);
}

void __syslog_chk(int priority, int flag, const char* format, ...)
{
    va_list ap;

    va_start(ap, format);
    vsyslog(priority, format, ap);
    va_end(ap);
}

int __fprintf_chk(FILE* stream, int flag, const char* format, ...)
{
    va_list ap;

    va_start(ap, format);
    int r = vfprintf(stream, format, ap);
    va_end(ap);

    return r;
}

int __sprintf_chk(char* str, int flag, size_t strlen, const char* format, ...)
{
    va_list ap;

    va_start(ap, format);
    int r = vsprintf(str, format, ap);
    va_end(ap);

    return r;
}

char* __realpath_chk(const char* path, char* resolved_path, size_t resolved_len)
{
    return realpath(path, resolved_path);
}

int __asprintf_chk(char** strp, const char* fmt, ...)
{
    int r;

    va_list ap;
    va_start(ap, fmt);
    r = vasprintf(strp, fmt, ap);
    va_end(ap);

    return r;
}

int __open_2(const char* file, int oflag)
{
    return open(file, oflag);
}

typedef struct _FTS FTS;
typedef struct _FTSENT FTSENT;

FTS* fts_open(
    char* const* path_argv,
    int options,
    int (*compar)(const FTSENT**, const FTSENT**))
{
    assert("unhandled" == NULL);
    abort();
    return NULL;
}

FTSENT* fts_read(FTS* ftsp)
{
    assert("unhandled" == NULL);
    abort();
    return NULL;
}

FTSENT* fts_children(FTS* ftsp, int options)
{
    assert("unhandled" == NULL);
    abort();
    return NULL;
}

int fts_set(FTS* ftsp, FTSENT* f, int options)
{
    assert("unhandled" == NULL);
    abort();
    return 0;
}

int fts_close(FTS* ftsp)
{
    fprintf(stderr, "%s() unhandled\n", __FUNCTION__);
    abort();
    return 0;
}

void error(int status, int errnum, const char* format, ...)
{
    va_list ap;

    fflush(stdout);
    va_start(ap, format);
    vfprintf(stderr, format, ap);

    if (errnum)
        fprintf(stderr, ": %s\n", strerror(errnum));

    va_end(ap);

    if (status)
        exit(status);
}

void* __memset_chk(void* dest, int c, size_t len, size_t destlen)
{
    return memset(dest, c, len);
}

int __vsnprintf_chk(
    char* s,
    size_t size,
    int flag,
    size_t slen,
    const char* format,
    va_list ap)
{
    return vsnprintf(s, size, format, ap);
}

long int __fdelt_chk(long int d)
{
    if (d < 0 || d >= FD_SETSIZE)
    {
        assert("__fdelt_chk() panic" == NULL);
        abort();
    }

    return d / NFDBITS;
}

size_t __fread_chk(
    void* ptr,
    size_t size,
    size_t nmemb,
    FILE* stream,
    size_t buf_size)
{
    return fread(ptr, size, nmemb, stream);
}
