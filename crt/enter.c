// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <myst/gcov.h>
#include <myst/libc.h>
#include <myst/syscallext.h>

void _dlstart_c(size_t* sp, size_t* dynv);

typedef long (*syscall_callback_t)(long n, long params[6]);

static syscall_callback_t _syscall_callback;

void myst_trace_ptr(const char* msg, const void* ptr);

void myst_trace(const char* msg);

void myst_dump_argv(int argc, const char* argv[]);

long myst_syscall(long n, long params[6])
{
    return (*_syscall_callback)(n, params);
}

void myst_load_symbols(void)
{
    long params[6];
    myst_syscall(SYS_myst_load_symbols, params);
}

void myst_dump_argv(int argc, const char* argv[])
{
    long params[6];
    params[0] = (long)argc;
    params[1] = (long)argv;

    myst_syscall(SYS_myst_dump_argv, params);
}

void myst_trace(const char* msg)
{
    long params[6] = {0};
    params[0] = (long)msg;
    (*_syscall_callback)(SYS_myst_trace, params);
}

void myst_dump_stack(const void* stack)
{
    long params[6] = {0};
    params[0] = (long)stack;
    (*_syscall_callback)(SYS_myst_dump_stack, params);
}

void myst_trace_ptr(const char* msg, const void* ptr)
{
    long params[6] = {0};
    params[0] = (long)msg;
    params[1] = (long)ptr;
    (*_syscall_callback)(SYS_myst_trace_ptr, params);
}

long myst_add_symbol_file(const char* path, const void* text, size_t text_size)
{
    long params[6] = {0};
    params[0] = (long)path;
    params[1] = (long)text;
    params[2] = (long)text_size;
    return (*_syscall_callback)(SYS_myst_add_symbol_file, params);
}

/* Replacement for __clone() defined in clone.s */
int __clone(int (*fn)(void*), void* child_stack, int flags, void* arg, ...)
{
    va_list ap;
    long args[7];

    va_start(ap, arg);
    pid_t* ptid = va_arg(ap, pid_t*);
    void* newtls = va_arg(ap, void*);
    pid_t* ctid = va_arg(ap, pid_t*);
    va_end(ap);

    args[0] = (long)fn;
    args[1] = (long)child_stack;
    args[2] = (long)flags;
    args[3] = (long)arg;
    args[4] = (long)ptid;
    args[5] = (long)newtls;
    args[6] = (long)ctid;

    long params[6] = {(long)args};
    return myst_syscall(SYS_myst_clone, params);
}

void myst_enter_crt(void* stack, void* dynv, syscall_callback_t callback)
{
    _syscall_callback = callback;

#ifdef MYST_ENABLE_GCOV
    /* Pass the libc interface back to the kernel */
    {
        static libc_t _libc = {
            fopen,
            fdopen,
            fread,
            fwrite,
            fseek,
            ftell,
            fclose,
            setbuf,
            open,
            close,
            fcntl,
            getenv,
            __errno_location,
            getpid,
            strtol,
            access,
            mkdir,
            abort,
            vfprintf,
        };

        long params[6] = {(long)&_libc, (long)stderr};
        myst_syscall(SYS_myst_gcov_init, params);

        gcov_init_libc(&_libc, stderr);
    }
#endif

    _dlstart_c((size_t*)stack, (size_t*)dynv);
}
