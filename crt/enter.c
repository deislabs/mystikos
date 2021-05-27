// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
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
#include <myst/syscall.h>
#include <myst/syscallext.h>
#include <myst/tee.h>

void _dlstart_c(size_t* sp, size_t* dynv);

typedef long (*syscall_callback_t)(long n, long params[6]);

static syscall_callback_t _syscall_callback;

void myst_trace_ptr(const char* msg, const void* ptr);

void myst_trace(const char* msg);

__attribute__((__returns_twice__)) pid_t myst_fork(void);

void myst_dump_argv(int argc, const char* argv[]);

static void _create_itimer_thread(void);

long myst_syscall(long n, long params[6])
{
    static pthread_once_t _once = PTHREAD_ONCE_INIT;

    /* create the itimer thread on demand (only if needed) */
    if (n == SYS_setitimer)
        pthread_once(&_once, _create_itimer_thread);

    if (n == SYS_fork)
    {
        /* fork is implemented in the CRT rather than the kernel.
         * Some aspects of the implementation are easier in the CRT, some easier
         * in the kernel. Overall it was decided it was best to be implemented
         * here, although there is an open debate on this. The jumping to a
         * different kernel stack will definitely make in the kernel problematic
         * with regards to copying and fixing up the stack.
         */
        pid_t ret = myst_fork();
        return ret;
    }

    return (*_syscall_callback)(n, params);
}

#ifdef MYST_ENABLE_GCOV

long myst_gcov(const char* func, long gcov_params[6])
{
    long params[6] = {(long)func, (long)gcov_params};
    return myst_syscall(SYS_myst_gcov, params);
}

#endif

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
    _dlstart_c((size_t*)stack, (size_t*)dynv);
}

static void* _itimer_thread(void* arg)
{
    (void)arg;

    /* Enter the kernel on the itimer thread */
    long params[6] = {0};
    myst_syscall(SYS_myst_run_itimer, params);

    return NULL;
}

// Create the itimer thread in user-space and then enter the kernel with the
// SYS_myst_run_itimer syscall. We create a user-space thread since
// kernel-space threads are not supported. Two complications include aligning
// with pthread struct and having a place to land on thread exit.
static void _create_itimer_thread(void)
{
    pthread_attr_t attr;
    pthread_t thread;
    const char* func = __FUNCTION__;

    if (pthread_attr_init(&attr) != 0)
    {
        fprintf(stderr, "%s(): pthread_attr_init() failed\n", func);
        abort();
    }

    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0)
    {
        fprintf(stderr, "%s(): pthread_attr_setdetachstate() failed\n", func);
        abort();
    }

    if (pthread_create(&thread, &attr, _itimer_thread, NULL) != 0)
    {
        fprintf(stderr, "%s(): pthread_create() failed\n", func);
        abort();
    }
}
