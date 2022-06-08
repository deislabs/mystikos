// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define hidden __attribute__((__visibility__("hidden")))

#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
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
#include <myst/kernel.h>
#include <myst/libc.h>
#include <myst/ssr.h>
#include <myst/syscall.h>
#include <myst/syscallext.h>
#include <myst/tee.h>

/* Locking functions used by MUSL to manage libc.threads_minus_1 */
#include <pthread_impl.h>
void __tl_lock(void);
void __tl_unlock(void);

static myst_wanted_secrets_t* _wanted_secrets;

void _dlstart_c(size_t* sp, size_t* dynv);

typedef long (*syscall_callback_t)(long n, long params[6]);

static syscall_callback_t _syscall_callback;

void myst_trace_ptr(const char* msg, const void* ptr);

void myst_trace(const char* msg);

__attribute__((__returns_twice__)) pid_t myst_fork(void);

void myst_dump_argv(int argc, const char* argv[]);

static void _create_itimer_thread(void);

static int myst_retrieve_wanted_secrets(void);

int myst_pre_launch_hook()
{
    int ret = 0;
    myst_retrieve_wanted_secrets();

    /* notify the kernel that main() is about to be called */
    {
        long params[6] = {0};
        return myst_syscall(SYS_myst_pre_launch_hook, params);
    }

    return ret;
}

long myst_syscall(long n, long params[6])
{
    if ((n == SYS_setitimer) || (n == SYS_getitimer))
    {
        /* itimer is requested by SYS_settimer returning EAGAIN. If this happens
         * we need to create the thread and re-invoke it */
        long ret = (*_syscall_callback)(n, params);
        if (ret == -EAGAIN)
        {
            _create_itimer_thread();
            return (*_syscall_callback)(n, params);
        }
        else
            return ret;
    }

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

    if (n == SYS_execve || n == SYS_execveat)
    {
        /* These system calls launch a new process with its own CRT and the
         * current thread then belongs to the new process. Therefore, decrement
         * the thread count of the current CRT that belongs to the parent
         * process.
         */
        __tl_lock();
        __libc.threads_minus_1--;
        __tl_unlock();
    }

    long ret = (*_syscall_callback)(n, params);

    // restore threads_minus_1 if execve fails
    // not checking ret, as execve should not return on success
    if (n == SYS_execve || n == SYS_execveat)
    {
        __tl_lock();
        __libc.threads_minus_1++;
        __tl_unlock();
    }

    return ret;
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

int allow_ld_preload(void)
{
    /* Allow LD_PRELOAD in musl libc */
    return 1;
}

void myst_enter_crt(
    void* stack,
    void* dynv,
    syscall_callback_t callback,
    myst_crt_args_t* args)
{
    _syscall_callback = callback;
    if (args)
    {
        _wanted_secrets = args->wanted_secrets;
    }
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

bool myst_get_exec_stack_option()
{
    long params[6] = {0};
    return myst_syscall(SYS_myst_get_exec_stack_option, params);
}

int myst_retrieve_wanted_secrets()
{
    int ret = -1;
    FILE* file = NULL;
    void* handle = NULL;

    if (_wanted_secrets == NULL || _wanted_secrets->secrets_count == 0)
        return 0;

    for (size_t i = 0; i < _wanted_secrets->secrets_count; i++)
    {
        // ATTN: group secrets from the same Secret Release Service so we can
        // retrieve them in one operation. No need to repeat initialization
        // and tear down of the client library.

        ReleasedSecret release_secret = {0};
        myst_wanted_secret_t* tmp = &_wanted_secrets->secrets[i];
        int r = 0;
        SSR_CLIENT_SET_VERBOSE_FN verbose_fn = NULL;
        SSR_CLIENT_INIT_FN init_fn = NULL;
        SSR_CLIENT_GET_SECRET_FN get_fn = NULL;
        SSR_CLIENT_FREE_SECRET_FN free_fn = NULL;
        SSR_CLIENT_TERMINATE_FN terminate_fn = NULL;

        // The required fields should have been validated in the kernel.

        handle = dlopen(tmp->clientlib, RTLD_NOW);
        if (handle == NULL)
        {
            fprintf(
                stderr,
                "SSR: the provided library %s for secret "
                "release is not found. Did you include it and its "
                "dependent libraries in your appplication folder?\n",
                tmp->clientlib);
            goto done;
        }

        /* Get all the function pointers */
        verbose_fn = (SSR_CLIENT_SET_VERBOSE_FN)dlsym(
            handle, SSR_CLIENT_SET_VERBOSE_FN_NAME);
        init_fn = (SSR_CLIENT_INIT_FN)dlsym(handle, SSR_CLIENT_INIT_FN_NAME);
        get_fn = (SSR_CLIENT_GET_SECRET_FN)dlsym(
            handle, SSR_CLIENT_GET_SECRET_FN_NAME);
        free_fn = (SSR_CLIENT_FREE_SECRET_FN)dlsym(
            handle, SSR_CLIENT_FREE_SECRET_FN_NAME);
        terminate_fn = (SSR_CLIENT_TERMINATE_FN)dlsym(
            handle, SSR_CLIENT_TERMINATE_FN_NAME);

        if (verbose_fn == NULL || init_fn == NULL || get_fn == NULL ||
            free_fn == NULL || terminate_fn == NULL)
        {
            fprintf(
                stderr,
                "SSR: the provided library %s for secret "
                "release does not implement all required APIs.\n",
                tmp->clientlib);
            goto done;
        }

        if ((r = verbose_fn(tmp->verbose)) != 0)
        {
            fprintf(
                stderr,
                "SSR: failed to set verbose level with the "
                "provided library %s for secret release. Error "
                "code %d.\n",
                tmp->clientlib,
                r);
            goto done;
        }

        if ((r = init_fn()) != 0)
        {
            fprintf(
                stderr,
                "SSR: failed to initialize with the "
                "provided library %s for secret release. Error "
                "code %d.\n",
                tmp->clientlib,
                r);
            goto done;
        }

        if (r = get_fn(
                    tmp->srs_addr,
                    tmp->srs_api_ver,
                    tmp->id,
                    &release_secret) != 0)
        {
            fprintf(
                stderr,
                "SSR: failed to retrieve the secret %s with the "
                "provided library %s for secret release. Error "
                "code %d.\n",
                tmp->id,
                tmp->clientlib,
                r);
            goto done;
        }

        terminate_fn();

        /* Save the released secret to the specified file */
        file = fopen(tmp->local_path, "w+");
        if (file == NULL)
        {
            fprintf(
                stderr,
                "SSR: failed to open file %s for write.\n",
                tmp->local_path);
            goto done;
        }

        fchmod(fileno(file), S_IWUSR | S_IRUSR | S_IRGRP);

        r = fwrite(release_secret.data, 1, release_secret.length, file);
        fclose(file);
        file = NULL;
        if (r != release_secret.length)
        {
            fprintf(
                stderr,
                "SSR: failed to write secret to file %s.\n",
                tmp->local_path);
            goto done;
        }

        free_fn(&release_secret);
        dlclose(handle);
        handle = NULL;
    }
    ret = 0;

done:

    if (file)
        fclose(file);

    if (handle)
        dlclose(handle);

    return ret;
}
