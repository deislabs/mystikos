// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <limits.h>
// #include <stdio.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include "myst_fuzzer_tcalls.h"
#include "symbol.h"

#include <setjmp.h>

#define _GNU_SOURCE 1
#include "unwind.h"

extern "C"
{
    long myst_tcall(long n, long params[6]);
    long myst_syscall(long n, long params[6]);
    long myst_syscall_isatty(int fd);

    size_t myst_backtrace(void** buffer, size_t size);

    __attribute__((visibility("default"))) uint64_t __sanitizer_get_host_tpc()
    {
        long params[6] = {0};
        return (uint64_t)myst_tcall(MYST_TCALL_GET_TPC, params);
    }

    __attribute__((visibility("default"))) void
    __asan_send_command_to_symbolizer(uint64_t module_offset, char** symbol)
    {
        long params[6] = {0};
        params[0] = (long)module_offset;
        params[1] = (long)symbol;
        (void)myst_tcall(MYST_TCALL_SYMBOLIZER, params);
    }

    void* __dlsym(void* handle, const char* name, void* sym_addr)
    {
        return kernel_dlsym(handle, name, sym_addr);
    }

    __attribute__((visibility("default"))) void __sanitizer_die()
    {
        long params[6] = {0};
        (void)myst_tcall(MYST_TCALL_DIE, params);
    }

    __attribute__((visibility("default"))) void InitializeSyscallHooks()
    {
    }

    int backtrace(void** buffer, int size)
    {
        long params[6] = {0};
        params[0] = (long)buffer;
        params[1] = (long)size;
        return (int)myst_tcall(MYST_TCALL_BACKTRACE, params);
    }

    char** backtrace_symbols(void* const* buffer, int size)
    {
        long params[6] = {0};
        params[0] = (long)buffer;
        params[1] = (long)size;
        return (char**)myst_tcall(MYST_TCALL_BACKTRACE_SYMBOLS, params);
    }

    int getrlimit(int resource, struct rlimit* rlim)
    {
        long params[6] = {0};
        params[0] = (long)resource;
        params[1] = (long)rlim;
        return (int)myst_tcall(MYST_TCALL_GETRLIMIT, params);
    }

    int dl_iterate_phdr(
        int (*callback)(struct dl_phdr_info* info, size_t size, void* data),
        void* data)
    {
        return _dl_iterate_phdr(callback, data);
    }

    int isatty(int fd)
    {
        return myst_syscall_isatty(fd);
    }

    bool oe_is_within_enclave(const void* ptr, size_t sz)
    {
        return true;
    }

    void oe_allocator_free(void* ptr)
    {
        free(ptr);
    }

    int oe_allocator_posix_memalign(
        void** memptr,
        size_t alignment,
        size_t size)
    {
        return posix_memalign(memptr, alignment, size);
    }

    void* oe_get_thread_data()
    {
        return NULL;
    }

    int pthread_key_create(pthread_key_t* k, void (*dtor)(void*))
    {
        long params[6] = {0};
        params[0] = (long)k;
        params[1] = (long)dtor;
        return (int)myst_tcall(MYST_TCALL_PTHREAD_KEY_CREATE, params);
    }

    int pthread_key_delete(pthread_key_t k)
    {
        long params[6] = {0};
        params[0] = (long)k;
        return (int)myst_tcall(MYST_TCALL_PTHREAD_KEY_DELETE, params);
    }

    int pthread_setspecific(pthread_key_t k, const void* x)
    {
        long params[6] = {0};
        params[0] = (long)k;
        params[1] = (long)x;
        return (int)myst_tcall(MYST_TCALL_PTHREAD_SET_SPECIFIC, params);
    }

    void* pthread_getspecific(pthread_key_t k)
    {
        long params[6] = {0};
        params[0] = (long)k;
        return (void*)myst_tcall(MYST_TCALL_PTHREAD_GET_SPECIFIC, params);
    }

    void* tss_get(pthread_key_t k)
    {
        return pthread_getspecific(k);
    }

    int pthread_mutex_lock(pthread_mutex_t* m)
    {
        long params[6] = {0};
        params[0] = (long)m;
        return (int)myst_tcall(MYST_TCALL_PTHREAD_MUTEX_LOCK, params);
    }

    int pthread_mutex_unlock(pthread_mutex_t* m)
    {
        long params[6] = {0};
        params[0] = (long)m;
        return (int)myst_tcall(MYST_TCALL_PTHREAD_MUTEX_UNLOCK, params);
    }

    int pthread_cond_wait(pthread_cond_t* cond, pthread_mutex_t* mutex)
    {
        long params[6] = {0};
        params[0] = (long)cond;
        params[1] = (long)mutex;
        return (int)myst_tcall(MYST_TCALL_PTHREAD_MUTEX_COND_WAIT, params);
    }

    int pthread_cond_signal(pthread_cond_t* cond)
    {
        long params[6] = {0};
        params[0] = (long)cond;
        return (int)myst_tcall(MYST_TCALL_PTHREAD_MUTEX_COND_SIGNAL, params);
    }

    long syscall(long n, ...)
    {
        va_list ap;
        va_start(ap, n);
        long params[6] = {0, 0, 0, 0, 0, 0};
        params[0] = va_arg(ap, long);
        params[1] = va_arg(ap, long);
        params[2] = va_arg(ap, long);
        params[3] = va_arg(ap, long);
        params[4] = va_arg(ap, long);
        params[5] = va_arg(ap, long);
        va_end(ap);

        switch (n)
        {
            case SYS_readlink:
            {
                const char* pathname = (const char*)params[0];
                char* buf = (char*)params[1];
                size_t bufsiz = (size_t)params[2];

                char kernel_mod[] = "libmystkernel.so";
                if (strcmp(pathname, "/proc/self/exe") == 0)
                {
                    strcpy(buf, kernel_mod);
                    return strlen(kernel_mod) + 1;
                }
            }
            break;
        }
        return myst_syscall(n, params);
    }

    ssize_t pread64(int fd, void* buf, size_t count, off_t offset)
    {
        return 0;
    }
    ssize_t pwrite64(int fd, const void* buf, size_t size, off_t ofs)
    {
        return 0;
    }
}
