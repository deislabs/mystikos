// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "syscall.h"
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/setjmp.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/syscall/device.h>
#include <openenclave/internal/syscall/dirent.h>
#include <openenclave/internal/syscall/fcntl.h>
#include <openenclave/internal/syscall/hook.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/sys/ioctl.h>
#include <openenclave/internal/syscall/sys/mount.h>
#include <openenclave/internal/syscall/sys/poll.h>
#include <openenclave/internal/syscall/sys/select.h>
#include <openenclave/internal/syscall/sys/socket.h>
#include <openenclave/internal/syscall/sys/stat.h>
#include <openenclave/internal/syscall/sys/syscall.h>
#include <openenclave/internal/syscall/sys/uio.h>
#include <openenclave/internal/syscall/sys/utsname.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/trace.h>
#include <sys/resource.h>
#include <sys/types.h>

#include "fuzzsupport_args.h"
#include "fuzzsupport_t.h"

#define PAGE_SIZE 4096

long oe_host_prlimit64(
    long pid,
    long resource,
    void* new_limit,
    void* old_limit)
{
    long ret = -1;
    oe_result_t ocall_retval = OE_UNEXPECTED;
    uint64_t syscall_retval = (uint64_t)-1;
    struct prlimit64_args* args =
        (struct prlimit64_args*)oe_host_malloc(sizeof(struct prlimit64_args));
    memset(args, 0, sizeof(struct prlimit64_args));

    args->pid = pid;
    args->resource = resource;

    if (new_limit)
    {
        args->new_limit =
            (struct oe_rlimit*)oe_host_malloc(sizeof(struct oe_rlimit));
        memcpy(args->new_limit, new_limit, sizeof(struct oe_rlimit));
    }

    if (old_limit)
    {
        args->old_limit =
            (struct oe_rlimit*)oe_host_malloc(sizeof(struct oe_rlimit));
        memcpy(args->old_limit, old_limit, sizeof(struct oe_rlimit));
    }

    if (oe_syscall_ocall(
            &ocall_retval, OE_OCALL_PRRLIMIT64, &syscall_retval, args) != OE_OK)
        goto done;

    if (ocall_retval != OE_OK)
        goto done;

    if (new_limit)
        memcpy(new_limit, args->new_limit, sizeof(struct oe_rlimit));

    if (old_limit)
        memcpy(old_limit, args->old_limit, sizeof(struct oe_rlimit));

    ret = (long)syscall_retval;

done:
    if (args->new_limit)
        oe_host_free(args->new_limit);

    if (args->old_limit)
        oe_host_free(args->old_limit);

    oe_host_free(args);
    return ret;
}

long oe_host_getrlimit(int resource, void* rlim)
{
    long ret = 0;
    oe_result_t ocall_retval = OE_UNEXPECTED;
    uint64_t syscall_retval = 0;
    struct getrlimit_args* args =
        (struct getrlimit_args*)oe_host_malloc(sizeof(struct getrlimit_args));
    memset(args, 0, sizeof(struct getrlimit_args));

    args->resource = resource;
    if (rlim)
    {
        args->rlim =
            (struct oe_rlimit*)oe_host_malloc(sizeof(struct oe_rlimit));
        memcpy(args->rlim, rlim, sizeof(struct oe_rlimit));
    }

    if (oe_syscall_ocall(
            &ocall_retval, OE_OCALL_GETLIMIT, &syscall_retval, args) != OE_OK)
        goto done;

    if (ocall_retval != OE_OK)
        goto done;

    if (rlim)
        memcpy(rlim, args->rlim, sizeof(struct oe_rlimit));

    ret = (long)syscall_retval;
done:
    if (args->rlim)
        oe_host_free(args->rlim);

    oe_host_free(args);
    return ret;
}

OE_DEFINE_SYSCALL3(SYS_readlink)
{
    char* link = (char*)arg1;
    char* buf = (char*)arg2;
    size_t bufsize = (size_t)arg3;

    if (strcmp(link, "/proc/self/exe") != 0)
    {
        oe_errno = OE_ENOSYS;
        return -1;
    }

    oe_errno = 0;
    char* path = (char*)oe_host_malloc(bufsize + 1);
    oe_get_enclave_module_path_ocall(oe_get_enclave(), path);
    strcpy(buf, path, bufsize);
    oe_host_free(path);
    return 0;
}

__attribute__((no_sanitize("enclaveaddress"))) OE_FUZZ_DEFINE_SYSCALL6(SYS_mmap)
{
    OE_UNUSED(arg1);
    OE_UNUSED(arg3);
    OE_UNUSED(arg4);
    OE_UNUSED(arg5);
    OE_UNUSED(arg6);
    void* ret = oe_memalign(PAGE_SIZE, (size_t)arg2);
    if (!ret)
        oe_abort();
    return ret;
}

__attribute__((no_sanitize("enclaveaddress")))
OE_FUZZ_DEFINE_SYSCALL2(SYS_munmap)
{
    OE_UNUSED(arg2);
    oe_free((void*)arg1);
    return 0;
}

OE_DEFINE_SYSCALL5(SYS_mremap)
{
    oe_errno = OE_ENOSYS;
    return -1;
}

OE_DEFINE_SYSCALL4(SYS_prlimit64)
{
    oe_errno = 0;
    long pid = (long)arg1;
    long resource = (long)arg2;
    oe_rlimit* new_limit = (oe_rlimit*)arg3;
    oe_rlimit* old_limit = (oe_rlimit*)arg4;

    return oe_host_prlimit64(pid, resource, new_limit, old_limit);
}

OE_DEFINE_SYSCALL2(SYS_getrlimit)
{
    oe_errno = 0;
    long resource = (long)arg1;
    oe_rlimit* rlim = (oe_rlimit*)arg2;

    return oe_host_getrlimit(resource, rlim);
}

OE_DEFINE_SYSCALL4(SYS_wait4)
{
    oe_errno = OE_ENOSYS;
    return -1;
}

OE_DEFINE_SYSCALL4(SYS_rt_sigprocmask)
{
    oe_errno = OE_ENOSYS;
    return -1;
}

OE_DEFINE_SYSCALL3(SYS_madvise)
{
    oe_errno = OE_ENOSYS;
    return -1;
}

OE_DEFINE_SYSCALL2(SYS_sigaltstack)
{
    oe_errno = OE_ENOSYS;
    return -1;
}

OE_DEFINE_SYSCALL2(SYS_lstat)
{
    oe_errno = OE_ENOSYS;
    return -1;
}

static long _syscall_dispatch(
    long number,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6)
{
    switch (number)
    {
        OE_SYSCALL_DISPATCH(SYS_readlink, arg1, arg2, arg3);
        OE_FUZZ_SYSCALL_DISPATCH(SYS_mmap, arg1, arg2, arg3, arg4, arg5, arg6);
        OE_FUZZ_SYSCALL_DISPATCH(SYS_munmap, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_mremap, arg1, arg2, arg3, arg4, arg5);
        OE_SYSCALL_DISPATCH(SYS_prlimit64, arg1, arg2, arg3, arg4);
        OE_SYSCALL_DISPATCH(SYS_getrlimit, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_rt_sigprocmask, arg1, arg2, arg3, arg4);
        OE_SYSCALL_DISPATCH(SYS_wait4, arg1, arg2, arg3, arg4);
        OE_SYSCALL_DISPATCH(SYS_madvise, arg1, arg2, arg3);
        OE_SYSCALL_DISPATCH(SYS_sigaltstack, arg1, arg2);
        OE_SYSCALL_DISPATCH(SYS_lstat, arg1, arg2);
    }

    oe_errno = OE_ENOSYS;
    OE_TRACE_WARNING("syscall num=%ld not handled", number);
    return -1;
}

static oe_result_t _syscall_hook(
    long number,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6,
    long* ret)
{
    oe_result_t result = OE_UNEXPECTED;
    if (ret)
        *ret = -1;

    *ret = _syscall_dispatch(number, arg1, arg2, arg3, arg4, arg5, arg6);
    if (*ret != -1)
        result = OE_OK;
done:
    return result;
}

__attribute__((visibility("default"))) void InitializeSyscallHooks()
{
    oe_register_syscall_hook(_syscall_hook);
}
