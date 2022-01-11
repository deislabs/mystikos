// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_H
#define _OE_SYSCALL_H

#include <bits/syscall.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/syscall/hook.h>
#include <openenclave/internal/syscall/sys/syscall.h>
#include <openenclave/internal/syscall/unistd.h>
#include <openenclave/internal/trace.h>

// For OE_SYS_ defines.
// They are just used for asserting that they are equal to the corresponding
// SYS_ ones.
#if __x86_64__ || _M_X64
#include <openenclave/internal/syscall/sys/bits/syscall_x86_64.h>
#elif defined(__aarch64__)
#include <openenclave/internal/syscall/sys/bits/syscall_aarch64.h>
#else
#error Unsupported architecture
#endif

OE_EXTERNC_BEGIN

#define OE_FUZZ_SYSCALL_NAME(index) oe_fuzz_##index##_impl

#define OE_FUZZ_SYSCALL_DISPATCH(index, ...) \
    case OE_##index:                         \
        return OE_FUZZ_SYSCALL_NAME(_##index)(__VA_ARGS__)

#define OE_FUZZ_DECLARE_SYSCALL0(index)    \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS0)
#define OE_FUZZ_DECLARE_SYSCALL1(index)    \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS1)
#define OE_FUZZ_DECLARE_SYSCALL2(index)    \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS2)
#define OE_FUZZ_DECLARE_SYSCALL3(index)    \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS3)
#define OE_FUZZ_DECLARE_SYSCALL4(index)    \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS4)
#define OE_FUZZ_DECLARE_SYSCALL5(index)    \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS5)
#define OE_FUZZ_DECLARE_SYSCALL6(index)    \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS6)
#define OE_FUZZ_DECLARE_SYSCALL7(index)    \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS7)

#define OE_FUZZ_DECLARE_SYSCALL1_M(index)  \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS1, ...)
#define OE_FUZZ_DECLARE_SYSCALL2_M(index)  \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS2, ...)
#define OE_FUZZ_DECLARE_SYSCALL3_M(index)  \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS3, ...)
#define OE_FUZZ_DECLARE_SYSCALL4_M(index)  \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS4, ...)
#define OE_FUZZ_DECLARE_SYSCALL5_M(index)  \
    OE_STATIC_ASSERT(index == OE_##index); \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS5, ...)

#define OE_FUZZ_DEFINE_SYSCALL0(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS0)
#define OE_FUZZ_DEFINE_SYSCALL1(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS1)
#define OE_FUZZ_DEFINE_SYSCALL2(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS2)
#define OE_FUZZ_DEFINE_SYSCALL3(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS3)
#define OE_FUZZ_DEFINE_SYSCALL4(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS4)
#define OE_FUZZ_DEFINE_SYSCALL5(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS5)
#define OE_FUZZ_DEFINE_SYSCALL6(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS6)
#define OE_FUZZ_DEFINE_SYSCALL7(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS7)

#define OE_FUZZ_DEFINE_SYSCALL1_M(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS1, ...)
#define OE_FUZZ_DEFINE_SYSCALL2_M(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS2, ...)
#define OE_FUZZ_DEFINE_SYSCALL3_M(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS3, ...)
#define OE_FUZZ_DEFINE_SYSCALL4_M(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS4, ...)
#define OE_FUZZ_DEFINE_SYSCALL5_M(index) \
    long OE_FUZZ_SYSCALL_NAME(_##index)(OE_SYSCALL_ARGS5, ...)

OE_DECLARE_SYSCALL3(SYS_readlink);
OE_FUZZ_DECLARE_SYSCALL6(SYS_mmap);
OE_FUZZ_DECLARE_SYSCALL2(SYS_munmap);
OE_DECLARE_SYSCALL5(SYS_mremap);
OE_DECLARE_SYSCALL4(SYS_prlimit64);
OE_DECLARE_SYSCALL2(SYS_getrlimit);
OE_DECLARE_SYSCALL4(SYS_rt_sigprocmask);
OE_DECLARE_SYSCALL4(SYS_wait4);
OE_DECLARE_SYSCALL3(SYS_madvise);
OE_DECLARE_SYSCALL2(SYS_sigaltstack);
OE_DECLARE_SYSCALL2(SYS_lstat);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_H */
