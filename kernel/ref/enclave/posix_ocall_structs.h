// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _POSIX_OCALLS_OCALL_STRUCTS_H
#define _POSIX_OCALLS_OCALL_STRUCTS_H

#include <openenclave/bits/types.h>
#include <openenclave/bits/result.h>
#include <openenclave/internal/defs.h>

#ifndef POSIX_STRUCT
#define POSIX_STRUCT(PREFIX, STRUCT) OE_CONCAT(PREFIX, STRUCT)
#endif

struct POSIX_STRUCT(posix_,timespec)
{
    int64_t tv_sec;
    uint64_t tv_nsec;
};

struct POSIX_STRUCT(posix_,sigaction)
{
    uint64_t handler;
    unsigned long flags;
    uint64_t restorer;
    unsigned mask[2];
};

struct POSIX_STRUCT(posix_,siginfo)
{
    uint8_t data[128];
};

struct POSIX_STRUCT(posix_,ucontext)
{
    uint8_t data[936];
};

struct POSIX_STRUCT(posix_,sigset)
{
    unsigned long __bits[16];
};

struct POSIX_STRUCT(posix_,sig_args)
{
    int sig;
    int enclave_sig;
    struct POSIX_STRUCT(posix_,siginfo) siginfo;
    struct POSIX_STRUCT(posix_,ucontext) ucontext;
};

struct POSIX_STRUCT(posix_,shared_block)
{
    struct POSIX_STRUCT(posix_,sig_args) sig_args;
    int32_t futex;
    uint32_t trace;
    volatile uint32_t kill_lock;
    uint8_t padding[3012];
};

OE_STATIC_ASSERT(
    sizeof(struct POSIX_STRUCT(posix_,shared_block)) == OE_PAGE_SIZE);

#endif //_POSIX_OCALLS_OCALL_STRUCTS_H
