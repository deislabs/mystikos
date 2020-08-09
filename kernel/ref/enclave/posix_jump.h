// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _POSIX_JUMP_H
#define _POSIX_JUMP_H

#include <stdint.h>

typedef struct _posix_jump_context
{
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
}
posix_jump_context_t;

void posix_jump(posix_jump_context_t* context);

#endif //_POSIX_JUMP_H
