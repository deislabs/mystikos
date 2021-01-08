// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_SETJMP_H
#define _MYST_SETJMP_H

#include <myst/types.h>

typedef struct myst_jmp_buf
{
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
} myst_jmp_buf_t;

__attribute__((returns_twice)) int myst_setjmp(myst_jmp_buf_t* env);

void myst_longjmp(myst_jmp_buf_t* env, int val);

void myst_jump(myst_jmp_buf_t* env);

#endif /* _MYST_SETJMP_H */
