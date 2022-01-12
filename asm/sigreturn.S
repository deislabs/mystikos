// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "asmdefs.h"

//==============================================================================
//
// void myst_sigreturn(mcontext_t* mcontext)
//
//     Function used to return from the signal handler.
//
//     %rdi := mcontext
//
//==============================================================================

.globl myst_sigreturn
.type myst_sigreturn, @function
myst_sigreturn:
.cfi_startproc

    // The fpregs member is a pointer instead of an array
    mov MYST_MCONTEXT_FPREGS(%rdi), %rax
    fxrstor (%rax)

    mov MYST_MCONTEXT_RAX(%rdi), %rax
    mov MYST_MCONTEXT_RBX(%rdi), %rbx
    mov MYST_MCONTEXT_RCX(%rdi), %rcx
    mov MYST_MCONTEXT_RDX(%rdi), %rdx

    mov MYST_MCONTEXT_RSI(%rdi), %rsi

    mov MYST_MCONTEXT_R8(%rdi), %r8
    mov MYST_MCONTEXT_R9(%rdi), %r9
    mov MYST_MCONTEXT_R10(%rdi), %r10
    mov MYST_MCONTEXT_R11(%rdi), %r11
    mov MYST_MCONTEXT_R12(%rdi), %r12
    mov MYST_MCONTEXT_R13(%rdi), %r13
    mov MYST_MCONTEXT_R14(%rdi), %r14
    mov MYST_MCONTEXT_R15(%rdi), %r15

    mov MYST_MCONTEXT_RBP(%rdi), %rbp
    mov MYST_MCONTEXT_RSP(%rdi), %rsp

    sub $MYST_X86_64_ABI_REDZONE_SIZE, %rsp

    pushq MYST_MCONTEXT_RIP(%rdi)

    pushq MYST_MCONTEXT_EFL(%rdi)
    popfq

    mov MYST_MCONTEXT_RDI(%rdi), %rdi

    // LVI mitigation
    notq (%rsp)
    notq (%rsp)
    lfence

    retq $MYST_X86_64_ABI_REDZONE_SIZE
.cfi_endproc
