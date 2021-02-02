// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.


//==============================================================================
//
// int myst_run_thread_asm(
//     [RDI] void* stack,
//     [RSI] uint64_t cookie,
//     [RDX] uint64_t event)
//
//==============================================================================

.globl myst_run_thread_asm
.type myst_run_thread_asm, @function
myst_run_thread_asm:
.cfi_startproc
    push %r14
    push %r15
    movq %rsp,%r14 # save original stack pointer
    movq %rbp,%r15 # save original base pointer
    movq %rdi,%rsp # set new stack pointer
    movq %rdi,%rbp # set new base pointer
    movq %rsi, %rdi # set first parameter (cookie)
    movq %rdx, %rsi # set second parameter (event)
    call myst_run_thread_c
    movq %r14, %rsp # restore original stack pointer
    movq %r15, %rbp # restore original base pointer
    pop %r15
    pop %r14
    ret
.cfi_endproc
