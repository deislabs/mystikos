// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//==============================================================================
//
// int myst_enter_asm(void* stack, void* arg)
//
//     %rdi := stack
//     %rsi := args
//
//==============================================================================

.globl myst_enter_asm
.type myst_enter_asm, @function
myst_enter_asm:
.cfi_startproc
    push %r14
    push %r15
    movq %rsp,%r14 # save original stack pointer
    movq %rbp,%r15 # save original base pointer
    movq %rdi,%rsp # set new stack pointer
    movq %rdi,%rbp # set new base pointer
    movq %rsi, %rdi # set first parameter (arg)
    call myst_enter
    movq %r14, %rsp # restore original stack pointer
    movq %r15, %rbp # restore original base pointer
    pop %r15
    pop %r14
    ret
.cfi_endproc
