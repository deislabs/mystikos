// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//==============================================================================
//
// void myst_syscall_asm(void* stack, long n, long params[6])
//
//     %rdi := stack
//     %rsi := n
//     %rdx := params
//
//==============================================================================

.globl myst_syscall_asm
.type myst_syscall_asm, @function
myst_syscall_asm:
.cfi_startproc
    push %r14
    push %r15
    movq %rsp,%r14 # save original stack pointer
    movq %rbp,%r15 # save original base pointer
    movq %rdi,%rsp # set new stack pointer
    movq %rdi,%rbp # set new base pointer
    movq %rsi, %rdi # set first parameter (n)
    movq %rdx, %rsi # set second parameter (params)
    call myst_syscall_c # call myst_syscall_c()
    movq %r14, %rsp # restore original stack pointer
    movq %r15, %rbp # restore original base pointer
    pop %r15
    pop %r14
    ret
.cfi_endproc
