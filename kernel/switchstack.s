// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//==============================================================================
//
// long myst_switch_stack(
//     [RDI] void* stack,
//     [RSI] long (*func)(void* arg),
//     [RDX] void* arg);
//
// Call a function on the given stack
//
//==============================================================================

.globl myst_switch_stack
.type myst_switch_stack, @function
myst_switch_stack:
.cfi_startproc

    pushq %rbp
    .cfi_def_cfa_offset 16
    .cfi_offset rbp,-16
    movq %rsp, %rbp
    .cfi_def_cfa_register rbp

    push %r14
    movq %rsp,%r14 # save original stack pointer
    movq %rdi,%rsp # set new stack pointer
    movq %rdx, %rdi # set the first parameter
    call *%rsi # call the function
    movq %r14, %rsp # restore original stack pointer
    pop %r14

    popq %rbp
    .cfi_def_cfa rsp, 8
    ret

.cfi_endproc
