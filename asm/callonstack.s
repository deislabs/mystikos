// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//==============================================================================
//
// long myst_call_on_stack(
//     [RDI] void* stack,
//     [RSI] long (*func)(void* arg),
//     [RDX] void* arg);
//
// Call a function on the given stack
//
//==============================================================================

.globl myst_call_on_stack
.type myst_call_on_stack, @function
myst_call_on_stack:
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
