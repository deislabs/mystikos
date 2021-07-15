// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//==============================================================================
//
// long myst_call_on_stack(
//     [RDI] void* stack,
//     [RSI] long (*func)(void* arg),
//     [RDX] void* arg);
//
// Call a function on the given stack.
//
// GDB normally will stop stack-walking at a function if it determines that
// the stack does not monotonically decrease at the function.
// This could be the case for some invocations of myst_call_on_stack, if the
// `stack` parameter is greater than RSP upon entry.
// To support the split-stack feature, GDB however relaxes the above
// constraint for functions named `__morestack`.
// We leverage this GDB behavior by moving the body of myst_call_on_stack to
// a local function name `__morestack` to which myst_call_on_stack jumps to.
//==============================================================================
.globl myst_call_on_stack
.type myst_call_on_stack, @function
myst_call_on_stack:
   jmp __morestack
.size myst_call_on_stack, .-myst_call_on_stack

.type __morestack, @function
__morestack:
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
.size __morestack, .-__morestack
