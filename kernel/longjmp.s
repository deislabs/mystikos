// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//==============================================================================
//
// void myst_longjmp(myst_jmp_buf* env, int val)
//
//     Implementation of standard longjmp() function.
//
//     %rdi := env
//     %rsi := val
//
//==============================================================================

// Modified from musl-libc root/src/setjmp/x86_64/longjmp.s

.globl myst_longjmp
.type myst_longjmp, @function
myst_longjmp:
.cfi_startproc
    mov %rsi, %rax
    // if (val == 0) then set val to 1.
    cmp $0, %rax
    jne val_is_nonzero
    mov $1, %rax # Return value (int)

val_is_nonzero:
    mov (%rdi),%rsp
    mov 8(%rdi),%rbp
    mov 24(%rdi),%rbx
    mov 32(%rdi),%r12
    mov 40(%rdi),%r13
    mov 48(%rdi),%r14
    mov 56(%rdi),%r15
    jmp *16(%rdi)
.cfi_endproc
