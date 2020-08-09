.globl posix_jump
.type posix_jump, @function
posix_jump:
.cfi_startproc
    mov (%rdi),%rsp
    mov 8(%rdi),%rbp
    mov 24(%rdi),%rbx
    mov 32(%rdi),%r12
    mov 40(%rdi),%r13
    mov 48(%rdi),%r14
    mov 56(%rdi),%r15
    jmp *16(%rdi)
.cfi_endproc
