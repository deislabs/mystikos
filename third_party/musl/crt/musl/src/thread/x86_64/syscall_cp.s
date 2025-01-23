.text
.global __cp_begin
.hidden __cp_begin
.global __cp_end
.hidden __cp_end
.global __cp_cancel
.hidden __cp_cancel
.hidden __cancel
.global __syscall_cp_asm
.hidden __syscall_cp_asm
.type   __syscall_cp_asm,@function
// __syscall_cp_asm(%rdi=cancel, %rsi=n, %rdx=params)
__syscall_cp_asm:

__cp_begin:
	mov (%rdi),%eax
	test %eax,%eax
	jnz __cp_cancel

	mov %rdi,%r11
        mov %rsi, %rdi
        mov %rdx, %rsi
	mov %r11,8(%rsp)
	jmp myst_syscall
__cp_end:
	ret
__cp_cancel:
	jmp __cancel
