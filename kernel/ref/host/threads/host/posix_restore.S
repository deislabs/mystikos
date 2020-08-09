        nop
.global posix_restore
.hidden posix_restore
.type posix_restore,@function
posix_restore:
        mov $15, %rax
        syscall
.size posix_restore,.-posix_restore
