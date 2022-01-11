#pragma once

/* Syscalls from arch/ia64/kernel/entry.S */

#include "sanitise.h"
#include "syscall.h"
#include "syscalls/syscalls.h"

struct syscalltable syscalls_ia64[] = {
	{ .entry = &syscall_ni_syscall },
	{ .entry = &syscall_exit },
	{ .entry = &syscall_read },
	{ .entry = &syscall_write },
	{ .entry = &syscall_open },
	{ .entry = &syscall_close },
	{ .entry = &syscall_creat },
	{ .entry = &syscall_link },
	{ .entry = &syscall_unlink },
	{ .entry = &syscall_execve },
	{ .entry = &syscall_chdir },
	{ .entry = &syscall_fchdir },
	{ .entry = &syscall_utimes },
	{ .entry = &syscall_mknod },
	{ .entry = &syscall_chmod },
	{ .entry = &syscall_chown },
	{ .entry = &syscall_lseek },
	{ .entry = &syscall_getpid },
	{ .entry = &syscall_getppid },
	{ .entry = &syscall_mount },
	{ .entry = &syscall_umount },
	{ .entry = &syscall_setuid },
	{ .entry = &syscall_getuid },
	{ .entry = &syscall_geteuid },
	{ .entry = &syscall_ptrace },
	{ .entry = &syscall_access },
	{ .entry = &syscall_sync },
	{ .entry = &syscall_fsync },
	{ .entry = &syscall_fdatasync },
	{ .entry = &syscall_kill },
	{ .entry = &syscall_rename },
	{ .entry = &syscall_mkdir },
	{ .entry = &syscall_rmdir },
	{ .entry = &syscall_dup },
	{ .entry = &syscall_pipe },
	{ .entry = &syscall_times },
	{ .entry = &syscall_brk },
	{ .entry = &syscall_setgid },
	{ .entry = &syscall_getgid },
	{ .entry = &syscall_getegid },
	{ .entry = &syscall_acct },
	{ .entry = &syscall_ioctl },
	{ .entry = &syscall_fcntl },
	{ .entry = &syscall_umask },
	{ .entry = &syscall_chroot },
	{ .entry = &syscall_ustat },
	{ .entry = &syscall_dup2 },
	{ .entry = &syscall_setreuid },
	{ .entry = &syscall_setregid },
	{ .entry = &syscall_getresuid },
	{ .entry = &syscall_setresuid },
	{ .entry = &syscall_getresgid },
	{ .entry = &syscall_setresgid },
	{ .entry = &syscall_getgroups },
	{ .entry = &syscall_setgroups },
	{ .entry = &syscall_getpgid },
	{ .entry = &syscall_setpgid },
	{ .entry = &syscall_setsid },
	{ .entry = &syscall_getsid },
	{ .entry = &syscall_sethostname },
	{ .entry = &syscall_setrlimit },
	{ .entry = &syscall_getrlimit },
	{ .entry = &syscall_getrusage },
	{ .entry = &syscall_gettimeofday },
	{ .entry = &syscall_settimeofday },
	{ .entry = &syscall_select },
	{ .entry = &syscall_poll },
	{ .entry = &syscall_symlink },
	{ .entry = &syscall_readlink },
	{ .entry = &syscall_uselib },
	{ .entry = &syscall_swapon },
	{ .entry = &syscall_swapoff },
	{ .entry = &syscall_reboot },
	{ .entry = &syscall_truncate },
	{ .entry = &syscall_ftruncate },
	{ .entry = &syscall_fchmod },
	{ .entry = &syscall_fchown },
	{ .entry = &syscall_getpriority },
	{ .entry = &syscall_setpriority },
	{ .entry = &syscall_statfs },
	{ .entry = &syscall_fstatfs },
	{ .entry = &syscall_gettid },
	{ .entry = &syscall_semget },
	{ .entry = &syscall_semop },
	{ .entry = &syscall_semctl },
	{ .entry = &syscall_msgget },
	{ .entry = &syscall_msgsnd },
	{ .entry = &syscall_msgrcv },
	{ .entry = &syscall_msgctl },
	{ .entry = &syscall_shmget },
	{ .entry = &syscall_shmat },
	{ .entry = &syscall_shmdt },
	{ .entry = &syscall_shmctl },
	{ .entry = &syscall_syslog },
	{ .entry = &syscall_setitimer },
	{ .entry = &syscall_getitimer },
	{ .entry = &syscall_ni_syscall },	/* obsolete "tux" syscall */
	{ .entry = &syscall_ni_syscall },	// ia64_oldlstat
	{ .entry = &syscall_ni_syscall },	// ia64_oldfstat
	{ .entry = &syscall_vhangup },
	{ .entry = &syscall_lchown },
	{ .entry = &syscall_remap_file_pages },
	{ .entry = &syscall_wait4 },
	{ .entry = &syscall_sysinfo },
	{ .entry = &syscall_clone },
	{ .entry = &syscall_setdomainname },
	{ .entry = &syscall_newuname },
	{ .entry = &syscall_adjtimex },
	{ .entry = &syscall_ni_syscall },	/* obsolete "create_module" syscall */
	{ .entry = &syscall_init_module },
	{ .entry = &syscall_delete_module },
	{ .entry = &syscall_ni_syscall },	// ?
	{ .entry = &syscall_ni_syscall },	/* obsolete "query_module" syscall */
	{ .entry = &syscall_quotactl },
	{ .entry = &syscall_bdflush },
	{ .entry = &syscall_sysfs },
	{ .entry = &syscall_personality },
	{ .entry = &syscall_ni_syscall },	/* obsolete "afs" syscall */
	{ .entry = &syscall_setfsuid },
	{ .entry = &syscall_setfsgid },
	{ .entry = &syscall_getdents },
	{ .entry = &syscall_flock },
	{ .entry = &syscall_readv },
	{ .entry = &syscall_writev },
	{ .entry = &syscall_pread64 },
	{ .entry = &syscall_pwrite64 },
	{ .entry = &syscall_sysctl },
	{ .entry = &syscall_mmap },
	{ .entry = &syscall_munmap },
	{ .entry = &syscall_mlock },
	{ .entry = &syscall_mlockall },
	{ .entry = &syscall_mprotect },
	{ .entry = &syscall_mremap },
	{ .entry = &syscall_msync },
	{ .entry = &syscall_munlock },
	{ .entry = &syscall_munlockall },
	{ .entry = &syscall_sched_getparam },
	{ .entry = &syscall_sched_setparam },
	{ .entry = &syscall_sched_getscheduler },
	{ .entry = &syscall_sched_setscheduler },
	{ .entry = &syscall_sched_yield },
	{ .entry = &syscall_sched_get_priority_max },
	{ .entry = &syscall_sched_get_priority_min },
	{ .entry = &syscall_sched_rr_get_interval },
	{ .entry = &syscall_nanosleep },
	{ .entry = &syscall_nfsservctl },
	{ .entry = &syscall_prctl },
	{ .entry = &syscall_getpagesize },
	{ .entry = &syscall_mmap2 },
	{ .entry = &syscall_pciconfig_read },
	{ .entry = &syscall_pciconfig_write },
	{ .entry = &syscall_perfmonctl },
	{ .entry = &syscall_sigaltstack },
	{ .entry = &syscall_rt_sigaction },
	{ .entry = &syscall_rt_sigpending },
	{ .entry = &syscall_rt_sigprocmask },
	{ .entry = &syscall_rt_sigqueueinfo },
	{ .entry = &syscall_rt_sigreturn },
	{ .entry = &syscall_rt_sigsuspend },
	{ .entry = &syscall_rt_sigtimedwait },
	{ .entry = &syscall_getcwd },
	{ .entry = &syscall_capget },
	{ .entry = &syscall_capset },
	{ .entry = &syscall_sendfile64 },
	{ .entry = &syscall_ni_syscall },	/* obsolete "getpmsg" syscall */
	{ .entry = &syscall_ni_syscall },	/* obsolete "putpmsg" syscall */
	{ .entry = &syscall_socket },
	{ .entry = &syscall_bind },
	{ .entry = &syscall_connect },
	{ .entry = &syscall_listen },
	{ .entry = &syscall_accept },
	{ .entry = &syscall_getsockname },
	{ .entry = &syscall_getpeername },
	{ .entry = &syscall_socketpair },
	{ .entry = &syscall_send },
	{ .entry = &syscall_sendto },
	{ .entry = &syscall_recv },
	{ .entry = &syscall_recvfrom },
	{ .entry = &syscall_shutdown },
	{ .entry = &syscall_setsockopt },
	{ .entry = &syscall_getsockopt },
	{ .entry = &syscall_sendmsg },
	{ .entry = &syscall_recvmsg },
	{ .entry = &syscall_pivot_root },
	{ .entry = &syscall_mincore },
	{ .entry = &syscall_madvise },
	{ .entry = &syscall_newstat },
	{ .entry = &syscall_newlstat },
	{ .entry = &syscall_newfstat },
	{ .entry = &syscall_clone2 },
	{ .entry = &syscall_getdents64 },
	{ .entry = &syscall_getunwind },
	{ .entry = &syscall_readahead },
	{ .entry = &syscall_setxattr },
	{ .entry = &syscall_lsetxattr },
	{ .entry = &syscall_fsetxattr },
	{ .entry = &syscall_getxattr },
	{ .entry = &syscall_lgetxattr },
	{ .entry = &syscall_fgetxattr },
	{ .entry = &syscall_listxattr },
	{ .entry = &syscall_llistxattr },
	{ .entry = &syscall_flistxattr },
	{ .entry = &syscall_removexattr },
	{ .entry = &syscall_lremovexattr },
	{ .entry = &syscall_fremovexattr },
	{ .entry = &syscall_tkill },
	{ .entry = &syscall_futex },
	{ .entry = &syscall_sched_setaffinity },
	{ .entry = &syscall_sched_getaffinity },
	{ .entry = &syscall_set_tid_address },
	{ .entry = &syscall_fadvise64_64 },
	{ .entry = &syscall_tgkill },
	{ .entry = &syscall_exit_group },
	{ .entry = &syscall_lookup_dcookie },
	{ .entry = &syscall_io_setup },
	{ .entry = &syscall_io_destroy },
	{ .entry = &syscall_io_getevents },
	{ .entry = &syscall_io_submit },
	{ .entry = &syscall_io_cancel },
	{ .entry = &syscall_epoll_create },
	{ .entry = &syscall_epoll_ctl },
	{ .entry = &syscall_epoll_wait },
	{ .entry = &syscall_restart_syscall },
	{ .entry = &syscall_semtimedop },
	{ .entry = &syscall_timer_create },
	{ .entry = &syscall_timer_settime },
	{ .entry = &syscall_timer_gettime },
	{ .entry = &syscall_timer_getoverrun },
	{ .entry = &syscall_timer_delete },
	{ .entry = &syscall_clock_settime },
	{ .entry = &syscall_clock_gettime },
	{ .entry = &syscall_clock_getres },
	{ .entry = &syscall_clock_nanosleep },
	{ .entry = &syscall_fstatfs64 },
	{ .entry = &syscall_statfs64 },
	{ .entry = &syscall_mbind },
	{ .entry = &syscall_get_mempolicy },
	{ .entry = &syscall_set_mempolicy },
	{ .entry = &syscall_mq_open },
	{ .entry = &syscall_mq_unlink },
	{ .entry = &syscall_mq_timedsend },
	{ .entry = &syscall_mq_timedreceive },
	{ .entry = &syscall_mq_notify },
	{ .entry = &syscall_mq_getsetattr },
	{ .entry = &syscall_kexec_load },
	{ .entry = &syscall_ni_syscall },	/* obsolete "vserver" syscall */
	{ .entry = &syscall_waitid },
	{ .entry = &syscall_add_key },
	{ .entry = &syscall_request_key },
	{ .entry = &syscall_keyctl },
	{ .entry = &syscall_ioprio_set },
	{ .entry = &syscall_ioprio_get },
	{ .entry = &syscall_ni_syscall },	/* ? */
	{ .entry = &syscall_inotify_init },
	{ .entry = &syscall_inotify_add_watch },
	{ .entry = &syscall_inotify_rm_watch },
	{ .entry = &syscall_migrate_pages },
	{ .entry = &syscall_openat },
	{ .entry = &syscall_mkdirat },
	{ .entry = &syscall_mknodat },
	{ .entry = &syscall_fchownat },
	{ .entry = &syscall_futimesat },
	{ .entry = &syscall_newfstatat },
	{ .entry = &syscall_unlinkat },
	{ .entry = &syscall_renameat },
	{ .entry = &syscall_linkat },
	{ .entry = &syscall_symlinkat },
	{ .entry = &syscall_readlinkat },
	{ .entry = &syscall_fchmodat },
	{ .entry = &syscall_faccessat },
	{ .entry = &syscall_pselect6 },
	{ .entry = &syscall_ni_syscall },	/* ? */
	{ .entry = &syscall_unshare },
	{ .entry = &syscall_splice },
	{ .entry = &syscall_set_robust_list },
	{ .entry = &syscall_get_robust_list },
	{ .entry = &syscall_sync_file_range },
	{ .entry = &syscall_tee },
	{ .entry = &syscall_vmsplice },
	{ .entry = &syscall_fallocate },
	{ .entry = &syscall_getcpu },
	{ .entry = &syscall_epoll_pwait },
	{ .entry = &syscall_utimensat },
	{ .entry = &syscall_signalfd },
	{ .entry = &syscall_ni_syscall },	/* ? */
	{ .entry = &syscall_eventfd },
	{ .entry = &syscall_timerfd_create },
	{ .entry = &syscall_timerfd_settime },
	{ .entry = &syscall_timerfd_gettime },
	{ .entry = &syscall_signalfd4 },
	{ .entry = &syscall_eventfd2 },
	{ .entry = &syscall_epoll_create1 },
	{ .entry = &syscall_dup3 },
	{ .entry = &syscall_pipe2 },
	{ .entry = &syscall_inotify_init1 },
	{ .entry = &syscall_preadv },
	{ .entry = &syscall_pwritev },
	{ .entry = &syscall_rt_tgsigqueueinfo },
	{ .entry = &syscall_recvmmsg },
	{ .entry = &syscall_fanotify_init },
	{ .entry = &syscall_fanotify_mark },
	{ .entry = &syscall_prlimit64 },
	{ .entry = &syscall_name_to_handle_at },
	{ .entry = &syscall_open_by_handle_at },
	{ .entry = &syscall_clock_adjtime },
	{ .entry = &syscall_syncfs },
	{ .entry = &syscall_setns },
	{ .entry = &syscall_sendmmsg },
	{ .entry = &syscall_process_vm_readv },
	{ .entry = &syscall_process_vm_writev },
	{ .entry = &syscall_accept4 },
	{ .entry = &syscall_finit_module },
	{ .entry = &syscall_sched_setattr },
	{ .entry = &syscall_sched_getattr },
	{ .entry = &syscall_renameat2 },
	{ .entry = &syscall_getrandom },
	{ .entry = &syscall_memfd_create },
#ifdef USE_BPF
	{ .entry = &syscall_bpf },
#else
	{ .entry = NULL },
#endif
	{ .entry = &syscall_userfaultfd },
	{ .entry = &syscall_membarrier },
	{ .entry = &syscall_kcmp },
};
