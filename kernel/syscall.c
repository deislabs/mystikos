// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <myst/mman.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <myst/backtrace.h>
#include <myst/barrier.h>
#include <myst/blkdev.h>
#include <myst/buf.h>
#include <myst/clock.h>
#include <myst/cpio.h>
#include <myst/cwd.h>
#include <myst/epolldev.h>
#include <myst/eraise.h>
#include <myst/errno.h>
#include <myst/exec.h>
#include <myst/ext2.h>
#include <myst/fdops.h>
#include <myst/fdtable.h>
#include <myst/file.h>
#include <myst/fs.h>
#include <myst/fsgs.h>
#include <myst/gcov.h>
#include <myst/hex.h>
#include <myst/hostfs.h>
#include <myst/id.h>
#include <myst/initfini.h>
#include <myst/inotifydev.h>
#include <myst/kernel.h>
#include <myst/kstack.h>
#include <myst/libc.h>
#include <myst/lsr.h>
#include <myst/mmanutils.h>
#include <myst/mount.h>
#include <myst/once.h>
#include <myst/options.h>
#include <myst/panic.h>
#include <myst/paths.h>
#include <myst/pipedev.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/pubkey.h>
#include <myst/ramfs.h>
#include <myst/setjmp.h>
#include <myst/signal.h>
#include <myst/spinlock.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/syscallext.h>
#include <myst/tcall.h>
#include <myst/tee.h>
#include <myst/thread.h>
#include <myst/time.h>
#include <myst/times.h>
#include <myst/trace.h>

#define MAX_IPADDR_LEN 64

#define COLOR_RED "\e[31m"
#define COLOR_BLUE "\e[34m"
#define COLOR_GREEN "\e[32m"
#define COLOR_RESET "\e[0m"

long myst_syscall_isatty(int fd);

typedef struct _pair
{
    long num;
    const char* str;
} pair_t;

static pair_t _pairs[] = {
    {SYS_read, "SYS_read"},
    {SYS_write, "SYS_write"},
    {SYS_open, "SYS_open"},
    {SYS_close, "SYS_close"},
    {SYS_stat, "SYS_stat"},
    {SYS_fstat, "SYS_fstat"},
    {SYS_lstat, "SYS_lstat"},
    {SYS_poll, "SYS_poll"},
    {SYS_lseek, "SYS_lseek"},
    {SYS_mmap, "SYS_mmap"},
    {SYS_mprotect, "SYS_mprotect"},
    {SYS_munmap, "SYS_munmap"},
    {SYS_brk, "SYS_brk"},
    {SYS_rt_sigaction, "SYS_rt_sigaction"},
    {SYS_rt_sigprocmask, "SYS_rt_sigprocmask"},
    {SYS_rt_sigreturn, "SYS_rt_sigreturn"},
    {SYS_ioctl, "SYS_ioctl"},
    {SYS_pread64, "SYS_pread64"},
    {SYS_pwrite64, "SYS_pwrite64"},
    {SYS_readv, "SYS_readv"},
    {SYS_writev, "SYS_writev"},
    {SYS_access, "SYS_access"},
    {SYS_pipe, "SYS_pipe"},
    {SYS_select, "SYS_select"},
    {SYS_sched_yield, "SYS_sched_yield"},
    {SYS_mremap, "SYS_mremap"},
    {SYS_msync, "SYS_msync"},
    {SYS_mincore, "SYS_mincore"},
    {SYS_madvise, "SYS_madvise"},
    {SYS_shmget, "SYS_shmget"},
    {SYS_shmat, "SYS_shmat"},
    {SYS_shmctl, "SYS_shmctl"},
    {SYS_dup, "SYS_dup"},
    {SYS_dup2, "SYS_dup2"},
    {SYS_pause, "SYS_pause"},
    {SYS_nanosleep, "SYS_nanosleep"},
    {SYS_getitimer, "SYS_getitimer"},
    {SYS_alarm, "SYS_alarm"},
    {SYS_setitimer, "SYS_setitimer"},
    {SYS_getpid, "SYS_getpid"},
    {SYS_sendfile, "SYS_sendfile"},
    {SYS_socket, "SYS_socket"},
    {SYS_connect, "SYS_connect"},
    {SYS_accept, "SYS_accept"},
    {SYS_sendto, "SYS_sendto"},
    {SYS_recvfrom, "SYS_recvfrom"},
    {SYS_sendmsg, "SYS_sendmsg"},
    {SYS_recvmsg, "SYS_recvmsg"},
    {SYS_shutdown, "SYS_shutdown"},
    {SYS_bind, "SYS_bind"},
    {SYS_listen, "SYS_listen"},
    {SYS_getsockname, "SYS_getsockname"},
    {SYS_getpeername, "SYS_getpeername"},
    {SYS_socketpair, "SYS_socketpair"},
    {SYS_setsockopt, "SYS_setsockopt"},
    {SYS_getsockopt, "SYS_getsockopt"},
    {SYS_clone, "SYS_clone"},
    {SYS_fork, "SYS_fork"},
    {SYS_vfork, "SYS_vfork"},
    {SYS_execve, "SYS_execve"},
    {SYS_exit, "SYS_exit"},
    {SYS_wait4, "SYS_wait4"},
    {SYS_kill, "SYS_kill"},
    {SYS_uname, "SYS_uname"},
    {SYS_semget, "SYS_semget"},
    {SYS_semop, "SYS_semop"},
    {SYS_semctl, "SYS_semctl"},
    {SYS_shmdt, "SYS_shmdt"},
    {SYS_msgget, "SYS_msgget"},
    {SYS_msgsnd, "SYS_msgsnd"},
    {SYS_msgrcv, "SYS_msgrcv"},
    {SYS_msgctl, "SYS_msgctl"},
    {SYS_fcntl, "SYS_fcntl"},
    {SYS_flock, "SYS_flock"},
    {SYS_fsync, "SYS_fsync"},
    {SYS_fdatasync, "SYS_fdatasync"},
    {SYS_truncate, "SYS_truncate"},
    {SYS_ftruncate, "SYS_ftruncate"},
    {SYS_getdents, "SYS_getdents"},
    {SYS_getcwd, "SYS_getcwd"},
    {SYS_chdir, "SYS_chdir"},
    {SYS_fchdir, "SYS_fchdir"},
    {SYS_rename, "SYS_rename"},
    {SYS_mkdir, "SYS_mkdir"},
    {SYS_rmdir, "SYS_rmdir"},
    {SYS_creat, "SYS_creat"},
    {SYS_link, "SYS_link"},
    {SYS_unlink, "SYS_unlink"},
    {SYS_symlink, "SYS_symlink"},
    {SYS_readlink, "SYS_readlink"},
    {SYS_chmod, "SYS_chmod"},
    {SYS_fchmod, "SYS_fchmod"},
    {SYS_chown, "SYS_chown"},
    {SYS_fchown, "SYS_fchown"},
    {SYS_lchown, "SYS_lchown"},
    {SYS_umask, "SYS_umask"},
    {SYS_gettimeofday, "SYS_gettimeofday"},
    {SYS_getrlimit, "SYS_getrlimit"},
    {SYS_getrusage, "SYS_getrusage"},
    {SYS_sysinfo, "SYS_sysinfo"},
    {SYS_times, "SYS_times"},
    {SYS_ptrace, "SYS_ptrace"},
    {SYS_getuid, "SYS_getuid"},
    {SYS_syslog, "SYS_syslog"},
    {SYS_getgid, "SYS_getgid"},
    {SYS_setuid, "SYS_setuid"},
    {SYS_setgid, "SYS_setgid"},
    {SYS_geteuid, "SYS_geteuid"},
    {SYS_getegid, "SYS_getegid"},
    {SYS_setpgid, "SYS_setpgid"},
    {SYS_getppid, "SYS_getppid"},
    {SYS_getpgrp, "SYS_getpgrp"},
    {SYS_setsid, "SYS_setsid"},
    {SYS_setreuid, "SYS_setreuid"},
    {SYS_setregid, "SYS_setregid"},
    {SYS_getgroups, "SYS_getgroups"},
    {SYS_setgroups, "SYS_setgroups"},
    {SYS_setresuid, "SYS_setresuid"},
    {SYS_getresuid, "SYS_getresuid"},
    {SYS_setresgid, "SYS_setresgid"},
    {SYS_getresgid, "SYS_getresgid"},
    {SYS_getpgid, "SYS_getpgid"},
    {SYS_setfsuid, "SYS_setfsuid"},
    {SYS_setfsgid, "SYS_setfsgid"},
    {SYS_getsid, "SYS_getsid"},
    {SYS_capget, "SYS_capget"},
    {SYS_capset, "SYS_capset"},
    {SYS_rt_sigpending, "SYS_rt_sigpending"},
    {SYS_rt_sigtimedwait, "SYS_rt_sigtimedwait"},
    {SYS_rt_sigqueueinfo, "SYS_rt_sigqueueinfo"},
    {SYS_rt_sigsuspend, "SYS_rt_sigsuspend"},
    {SYS_sigaltstack, "SYS_sigaltstack"},
    {SYS_utime, "SYS_utime"},
    {SYS_mknod, "SYS_mknod"},
    {SYS_uselib, "SYS_uselib"},
    {SYS_personality, "SYS_personality"},
    {SYS_ustat, "SYS_ustat"},
    {SYS_statfs, "SYS_statfs"},
    {SYS_fstatfs, "SYS_fstatfs"},
    {SYS_sysfs, "SYS_sysfs"},
    {SYS_getpriority, "SYS_getpriority"},
    {SYS_setpriority, "SYS_setpriority"},
    {SYS_sched_setparam, "SYS_sched_setparam"},
    {SYS_sched_getparam, "SYS_sched_getparam"},
    {SYS_sched_setscheduler, "SYS_sched_setscheduler"},
    {SYS_sched_getscheduler, "SYS_sched_getscheduler"},
    {SYS_sched_get_priority_max, "SYS_sched_get_priority_max"},
    {SYS_sched_get_priority_min, "SYS_sched_get_priority_min"},
    {SYS_sched_rr_get_interval, "SYS_sched_rr_get_interval"},
    {SYS_mlock, "SYS_mlock"},
    {SYS_munlock, "SYS_munlock"},
    {SYS_mlockall, "SYS_mlockall"},
    {SYS_munlockall, "SYS_munlockall"},
    {SYS_vhangup, "SYS_vhangup"},
    {SYS_modify_ldt, "SYS_modify_ldt"},
    {SYS_pivot_root, "SYS_pivot_root"},
    {SYS__sysctl, "SYS__sysctl"},
    {SYS_prctl, "SYS_prctl"},
    {SYS_arch_prctl, "SYS_arch_prctl"},
    {SYS_adjtimex, "SYS_adjtimex"},
    {SYS_setrlimit, "SYS_setrlimit"},
    {SYS_chroot, "SYS_chroot"},
    {SYS_sync, "SYS_sync"},
    {SYS_acct, "SYS_acct"},
    {SYS_settimeofday, "SYS_settimeofday"},
    {SYS_mount, "SYS_mount"},
    {SYS_umount2, "SYS_umount2"},
    {SYS_swapon, "SYS_swapon"},
    {SYS_swapoff, "SYS_swapoff"},
    {SYS_reboot, "SYS_reboot"},
    {SYS_sethostname, "SYS_sethostname"},
    {SYS_setdomainname, "SYS_setdomainname"},
    {SYS_iopl, "SYS_iopl"},
    {SYS_ioperm, "SYS_ioperm"},
    {SYS_create_module, "SYS_create_module"},
    {SYS_init_module, "SYS_init_module"},
    {SYS_delete_module, "SYS_delete_module"},
    {SYS_get_kernel_syms, "SYS_get_kernel_syms"},
    {SYS_query_module, "SYS_query_module"},
    {SYS_quotactl, "SYS_quotactl"},
    {SYS_nfsservctl, "SYS_nfsservctl"},
    {SYS_getpmsg, "SYS_getpmsg"},
    {SYS_putpmsg, "SYS_putpmsg"},
    {SYS_afs_syscall, "SYS_afs_syscall"},
    {SYS_tuxcall, "SYS_tuxcall"},
    {SYS_security, "SYS_security"},
    {SYS_gettid, "SYS_gettid"},
    {SYS_readahead, "SYS_readahead"},
    {SYS_setxattr, "SYS_setxattr"},
    {SYS_lsetxattr, "SYS_lsetxattr"},
    {SYS_fsetxattr, "SYS_fsetxattr"},
    {SYS_getxattr, "SYS_getxattr"},
    {SYS_lgetxattr, "SYS_lgetxattr"},
    {SYS_fgetxattr, "SYS_fgetxattr"},
    {SYS_listxattr, "SYS_listxattr"},
    {SYS_llistxattr, "SYS_llistxattr"},
    {SYS_flistxattr, "SYS_flistxattr"},
    {SYS_removexattr, "SYS_removexattr"},
    {SYS_lremovexattr, "SYS_lremovexattr"},
    {SYS_fremovexattr, "SYS_fremovexattr"},
    {SYS_tkill, "SYS_tkill"},
    {SYS_time, "SYS_time"},
    {SYS_futex, "SYS_futex"},
    {SYS_sched_setaffinity, "SYS_sched_setaffinity"},
    {SYS_sched_getaffinity, "SYS_sched_getaffinity"},
    {SYS_set_thread_area, "SYS_set_thread_area"},
    {SYS_io_setup, "SYS_io_setup"},
    {SYS_io_destroy, "SYS_io_destroy"},
    {SYS_io_getevents, "SYS_io_getevents"},
    {SYS_io_submit, "SYS_io_submit"},
    {SYS_io_cancel, "SYS_io_cancel"},
    {SYS_get_thread_area, "SYS_get_thread_area"},
    {SYS_lookup_dcookie, "SYS_lookup_dcookie"},
    {SYS_epoll_create, "SYS_epoll_create"},
    {SYS_epoll_ctl_old, "SYS_epoll_ctl_old"},
    {SYS_epoll_wait_old, "SYS_epoll_wait_old"},
    {SYS_remap_file_pages, "SYS_remap_file_pages"},
    {SYS_getdents64, "SYS_getdents64"},
    {SYS_set_tid_address, "SYS_set_tid_address"},
    {SYS_restart_syscall, "SYS_restart_syscall"},
    {SYS_semtimedop, "SYS_semtimedop"},
    {SYS_fadvise64, "SYS_fadvise64"},
    {SYS_timer_create, "SYS_timer_create"},
    {SYS_timer_settime, "SYS_timer_settime"},
    {SYS_timer_gettime, "SYS_timer_gettime"},
    {SYS_timer_getoverrun, "SYS_timer_getoverrun"},
    {SYS_timer_delete, "SYS_timer_delete"},
    {SYS_clock_settime, "SYS_clock_settime"},
    {SYS_clock_gettime, "SYS_clock_gettime"},
    {SYS_clock_getres, "SYS_clock_getres"},
    {SYS_clock_nanosleep, "SYS_clock_nanosleep"},
    {SYS_exit_group, "SYS_exit_group"},
    {SYS_epoll_wait, "SYS_epoll_wait"},
    {SYS_epoll_ctl, "SYS_epoll_ctl"},
    {SYS_tgkill, "SYS_tgkill"},
    {SYS_utimes, "SYS_utimes"},
    {SYS_vserver, "SYS_vserver"},
    {SYS_mbind, "SYS_mbind"},
    {SYS_set_mempolicy, "SYS_set_mempolicy"},
    {SYS_get_mempolicy, "SYS_get_mempolicy"},
    {SYS_mq_open, "SYS_mq_open"},
    {SYS_mq_unlink, "SYS_mq_unlink"},
    {SYS_mq_timedsend, "SYS_mq_timedsend"},
    {SYS_mq_timedreceive, "SYS_mq_timedreceive"},
    {SYS_mq_notify, "SYS_mq_notify"},
    {SYS_mq_getsetattr, "SYS_mq_getsetattr"},
    {SYS_kexec_load, "SYS_kexec_load"},
    {SYS_waitid, "SYS_waitid"},
    {SYS_add_key, "SYS_add_key"},
    {SYS_request_key, "SYS_request_key"},
    {SYS_keyctl, "SYS_keyctl"},
    {SYS_ioprio_set, "SYS_ioprio_set"},
    {SYS_ioprio_get, "SYS_ioprio_get"},
    {SYS_inotify_init, "SYS_inotify_init"},
    {SYS_inotify_add_watch, "SYS_inotify_add_watch"},
    {SYS_inotify_rm_watch, "SYS_inotify_rm_watch"},
    {SYS_migrate_pages, "SYS_migrate_pages"},
    {SYS_openat, "SYS_openat"},
    {SYS_mkdirat, "SYS_mkdirat"},
    {SYS_mknodat, "SYS_mknodat"},
    {SYS_fchownat, "SYS_fchownat"},
    {SYS_futimesat, "SYS_futimesat"},
    {SYS_newfstatat, "SYS_newfstatat"},
    {SYS_unlinkat, "SYS_unlinkat"},
    {SYS_renameat, "SYS_renameat"},
    {SYS_linkat, "SYS_linkat"},
    {SYS_symlinkat, "SYS_symlinkat"},
    {SYS_readlinkat, "SYS_readlinkat"},
    {SYS_fchmodat, "SYS_fchmodat"},
    {SYS_faccessat, "SYS_faccessat"},
    {SYS_pselect6, "SYS_pselect6"},
    {SYS_ppoll, "SYS_ppoll"},
    {SYS_unshare, "SYS_unshare"},
    {SYS_set_robust_list, "SYS_set_robust_list"},
    {SYS_get_robust_list, "SYS_get_robust_list"},
    {SYS_splice, "SYS_splice"},
    {SYS_tee, "SYS_tee"},
    {SYS_sync_file_range, "SYS_sync_file_range"},
    {SYS_vmsplice, "SYS_vmsplice"},
    {SYS_move_pages, "SYS_move_pages"},
    {SYS_utimensat, "SYS_utimensat"},
    {SYS_epoll_pwait, "SYS_epoll_pwait"},
    {SYS_signalfd, "SYS_signalfd"},
    {SYS_timerfd_create, "SYS_timerfd_create"},
    {SYS_eventfd, "SYS_eventfd"},
    {SYS_fallocate, "SYS_fallocate"},
    {SYS_timerfd_settime, "SYS_timerfd_settime"},
    {SYS_timerfd_gettime, "SYS_timerfd_gettime"},
    {SYS_accept4, "SYS_accept4"},
    {SYS_signalfd4, "SYS_signalfd4"},
    {SYS_eventfd2, "SYS_eventfd2"},
    {SYS_epoll_create1, "SYS_epoll_create1"},
    {SYS_dup3, "SYS_dup3"},
    {SYS_pipe2, "SYS_pipe2"},
    {SYS_inotify_init1, "SYS_inotify_init1"},
    {SYS_preadv, "SYS_preadv"},
    {SYS_pwritev, "SYS_pwritev"},
    {SYS_rt_tgsigqueueinfo, "SYS_rt_tgsigqueueinfo"},
    {SYS_perf_event_open, "SYS_perf_event_open"},
    {SYS_recvmmsg, "SYS_recvmmsg"},
    {SYS_fanotify_init, "SYS_fanotify_init"},
    {SYS_fanotify_mark, "SYS_fanotify_mark"},
    {SYS_prlimit64, "SYS_prlimit64"},
    {SYS_name_to_handle_at, "SYS_name_to_handle_at"},
    {SYS_open_by_handle_at, "SYS_open_by_handle_at"},
    {SYS_clock_adjtime, "SYS_clock_adjtime"},
    {SYS_syncfs, "SYS_syncfs"},
    {SYS_sendmmsg, "SYS_sendmmsg"},
    {SYS_setns, "SYS_setns"},
    {SYS_getcpu, "SYS_getcpu"},
    {SYS_process_vm_readv, "SYS_process_vm_readv"},
    {SYS_process_vm_writev, "SYS_process_vm_writev"},
    {SYS_kcmp, "SYS_kcmp"},
    {SYS_finit_module, "SYS_finit_module"},
    {SYS_sched_setattr, "SYS_sched_setattr"},
    {SYS_sched_getattr, "SYS_sched_getattr"},
    {SYS_renameat2, "SYS_renameat2"},
    {SYS_seccomp, "SYS_seccomp"},
    {SYS_getrandom, "SYS_getrandom"},
    {SYS_memfd_create, "SYS_memfd_create"},
    {SYS_kexec_file_load, "SYS_kexec_file_load"},
    {SYS_bpf, "SYS_bpf"},
    {SYS_execveat, "SYS_execveat"},
    {SYS_userfaultfd, "SYS_userfaultfd"},
    {SYS_membarrier, "SYS_membarrier"},
    {SYS_mlock2, "SYS_mlock2"},
    {SYS_copy_file_range, "SYS_copy_file_range"},
    {SYS_preadv2, "SYS_preadv2"},
    {SYS_pwritev2, "SYS_pwritev2"},
    {SYS_pkey_mprotect, "SYS_pkey_mprotect"},
    {SYS_pkey_alloc, "SYS_pkey_alloc"},
    {SYS_pkey_free, "SYS_pkey_free"},
    {SYS_statx, "SYS_statx"},
    {SYS_io_pgetevents, "SYS_io_pgetevents"},
    {SYS_rseq, "SYS_rseq"},
    {SYS_myst_trace, "SYS_myst_trace"},
    {SYS_myst_trace_ptr, "SYS_myst_trace_ptr"},
    {SYS_myst_dump_ehdr, "SYS_myst_dump_ehdr"},
    {SYS_myst_dump_argv, "SYS_myst_dump_argv"},
    {SYS_myst_dump_stack, "SYS_myst_dump_stack"},
    {SYS_myst_add_symbol_file, "SYS_myst_add_symbol_file"},
    {SYS_myst_load_symbols, "SYS_myst_load_symbols"},
    {SYS_myst_unload_symbols, "SYS_myst_unload_symbols"},
    {SYS_myst_gen_creds, "SYS_myst_gen_creds"},
    {SYS_myst_free_creds, "SYS_myst_free_creds"},
    {SYS_myst_verify_cert, "SYS_myst_verify_cert"},
    {SYS_myst_gen_creds_ex, "SYS_myst_gen_creds_ex"},
    {SYS_myst_clone, "SYS_myst_clone"},
    {SYS_myst_gcov_init, "SYS_myst_gcov_init"},
    {SYS_myst_max_threads, "SYS_myst_max_threads"},
    {SYS_myst_run_itimer, "SYS_myst_run_itimer"},
    /* Open Enclave extensions */
    {SYS_myst_oe_get_report_v2, "SYS_myst_oe_get_report_v2"},
    {SYS_myst_oe_free_report, "SYS_myst_oe_free_report"},
    {SYS_myst_oe_get_target_info_v2, "SYS_myst_oe_get_target_info_v2"},
    {SYS_myst_oe_free_target_info, "SYS_myst_oe_free_target_info"},
    {SYS_myst_oe_parse_report, "SYS_myst_oe_parse_report"},
    {SYS_myst_oe_verify_report, "SYS_myst_oe_verify_report"},
    {SYS_myst_oe_get_seal_key_by_policy_v2,
     "SYS_myst_oe_get_seal_key_by_policy_v2"},
    {SYS_myst_oe_get_public_key_by_policy,
     "SYS_myst_oe_get_public_key_by_policy"},
    {SYS_myst_oe_get_public_key, "SYS_myst_oe_get_public_key"},
    {SYS_myst_oe_get_private_key_by_policy,
     "SYS_myst_oe_get_private_key_by_policy"},
    {SYS_myst_oe_get_private_key, "SYS_myst_oe_get_private_key"},
    {SYS_myst_oe_free_key, "SYS_myst_oe_free_key"},
    {SYS_myst_oe_get_seal_key_v2, "SYS_myst_oe_get_seal_key_v2"},
    {SYS_myst_oe_free_seal_key, "SYS_myst_oe_free_seal_key"},
    {SYS_myst_oe_generate_attestation_certificate,
     "SYS_myst_oe_generate_attestation_certificate"},
    {SYS_myst_oe_free_attestation_certificate,
     "SYS_myst_oe_free_attestation_certificate"},
    {SYS_myst_oe_verify_attestation_certificate,
     "SYS_myst_oe_verify_attestation_certificate"},
    {SYS_myst_oe_result_str, "SYS_myst_oe_result_str"},
};

// The kernel should eventually use _bad_addr() to check all incoming addresses
// from user space. This is a stop gap until the kernel is able to check
// the access rights for a given address (memory obtained with mman and brk).
static bool _bad_addr(const void* p)
{
    if (p == (void*)0xffffffffffffffff)
        return true;

    return false;
}

static bool _iov_bad_addr(const struct iovec* iov, int iovcnt)
{
    if (iov)
    {
        for (int i = 0; i < iovcnt; i++)
        {
            const struct iovec* v = &iov[i];

            if (v->iov_len && _bad_addr(v->iov_base))
                return true;
        }
    }

    return false;
}

static size_t _n_pairs = sizeof(_pairs) / sizeof(_pairs[0]);

const char* syscall_str(long n)
{
    for (size_t i = 0; i < _n_pairs; i++)
    {
        if (n == _pairs[i].num)
            return _pairs[i].str;
    }

    return "unknown";
}

__attribute__((format(printf, 2, 3))) static void _strace(
    long n,
    const char* fmt,
    ...)
{
    if (__options.trace_syscalls)
    {
        char null_char = '\0';
        char* buf = &null_char;
        const bool isatty = myst_syscall_isatty(STDERR_FILENO) == 1;
        const char* blue = isatty ? COLOR_GREEN : "";
        const char* reset = isatty ? COLOR_RESET : "";

        if (fmt)
        {
            const size_t buf_size = 1024;

            if (!(buf = malloc(buf_size)))
                myst_panic("out of memory");

            va_list ap;
            va_start(ap, fmt);
            vsnprintf(buf, buf_size, fmt, ap);
            va_end(ap);
        }

        myst_eprintf(
            "=== %s%s%s(%s): tid=%d\n",
            blue,
            syscall_str(n),
            reset,
            buf,
            myst_gettid());

        if (buf != &null_char)
            free(buf);
    }
}

static long _forward_syscall(long n, long params[6])
{
    if (__options.trace_syscalls)
        myst_eprintf("    [forward syscall]\n");

    return myst_tcall(n, params);
}

typedef struct fd_entry
{
    int fd;
    char path[PATH_MAX];
} fd_entry_t;

static long _return(long n, long ret)
{
    if (__options.trace_syscalls)
    {
        const char* red = "";
        const char* reset = "";
        const char* error_name = NULL;

        if (ret < 0)
        {
            const bool isatty = myst_syscall_isatty(STDERR_FILENO) == 1;

            if (isatty)
            {
                red = COLOR_RED;
                reset = COLOR_RESET;
            }

            error_name = myst_error_name(-ret);
        }

        if (error_name)
        {
            myst_eprintf(
                "    %s%s(): return=-%s(%ld)%s: tid=%d\n",
                red,
                syscall_str(n),
                error_name,
                ret,
                reset,
                myst_gettid());
        }
        else
        {
            myst_eprintf(
                "    %s%s(): return=%ld(%lx)%s: tid=%d\n",
                red,
                syscall_str(n),
                ret,
                ret,
                reset,
                myst_gettid());
        }
    }

    return ret;
}

static int _socketaddr_to_str(
    const struct sockaddr* addr,
    char out[],
    size_t limit)
{
    int ret = 0;

    if (addr == NULL)
    {
        myst_assume(limit >= 5);
        sprintf(out, "NULL");
        goto done;
    }

    const uint8_t* p = (uint8_t*)addr->sa_data;
    uint16_t port = (uint16_t)((p[0] << 8) | p[1]);
    const uint8_t ip1 = p[2];
    const uint8_t ip2 = p[3];
    const uint8_t ip3 = p[4];
    const uint8_t ip4 = p[5];

    if (snprintf(out, limit, "%u.%u.%u.%u:%u", ip1, ip2, ip3, ip4, port) >=
        (int)limit)
    {
        ERAISE(-ENAMETOOLONG);
    }

done:
    return ret;
}

static int _add_fd_link(myst_fs_t* fs, myst_file_t* file, int fd)
{
    int ret = 0;
    struct locals
    {
        char realpath[PATH_MAX];
        char linkpath[PATH_MAX];
    };
    struct locals* locals = NULL;
    const size_t n = sizeof(locals->linkpath);

    if (!fs || !file)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK((*fs->fs_realpath)(
        fs, file, locals->realpath, sizeof(locals->realpath)));

    if (snprintf(locals->linkpath, n, "/proc/%d/fd/%d", myst_getpid(), fd) >=
        (int)n)
        ERAISE(-ENAMETOOLONG);

    ECHECK(symlink(locals->realpath, locals->linkpath));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_creat(const char* pathname, mode_t mode)
{
    long ret = 0;
    int fd;
    myst_fs_t *fs, *fs_out;
    myst_file_t* file;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_FILE;
    long r;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_creat)(fs, locals->suffix, mode, &fs_out, &file));

    if ((fd = myst_fdtable_assign(fdtable, fdtype, fs_out, file)) < 0)
    {
        (*fs_out->fs_close)(fs_out, file);
        ERAISE(fd);
    }

    if ((r = _add_fd_link(fs_out, file, fd)) != 0)
    {
        myst_fdtable_remove(fdtable, fd);
        (*fs_out->fs_close)(fs_out, file);
        ERAISE(r);
    }

    ret = fd;

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_open(const char* pathname, int flags, mode_t mode)
{
    long ret = 0;
    myst_fs_t *fs, *fs_out;
    myst_file_t* file;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_FILE;
    int fd;
    int r;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_open)(fs, locals->suffix, flags, mode, &fs_out, &file));

    if ((fd = myst_fdtable_assign(fdtable, fdtype, fs_out, file)) < 0)
    {
        (*fs_out->fs_close)(fs_out, file);
        ERAISE(fd);
    }

    if ((r = _add_fd_link(fs_out, file, fd)) != 0)
    {
        myst_fdtable_remove(fdtable, fd);
        (*fs_out->fs_close)(fs_out, file);
        ERAISE(r);
    }

    ret = fd;

done:

    if (locals)
        free(locals);

    return ret;
}

static long _openat(
    int dirfd,
    const char* pathname,
    int flags,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file_out)
{
    long ret = 0;
    struct locals
    {
        char suffix[PATH_MAX];
        char dirname[PATH_MAX];
        char filename[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (fs_out)
        *fs_out = NULL;

    if (file_out)
        *file_out = NULL;

    if (!pathname)
        ERAISE(-EINVAL);

    if (*pathname == '\0')
        ERAISE(-ENOENT);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* if pathname is absolute or AT_FDCWD */
    if (*pathname == '/' || dirfd == AT_FDCWD)
    {
        if (fs_out && file_out)
        {
            myst_fs_t* fs;

            ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
            ECHECK((*fs->fs_open)(
                fs, locals->suffix, flags, mode, fs_out, file_out));
        }
        else
        {
            ret = myst_syscall_open(pathname, flags, mode);
        }
    }
    else
    {
        myst_fdtable_t* fdtable = myst_fdtable_current();
        myst_fs_t* fs;
        myst_file_t* file;

        if (dirfd < 0)
            ERAISE(-EBADF);

        /* get the file object for the dirfd */
        ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));

        /* fail if not a directory */
        {
            struct stat buf;
            ERAISE((*fs->fs_fstat)(fs, file, &buf));

            if (!S_ISDIR(buf.st_mode))
                ERAISE(-ENOTDIR);
        }

        /* get the full path of dirfd */
        ECHECK((*fs->fs_realpath)(
            fs, file, locals->dirname, sizeof(locals->dirname)));
        ECHECK(myst_make_path(
            locals->filename,
            sizeof(locals->filename),
            locals->dirname,
            pathname));

        if (fs_out && file_out)
        {
            myst_fs_t* fs;

            ECHECK(myst_mount_resolve(locals->filename, locals->suffix, &fs));
            ECHECK((*fs->fs_open)(
                fs, locals->suffix, flags, mode, fs_out, file_out));
        }
        else
        {
            ret = myst_syscall_open(locals->filename, flags, mode);
        }
    }

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_openat(
    int dirfd,
    const char* pathname,
    int flags,
    mode_t mode)
{
    return _openat(dirfd, pathname, flags, mode, NULL, NULL);
}

long myst_syscall_epoll_create1(int flags)
{
    long ret = 0;
    myst_epolldev_t* ed = myst_epolldev_get();
    myst_epoll_t* epoll;
    int fd;

    if (!ed)
        ERAISE(-EINVAL);

    /* create the epoll object */
    ECHECK((*ed->ed_epoll_create1)(ed, flags, &epoll));

    /* add to file descriptor table */
    {
        myst_fdtable_t* fdtable = myst_fdtable_current();
        const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_EPOLL;

        if ((fd = myst_fdtable_assign(fdtable, fdtype, ed, epoll)) < 0)
        {
            (*ed->ed_close)(ed, epoll);
            ERAISE(fd);
        }
    }

    ret = fd;

done:

    return ret;
}

long myst_syscall_lseek(int fd, off_t offset, int whence)
{
    long ret = 0;
    myst_fs_t* fs;
    myst_file_t* file;
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_FILE;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    ECHECK(myst_fdtable_get(fdtable, fd, type, (void**)&fs, (void**)&file));

    ret = ((*fs->fs_lseek)(fs, file, offset, whence));

done:
    return ret;
}

long myst_syscall_close(int fd)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdtable_type_t type;
    void* device = NULL;
    void* object = NULL;
    myst_fdops_t* fdops;

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    if (type == MYST_FDTABLE_TYPE_FILE)
    {
        /* why does this sometimes fail? */
        myst_remove_fd_link(fd);
    }

    myst_mman_close_notify(fd);
    ECHECK((*fdops->fd_close)(device, object));
    ECHECK(myst_fdtable_remove(fdtable, fd));

done:
    return ret;
}

long myst_syscall_read(int fd, void* buf, size_t count)
{
    long ret = 0;
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdops_t* fdops;

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_read)(device, object, buf, count);

done:
    return ret;
}

long myst_syscall_write(int fd, const void* buf, size_t count)
{
    long ret = 0;
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdops_t* fdops;

    if (!buf && count)
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_write)(device, object, buf, count);

done:
    return ret;
}

long myst_syscall_pread(int fd, void* buf, size_t count, off_t offset)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdtable_type_t type;
    void* device = NULL;
    void* object = NULL;

    if (!buf && count)
        ERAISE(-EFAULT);

    if (offset < 0)
        ERAISE(-EINVAL);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));

    switch (type)
    {
        case MYST_FDTABLE_TYPE_FILE:
        {
            myst_fs_t* fs = device;
            myst_file_t* file = object;
            ret = (*fs->fs_pread)(fs, file, buf, count, offset);
            break;
        }
        case MYST_FDTABLE_TYPE_PIPE:
        {
            ret = -ESPIPE;
            break;
        }
        default:
        {
            ret = -ENOENT;
            break;
        }
    }

done:
    return ret;
}

long myst_syscall_pwrite(int fd, const void* buf, size_t count, off_t offset)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdtable_type_t type;
    void* device = NULL;
    void* object = NULL;

    if (!buf && count)
        ERAISE(-EFAULT);

    if (offset < 0)
        ERAISE(-EINVAL);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));

    switch (type)
    {
        case MYST_FDTABLE_TYPE_FILE:
        {
            myst_fs_t* fs = device;
            myst_file_t* file = object;
            ret = (*fs->fs_pwrite)(fs, file, buf, count, offset);
            break;
        }
        case MYST_FDTABLE_TYPE_PIPE:
        {
            ret = -ESPIPE;
            break;
        }
        default:
        {
            ret = -ENOENT;
            break;
        }
    }

done:
    return ret;
}

long myst_syscall_readv(int fd, const struct iovec* iov, int iovcnt)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdops_t* fdops;

    if (_iov_bad_addr(iov, iovcnt))
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_readv)(device, object, iov, iovcnt);

done:
    return ret;
}

long myst_syscall_writev(int fd, const struct iovec* iov, int iovcnt)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdops_t* fdops;

    if (_iov_bad_addr(iov, iovcnt))
        ERAISE(-EFAULT);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_writev)(device, object, iov, iovcnt);

done:
    return ret;
}

long myst_syscall_stat(const char* pathname, struct stat* statbuf)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_stat)(fs, locals->suffix, statbuf));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_lstat(const char* pathname, struct stat* statbuf)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_lstat)(fs, locals->suffix, statbuf));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_fstat(int fd, struct stat* statbuf)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdtable_type_t type;
    void* device;
    void* object;
    myst_fdops_t* fdops;

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_fstat)(device, object, statbuf);

done:
    return ret;
}

long myst_syscall_fstatat(
    int dirfd,
    const char* pathname,
    struct stat* statbuf,
    int flags)
{
    long ret = 0;
    struct locals
    {
        char realpath[PATH_MAX];
        char dirpath[PATH_MAX];
        char path[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!pathname || !statbuf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* If pathname is absolute, then ignore dirfd */
    if (*pathname == '/' || dirfd == AT_FDCWD)
    {
        if (flags & AT_SYMLINK_NOFOLLOW)
        {
            ECHECK(myst_syscall_lstat(pathname, statbuf));
            goto done;
        }
        else
        {
            ECHECK(myst_syscall_stat(pathname, statbuf));
            goto done;
        }
    }
    else if (*pathname == '\0')
    {
        if (!(flags & AT_EMPTY_PATH))
            ERAISE(-EINVAL);

        if (flags & AT_SYMLINK_NOFOLLOW)
        {
            myst_fdtable_t* fdtable = myst_fdtable_current();
            myst_fs_t* fs;
            myst_file_t* file;

            ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));
            ECHECK((*fs->fs_realpath)(
                fs, file, locals->realpath, sizeof(locals->realpath)));
            ECHECK(myst_syscall_lstat(locals->realpath, statbuf));
            goto done;
        }
        else
        {
            ECHECK(myst_syscall_fstat(dirfd, statbuf));
            goto done;
        }
    }
    else
    {
        myst_fdtable_t* fdtable = myst_fdtable_current();
        myst_fs_t* fs;
        myst_file_t* file;

        ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));
        ECHECK((*fs->fs_realpath)(
            fs, file, locals->dirpath, sizeof(locals->dirpath)));
        ECHECK(myst_make_path(
            locals->path, sizeof(locals->path), locals->dirpath, pathname));

        if (flags & AT_SYMLINK_NOFOLLOW)
        {
            ECHECK(myst_syscall_lstat(locals->path, statbuf));
            goto done;
        }
        else
        {
            ECHECK(myst_syscall_stat(locals->path, statbuf));
            goto done;
        }
    }

done:

    if (locals)
        free(locals);

    return ret;
}

static const char* _trim_trailing_slashes(
    const char* pathname,
    char* buf,
    size_t size)
{
    size_t len = strlen(pathname);

    if (len >= size)
        return NULL;

    /* remove trailing slashes from the pathname if any */
    if ((len = strlen(pathname)) && pathname[len - 1] == '/')
    {
        memcpy(buf, pathname, len + 1);

        for (char* p = buf + len; p != buf && p[-1] == '/'; *--p = '\0')
            ;

        pathname = buf;
    }

    return pathname;
}

long myst_syscall_mkdir(const char* pathname, mode_t mode)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
        char buf[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* remove trailing slash from directory name if any */
    if (!(pathname = _trim_trailing_slashes(
              pathname, locals->buf, sizeof(locals->buf))))
        ERAISE(-ENAMETOOLONG);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_mkdir)(fs, locals->suffix, mode));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_rmdir(const char* pathname)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_rmdir)(fs, locals->suffix));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_getdents64(int fd, struct dirent* dirp, size_t count)
{
    long ret = 0;
    myst_fs_t* fs;
    myst_file_t* file;
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_FILE;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    ECHECK(myst_fdtable_get(fdtable, fd, type, (void**)&fs, (void**)&file));

    ret = (*fs->fs_getdents64)(fs, file, dirp, count);

done:
    return ret;
}

long myst_syscall_link(const char* oldpath, const char* newpath)
{
    long ret = 0;
    myst_fs_t* old_fs;
    myst_fs_t* new_fs;
    struct locals
    {
        char old_suffix[PATH_MAX];
        char new_suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(oldpath, locals->old_suffix, &old_fs));
    ECHECK(myst_mount_resolve(newpath, locals->new_suffix, &new_fs));

    if (old_fs != new_fs)
    {
        /* oldpath and newpath are not on the same mounted file system */
        ERAISE(-EXDEV);
    }

    ECHECK((*old_fs->fs_link)(old_fs, locals->old_suffix, locals->new_suffix));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_unlink(const char* pathname)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_unlink)(fs, locals->suffix));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_access(const char* pathname, int mode)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ECHECK((*fs->fs_access)(fs, locals->suffix, mode));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_rename(const char* oldpath, const char* newpath)
{
    long ret = 0;
    myst_fs_t* old_fs;
    myst_fs_t* new_fs;
    struct locals
    {
        char old_suffix[PATH_MAX];
        char new_suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(oldpath, locals->old_suffix, &old_fs));
    ECHECK(myst_mount_resolve(newpath, locals->new_suffix, &new_fs));

    if (old_fs != new_fs)
    {
        /* oldpath and newpath are not on the same mounted file system */
        ERAISE(-EXDEV);
    }

    ECHECK(
        (*old_fs->fs_rename)(old_fs, locals->old_suffix, locals->new_suffix));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_truncate(const char* path, off_t length)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(path, locals->suffix, &fs));
    ERAISE((*fs->fs_truncate)(fs, locals->suffix, length));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_ftruncate(int fd, off_t length)
{
    long ret = 0;
    myst_fs_t* fs;
    myst_file_t* file;
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_FILE;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    ECHECK(myst_fdtable_get(fdtable, fd, type, (void**)&fs, (void**)&file));
    ERAISE((*fs->fs_ftruncate)(fs, file, length));

done:
    return ret;
}

long myst_syscall_readlink(const char* pathname, char* buf, size_t bufsiz)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));
    ERAISE((*fs->fs_readlink)(fs, locals->suffix, buf, bufsiz));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_symlink(const char* target, const char* linkpath)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(linkpath, locals->suffix, &fs));
    ERAISE((*fs->fs_symlink)(fs, target, locals->suffix));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_chdir(const char* path)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();
    myst_thread_t* process_thread = myst_find_process_thread(thread);
    struct locals
    {
        char buf[PATH_MAX];
        char buf2[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (_bad_addr(path))
        ERAISE(-EFAULT);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    myst_spin_lock(&process_thread->main.cwd_lock);

    if (!path)
        ERAISE(-EINVAL);

    /* filenames cannot be longer than NAME_MAX in Linux */
    if (strlen(myst_basename(path)) > NAME_MAX)
        ERAISE(-ENAMETOOLONG);

    ECHECK(myst_path_absolute_cwd(
        process_thread->main.cwd, path, locals->buf, sizeof(locals->buf)));
    ECHECK(myst_normalize(locals->buf, locals->buf2, sizeof(locals->buf2)));

    /* fail if the directory does not exist */
    {
        struct stat buf;

        if (myst_syscall_stat(locals->buf2, &buf) != 0 || !S_ISDIR(buf.st_mode))
            ERAISE(-ENOENT);
    }

    char* tmp = strdup(locals->buf2);
    if (tmp == NULL)
        ERAISE(-ENOMEM);
    free(process_thread->main.cwd);
    process_thread->main.cwd = tmp;

done:

    if (locals)
        free(locals);

    myst_spin_unlock(&process_thread->main.cwd_lock);

    return ret;
}

long myst_syscall_getcwd(char* buf, size_t size)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();
    myst_thread_t* process_thread = myst_find_process_thread(thread);

    myst_spin_lock(&process_thread->main.cwd_lock);

    if (!buf)
        ERAISE(-EINVAL);

    if (myst_strlcpy(buf, process_thread->main.cwd, size) >= size)
        ERAISE(-ERANGE);

    ret = (long)buf;

done:

    myst_spin_unlock(&process_thread->main.cwd_lock);

    return ret;
}

long myst_syscall_statfs(const char* path, struct statfs* buf)
{
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(path, locals->suffix, &fs));
    if (buf)
        memset(buf, 0, sizeof(*buf));
    ECHECK((*fs->fs_statfs)(fs, locals->suffix, buf));

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_syscall_fstatfs(int fd, struct statfs* buf)
{
    long ret = 0;
    myst_fs_t* fs;
    myst_file_t* file;

    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_FILE;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    ECHECK(myst_fdtable_get(fdtable, fd, type, (void**)&fs, (void**)&file));
    if (buf)
        memset(buf, 0, sizeof(*buf));
    ECHECK((*fs->fs_fstatfs)(fs, file, buf));

done:

    return ret;
}

static char _hostname[HOST_NAME_MAX] = "TEE";
static myst_spinlock_t _hostname_lock = MYST_SPINLOCK_INITIALIZER;

long myst_syscall_uname(struct utsname* buf)
{
    // We are emulating Linux syscalls. 5.4.0 is the LTS release we
    // try to emulate. The release number should be updated when
    // Mystikos adapts to syscall API changes in future Linux releases.
    MYST_STRLCPY(buf->sysname, "Linux");
    MYST_STRLCPY(buf->release, "5.4.0");
    MYST_STRLCPY(buf->version, "Mystikos 1.0.0");
    MYST_STRLCPY(buf->machine, "x86_64");

    myst_spin_lock(&_hostname_lock);
    MYST_STRLCPY(buf->nodename, _hostname);
    myst_spin_unlock(&_hostname_lock);

    return 0;
}

long myst_syscall_sethostname(const char* hostname, MYST_UNUSED size_t len)
{
    myst_spin_lock(&_hostname_lock);
    MYST_STRLCPY(_hostname, hostname);
    myst_spin_unlock(&_hostname_lock);

    return 0;
}

long myst_syscall_getrandom(void* buf, size_t buflen, unsigned int flags)
{
    long ret = 0;

    (void)flags;

    if (!buf && buflen)
        ERAISE(-EINVAL);

    if (buf && buflen && myst_tcall_random(buf, buflen) != 0)
        ERAISE(-EINVAL);

    ret = (long)buflen;

done:
    return ret;
}

long myst_syscall_fcntl(int fd, int cmd, long arg)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    if (cmd == F_DUPFD)
    {
        ret = myst_fdtable_dup(fdtable, MYST_DUPFD, fd, (int)arg, -1);
    }
    else if (cmd == F_DUPFD_CLOEXEC)
    {
        ret = myst_fdtable_dup(fdtable, MYST_DUPFD_CLOEXEC, fd, (int)arg, -1);
    }
    else
    {
        void* device = NULL;
        void* object = NULL;
        myst_fdtable_type_t type;
        myst_fdops_t* fdops;

        ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
        fdops = device;
        ret = (*fdops->fd_fcntl)(device, object, cmd, arg);
    }

done:
    return ret;
}

long myst_syscall_chmod(const char* pathname, mode_t mode)
{
    (void)pathname;
    (void)mode;
    return 0;
}

long myst_syscall_fchmod(int fd, mode_t mode)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdtable_type_t type;
    void* device = NULL;
    void* object = NULL;

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));

    if (type == MYST_FDTABLE_TYPE_SOCK)
    {
        myst_fdops_t* fdops = device;
        int target_fd = (*fdops->fd_target_fd)(fdops, object);

        if (target_fd < 0)
            ERAISE(-EBADF);

        long params[] = {target_fd, mode};
        ret = _forward_syscall(SYS_fchmod, params);
    }
    else if (type == MYST_FDTABLE_TYPE_FILE)
    {
        /* ignore fchmod on files */
    }
    else
    {
        ERAISE(-ENOTSUP);
    }

done:
    return ret;
}

long myst_syscall_pipe2(int pipefd[2], int flags)
{
    int ret = 0;
    myst_pipe_t* pipe[2];
    int fd0;
    int fd1;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_PIPE;
    myst_pipedev_t* pd = myst_pipedev_get();

    if (!pipefd)
        ERAISE(-EINVAL);

    ECHECK((*pd->pd_pipe2)(pd, pipe, flags));

    if ((fd0 = myst_fdtable_assign(fdtable, type, pd, pipe[0])) < 0)
    {
        (*pd->pd_close)(pd, pipe[0]);
        (*pd->pd_close)(pd, pipe[1]);
        ERAISE(fd0);
    }

    if ((fd1 = myst_fdtable_assign(fdtable, type, pd, pipe[1])) < 0)
    {
        myst_fdtable_remove(fdtable, fd0);
        (*pd->pd_close)(pd, pipe[0]);
        (*pd->pd_close)(pd, pipe[1]);
        ERAISE(fd1);
    }

    pipefd[0] = fd0;
    pipefd[1] = fd1;

    if (__options.trace_syscalls)
        myst_eprintf("pipe2(): [%d:%d]\n", fd0, fd1);

done:
    return ret;
}

long myst_syscall_inotify_init1(int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_INOTIFY;
    myst_inotifydev_t* dev = myst_inotifydev_get();
    myst_inotify_t* obj = NULL;
    int fd;

    ECHECK((*dev->id_inotify_init1)(dev, flags, &obj));

    if ((fd = myst_fdtable_assign(fdtable, type, dev, obj)) < 0)
    {
        (*dev->id_close)(dev, obj);
        ERAISE(fd);
    }

    ret = fd;

done:
    return ret;
}

long myst_syscall_inotify_add_watch(int fd, const char* pathname, uint32_t mask)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_inotifydev_t* dev;
    myst_inotify_t* obj;
    int wd;

    ECHECK(myst_fdtable_get_inotify(fdtable, fd, &dev, &obj));
    ECHECK(wd = (*dev->id_inotify_add_watch)(dev, obj, pathname, mask));
    ret = wd;

done:
    return ret;
}

long myst_syscall_inotify_rm_watch(int fd, int wd)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_inotifydev_t* dev;
    myst_inotify_t* obj;

    ECHECK(myst_fdtable_get_inotify(fdtable, fd, &dev, &obj));
    ECHECK((*dev->id_inotify_rm_watch)(dev, obj, wd));

done:
    return ret;
}

static size_t _count_args(const char* const args[])
{
    size_t n = 0;

    if (args)
    {
        while (*args++)
            n++;
    }

    return n;
}

long myst_syscall_execve(
    const char* filename,
    char* const argv_in[],
    char* const envp[])
{
    long ret = 0;
    const char** argv = NULL;
    myst_thread_t* current_thread = myst_thread_self();

    /* ATTN: the filename should be resolved if not an absolute path */
    if (!filename || filename[0] != '/')
        ERAISE(-EINVAL);

    /* Make a copy of argv_in[] and inject filename into argv[0] */
    {
        size_t argc = _count_args((const char* const*)argv_in);

        if (!(argv = calloc(argc + 1, sizeof(char*))))
            ERAISE(-ENOMEM);

        for (size_t i = 0; i < argc; i++)
            argv[i] = argv_in[i];

        argv[0] = filename;
        argv[argc] = NULL;
    }

    /* only returns on failure */
    if (myst_exec(
            current_thread,
            __myst_kernel_args.crt_data,
            __myst_kernel_args.crt_size,
            __myst_kernel_args.crt_reloc_data,
            __myst_kernel_args.crt_reloc_size,
            _count_args(argv),
            (const char**)argv,
            _count_args((const char* const*)envp),
            (const char**)envp,
            free,
            argv) != 0)
    {
        return -ENOENT;
    }

done:
    return ret;
}

long myst_syscall_ioctl(int fd, unsigned long request, long arg)
{
    long ret = 0;
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fdops_t* fdops;

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));
    fdops = device;

    ret = (*fdops->fd_ioctl)(device, object, request, arg);

done:
    return ret;
}

int myst_syscall_bind(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_bind)(sd, sock, addr, addrlen);

done:
    return ret;
}

long myst_syscall_connect(
    int sockfd,
    const struct sockaddr* addr,
    socklen_t addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_connect)(sd, sock, addr, addrlen);

done:
    return ret;
}

long myst_syscall_recvfrom(
    int sockfd,
    void* buf,
    size_t len,
    int flags,
    struct sockaddr* src_addr,
    socklen_t* addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_recvfrom)(sd, sock, buf, len, flags, src_addr, addrlen);

done:
    return ret;
}

long myst_syscall_sendto(
    int sockfd,
    const void* buf,
    size_t len,
    int flags,
    const struct sockaddr* dest_addr,
    socklen_t addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_sendto)(sd, sock, buf, len, flags, dest_addr, addrlen);

done:
    return ret;
}

long myst_syscall_socket(int domain, int type, int protocol)
{
    long ret = 0;
    myst_sockdev_t* sd = myst_sockdev_get();
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sock_t* sock = NULL;
    int sockfd;
    const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_SOCK;

    ECHECK((*sd->sd_socket)(sd, domain, type, protocol, &sock));

    if ((sockfd = myst_fdtable_assign(fdtable, fdtype, sd, sock)) < 0)
    {
        (*sd->sd_close)(sd, sock);
        ERAISE(sockfd);
    }

    ret = sockfd;

done:

    return ret;
}

long myst_syscall_accept4(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen,
    int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;
    myst_sock_t* new_sock = NULL;
    const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_SOCK;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ECHECK((*sd->sd_accept4)(sd, sock, addr, addrlen, flags, &new_sock));

    if ((sockfd = myst_fdtable_assign(fdtable, fdtype, sd, new_sock)) < 0)
    {
        (*sd->sd_close)(sd, new_sock);
        ERAISE(sockfd);
    }

    ret = sockfd;

done:

    return ret;
}

long myst_syscall_sendmsg(int sockfd, const struct msghdr* msg, int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_sendmsg)(sd, sock, msg, flags);

done:
    return ret;
}

long myst_syscall_recvmsg(int sockfd, struct msghdr* msg, int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_recvmsg)(sd, sock, msg, flags);

done:
    return ret;
}

long myst_syscall_shutdown(int sockfd, int how)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_shutdown)(sd, sock, how);

done:
    return ret;
}

long myst_syscall_listen(int sockfd, int backlog)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_listen)(sd, sock, backlog);

done:
    return ret;
}

long myst_syscall_getsockname(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_getsockname)(sd, sock, addr, addrlen);

done:
    return ret;
}

long myst_syscall_socketpair(int domain, int type, int protocol, int sv[2])
{
    int ret = 0;
    int fd0;
    int fd1;
    myst_sock_t* pair[2];
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd = myst_sockdev_get();
    const myst_fdtable_type_t fdtype = MYST_FDTABLE_TYPE_SOCK;

    ECHECK((*sd->sd_socketpair)(sd, domain, type, protocol, pair));

    if ((fd0 = myst_fdtable_assign(fdtable, fdtype, sd, pair[0])) < 0)
    {
        (*sd->sd_close)(sd, pair[0]);
        (*sd->sd_close)(sd, pair[1]);
        ERAISE(fd0);
    }

    if ((fd1 = myst_fdtable_assign(fdtable, fdtype, sd, pair[1])) < 0)
    {
        myst_fdtable_remove(fdtable, fd0);
        (*sd->sd_close)(sd, pair[0]);
        (*sd->sd_close)(sd, pair[1]);
        ERAISE(fd1);
    }

    sv[0] = fd0;
    sv[1] = fd1;

done:
    return ret;
}

long myst_syscall_getpeername(
    int sockfd,
    struct sockaddr* addr,
    socklen_t* addrlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_getpeername)(sd, sock, addr, addrlen);

done:
    return ret;
}

long myst_syscall_setsockopt(
    int sockfd,
    int level,
    int optname,
    const void* optval,
    socklen_t optlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_setsockopt)(sd, sock, level, optname, optval, optlen);

done:
    return ret;
}

long myst_syscall_getsockopt(
    int sockfd,
    int level,
    int optname,
    void* optval,
    socklen_t* optlen)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_sockdev_t* sd;
    myst_sock_t* sock;

    ECHECK(myst_fdtable_get_sock(fdtable, sockfd, &sd, &sock));
    ret = (*sd->sd_getsockopt)(sd, sock, level, optname, optval, optlen);

done:
    return ret;
}

long myst_syscall_dup(int oldfd)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_dup_type_t duptype = MYST_DUP;

    ret = myst_fdtable_dup(fdtable, duptype, oldfd, -1, -1);
    ECHECK(ret);

done:
    return ret;
}

long myst_syscall_dup2(int oldfd, int newfd)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_dup_type_t duptype = MYST_DUP2;

    ret = myst_fdtable_dup(fdtable, duptype, oldfd, newfd, -1);
    ECHECK(ret);

done:
    return ret;
}

long myst_syscall_dup3(int oldfd, int newfd, int flags)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_dup_type_t duptype = MYST_DUP3;

    ret = myst_fdtable_dup(fdtable, duptype, oldfd, newfd, flags);
    ECHECK(ret);

done:
    return ret;
}

long myst_syscall_sched_yield(void)
{
    long params[] = {0};
    return myst_tcall(SYS_sched_yield, params);
}

long myst_syscall_nanosleep(const struct timespec* req, struct timespec* rem)
{
    long params[6] = {(long)req, (long)rem};
    return _forward_syscall(SYS_nanosleep, params);
}
#define NANO_IN_SECOND 1000000000

long myst_syscall_sysinfo(struct sysinfo* info)
{
    long ret = 0;
    long uptime_in_nsecs;
    size_t totalram;
    size_t freeram;

    if (!info)
        ERAISE(-EINVAL);

    ECHECK(myst_get_total_ram(&totalram));
    ECHECK(myst_get_free_ram(&freeram));

    // Only clear out non-reserved portion of the structure.
    // This is to be defensive against different sizes of this
    // structure in musl and glibc.
    memset(info, 0, sizeof(struct sysinfo) - 256);
    info->totalram = totalram;
    info->freeram = freeram;
    info->mem_unit = 1;

    ECHECK((info->procs = myst_get_num_threads()));

    ECHECK((uptime_in_nsecs = myst_times_uptime()));
    info->uptime = uptime_in_nsecs / NANO_IN_SECOND;

    // loads[3], sharedram, bufferram, totalswap,
    // freeswap, totalhigh and freehigh are not supported.

done:
    return ret;
}

long myst_syscall_epoll_ctl(int epfd, int op, int fd, struct epoll_event* event)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_epolldev_t* ed;
    myst_epoll_t* epoll;

    ECHECK(myst_fdtable_get_epoll(fdtable, epfd, &ed, &epoll));

    ret = (*ed->ed_epoll_ctl)(ed, epoll, op, fd, event);

done:
    return ret;
}

long myst_syscall_epoll_wait(
    int epfd,
    struct epoll_event* events,
    int maxevents,
    int timeout)
{
    long ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_epolldev_t* ed;
    myst_epoll_t* epoll;

    ECHECK(myst_fdtable_get_epoll(fdtable, epfd, &ed, &epoll));

    ret = (*ed->ed_epoll_wait)(ed, epoll, events, maxevents, timeout);

done:
    return ret;
}

long myst_syscall_getrusage(int who, struct rusage* usage)
{
    // ATTN: support child process and per-thread usage reporting.
    if (who == RUSAGE_CHILDREN || who == RUSAGE_THREAD)
        return -EINVAL;

    long stime = myst_times_system_time();
    long utime = myst_times_user_time();
    usage->ru_utime.tv_sec = utime / 1000000000;
    usage->ru_utime.tv_usec = utime % 1000000000 * 1000;
    usage->ru_stime.tv_sec = stime / 1000000000;
    usage->ru_stime.tv_usec = stime % 1000000000 * 1000;

    return 0;
}

long myst_syscall_prlimit64(
    int pid,
    int resource,
    struct rlimit* new_rlim,
    struct rlimit* old_rlim)
{
    if (resource >= RLIM_NLIMITS)
        return -EINVAL;

    // Only support for current process
    if (pid)
        return -EINVAL;

    // Only support resource NOFILE
    if (resource != RLIMIT_NOFILE)
        return -EINVAL;

    if (old_rlim)
    {
        // ATTN: return currently effective RLIMIT_NOFILE settings
        old_rlim->rlim_cur = 65536;
        old_rlim->rlim_max = 65536;
    }

    if (new_rlim)
    {
        // ATTN: make RLIMIT_NOFILE settings effective ;
    }

    return 0;
}

long myst_syscall_fsync(int fd)
{
    long ret = 0;
    void* device = NULL;
    void* object = NULL;
    myst_fdtable_type_t type;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    if (fd < 0)
        ERAISE(-EBADF);

    ECHECK(myst_fdtable_get_any(fdtable, fd, &type, &device, &object));

    if (type != MYST_FDTABLE_TYPE_FILE)
        ERAISE(-EROFS);

done:
    return ret;
}

long myst_syscall_utimensat(
    int dirfd,
    const char* pathname,
    const struct timespec times[2],
    int flags)
{
    long ret = 0;

    if (pathname == NULL)
    {
        myst_file_t* file = NULL;
        myst_fs_t* fs = NULL;
        myst_fdtable_t* fdtable = myst_fdtable_current();

        ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));
        ECHECK((*fs->fs_futimens)(fs, file, times));
    }
    else
    {
        myst_fs_t* fs;
        myst_file_t* file;
        int oflags = (flags & ~AT_SYMLINK_NOFOLLOW);
        long r;

        /* translate AT_SYMLINK_NOFOLLOW to O_NOFOLLOW */
        if ((flags & AT_SYMLINK_NOFOLLOW))
            oflags |= O_NOFOLLOW;

        ECHECK(_openat(dirfd, pathname, oflags, O_RDONLY, &fs, &file));

        if ((r = (*fs->fs_futimens)(fs, file, times)) < 0)
        {
            (*fs->fs_close)(fs, file);
            ERAISE(r);
        }

        (*fs->fs_close)(fs, file);
    }

done:
    return ret;
}

long myst_syscall_futimesat(
    int dirfd,
    const char* pathname,
    const struct timeval times[2])
{
    long ret = 0;
    struct timespec buf[2];
    struct timespec* ts = NULL;

    if (times)
    {
        for (size_t i = 0; i < 2; i++)
        {
            const struct timeval* tv = &times[i];
            buf[i].tv_sec = tv->tv_sec + (tv->tv_usec / MICRO_IN_SECOND);
            buf[i].tv_nsec = (tv->tv_usec % MICRO_IN_SECOND) * 1000;
        }

        ts = buf;
    }

    ECHECK(myst_syscall_utimensat(dirfd, pathname, ts, 0));

done:
    return ret;
}

long myst_syscall_get_robust_list(
    int pid,
    myst_robust_list_head_t** head_ptr,
    size_t* len_ptr)
{
    long ret = 0;
    myst_thread_t* thread;

    if (pid < 0)
        ERAISE(-EINVAL);

    if (pid == 0)
        thread = myst_thread_self();
    else if (!(thread = myst_find_thread(pid)))
        ERAISE(-ESRCH);

    myst_spin_lock(&thread->robust_list_head_lock);
    {
        if (head_ptr)
            *head_ptr = thread->robust_list_head;

        if (len_ptr)
            *len_ptr = thread->robust_list_len;
    }
    myst_spin_unlock(&thread->robust_list_head_lock);

done:
    return ret;
}

long myst_syscall_set_robust_list(myst_robust_list_head_t* head, size_t len)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();

    if (len != sizeof(myst_robust_list_head_t))
        ERAISE(-EINVAL);

    myst_spin_lock(&thread->robust_list_head_lock);
    thread->robust_list_head = head;
    thread->robust_list_len = len;
    myst_spin_unlock(&thread->robust_list_head_lock);

done:
    return ret;
}

long myst_syscall_ret(long ret)
{
    if (ret < 0)
    {
        errno = (int)-ret;
        ret = -1;
    }

    return ret;
}

static const char* _fcntl_cmdstr(int cmd)
{
    switch (cmd)
    {
        case F_DUPFD:
            return "F_DUPFD";
        case F_SETFD:
            return "F_SETFD";
        case F_GETFD:
            return "F_GETFD";
        case F_SETFL:
            return "F_SETFL";
        case F_GETFL:
            return "F_GETFL";
        case F_SETOWN:
            return "F_SETOWN";
        case F_GETOWN:
            return "F_GETOWN";
        case F_SETSIG:
            return "F_SETSIG";
        case F_GETSIG:
            return "F_GETSIG";
        case F_SETLK:
            return "F_SETLK";
        case F_GETLK:
            return "F_GETLK";
        case F_SETLKW:
            return "F_SETLKW";
        case F_SETOWN_EX:
            return "F_SETOWN_EX";
        case F_GETOWN_EX:
            return "F_GETOWN_EX";
        case F_GETOWNER_UIDS:
            return "F_GETOWNER_UIDS";
        default:
            return "unknown";
    }
}

#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_FD 2
#define FUTEX_REQUEUE 3
#define FUTEX_CMP_REQUEUE 4
#define FUTEX_WAKE_OP 5
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_WAIT_BITSET 9
#define FUTEX_PRIVATE 128
#define FUTEX_CLOCK_REALTIME 256

static const char* _futex_op_str(int op)
{
    switch (op & ~FUTEX_PRIVATE)
    {
        case FUTEX_WAIT:
            return "FUTEX_WAIT";
        case FUTEX_WAKE:
            return "FUTEX_WAKE";
        case FUTEX_FD:
            return "FUTEX_FD";
        case FUTEX_REQUEUE:
            return "FUTEX_REQUEUE";
        case FUTEX_CMP_REQUEUE:
            return "FUTEX_CMP_REQUEUE";
        case FUTEX_WAKE_OP:
            return "FUTEX_WAKE_OP";
        case FUTEX_LOCK_PI:
            return "FUTEX_LOCK_PI";
        case FUTEX_UNLOCK_PI:
            return "FUTEX_UNLOCK_PI";
        case FUTEX_TRYLOCK_PI:
            return "FUTEX_TRYLOCK_PI";
        case FUTEX_WAIT_BITSET:
            return "FUTEX_WAIT_BITSET";
        default:
            return "UNKNOWN";
    }
}

void myst_dump_ramfs(void)
{
    myst_strarr_t paths = MYST_STRARR_INITIALIZER;

    if (myst_lsr("/", &paths, true) != 0)
        myst_panic("unexpected");

    for (size_t i = 0; i < paths.size; i++)
    {
        printf("%s\n", paths.data[i]);
    }

    myst_strarr_release(&paths);
}

int myst_export_ramfs(void)
{
    int ret = -1;
    myst_strarr_t paths = MYST_STRARR_INITIALIZER;
    void* data = NULL;
    size_t size = 0;

    if (myst_lsr("/", &paths, false) != 0)
        goto done;

    for (size_t i = 0; i < paths.size; i++)
    {
        const char* path = paths.data[i];

        /* Skip over entries in the /proc file system */
        if (strncmp(path, "/proc", 5) == 0)
            continue;

        if (myst_load_file(path, &data, &size) != 0)
        {
            myst_eprintf("Warning! failed to load %s from ramfs\n", path);
            continue;
        }

        if (myst_tcall_export_file(path, data, size) != 0)
        {
            myst_eprintf("Warning! failed to export %s from ramfs\n", path);
            continue;
        }

        free(data);
        data = NULL;
        size = 0;
    }

    ret = 0;

done:
    myst_strarr_release(&paths);

    if (data)
        free(data);

    return ret;
}

#define BREAK(RET)           \
    do                       \
    {                        \
        syscall_ret = (RET); \
        goto done;           \
    } while (0)

typedef struct syscall_args
{
    long n;
    long* params;
    myst_kstack_t* kstack;
} syscall_args_t;

/*
**==============================================================================
**
** _syscall()
**
**==============================================================================
*/

struct syscall_context
{
    myst_thread_t* thread;
    myst_td_t* crt_td;
    myst_td_t* target_td;
    myst_kstack_t* kstack;
    bool* set_thread_area_called;
};

static long _SYS_myst_trace(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* msg = (const char*)params[0];

    _strace(n, "msg=%s", msg);

    return _return(n, 0);
}

static long _SYS_myst_gcov_init(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    long ret = 0;

    (void)params;

#ifdef MYST_ENABLE_GCOV
    {
        libc_t* libc = (libc_t*)params[0];
        FILE* stream = (FILE*)params[1];

        _strace(n, "libc=%p stream=%p", libc, stream);

        if (gcov_init_libc(libc, stream) != 0)
            myst_panic("gcov_init_libc() failed");
    }
#endif

    return _return(n, ret);
}

static long _SYS_myst_trace_ptr(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    printf(
        "trace: %s: %lx %ld\n", (const char*)params[0], params[1], params[1]);
    return _return(n, 0);
}

static long _SYS_myst_dump_stack(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const void* stack = (void*)params[0];

    _strace(n, NULL);

    myst_dump_stack((void*)stack);
    return _return(n, 0);
}

static long _SYS_myst_dump_ehdr(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    myst_dump_ehdr((void*)params[0]);
    return _return(n, 0);
}

static long _SYS_myst_dump_argv(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int argc = (int)params[0];
    const char** argv = (const char**)params[1];

    printf("=== SYS_myst_dump_argv\n");

    printf("argc=%d\n", argc);
    printf("argv=%p\n", argv);

    for (int i = 0; i < argc; i++)
    {
        printf("argv[%d]=%s\n", i, argv[i]);
    }

    printf("argv[argc]=%p\n", argv[argc]);

    return _return(n, 0);
}

static long _SYS_myst_add_symbol_file(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* path = (const char*)params[0];
    const void* text = (const void*)params[1];
    size_t text_size = (size_t)params[2];
    long ret;

    _strace(n, "path=\"%s\" text=%p text_size=%zu\n", path, text, text_size);

    ret = myst_syscall_add_symbol_file(path, text, text_size);

    return _return(n, ret);
}

static long _SYS_myst_load_symbols(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);

    return _return(n, myst_syscall_load_symbols());
}

static long _SYS_myst_unload_symbols(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);

    return _return(n, myst_syscall_unload_symbols());
}

static long _SYS_myst_gen_creds(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    _strace(n, NULL);
    return _forward_syscall(MYST_TCALL_GEN_CREDS, params);
}

static long _SYS_myst_free_creds(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    _strace(n, NULL);
    return _forward_syscall(MYST_TCALL_FREE_CREDS, params);
}

static long _SYS_myst_gen_creds_ex(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    _strace(n, NULL);
    return _forward_syscall(MYST_TCALL_GEN_CREDS_EX, params);
}

static long _SYS_myst_verify_cert(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    _strace(n, NULL);
    return _forward_syscall(MYST_TCALL_VERIFY_CERT, params);
}

static long _SYS_myst_max_threads(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);
    return _return(n, __myst_kernel_args.max_threads);
}

static long _SYS_myst_poll_wake(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);
    return _return(n, myst_tcall_poll_wake());
}

static long _SYS_read(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    void* buf = (void*)params[1];
    size_t count = (size_t)params[2];

    _strace(n, "fd=%d buf=%p count=%zu", fd, buf, count);

    return _return(n, myst_syscall_read(fd, buf, count));
}

static long _SYS_write(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    const void* buf = (const void*)params[1];
    size_t count = (size_t)params[2];

    _strace(n, "fd=%d buf=%p count=%zu", fd, buf, count);

    return _return(n, myst_syscall_write(fd, buf, count));
}

static long _SYS_pread64(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    void* buf = (void*)params[1];
    size_t count = (size_t)params[2];
    off_t offset = (off_t)params[3];

    _strace(n, "fd=%d buf=%p count=%zu offset=%ld", fd, buf, count, offset);

    return _return(n, myst_syscall_pread(fd, buf, count, offset));
}

static long _SYS_pwrite64(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    void* buf = (void*)params[1];
    size_t count = (size_t)params[2];
    off_t offset = (off_t)params[3];

    _strace(n, "fd=%d buf=%p count=%zu offset=%ld", fd, buf, count, offset);

    return _return(n, myst_syscall_pwrite(fd, buf, count, offset));
}

static long _SYS_open(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* path = (const char*)params[0];
    int flags = (int)params[1];
    mode_t mode = (mode_t)params[2];
    long ret;

    _strace(n, "path=\"%s\" flags=0%o mode=0%o", path, flags, mode);

    ret = myst_syscall_open(path, flags, mode);

    return _return(n, ret);
}

static long _SYS_close(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];

    _strace(n, "fd=%d", fd);

    return _return(n, myst_syscall_close(fd));
}

static long _SYS_stat(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* pathname = (const char*)params[0];
    struct stat* statbuf = (struct stat*)params[1];

    _strace(n, "pathname=\"%s\" statbuf=%p", pathname, statbuf);

    return _return(n, myst_syscall_stat(pathname, statbuf));
}

static long _SYS_fstat(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    void* statbuf = (void*)params[1];

    _strace(n, "fd=%d statbuf=%p", fd, statbuf);

    return _return(n, myst_syscall_fstat(fd, statbuf));
}

static long _SYS_lstat(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    /* ATTN: remove this! */
    const char* pathname = (const char*)params[0];
    struct stat* statbuf = (struct stat*)params[1];

    _strace(n, "pathname=\"%s\" statbuf=%p", pathname, statbuf);

    return _return(n, myst_syscall_lstat(pathname, statbuf));
}

static long _SYS_poll(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    struct pollfd* fds = (struct pollfd*)params[0];
    nfds_t nfds = (nfds_t)params[1];
    int timeout = (int)params[2];
    long ret;

    _strace(n, "fds=%p nfds=%ld timeout=%d", fds, nfds, timeout);

    ret = myst_syscall_poll(fds, nfds, timeout);
    return _return(n, ret);
}

static long _SYS_lseek(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    off_t offset = (off_t)params[1];
    int whence = (int)params[2];

    _strace(n, "fd=%d offset=%ld whence=%d", fd, offset, whence);

    return _return(n, myst_syscall_lseek(fd, offset, whence));
}

static long _SYS_mmap(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    void* addr = (void*)params[0];
    size_t length = (size_t)params[1];
    int prot = (int)params[2];
    int flags = (int)params[3];
    int fd = (int)params[4];
    off_t offset = (off_t)params[5];
    void* ptr;
    long ret = 0;

    _strace(
        n,
        "addr=%lx length=%zu(%lx) prot=%d flags=%d fd=%d offset=%lu",
        (long)addr,
        length,
        length,
        prot,
        flags,
        fd,
        offset);

    ptr = myst_mmap(addr, length, prot, flags, fd, offset);

    if (ptr == MAP_FAILED || !ptr)
    {
        ret = -ENOMEM;
    }
    else
    {
        pid_t pid = myst_getpid();

        if (myst_register_process_mapping(pid, ptr, length) != 0)
            myst_panic("failed to register process mapping");

        ret = (long)ptr;
    }

    return _return(n, ret);
}

static long _SYS_mprotect(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const void* addr = (void*)params[0];
    const size_t length = (size_t)params[1];
    const int prot = (int)params[2];

    _strace(
        n,
        "addr=%lx length=%zu(%lx) prot=%d",
        (long)addr,
        length,
        length,
        prot);

    return _return(n, 0);
}

static long _SYS_munmap(long n, long params[6], struct syscall_context* context)
{
    void* addr = (void*)params[0];
    size_t length = (size_t)params[1];

    _strace(n, "addr=%lx length=%zu(%lx)", (long)addr, length, length);

    // if the ummapped region overlaps the CRT thread descriptor, then
    // postpone the unmap because unmapping now would invalidate the
    // stack canary and would raise __stack_chk_fail(); this occurs
    // when munmap() is called from __unmapself()
    if (context->crt_td && addr && length)
    {
        const uint8_t* p = (const uint8_t*)context->crt_td;
        const uint8_t* pend = p + sizeof(myst_td_t);
        const uint8_t* q = (const uint8_t*)addr;
        const uint8_t* qend = q + length;

        if ((p >= q && p < qend) || (pend >= q && pend < qend))
        {
            myst_thread_t* thread = myst_thread_self();

            /* unmap this later when the thread exits */
            if (thread)
            {
                thread->unmapself_addr = addr;
                thread->unmapself_length = length;
            }

            return _return(n, 0);
        }
    }

    return _return(n, (long)myst_munmap(addr, length));
}

static long _SYS_brk(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    void* addr = (void*)params[0];

    _strace(n, "addr=%lx", (long)addr);

    return _return(n, myst_syscall_brk(addr));
}

static long _SYS_rt_sigaction(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int signum = (int)params[0];
    const posix_sigaction_t* act = (const posix_sigaction_t*)params[1];
    posix_sigaction_t* oldact = (posix_sigaction_t*)params[2];

    _strace(n, "signum=%d act=%p oldact=%p", signum, act, oldact);

    long ret = myst_signal_sigaction(signum, act, oldact);
    return _return(n, ret);
}

static long _SYS_rt_sigprocmask(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int how = (int)params[0];
    const sigset_t* set = (sigset_t*)params[1];
    sigset_t* oldset = (sigset_t*)params[2];

    _strace(n, "how=%d set=%p oldset=%p", how, set, oldset);

    long ret = myst_signal_sigprocmask(how, set, oldset);
    return _return(n, ret);
}

static long _SYS_ioctl(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    unsigned long request = (unsigned long)params[1];
    long arg = (long)params[2];
    int iarg = -1;

    if (request == FIONBIO && arg)
        iarg = *(int*)arg;

    _strace(n, "fd=%d request=0x%lx arg=%lx iarg=%d", fd, request, arg, iarg);

    return _return(n, myst_syscall_ioctl(fd, request, arg));
}

static long _SYS_readv(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    const struct iovec* iov = (const struct iovec*)params[1];
    int iovcnt = (int)params[2];

    _strace(n, "fd=%d iov=%p iovcnt=%d", fd, iov, iovcnt);

    return _return(n, myst_syscall_readv(fd, iov, iovcnt));
}

static long _SYS_writev(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    const struct iovec* iov = (const struct iovec*)params[1];
    int iovcnt = (int)params[2];

    _strace(n, "fd=%d iov=%p iovcnt=%d", fd, iov, iovcnt);

    return _return(n, myst_syscall_writev(fd, iov, iovcnt));
}

static long _SYS_access(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* pathname = (const char*)params[0];
    int mode = (int)params[1];

    _strace(n, "pathname=\"%s\" mode=%d", pathname, mode);

    return _return(n, myst_syscall_access(pathname, mode));
}

static long _SYS_pipe(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int* pipefd = (int*)params[0];

    _strace(n, "pipefd=%p flags=%0o", pipefd, 0);

    return _return(n, myst_syscall_pipe2(pipefd, 0));
}

static long _SYS_select(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int nfds = (int)params[0];
    fd_set* rfds = (fd_set*)params[1];
    fd_set* wfds = (fd_set*)params[2];
    fd_set* efds = (fd_set*)params[3];
    struct timeval* timeout = (struct timeval*)params[4];
    long ret;

    _strace(
        n,
        "nfds=%d rfds=%p wfds=%p xfds=%p timeout=%p",
        nfds,
        rfds,
        wfds,
        efds,
        timeout);

    ret = myst_syscall_select(nfds, rfds, wfds, efds, timeout);
    return _return(n, ret);
}

static long _SYS_sched_yield(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);

    return _return(n, myst_syscall_sched_yield());
}

static long _SYS_mremap(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    void* old_address = (void*)params[0];
    size_t old_size = (size_t)params[1];
    size_t new_size = (size_t)params[2];
    int flags = (int)params[3];
    void* new_address = (void*)params[4];
    long ret;

    _strace(
        n,
        "old_address=%p "
        "old_size=%zu "
        "new_size=%zu "
        "flags=%d "
        "new_address=%p ",
        old_address,
        old_size,
        new_size,
        flags,
        new_address);

    ret =
        (long)myst_mremap(old_address, old_size, new_size, flags, new_address);

    return _return(n, ret);
}

static long _SYS_msync(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    void* addr = (void*)params[0];
    size_t length = (size_t)params[1];
    int flags = (int)params[2];

    _strace(n, "addr=%p length=%zu flags=%d ", addr, length, flags);

    return _return(n, myst_msync(addr, length, flags));
}

static long _SYS_madvise(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    void* addr = (void*)params[0];
    size_t length = (size_t)params[1];
    int advice = (int)params[2];

    _strace(n, "addr=%p length=%zu advice=%d", addr, length, advice);

    return _return(n, 0);
}

static long _SYS_dup(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int oldfd = (int)params[0];
    long ret;

    _strace(n, "oldfd=%d", oldfd);

    ret = myst_syscall_dup(oldfd);
    return _return(n, ret);
}

static long _SYS_dup2(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int oldfd = (int)params[0];
    int newfd = (int)params[1];
    long ret;

    _strace(n, "oldfd=%d newfd=%d", oldfd, newfd);

    ret = myst_syscall_dup2(oldfd, newfd);
    return _return(n, ret);
}

static long _SYS_dup3(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int oldfd = (int)params[0];
    int newfd = (int)params[1];
    int flags = (int)params[2];
    long ret;

    _strace(n, "oldfd=%d newfd=%d flags=%o", oldfd, newfd, flags);

    ret = myst_syscall_dup3(oldfd, newfd, flags);
    return _return(n, ret);
}

static long _SYS_nanosleep(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const struct timespec* req = (const struct timespec*)params[0];
    struct timespec* rem = (struct timespec*)params[1];

    _strace(n, "req=%p rem=%p", req, rem);

    return _return(n, myst_syscall_nanosleep(req, rem));
}

static long _SYS_myst_run_itimer(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);
    return _return(n, myst_syscall_run_itimer());
}

static long _SYS_myst_start_shell(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
#if !defined(MYST_RELEASE)
    _strace(n, NULL);
    myst_start_shell("\nMystikos shell (syscall)\n");
#endif
    return _return(n, 0);
}

static long _SYS_getitimer(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int which = (int)params[0];
    struct itimerval* curr_value = (void*)params[1];

    _strace(n, "which=%d curr_value=%p", which, curr_value);

    return _return(n, myst_syscall_getitimer(which, curr_value));
}

static long _SYS_setitimer(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int which = (int)params[0];
    const struct itimerval* new_value = (void*)params[1];
    struct itimerval* old_value = (void*)params[2];

    _strace(
        n, "which=%d new_value=%p old_value=%p", which, new_value, old_value);

    return _return(n, myst_syscall_setitimer(which, new_value, old_value));
}

static long _SYS_getpid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);
    return _return(n, myst_getpid());
}

static long _SYS_myst_clone(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    long* args = (long*)params[0];
    int (*fn)(void*) = (void*)args[0];
    void* child_stack = (void*)args[1];
    int flags = (int)args[2];
    void* arg = (void*)args[3];
    pid_t* ptid = (pid_t*)args[4];
    void* newtls = (void*)args[5];
    pid_t* ctid = (void*)args[6];

    _strace(
        n,
        "fn=%p "
        "child_stack=%p "
        "flags=%x "
        "arg=%p "
        "ptid=%p "
        "newtls=%p "
        "ctid=%p",
        fn,
        child_stack,
        flags,
        arg,
        ptid,
        newtls,
        ctid);

    long ret =
        myst_syscall_clone(fn, child_stack, flags, arg, ptid, newtls, ctid);

    if ((flags & CLONE_VFORK))
    {
        // ATTN: give the thread a little time to start to avoid a
        // syncyhronization error. This suppresses a failure in the
        // popen test. This should be investigated later.
        myst_sleep_msec(5);
    }

    return _return(n, ret);
}

static long _SYS_execve(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* filename = (const char*)params[0];
    char** argv = (char**)params[1];
    char** envp = (char**)params[2];

    _strace(n, "filename=%s argv=%p envp=%p", filename, argv, envp);

    long ret = myst_syscall_execve(filename, argv, envp);
    return _return(n, ret);
}

static long _SYS_exit(long n, long params[6], struct syscall_context* context)
{
    const int status = (int)params[0];
    myst_thread_t* thread = myst_thread_self();

    _strace(n, "status=%d", status);

    if (!thread || thread->magic != MYST_THREAD_MAGIC)
        myst_panic("unexpected");

    thread->exit_status = status;

    /* the kstack is freed after the long-jump below */
    thread->kstack = context->kstack;

    if (thread == __myst_main_thread)
    {
        // execute fini functions with the CRT fsbase since only
        // gcov uses them and gcov calls into CRT.
        myst_set_fsbase(context->crt_td);
        myst_call_fini_functions();
        myst_set_fsbase(context->target_td);

        if (__options.export_ramfs)
            myst_export_ramfs();
    }

    myst_longjmp(&thread->jmpbuf, 1);

    /* unreachable */
    return _return(n, 0);
}

static long _SYS_wait4(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    pid_t pid = (pid_t)params[0];
    int* wstatus = (int*)params[1];
    int options = (int)params[2];
    struct rusage* rusage = (struct rusage*)params[3];
    long ret;

    ret = myst_syscall_wait4(pid, wstatus, options, rusage);
    return _return(n, ret);
}

static long _SYS_kill(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int pid = (int)params[0];
    int sig = (int)params[1];

    _strace(n, "pid=%d sig=%d", pid, sig);

    long ret = myst_syscall_kill(pid, sig);
    return _return(n, ret);
}

static long _SYS_uname(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    struct utsname* buf = (struct utsname*)params[0];

    return _return(n, myst_syscall_uname(buf));
}

static long _SYS_fcntl(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    int cmd = (int)params[1];
    long arg = (long)params[2];
    long ret;

    const char* cmdstr = _fcntl_cmdstr(cmd);
    _strace(n, "fd=%d cmd=%d(%s) arg=0%lo", fd, cmd, cmdstr, arg);

    ret = myst_syscall_fcntl(fd, cmd, arg);
    return _return(n, ret);
}

static long _SYS_flock(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    int cmd = (int)params[1];

    _strace(n, "fd=%d cmd=%d", fd, cmd);

    return _return(n, 0);
}

static long _SYS_fsync(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];

    _strace(n, "fd=%d", fd);

    return _return(n, myst_syscall_fsync(fd));
}

static long _SYS_truncate(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* path = (const char*)params[0];
    off_t length = (off_t)params[1];

    _strace(n, "path=\"%s\" length=%ld", path, length);

    return _return(n, myst_syscall_truncate(path, length));
}

static long _SYS_ftruncate(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    off_t length = (off_t)params[1];

    _strace(n, "fd=%d length=%ld", fd, length);

    return _return(n, myst_syscall_ftruncate(fd, length));
}

static long _SYS_getcwd(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    char* buf = (char*)params[0];
    size_t size = (size_t)params[1];

    _strace(n, "buf=%p size=%zu", buf, size);

    return _return(n, myst_syscall_getcwd(buf, size));
}

static long _SYS_chdir(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* path = (const char*)params[0];

    _strace(n, "path=\"%s\"", path);

    return _return(n, myst_syscall_chdir(path));
}

static long _SYS_rename(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* oldpath = (const char*)params[0];
    const char* newpath = (const char*)params[1];

    _strace(n, "oldpath=\"%s\" newpath=\"%s\"", oldpath, newpath);

    return _return(n, myst_syscall_rename(oldpath, newpath));
}

static long _SYS_mkdir(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* pathname = (const char*)params[0];
    mode_t mode = (mode_t)params[1];

    _strace(n, "pathname=\"%s\" mode=0%o", pathname, mode);

    return _return(n, myst_syscall_mkdir(pathname, mode));
}

static long _SYS_rmdir(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* pathname = (const char*)params[0];

    _strace(n, "pathname=\"%s\"", pathname);

    return _return(n, myst_syscall_rmdir(pathname));
}

static long _SYS_creat(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* pathname = (const char*)params[0];
    mode_t mode = (mode_t)params[1];

    _strace(n, "pathname=\"%s\" mode=%x", pathname, mode);

    return _return(n, myst_syscall_creat(pathname, mode));
}

static long _SYS_link(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* oldpath = (const char*)params[0];
    const char* newpath = (const char*)params[1];

    _strace(n, "oldpath=\"%s\" newpath=\"%s\"", oldpath, newpath);

    return _return(n, myst_syscall_link(oldpath, newpath));
}

static long _SYS_unlink(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* pathname = (const char*)params[0];

    _strace(n, "pathname=\"%s\"", pathname);

    return _return(n, myst_syscall_unlink(pathname));
}

static long _SYS_symlink(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* target = (const char*)params[0];
    const char* linkpath = (const char*)params[1];

    _strace(n, "target=\"%s\" linkpath=\"%s\"", target, linkpath);

    return _return(n, myst_syscall_symlink(target, linkpath));
}

static long _SYS_readlink(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* pathname = (const char*)params[0];
    char* buf = (char*)params[1];
    size_t bufsiz = (size_t)params[2];

    _strace(n, "pathname=\"%s\" buf=%p bufsiz=%zu", pathname, buf, bufsiz);

    return _return(n, myst_syscall_readlink(pathname, buf, bufsiz));
}

static long _SYS_chmod(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* pathname = (const char*)params[0];
    mode_t mode = (mode_t)params[1];

    _strace(n, "pathname=\"%s\" mode=%o", pathname, mode);

    return _return(n, myst_syscall_chmod(pathname, mode));
}

static long _SYS_fchmod(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    mode_t mode = (mode_t)params[1];

    _strace(n, "fd=%d mode=%o", fd, mode);

    return _return(n, myst_syscall_fchmod(fd, mode));
}

static long _SYS_chown(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* pathname = (const char*)params[0];
    uid_t owner = (uid_t)params[1];
    gid_t group = (gid_t)params[2];

    _strace(n, "pathname=%s owner=%u group=%u", pathname, owner, group);

    /* owner is a no-op for now since kernel executes as root */
    return _return(n, 0);
}

static long _SYS_umask(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    mode_t mask = (mode_t)params[0];

    _strace(n, "mask=%o", mask);

    return _return(n, myst_syscall_umask(mask));
}

static long _SYS_gettimeofday(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    struct timeval* tv = (struct timeval*)params[0];
    struct timezone* tz = (void*)params[1];

    _strace(n, "tv=%p tz=%p", tv, tz);

    long ret = myst_syscall_gettimeofday(tv, tz);
    return _return(n, ret);
}

static long _SYS_getrusage(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int who = (int)params[0];
    struct rusage* usage = (struct rusage*)params[1];

    _strace(n, "who=%d usage=%p", who, usage);

    long ret = myst_syscall_getrusage(who, usage);
    return _return(n, ret);
}

static long _SYS_sysinfo(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    struct sysinfo* info = (struct sysinfo*)params[0];
    _strace(n, "info=%p", info);
    long ret = myst_syscall_sysinfo(info);
    return _return(n, ret);
}

static long _SYS_times(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    struct tms* tm = (struct tms*)params[0];
    _strace(n, "tm=%p", tm);

    long stime = myst_times_system_time();
    long utime = myst_times_user_time();
    if (tm != NULL)
    {
        tm->tms_utime = utime;
        tm->tms_stime = stime;
        tm->tms_cutime = 0;
        tm->tms_cstime = 0;
    }

    return _return(n, stime + utime);
}

static long _SYS_syslog(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    /* Ignore syslog for now */
    return _return(n, 0);
}

static long _SYS_setpgid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    gid_t gid = (gid_t)params[0];
    long ret = 0;

    _strace(n, "gid=%u", gid);

    /* do not allow the GID to be changed */
    if (gid != MYST_DEFAULT_GID)
        ret = -EPERM;

    return _return(n, ret);
}

static long _SYS_getpgid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);
    return _return(n, MYST_DEFAULT_GID);
}

static long _SYS_getppid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);
    return _return(n, myst_getppid());
}

static long _SYS_getsid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);
    return _return(n, myst_getsid());
}

static long _SYS_getgroups(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    size_t size = (size_t)params[0];
    gid_t* list = (gid_t*)params[1];
    /* return the extra groups on the thread */;
    _strace(n, NULL);
    return _return(n, myst_syscall_getgroups(size, list));
}

static long _SYS_setgroups(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int size = (int)params[0];
    const gid_t* list = (const gid_t*)params[1];

    /* return the extra groups on the thread */;
    _strace(n, NULL);
    return _return(n, myst_syscall_setgroups(size, list));
}

static long _SYS_getuid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    /* return the real uid of the thread */;
    _strace(n, NULL);
    return _return(n, myst_syscall_getuid());
}

static long _SYS_setuid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    /* Set euid and fsuid to arg1, and if euid is already set to root
     * also set uid and savuid of the thread */
    uid_t uid = (uid_t)params[0];
    _strace(n, "uid=%u", uid);

    return _return(n, myst_syscall_setuid(uid));
}

static long _SYS_getgid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    /* return the gid of the thread */;
    _strace(n, NULL);
    return _return(n, myst_syscall_getgid());
}

static long _SYS_setgid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    /* set the effective gid (euid) of the thread, unless egid is root
     * in which case set all gids */
    gid_t gid = (gid_t)params[0];
    _strace(n, "gid=%u", gid);
    return _return(n, myst_syscall_setgid(gid));
}

static long _SYS_geteuid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    /* return threads effective uid (euid) */
    _strace(n, NULL);
    return _return(n, myst_syscall_geteuid());
}

static long _SYS_getegid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    /* return threads effective gid (egid) */
    _strace(n, NULL);
    return _return(n, myst_syscall_getegid());
}

static long _SYS_setreuid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    /* set the real and effective uid of the thread */
    uid_t ruid = (uid_t)params[0];
    uid_t euid = (uid_t)params[1];
    _strace(n, "Changing IDs to ruid=%u, euid=%u", ruid, euid);
    return _return(n, myst_syscall_setreuid(ruid, euid));
}

static long _SYS_setregid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    /* set the real and effective uid of the thread */
    gid_t rgid = (gid_t)params[0];
    gid_t egid = (gid_t)params[1];
    _strace(n, "Changing setting to rgid=%u, egid=%u", rgid, egid);
    return _return(n, myst_syscall_setregid(rgid, egid));
}

static long _SYS_setresuid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    /* set the real and effective uid of the thread */
    uid_t ruid = (uid_t)params[0];
    uid_t euid = (uid_t)params[1];
    uid_t savuid = (uid_t)params[2];
    _strace(
        n,
        "Changing setting to ruid=%u, euid=%u, savuid=%u",
        ruid,
        euid,
        savuid);
    return _return(n, myst_syscall_setresuid(ruid, euid, savuid));
}

static long _SYS_getresuid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    uid_t* ruid = (uid_t*)params[0];
    uid_t* euid = (uid_t*)params[1];
    uid_t* savuid = (uid_t*)params[2];
    _strace(n, NULL);
    return _return(n, myst_syscall_getresuid(ruid, euid, savuid));
}

static long _SYS_setresgid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    /* set the real and effective uid of the thread */
    gid_t rgid = (gid_t)params[0];
    gid_t egid = (gid_t)params[1];
    gid_t savgid = (gid_t)params[2];
    _strace(
        n,
        "Changing setting to rgid=%u, egid=%u, savgid=%u",
        rgid,
        egid,
        savgid);
    return _return(n, myst_syscall_setresgid(rgid, egid, savgid));
}

static long _SYS_getresgid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    gid_t* rgid = (gid_t*)params[0];
    gid_t* egid = (gid_t*)params[1];
    gid_t* savgid = (gid_t*)params[2];
    _strace(n, NULL);
    return _return(n, myst_syscall_getresgid(rgid, egid, savgid));
}

static long _SYS_setfsuid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    uid_t fsuid = (uid_t)params[0];
    _strace(n, "fsuid=%u", fsuid);
    return _return(n, myst_syscall_setfsuid(fsuid));
}

static long _SYS_setfsgid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    gid_t fsgid = (gid_t)params[0];
    _strace(n, "fsgid=%u", fsgid);
    return _return(n, myst_syscall_setfsgid(fsgid));
}

static long _SYS_rt_sigpending(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    sigset_t* set = (sigset_t*)params[0];
    unsigned size = (unsigned)params[1];
    return _return(n, myst_signal_sigpending(set, size));
}

static long _SYS_sigaltstack(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    /* ATTN: support user space stack for segv handling. */
    return _return(n, 0);
}

static long _SYS_mknod(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* pathname = (const char*)params[0];
    mode_t mode = (mode_t)params[1];
    dev_t dev = (dev_t)params[2];
    long ret = 0;

    _strace(n, "pathname=%s mode=%d dev=%lu", pathname, mode, dev);

    if (S_ISFIFO(mode))
    {
        /* ATTN: create a pipe here! */
    }
    else
    {
        ret = -ENOTSUP;
    }

    return _return(n, ret);
}

static long _SYS_statfs(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* path = (const char*)params[0];
    struct statfs* buf = (struct statfs*)params[1];

    _strace(n, "path=%s buf=%p", path, buf);

    long ret = myst_syscall_statfs(path, buf);

    return _return(n, ret);
}

static long _SYS_fstatfs(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    struct statfs* buf = (struct statfs*)params[1];

    _strace(n, "fd=%d buf=%p", fd, buf);

    long ret = myst_syscall_fstatfs(fd, buf);

    return _return(n, ret);
}

static long _SYS_sched_setparam(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    /* ATTN: support setting thread priorities. */
    return _return(n, 0);
}

static long _SYS_sched_getparam(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    pid_t pid = (pid_t)params[0];
    struct sched_param* param = (struct sched_param*)params[1];

    _strace(n, "pid=%d param=%p", pid, param);

    // ATTN: Return the priority from SYS_sched_setparam.
    if (param != NULL)
    {
        // Only memset the non reserved part of the structure
        // This is to be defensive against different sizes of this
        // struct in musl and glibc.
        memset(param, 0, sizeof(*param) - 40);
    }
    return _return(n, 0);
}

static long _SYS_sched_setscheduler(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    // ATTN: support different schedules, FIFO, RR, BATCH, etc.
    // The more control we have on threads inside the kernel, the more
    // schedulers we could support.
    return _return(n, 0);
}

static long _SYS_sched_getscheduler(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    /* ATTN: return the scheduler installed from sched_setscheduler. */
    return _return(n, SCHED_OTHER);
}

static long _SYS_sched_get_priority_max(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    /* ATTN: support thread priorities */
    return _return(n, 0);
}

static long _SYS_sched_get_priority_min(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    /* ATTN: support thread priorities */
    return _return(n, 0);
}

static long _SYS_mlock(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const void* addr = (const void*)params[0];
    size_t len = (size_t)params[1];
    long ret = 0;

    _strace(n, "addr=%p len=%zu\n", addr, len);

    if (!addr)
        ret = -EINVAL;

    // ATTN: forward the request to target.
    // Some targets, such as sgx, probably just ignore it.

    return _return(n, ret);
}

static long _SYS_prctl(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int option = (int)params[0];
    long ret = 0;

    _strace(n, "option=%d\n", option);

    if (option == PR_GET_NAME)
    {
        char* arg2 = (char*)params[1];
        if (!arg2)
            return _return(n, -EINVAL);

        strcpy(arg2, myst_get_thread_name(myst_thread_self()));
    }
    else if (option == PR_SET_NAME)
    {
        char* arg2 = (char*)params[1];
        if (!arg2)
            return _return(n, -EINVAL);

        ret = myst_set_thread_name(myst_thread_self(), arg2);
    }
    else
    {
        ret = -EINVAL;
    }

    return _return(n, ret);
}

static long _SYS_mount(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* source = (const char*)params[0];
    const char* target = (const char*)params[1];
    const char* filesystemtype = (const char*)params[2];
    unsigned long mountflags = (unsigned long)params[3];
    void* data = (void*)params[4];
    long ret;

    _strace(
        n,
        "source=%s target=%s filesystemtype=%s mountflags=%lu data=%p",
        source,
        target,
        filesystemtype,
        mountflags,
        data);

    ret = myst_syscall_mount(source, target, filesystemtype, mountflags, data);

    return _return(n, ret);
}

static long _SYS_umount2(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* target = (const char*)params[0];
    int flags = (int)params[1];
    long ret;

    _strace(n, "target=%p flags=%d", target, flags);

    ret = myst_syscall_umount2(target, flags);

    return _return(n, ret);
}

static long _SYS_sethostname(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    const char* name = (const char*)params[0];
    size_t len = (size_t)params[1];

    _strace(n, "name=\"%s\" len=%zu", name, len);

    return _return(n, myst_syscall_sethostname(name, len));
}

static long _SYS_gettid(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);
    return _return(n, myst_gettid());
}

static long _SYS_tkill(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int tid = (int)params[0];
    int sig = (int)params[1];

    _strace(n, "tid=%d sig=%d", tid, sig);

    myst_thread_t* thread = myst_thread_self();
    int tgid = thread->pid;

    long ret = myst_syscall_tgkill(tgid, tid, sig);
    return _return(n, ret);
}

static long _SYS_time(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    time_t* tloc = (time_t*)params[0];

    _strace(n, "tloc=%p", tloc);
    long ret = myst_syscall_time(tloc);
    return _return(n, ret);
}

static long _SYS_futex(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int* uaddr = (int*)params[0];
    int futex_op = (int)params[1];
    int val = (int)params[2];
    long arg = (long)params[3];
    int* uaddr2 = (int*)params[4];
    int val3 = (int)val3;

    _strace(
        n,
        "uaddr=0x%lx(%d) futex_op=%u(%s) val=%d",
        (long)uaddr,
        (uaddr ? *uaddr : -1),
        futex_op,
        _futex_op_str(futex_op),
        val);

    return _return(
        n, myst_syscall_futex(uaddr, futex_op, val, arg, uaddr2, val3));
}

static long _SYS_sched_setaffinity(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    pid_t pid = (pid_t)params[0];
    size_t cpusetsize = (pid_t)params[1];
    cpu_set_t* mask = (cpu_set_t*)params[2];

    _strace(n, "pid=%d cpusetsize=%zu mask=%p\n", pid, cpusetsize, mask);

    /* ATTN: support set affinity requests */

    return _return(n, 0);
}

static long _SYS_sched_getaffinity(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    pid_t pid = (pid_t)params[0];
    size_t cpusetsize = (pid_t)params[1];
    cpu_set_t* mask = (cpu_set_t*)params[2];

    _strace(n, "pid=%d cpusetsize=%zu mask=%p\n", pid, cpusetsize, mask);

    // ATTN: return the cpu id from sched_setaffinity.
    // for now, make all threads fixed to cpu 0.
    if (mask != NULL)
    {
        CPU_ZERO(mask);
        CPU_SET(0, mask);
    }

    return _return(n, cpusetsize);
}

static long _SYS_set_thread_area(
    long n,
    long params[6],
    struct syscall_context* context)
{
    void* tp = (void*)params[0];

    _strace(n, "tp=%p", tp);

    /* ---------- running target thread descriptor ---------- */

#ifdef DISABLE_MULTIPLE_SET_THREAD_AREA_SYSCALLS
    if (_set_thread_area_called)
        myst_panic("SYS_set_thread_area called twice");
#endif

    /* get the C-runtime thread descriptor */
    context->crt_td = (myst_td_t*)tp;
    assert(myst_valid_td(context->crt_td));

    /* set the C-runtime thread descriptor for this thread */
    context->thread->crt_td = context->crt_td;

    /* propagate the canary from the old thread descriptor */
    (context->crt_td)->canary = context->target_td->canary;

    *context->set_thread_area_called = true;

    return _return(n, 0);
}

static long _SYS_epoll_create(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int size = (int)params[0];

    _strace(n, "size=%d", size);

    if (size <= 0)
        return _return(n, -EINVAL);

    return _return(n, myst_syscall_epoll_create1(0));
}

static long _SYS_getdents64(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    unsigned int fd = (unsigned int)params[0];
    struct dirent* dirp = (struct dirent*)params[1];
    unsigned int count = (unsigned int)params[2];

    _strace(n, "fd=%d dirp=%p count=%u", fd, dirp, count);

    return _return(n, myst_syscall_getdents64((int)fd, dirp, count));
}

static long _SYS_set_tid_address(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int* tidptr = (int*)params[0];

    /* ATTN: unused */

    _strace(n, "tidptr=%p *tidptr=%d", tidptr, tidptr ? *tidptr : -1);

    return _return(n, myst_getpid());
}

static long _SYS_fadvise64(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    loff_t offset = (loff_t)params[1];
    loff_t len = (loff_t)params[2];
    int advice = (int)params[3];

    _strace(n, "fd=%d offset=%ld len=%ld advice=%d", fd, offset, len, advice);

    /* ATTN: no-op */
    return _return(n, 0);
}

static long _SYS_clock_settime(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    clockid_t clk_id = (clockid_t)params[0];
    struct timespec* tp = (struct timespec*)params[1];

    _strace(n, "clk_id=%u tp=%p", clk_id, tp);

    return _return(n, myst_syscall_clock_settime(clk_id, tp));
}

static long _SYS_clock_gettime(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    clockid_t clk_id = (clockid_t)params[0];
    struct timespec* tp = (struct timespec*)params[1];

    _strace(n, "clk_id=%u tp=%p", clk_id, tp);

    return _return(n, myst_syscall_clock_gettime(clk_id, tp));
}

static long _SYS_clock_getres(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    clockid_t clk_id = (clockid_t)params[0];
    struct timespec* res = (struct timespec*)params[1];

    _strace(n, "clk_id=%u tp=%p", clk_id, res);

    return _return(n, myst_syscall_clock_getres(clk_id, res));
}

static long _SYS_exit_group(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int status = (int)params[0];
    _strace(n, "status=%d", status);

    myst_kill_thread_group();
    return _return(n, 0);
}

static long _SYS_epoll_wait(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int epfd = (int)params[0];
    struct epoll_event* events = (struct epoll_event*)params[1];
    int maxevents = (int)params[2];
    int timeout = (int)params[3];
    long ret;

    _strace(
        n,
        "edpf=%d events=%p maxevents=%d timeout=%d",
        epfd,
        events,
        maxevents,
        timeout);

    ret = myst_syscall_epoll_wait(epfd, events, maxevents, timeout);
    return _return(n, ret);
}

static long _SYS_epoll_ctl(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int epfd = (int)params[0];
    int op = (int)params[1];
    int fd = (int)params[2];
    struct epoll_event* event = (struct epoll_event*)params[3];
    long ret;

    _strace(n, "edpf=%d op=%d fd=%d event=%p", epfd, op, fd, event);

    ret = myst_syscall_epoll_ctl(epfd, op, fd, event);
    return _return(n, ret);
}

static long _SYS_tgkill(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int tgid = (int)params[0];
    int tid = (int)params[1];
    int sig = (int)params[2];

    _strace(n, "tgid=%d tid=%d sig=%d", tgid, tid, sig);

    long ret = myst_syscall_tgkill(tgid, tid, sig);
    return _return(n, ret);
}

static long _SYS_inotify_init(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)params;
    _strace(n, NULL);

    long ret = myst_syscall_inotify_init1(0);
    return _return(n, ret);
}

static long _SYS_inotify_add_watch(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    const char* pathname = (const char*)params[1];
    uint32_t mask = (uint32_t)params[2];

    _strace(n, "fd=%d pathname=%s mask=%x", fd, pathname, mask);

    long ret = myst_syscall_inotify_add_watch(fd, pathname, mask);
    return _return(n, ret);
}

static long _SYS_inotify_rm_watch(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    int wd = (int)params[1];

    _strace(n, "fd=%d wd=%d", fd, wd);

    long ret = myst_syscall_inotify_rm_watch(fd, wd);
    return _return(n, ret);
}

static long _SYS_openat(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int dirfd = (int)params[0];
    const char* path = (const char*)params[1];
    int flags = (int)params[2];
    mode_t mode = (mode_t)params[3];
    long ret;

    _strace(
        n, "dirfd=%d path=\"%s\" flags=0%o mode=0%o", dirfd, path, flags, mode);

    ret = myst_syscall_openat(dirfd, path, flags, mode);

    return _return(n, ret);
}

static long _SYS_futimesat(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    const struct timeval* times = (const struct timeval*)params[2];
    long ret;

    _strace(n, "dirfd=%d pathname=%s times=%p", dirfd, pathname, times);

    ret = myst_syscall_futimesat(dirfd, pathname, times);
    return _return(n, ret);
}

static long _SYS_newfstatat(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    struct stat* statbuf = (struct stat*)params[2];
    int flags = (int)params[3];
    long ret;

    _strace(
        n,
        "dirfd=%d pathname=%s statbuf=%p flags=%d",
        dirfd,
        pathname,
        statbuf,
        flags);

    ret = myst_syscall_fstatat(dirfd, pathname, statbuf, flags);
    return _return(n, ret);
}

static long _SYS_set_robust_list(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    struct myst_robust_list_head* head = (void*)params[0];
    size_t len = (size_t)params[1];
    long ret;

    _strace(n, "head=%p len=%zu", head, len);

    ret = myst_syscall_set_robust_list(head, len);
    return _return(n, ret);
}

static long _SYS_get_robust_list(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int pid = (int)params[0];
    struct myst_robust_list_head** head_ptr = (void*)params[1];
    size_t* len_ptr = (size_t*)params[2];
    long ret;

    _strace(n, "pid=%d head=%p len=%p", pid, head_ptr, len_ptr);

    ret = myst_syscall_get_robust_list(pid, head_ptr, len_ptr);
    return _return(n, ret);
}

static long _SYS_utimensat(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int dirfd = (int)params[0];
    const char* pathname = (const char*)params[1];
    const struct timespec* times = (const struct timespec*)params[2];
    int flags = (int)params[3];
    long ret;

    _strace(
        n,
        "dirfd=%d pathname=%s times=%p flags=%o",
        dirfd,
        pathname,
        times,
        flags);

    ret = myst_syscall_utimensat(dirfd, pathname, times, flags);
    return _return(n, ret);
}

static long _SYS_epoll_pwait(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int epfd = (int)params[0];
    struct epoll_event* events = (struct epoll_event*)params[1];
    int maxevents = (int)params[2];
    int timeout = (int)params[3];
    const sigset_t* sigmask = (const sigset_t*)params[4];
    long ret;

    _strace(
        n,
        "edpf=%d events=%p maxevents=%d timeout=%d sigmask=%p",
        epfd,
        events,
        maxevents,
        timeout,
        sigmask);

    /* ATTN: ignore sigmask */
    ret = myst_syscall_epoll_wait(epfd, events, maxevents, timeout);
    return _return(n, ret);
}

static long _SYS_fallocate(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int fd = (int)params[0];
    int mode = (int)params[1];
    off_t offset = (off_t)params[2];
    off_t len = (off_t)params[3];

    _strace(n, "fd=%d mode=%d offset=%ld len=%ld", fd, mode, offset, len);

    /* ATTN: treated as advisory only */
    return _return(n, 0);
}

static long _SYS_accept4(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    long ret = 0;
    int sockfd = (int)params[0];
    struct sockaddr* addr = (struct sockaddr*)params[1];
    socklen_t* addrlen = (socklen_t*)params[2];
    int flags = (int)params[3];
    char addrstr[MAX_IPADDR_LEN];

    ECHECK(_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN));

    _strace(
        n,
        "sockfd=%d addr=%s addrlen=%p flags=%x",
        sockfd,
        addrstr,
        addrlen,
        flags);

    ret = myst_syscall_accept4(sockfd, addr, addrlen, flags);

done:
    return _return(n, ret);
}

static long _SYS_epoll_create1(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int flags = (int)params[0];

    _strace(n, "flags=%d", flags);
    return _return(n, myst_syscall_epoll_create1(flags));
}

static long _SYS_pipe2(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int* pipefd = (int*)params[0];
    int flags = (int)params[1];
    long ret;

    _strace(n, "pipefd=%p flags=%0o", pipefd, flags);
    ret = myst_syscall_pipe2(pipefd, flags);

    if (__options.trace_syscalls)
        myst_eprintf("    pipefd[]=[%d:%d]\n", pipefd[0], pipefd[1]);

    return _return(n, ret);
}

static long _SYS_inotify_init1(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int flags = (int)params[0];

    _strace(n, "flags=%x", flags);

    long ret = myst_syscall_inotify_init1(flags);
    return _return(n, ret);
}

static long _SYS_prlimit64(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int pid = (int)params[0];
    int resource = (int)params[1];
    struct rlimit* new_rlim = (struct rlimit*)params[2];
    struct rlimit* old_rlim = (struct rlimit*)params[3];

    _strace(
        n,
        "pid=%d, resource=%d, new_rlim=%p, old_rlim=%p",
        pid,
        resource,
        new_rlim,
        old_rlim);

    int ret = myst_syscall_prlimit64(pid, resource, new_rlim, old_rlim);
    return _return(n, ret);
}

static long _SYS_getcpu(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    unsigned* cpu = (unsigned*)params[0];
    unsigned* node = (unsigned*)params[1];
    struct getcpu_cache* tcache = (struct getcpu_cache*)params[2];

    _strace(n, "cpu=%p node=%p, tcache=%p", cpu, node, tcache);

    // ATTN: report the real NUMA node id and cpu id.
    // For now, always report id 0 for them.
    if (cpu)
        *cpu = 0;

    if (node)
        *node = 0;

    return _return(n, 0);
}

static long _SYS_getrandom(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    void* buf = (void*)params[0];
    size_t buflen = (size_t)params[1];
    unsigned int flags = (unsigned int)params[2];

    _strace(n, "buf=%p buflen=%zu flags=%d", buf, buflen, flags);

    return _return(n, myst_syscall_getrandom(buf, buflen, flags));
}

static long _SYS_membarrier(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int cmd = (int)params[0];
    int flags = (int)params[1];

    _strace(n, "cmd=%d flags=%d", cmd, flags);

    myst_barrier();

    return _return(n, 0);
}

static long _SYS_bind(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    long ret = 0;
    int sockfd = (int)params[0];
    const struct sockaddr* addr = (const struct sockaddr*)params[1];
    socklen_t addrlen = (socklen_t)params[2];
    char addrstr[MAX_IPADDR_LEN];

    ECHECK(_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN));

    _strace(n, "sockfd=%d addr=%s addrlen=%u", sockfd, addrstr, addrlen);

    ret = myst_syscall_bind(sockfd, addr, addrlen);

done:
    return _return(n, ret);
}

static long _SYS_connect(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    /* connect() and bind() have the same parameters */
    long ret = 0;
    int sockfd = (int)params[0];
    const struct sockaddr* addr = (const struct sockaddr*)params[1];
    socklen_t addrlen = (socklen_t)params[2];
    char addrstr[MAX_IPADDR_LEN];

    ECHECK(_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN));

    _strace(
        n,
        "sockfd=%d addrlen=%u family=%u ip=%s",
        sockfd,
        addrlen,
        addr->sa_family,
        addrstr);

    ret = myst_syscall_connect(sockfd, addr, addrlen);

done:
    return _return(n, ret);
}

static long _SYS_recvfrom(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    long ret = 0;
    int sockfd = (int)params[0];
    void* buf = (void*)params[1];
    size_t len = (size_t)params[2];
    int flags = (int)params[3];
    struct sockaddr* src_addr = (struct sockaddr*)params[4];
    socklen_t* addrlen = (socklen_t*)params[5];
    char addrstr[MAX_IPADDR_LEN];

    ECHECK(_socketaddr_to_str(src_addr, addrstr, MAX_IPADDR_LEN));

    _strace(
        n,
        "sockfd=%d buf=%p len=%zu flags=%d src_addr=%s addrlen=%p",
        sockfd,
        buf,
        len,
        flags,
        addrstr,
        addrlen);

#ifdef MYST_NO_RECVMSG_MITIGATION
    ret = myst_syscall_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
#else  /* MYST_NO_RECVMSG_WORKAROUND */
    /* ATTN: this mitigation introduces a severe performance penalty */
    // This mitigation works around a problem with a certain
    // application that fails handle EGAIN. This should be removed
    // when possible.
    for (size_t i = 0; i < 10; i++)
    {
        ret = myst_syscall_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

        if (ret != -EAGAIN)
            break;

        {
            struct timespec req;
            req.tv_sec = 0;
            req.tv_nsec = 1000000000 / 10;
            long args[6];
            args[0] = (long)&req;
            args[1] = (long)NULL;
            _forward_syscall(SYS_nanosleep, args);
            continue;
        }
    }
#endif /* MYST_NO_RECVMSG_WORKAROUND */

done:
    return _return(n, ret);
}

static long _SYS_sendto(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    long ret = 0;
    int sockfd = (int)params[0];
    void* buf = (void*)params[1];
    size_t len = (size_t)params[2];
    int flags = (int)params[3];
    struct sockaddr* dest_addr = (struct sockaddr*)params[4];
    socklen_t addrlen = (socklen_t)params[5];
    char addrstr[MAX_IPADDR_LEN];

    ECHECK(_socketaddr_to_str(dest_addr, addrstr, MAX_IPADDR_LEN));

    _strace(
        n,
        "sockfd=%d buf=%p len=%zu flags=%d dest_addr=%s addrlen=%u",
        sockfd,
        buf,
        len,
        flags,
        addrstr,
        addrlen);

    ret = myst_syscall_sendto(sockfd, buf, len, flags, dest_addr, addrlen);

done:
    return _return(n, ret);
}

static long _SYS_socket(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int domain = (int)params[0];
    int type = (int)params[1];
    int protocol = (int)params[2];
    long ret;

    _strace(n, "domain=%d type=%d protocol=%d", domain, type, protocol);

    ret = myst_syscall_socket(domain, type, protocol);
    return _return(n, ret);
}

static long _SYS_accept(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    long ret = 0;
    int sockfd = (int)params[0];
    struct sockaddr* addr = (struct sockaddr*)params[1];
    socklen_t* addrlen = (socklen_t*)params[2];
    char addrstr[MAX_IPADDR_LEN];

    ECHECK(_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN));

    _strace(n, "sockfd=%d addr=%s addrlen=%p", sockfd, addrstr, addrlen);

    ret = myst_syscall_accept4(sockfd, addr, addrlen, 0);

done:
    return _return(n, ret);
}

static long _SYS_sendmsg(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int sockfd = (int)params[0];
    const struct msghdr* msg = (const struct msghdr*)params[1];
    int flags = (int)params[2];
    long ret;

    _strace(n, "sockfd=%d msg=%p flags=%d", sockfd, msg, flags);

    ret = myst_syscall_sendmsg(sockfd, msg, flags);
    return _return(n, ret);
}

static long _SYS_recvmsg(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int sockfd = (int)params[0];
    struct msghdr* msg = (struct msghdr*)params[1];
    int flags = (int)params[2];
    long ret;

    _strace(n, "sockfd=%d msg=%p flags=%d", sockfd, msg, flags);

    ret = myst_syscall_recvmsg(sockfd, msg, flags);
    return _return(n, ret);
}

static long _SYS_shutdown(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int sockfd = (int)params[0];
    int how = (int)params[1];
    long ret;

    _strace(n, "sockfd=%d how=%d", sockfd, how);

    ret = myst_syscall_shutdown(sockfd, how);
    return _return(n, ret);
}

static long _SYS_listen(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int sockfd = (int)params[0];
    int backlog = (int)params[1];
    long ret;

    _strace(n, "sockfd=%d backlog=%d", sockfd, backlog);

    ret = myst_syscall_listen(sockfd, backlog);
    return _return(n, ret);
}

static long _SYS_getsockname(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    long ret = 0;
    int sockfd = (int)params[0];
    struct sockaddr* addr = (struct sockaddr*)params[1];
    socklen_t* addrlen = (socklen_t*)params[2];
    char addrstr[MAX_IPADDR_LEN];

    ECHECK(_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN));

    _strace(n, "sockfd=%d addr=%s addrlen=%p", sockfd, addrstr, addrlen);

    ret = myst_syscall_getsockname(sockfd, addr, addrlen);

done:
    return _return(n, ret);
}

static long _SYS_getpeername(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    long ret = 0;
    int sockfd = (int)params[0];
    struct sockaddr* addr = (struct sockaddr*)params[1];
    socklen_t* addrlen = (socklen_t*)params[2];
    char addrstr[MAX_IPADDR_LEN];

    ECHECK(_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN));

    _strace(n, "sockfd=%d addr=%s addrlen=%p", sockfd, addrstr, addrlen);

    ret = myst_syscall_getpeername(sockfd, addr, addrlen);

done:
    return _return(n, ret);
}

static long _SYS_socketpair(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int domain = (int)params[0];
    int type = (int)params[1];
    int protocol = (int)params[2];
    int* sv = (int*)params[3];
    long ret;

    _strace(
        n, "domain=%d type=%d protocol=%d sv=%p", domain, type, protocol, sv);

    ret = myst_syscall_socketpair(domain, type, protocol, sv);
    return _return(n, ret);
}

static long _SYS_setsockopt(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int sockfd = (int)params[0];
    int level = (int)params[1];
    int optname = (int)params[2];
    const void* optval = (const void*)params[3];
    socklen_t optlen = (socklen_t)params[4];
    long ret;

    _strace(
        n,
        "sockfd=%d level=%d optname=%d optval=%p optlen=%u",
        sockfd,
        level,
        optname,
        optval,
        optlen);

    ret = myst_syscall_setsockopt(sockfd, level, optname, optval, optlen);
    return _return(n, ret);
}

static long _SYS_getsockopt(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int sockfd = (int)params[0];
    int level = (int)params[1];
    int optname = (int)params[2];
    void* optval = (void*)params[3];
    socklen_t* optlen = (socklen_t*)params[4];
    long ret;

    _strace(
        n,
        "sockfd=%d level=%d optname=%d optval=%p optlen=%p",
        sockfd,
        level,
        optname,
        optval,
        optlen);

    ret = myst_syscall_getsockopt(sockfd, level, optname, optval, optlen);
    return _return(n, ret);
}

static long _SYS_sendfile(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    int out_fd = (int)params[0];
    int in_fd = (int)params[1];
    off_t* offset = (off_t*)params[2];
    size_t count = (size_t)params[3];
    off_t off = offset ? *offset : 0;

    _strace(
        n,
        "out_fd=%d in_fd=%d offset=%p *offset=%ld count=%zu",
        out_fd,
        in_fd,
        offset,
        off,
        count);

    long ret = myst_syscall_sendfile(out_fd, in_fd, offset, count);
    return _return(n, ret);
}

static long _SYS_unsupported(
    long n,
    long params[6],
    MYST_UNUSED struct syscall_context* context)
{
    (void)n;
    (void)params;

    return LONG_MIN;
}

MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mincore);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_shmget);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_shmat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_shmctl);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_pause);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_alarm);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fork);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_vfork);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_semget);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_semop);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_semctl);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_shmdt);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_msgget);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_msgsnd);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_msgrcv);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_msgctl);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fdatasync);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fchdir);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fchown);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_lchown);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_getrlimit);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_ptrace);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_capget);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_capset);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_rt_sigtimedwait);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_rt_sigqueueinfo);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_rt_sigsuspend);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_uselib);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_personality);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_ustat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_sysfs);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_getpriority);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_setpriority);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_sched_rr_get_interval);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_munlock);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mlockall);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_munlockall);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_vhangup);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_modify_ldt);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_pivot_root);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS__sysctl);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_arch_prctl);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_adjtimex);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_setrlimit);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_chroot);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_sync);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_acct);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_settimeofday);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_swapon);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_swapoff);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_reboot);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_setdomainname);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_iopl);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_ioperm);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_create_module);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_init_module);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_delete_module);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_get_kernel_syms);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_query_module);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_quotactl);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_nfsservctl);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_getpmsg);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_putpmsg);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_afs_syscall);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_tuxcall);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_security);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_readahead);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_setxattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_lsetxattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fsetxattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_getxattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_lgetxattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fgetxattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_listxattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_llistxattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_flistxattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_removexattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_lremovexattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fremovexattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_io_setup);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_io_destroy);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_io_getevents);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_io_submit);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_io_cancel);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_get_thread_area);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_lookup_dcookie);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_epoll_ctl_old);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_epoll_wait_old);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_remap_file_pages);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_restart_syscall);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_semtimedop);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_timer_create);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_timer_settime);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_timer_gettime);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_timer_getoverrun);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_timer_delete);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_clock_nanosleep);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_utimes);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_vserver);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mbind);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_set_mempolicy);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_get_mempolicy);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mq_open);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mq_unlink);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mq_timedsend);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mq_timedreceive);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mq_notify);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mq_getsetattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_kexec_load);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_waitid);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_add_key);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_request_key);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_keyctl);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_ioprio_set);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_ioprio_get);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_migrate_pages);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mkdirat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mknodat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fchownat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_unlinkat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_renameat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_linkat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_symlinkat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_readlinkat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fchmodat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_faccessat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_pselect6);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_ppoll);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_unshare);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_splice);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_tee);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_sync_file_range);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_vmsplice);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_move_pages);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_signalfd);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_timerfd_create);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_eventfd);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_timerfd_settime);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_timerfd_gettime);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_signalfd4);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_eventfd2);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_preadv);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_pwritev);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_rt_tgsigqueueinfo);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_perf_event_open);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_recvmmsg);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fanotify_init);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fanotify_mark);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_name_to_handle_at);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_open_by_handle_at);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_clock_adjtime);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_syncfs);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_sendmmsg);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_setns);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_process_vm_readv);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_process_vm_writev);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_kcmp);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_finit_module);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_sched_setattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_sched_getattr);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_renameat2);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_seccomp);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_memfd_create);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_kexec_file_load);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_bpf);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_execveat);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_userfaultfd);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_mlock2);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_copy_file_range);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_preadv2);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_pwritev2);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_pkey_mprotect);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_pkey_alloc);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_pkey_free);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_statx);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_io_pgetevents);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_rseq);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_pidfd_send_signal);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_io_uring_setup);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_io_uring_enter);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_io_uring_register);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_open_tree);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_move_mount);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fsopen);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fsconfig);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fsmount);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_fspick);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_pidfd_open);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_clone3);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_rt_sigreturn);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_clone);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_getdents);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_getpgrp);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_setsid);
MYST_WEAK_ALIAS(_SYS_unsupported, _SYS_utime);

typedef long (
    *syscall_t)(long n, long params[6], struct syscall_context* context);

MYST_UNUSED
static const syscall_t _syscalls[] = {
    _SYS_read,
    _SYS_write,
    _SYS_open,
    _SYS_close,
    _SYS_stat,
    _SYS_fstat,
    _SYS_lstat,
    _SYS_poll,
    _SYS_lseek,
    _SYS_mmap,
    _SYS_mprotect,
    _SYS_munmap,
    _SYS_brk,
    _SYS_rt_sigaction,
    _SYS_rt_sigprocmask,
    _SYS_rt_sigreturn,
    _SYS_ioctl,
    _SYS_pread64,
    _SYS_pwrite64,
    _SYS_readv,
    _SYS_writev,
    _SYS_access,
    _SYS_pipe,
    _SYS_select,
    _SYS_sched_yield,
    _SYS_mremap,
    _SYS_msync,
    _SYS_mincore,
    _SYS_madvise,
    _SYS_shmget,
    _SYS_shmat,
    _SYS_shmctl,
    _SYS_dup,
    _SYS_dup2,
    _SYS_pause,
    _SYS_nanosleep,
    _SYS_getitimer,
    _SYS_alarm,
    _SYS_setitimer,
    _SYS_getpid,
    _SYS_sendfile,
    _SYS_socket,
    _SYS_connect,
    _SYS_accept,
    _SYS_sendto,
    _SYS_recvfrom,
    _SYS_sendmsg,
    _SYS_recvmsg,
    _SYS_shutdown,
    _SYS_bind,
    _SYS_listen,
    _SYS_getsockname,
    _SYS_getpeername,
    _SYS_socketpair,
    _SYS_setsockopt,
    _SYS_getsockopt,
    _SYS_clone,
    _SYS_fork,
    _SYS_vfork,
    _SYS_execve,
    _SYS_exit,
    _SYS_wait4,
    _SYS_kill,
    _SYS_uname,
    _SYS_semget,
    _SYS_semop,
    _SYS_semctl,
    _SYS_shmdt,
    _SYS_msgget,
    _SYS_msgsnd,
    _SYS_msgrcv,
    _SYS_msgctl,
    _SYS_fcntl,
    _SYS_flock,
    _SYS_fsync,
    _SYS_fdatasync,
    _SYS_truncate,
    _SYS_ftruncate,
    _SYS_getdents,
    _SYS_getcwd,
    _SYS_chdir,
    _SYS_fchdir,
    _SYS_rename,
    _SYS_mkdir,
    _SYS_rmdir,
    _SYS_creat,
    _SYS_link,
    _SYS_unlink,
    _SYS_symlink,
    _SYS_readlink,
    _SYS_chmod,
    _SYS_fchmod,
    _SYS_chown,
    _SYS_fchown,
    _SYS_lchown,
    _SYS_umask,
    _SYS_gettimeofday,
    _SYS_getrlimit,
    _SYS_getrusage,
    _SYS_sysinfo,
    _SYS_times,
    _SYS_ptrace,
    _SYS_getuid,
    _SYS_syslog,
    _SYS_getgid,
    _SYS_setuid,
    _SYS_setgid,
    _SYS_geteuid,
    _SYS_getegid,
    _SYS_setpgid,
    _SYS_getppid,
    _SYS_getpgrp,
    _SYS_setsid,
    _SYS_setreuid,
    _SYS_setregid,
    _SYS_getgroups,
    _SYS_setgroups,
    _SYS_setresuid,
    _SYS_getresuid,
    _SYS_setresgid,
    _SYS_getresgid,
    _SYS_getpgid,
    _SYS_setfsuid,
    _SYS_setfsgid,
    _SYS_getsid,
    _SYS_capget,
    _SYS_capset,
    _SYS_rt_sigpending,
    _SYS_rt_sigtimedwait,
    _SYS_rt_sigqueueinfo,
    _SYS_rt_sigsuspend,
    _SYS_sigaltstack,
    _SYS_utime,
    _SYS_mknod,
    _SYS_uselib,
    _SYS_personality,
    _SYS_ustat,
    _SYS_statfs,
    _SYS_fstatfs,
    _SYS_sysfs,
    _SYS_getpriority,
    _SYS_setpriority,
    _SYS_sched_setparam,
    _SYS_sched_getparam,
    _SYS_sched_setscheduler,
    _SYS_sched_getscheduler,
    _SYS_sched_get_priority_max,
    _SYS_sched_get_priority_min,
    _SYS_sched_rr_get_interval,
    _SYS_mlock,
    _SYS_munlock,
    _SYS_mlockall,
    _SYS_munlockall,
    _SYS_vhangup,
    _SYS_modify_ldt,
    _SYS_pivot_root,
    _SYS__sysctl,
    _SYS_prctl,
    _SYS_arch_prctl,
    _SYS_adjtimex,
    _SYS_setrlimit,
    _SYS_chroot,
    _SYS_sync,
    _SYS_acct,
    _SYS_settimeofday,
    _SYS_mount,
    _SYS_umount2,
    _SYS_swapon,
    _SYS_swapoff,
    _SYS_reboot,
    _SYS_sethostname,
    _SYS_setdomainname,
    _SYS_iopl,
    _SYS_ioperm,
    _SYS_create_module,
    _SYS_init_module,
    _SYS_delete_module,
    _SYS_get_kernel_syms,
    _SYS_query_module,
    _SYS_quotactl,
    _SYS_nfsservctl,
    _SYS_getpmsg,
    _SYS_putpmsg,
    _SYS_afs_syscall,
    _SYS_tuxcall,
    _SYS_security,
    _SYS_gettid,
    _SYS_readahead,
    _SYS_setxattr,
    _SYS_lsetxattr,
    _SYS_fsetxattr,
    _SYS_getxattr,
    _SYS_lgetxattr,
    _SYS_fgetxattr,
    _SYS_listxattr,
    _SYS_llistxattr,
    _SYS_flistxattr,
    _SYS_removexattr,
    _SYS_lremovexattr,
    _SYS_fremovexattr,
    _SYS_tkill,
    _SYS_time,
    _SYS_futex,
    _SYS_sched_setaffinity,
    _SYS_sched_getaffinity,
    _SYS_set_thread_area,
    _SYS_io_setup,
    _SYS_io_destroy,
    _SYS_io_getevents,
    _SYS_io_submit,
    _SYS_io_cancel,
    _SYS_get_thread_area,
    _SYS_lookup_dcookie,
    _SYS_epoll_create,
    _SYS_epoll_ctl_old,
    _SYS_epoll_wait_old,
    _SYS_remap_file_pages,
    _SYS_getdents64,
    _SYS_set_tid_address,
    _SYS_restart_syscall,
    _SYS_semtimedop,
    _SYS_fadvise64,
    _SYS_timer_create,
    _SYS_timer_settime,
    _SYS_timer_gettime,
    _SYS_timer_getoverrun,
    _SYS_timer_delete,
    _SYS_clock_settime,
    _SYS_clock_gettime,
    _SYS_clock_getres,
    _SYS_clock_nanosleep,
    _SYS_exit_group,
    _SYS_epoll_wait,
    _SYS_epoll_ctl,
    _SYS_tgkill,
    _SYS_utimes,
    _SYS_vserver,
    _SYS_mbind,
    _SYS_set_mempolicy,
    _SYS_get_mempolicy,
    _SYS_mq_open,
    _SYS_mq_unlink,
    _SYS_mq_timedsend,
    _SYS_mq_timedreceive,
    _SYS_mq_notify,
    _SYS_mq_getsetattr,
    _SYS_kexec_load,
    _SYS_waitid,
    _SYS_add_key,
    _SYS_request_key,
    _SYS_keyctl,
    _SYS_ioprio_set,
    _SYS_ioprio_get,
    _SYS_inotify_init,
    _SYS_inotify_add_watch,
    _SYS_inotify_rm_watch,
    _SYS_migrate_pages,
    _SYS_openat,
    _SYS_mkdirat,
    _SYS_mknodat,
    _SYS_fchownat,
    _SYS_futimesat,
    _SYS_newfstatat,
    _SYS_unlinkat,
    _SYS_renameat,
    _SYS_linkat,
    _SYS_symlinkat,
    _SYS_readlinkat,
    _SYS_fchmodat,
    _SYS_faccessat,
    _SYS_pselect6,
    _SYS_ppoll,
    _SYS_unshare,
    _SYS_set_robust_list,
    _SYS_get_robust_list,
    _SYS_splice,
    _SYS_tee,
    _SYS_sync_file_range,
    _SYS_vmsplice,
    _SYS_move_pages,
    _SYS_utimensat,
    _SYS_epoll_pwait,
    _SYS_signalfd,
    _SYS_timerfd_create,
    _SYS_eventfd,
    _SYS_fallocate,
    _SYS_timerfd_settime,
    _SYS_timerfd_gettime,
    _SYS_accept4,
    _SYS_signalfd4,
    _SYS_eventfd2,
    _SYS_epoll_create1,
    _SYS_dup3,
    _SYS_pipe2,
    _SYS_inotify_init1,
    _SYS_preadv,
    _SYS_pwritev,
    _SYS_rt_tgsigqueueinfo,
    _SYS_perf_event_open,
    _SYS_recvmmsg,
    _SYS_fanotify_init,
    _SYS_fanotify_mark,
    _SYS_prlimit64,
    _SYS_name_to_handle_at,
    _SYS_open_by_handle_at,
    _SYS_clock_adjtime,
    _SYS_syncfs,
    _SYS_sendmmsg,
    _SYS_setns,
    _SYS_getcpu,
    _SYS_process_vm_readv,
    _SYS_process_vm_writev,
    _SYS_kcmp,
    _SYS_finit_module,
    _SYS_sched_setattr,
    _SYS_sched_getattr,
    _SYS_renameat2,
    _SYS_seccomp,
    _SYS_getrandom,
    _SYS_memfd_create,
    _SYS_kexec_file_load,
    _SYS_bpf,
    _SYS_execveat,
    _SYS_userfaultfd,
    _SYS_membarrier,
    _SYS_mlock2,
    _SYS_copy_file_range,
    _SYS_preadv2,
    _SYS_pwritev2,
    _SYS_pkey_mprotect,
    _SYS_pkey_alloc,
    _SYS_pkey_free,
    _SYS_statx,
    _SYS_io_pgetevents,
    _SYS_rseq,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_unsupported,
    _SYS_pidfd_send_signal,
    _SYS_io_uring_setup,
    _SYS_io_uring_enter,
    _SYS_io_uring_register,
    _SYS_open_tree,
    _SYS_move_mount,
    _SYS_fsopen,
    _SYS_fsconfig,
    _SYS_fsmount,
    _SYS_fspick,
    _SYS_pidfd_open,
    _SYS_clone3,
};

static size_t _nsyscalls = MYST_COUNTOF(_syscalls);

static long _syscall(void* args_)
{
    syscall_args_t* args = (syscall_args_t*)args_;
    const long n = args->n;
    long* params = args->params;
    long syscall_ret = 0;
    static bool _set_thread_area_called;
    struct syscall_context context;
    context.set_thread_area_called = &_set_thread_area_called;
    context.kstack = args->kstack;

    myst_times_enter_kernel();

    /* resolve the target-thread-descriptor and the crt-thread-descriptor */
    if (_set_thread_area_called)
    {
        /* ---------- running C-runtime thread descriptor ---------- */

        /* get crt_td */
        context.crt_td = myst_get_fsbase();
        myst_assume(myst_valid_td(context.crt_td));

        /* get thread */
        myst_assume(myst_tcall_get_tsd((uint64_t*)&context.thread) == 0);
        myst_assume(myst_valid_thread(context.thread));

        /* get target_td */
        context.target_td = context.thread->target_td;
        myst_assume(myst_valid_td(context.target_td));

        /* the syscall on the target thread descriptor */
        myst_set_fsbase(context.target_td);
    }
    else
    {
        /* ---------- running target thread descriptor ---------- */

        /* get target_td */
        context.target_td = myst_get_fsbase();
        myst_assume(myst_valid_td(context.target_td));

        /* get thread */
        myst_assume(myst_tcall_get_tsd((uint64_t*)&context.thread) == 0);
        myst_assume(myst_valid_thread(context.thread));

        /* crt_td is null */
    }

    // Process signals pending for this thread, if there is any.
    myst_signal_process(context.thread);

    /* ---------- running target thread descriptor ---------- */

    myst_assume(context.target_td != NULL);
    myst_assume(context.thread != NULL);

    /* handle standard syscalls with jump table */
    if ((size_t)n < _nsyscalls)
    {
        long ret = (*_syscalls[n])(n, params, &context);

        if (ret == LONG_MIN)
            myst_panic("unhandled syscall: %s()", syscall_str(n));

        BREAK(ret);
    }

    /* handle extended syscalls */
    switch (n)
    {
        case SYS_myst_gcov_init:
            BREAK(_SYS_myst_gcov_init(n, params, NULL));
        case SYS_myst_trace:
            BREAK(_SYS_myst_trace(n, params, NULL));
        case SYS_myst_trace_ptr:
            BREAK(_SYS_myst_trace_ptr(n, params, NULL));
        case SYS_myst_dump_stack:
            BREAK(_SYS_myst_dump_stack(n, params, NULL));
        case SYS_myst_dump_ehdr:
            BREAK(_SYS_myst_dump_ehdr(n, params, NULL));
        case SYS_myst_dump_argv:
            BREAK(_SYS_myst_dump_argv(n, params, NULL));
        case SYS_myst_add_symbol_file:
            BREAK(_SYS_myst_add_symbol_file(n, params, NULL));
        case SYS_myst_load_symbols:
            BREAK(_SYS_myst_load_symbols(n, params, NULL));
        case SYS_myst_unload_symbols:
            BREAK(_SYS_myst_unload_symbols(n, params, NULL));
        case SYS_myst_gen_creds:
            BREAK(_SYS_myst_gen_creds(n, params, NULL));
        case SYS_myst_free_creds:
            BREAK(_SYS_myst_free_creds(n, params, NULL));
        case SYS_myst_gen_creds_ex:
            BREAK(_SYS_myst_gen_creds_ex(n, params, NULL));
        case SYS_myst_verify_cert:
            BREAK(_SYS_myst_verify_cert(n, params, NULL));
        case SYS_myst_max_threads:
            BREAK(_SYS_myst_max_threads(n, params, NULL));
        case SYS_myst_poll_wake:
            BREAK(_SYS_myst_poll_wake(n, params, NULL));
        case SYS_myst_run_itimer:
            BREAK(_SYS_myst_run_itimer(n, params, NULL));
        case SYS_myst_start_shell:
            BREAK(_SYS_myst_start_shell(n, params, NULL));
        case SYS_getitimer:
            BREAK(_SYS_getitimer(n, params, NULL));
        case SYS_myst_clone:
            BREAK(_SYS_myst_clone(n, params, NULL));
        /* forward Open Enclave extensions to the target */
        case SYS_myst_oe_get_report_v2:
        case SYS_myst_oe_free_report:
        case SYS_myst_oe_get_target_info_v2:
        case SYS_myst_oe_free_target_info:
        case SYS_myst_oe_parse_report:
        case SYS_myst_oe_verify_report:
        case SYS_myst_oe_get_seal_key_by_policy_v2:
        case SYS_myst_oe_get_public_key_by_policy:
        case SYS_myst_oe_get_public_key:
        case SYS_myst_oe_get_private_key_by_policy:
        case SYS_myst_oe_get_private_key:
        case SYS_myst_oe_free_key:
        case SYS_myst_oe_get_seal_key_v2:
        case SYS_myst_oe_free_seal_key:
        case SYS_myst_oe_generate_attestation_certificate:
        case SYS_myst_oe_free_attestation_certificate:
        case SYS_myst_oe_verify_attestation_certificate:
        case SYS_myst_oe_result_str:
        {
            _strace(n, "forwarded");
            BREAK(_return(n, _forward_syscall(n, params)));
        }
        default:
        {
            myst_panic("unknown syscall: %s(): %ld", syscall_str(n), n);
        }
    }

done:

    /* ---------- running target thread descriptor ---------- */

    /* the C-runtime must execute on its own thread descriptor */
    if (context.crt_td)
        myst_set_fsbase(context.crt_td);

    myst_times_leave_kernel();

    // Process signals pending for this thread, if there is any.
    myst_signal_process(context.thread);

    return syscall_ret;
}

long myst_syscall(long n, long params[6])
{
    long ret;
    myst_kstack_t* kstack;

    if (!(kstack = myst_get_kstack()))
        myst_panic("no more kernel stacks");

    syscall_args_t args = {.n = n, .params = params, .kstack = kstack};
    ret = myst_call_on_stack(myst_kstack_end(kstack), _syscall, &args);
    myst_put_kstack(kstack);

    return ret;
}

/*
**==============================================================================
**
** syscalls
**
**==============================================================================
*/

static myst_spinlock_t _get_time_lock = MYST_SPINLOCK_INITIALIZER;
static myst_spinlock_t _set_time_lock = MYST_SPINLOCK_INITIALIZER;

long myst_syscall_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    if (!tp)
        return -EFAULT;

    if (clk_id < 0)
    {
        // ATTN: Support Dynamic clocks
        if (IS_DYNAMIC_CLOCK(clk_id))
            return -ENOTSUP;
        else
            return myst_times_get_cpu_clock_time(clk_id, tp);
    }

    if (clk_id == CLOCK_PROCESS_CPUTIME_ID)
    {
        long nanoseconds = myst_times_process_time();
        tp->tv_sec = nanoseconds / NANO_IN_SECOND;
        tp->tv_nsec = nanoseconds % NANO_IN_SECOND;
        return 0;
    }
    if (clk_id == CLOCK_THREAD_CPUTIME_ID)
    {
        long nanoseconds = myst_times_thread_time();
        tp->tv_sec = nanoseconds / NANO_IN_SECOND;
        tp->tv_nsec = nanoseconds % NANO_IN_SECOND;
        return 0;
    }

    myst_spin_lock(&_get_time_lock);
    long params[6] = {(long)clk_id, (long)tp};
    long ret = myst_tcall(MYST_TCALL_CLOCK_GETTIME, params);
    myst_spin_unlock(&_get_time_lock);
    return ret;
}

long myst_syscall_clock_settime(clockid_t clk_id, struct timespec* tp)
{
    long params[6] = {(long)clk_id, (long)tp};
    myst_spin_lock(&_set_time_lock);
    long ret = myst_tcall(MYST_TCALL_CLOCK_SETTIME, params);
    myst_spin_unlock(&_set_time_lock);
    return ret;
}

long myst_syscall_gettimeofday(struct timeval* tv, struct timezone* tz)
{
    (void)tz;
    struct timespec tp = {0};
    if (tv == NULL)
        return 0;

    long ret = myst_syscall_clock_gettime(CLOCK_REALTIME, &tp);
    if (ret == 0)
    {
        tv->tv_sec = tp.tv_sec;
        tv->tv_usec = tp.tv_nsec / 1000;
    }
    return ret;
}

long myst_syscall_time(time_t* tloc)
{
    struct timespec tp = {0};
    long ret = myst_syscall_clock_gettime(CLOCK_REALTIME, &tp);
    if (ret == 0)
    {
        if (tloc != NULL)
            *tloc = tp.tv_sec;
        ret = tp.tv_sec;
    }
    return ret;
}

long myst_syscall_clock_getres(clockid_t clk_id, struct timespec* res)
{
    long params[6] = {(long)clk_id, (long)res};
    long ret = myst_tcall(MYST_TCALL_CLOCK_GETRES, params);
    return ret;
}

long myst_syscall_tgkill(int tgid, int tid, int sig)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();
    myst_thread_t* target = myst_find_thread(tid);

    if (target == NULL)
        ERAISE(-ESRCH);

    // Only allow a thread to kill other threads in the same group.
    if (tgid != thread->pid)
        ERAISE(-EINVAL);

    siginfo_t* siginfo = calloc(1, sizeof(siginfo_t));
    siginfo->si_code = SI_TKILL;
    siginfo->si_signo = sig;
    myst_signal_deliver(target, sig, siginfo);

done:
    return ret;
}

long myst_syscall_kill(int pid, int sig)
{
    long ret = 0;
    myst_thread_t* thread = myst_thread_self();
    myst_thread_t* process_thread = myst_find_process_thread(thread);

    myst_spin_lock(&myst_process_list_lock);

    // If not this thread search back through list of processes
    while ((process_thread->pid != pid) &&
           (process_thread->main.prev_process_thread != NULL))
    {
        process_thread = process_thread->main.prev_process_thread;
    }

    // If still not found search forwards through processes
    if (process_thread->pid != pid)
    {
        process_thread = process_thread;

        while ((process_thread->pid != pid) &&
               (process_thread->main.next_process_thread != NULL))
        {
            process_thread = process_thread->main.next_process_thread;
        }
    }

    myst_spin_unlock(&myst_process_list_lock);

    // Did we finally find it?
    if (process_thread->pid == pid)
    {
        // Deliver signal
        siginfo_t* siginfo = calloc(1, sizeof(siginfo_t));
        siginfo->si_code = SI_USER;
        siginfo->si_signo = sig;
        siginfo->si_pid = thread->pid;
        siginfo->si_uid = MYST_DEFAULT_UID;

        ret = myst_signal_deliver(process_thread, sig, siginfo);
    }
    else
        ERAISE(-ESRCH);

done:
    return ret;
}

long myst_syscall_isatty(int fd)
{
    long params[6] = {(long)fd};
    return myst_tcall(MYST_TCALL_ISATTY, params);
}

long myst_syscall_add_symbol_file(
    const char* path,
    const void* text,
    size_t text_size)
{
    long ret = 0;
    void* file_data = NULL;
    size_t file_size;
    long params[6] = {0};

    ECHECK(myst_load_file(path, &file_data, &file_size));

    params[0] = (long)file_data;
    params[1] = (long)file_size;
    params[2] = (long)text;
    params[3] = (long)text_size;

    ECHECK(myst_tcall(MYST_TCALL_ADD_SYMBOL_FILE, params));

done:

    if (file_data)
        free(file_data);

    return ret;
}

long myst_syscall_load_symbols(void)
{
    long params[6] = {0};
    return myst_tcall(MYST_TCALL_LOAD_SYMBOLS, params);
}

long myst_syscall_unload_symbols(void)
{
    long params[6] = {0};
    return myst_tcall(MYST_TCALL_UNLOAD_SYMBOLS, params);
}
