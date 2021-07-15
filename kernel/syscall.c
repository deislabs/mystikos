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
#include <myst/bufalloc.h>
#include <myst/clock.h>
#include <myst/cpio.h>
#include <myst/cwd.h>
#include <myst/epolldev.h>
#include <myst/eraise.h>
#include <myst/errno.h>
#include <myst/eventfddev.h>
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
#include <myst/iov.h>
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
#include <myst/round.h>
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
#include <myst/uid_gid.h>

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
    {SYS_myst_max_threads, "SYS_myst_max_threads"},
    {SYS_myst_poll_wake, "SYS_myst_poll_wake"},
    {SYS_get_process_thread_stack, "SYS_get_process_thread_stack"},
    {SYS_myst_run_itimer, "SYS_myst_run_itimer"},
    {SYS_myst_get_fork_info, "SYS_myst_get_fork_info"},
    {SYS_fork_wait_exec_exit, "SYS_fork_wait_exec_exit"},
    {SYS_myst_kill_wait_child_forks, "SYS_myst_kill_wait_child_forks"},
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
#ifdef MYST_ENABLE_GCOV
    {SYS_myst_gcov, "SYS_myst_gcov"},
#endif
    {SYS_myst_unmap_on_exit, "SYS_myst_unmap_on_exit"},
};

static size_t _n_pairs = sizeof(_pairs) / sizeof(_pairs[0]);

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

long myst_syscall_get_fork_info(myst_thread_t* thread, myst_fork_info_t* arg)
{
    long ret = 0;
    myst_thread_t* process;

    /* preinitialize this in case something goes wrong */
    if (arg)
        *arg = (myst_fork_info_t)MYST_FORK_INFO_INITIALIZER;

    if (!arg)
        ERAISE(-EINVAL);

    if (!(process = myst_find_process_thread(thread)))
        ERAISE(-ENOSYS);

    arg->fork_mode = __myst_kernel_args.fork_mode;

    if (arg->fork_mode == myst_fork_none)
    {
        arg->is_child_fork = false;
        arg->is_parent_of_fork = false;
    }
    else
    {
        /* Check if we are child fork by looking at clone flag */
        if (process->clone.flags & CLONE_VFORK)
            arg->is_child_fork = true;
        else
            arg->is_child_fork = false;

        /* Check if we have a child process which is a clone */
        arg->is_parent_of_fork = myst_have_child_forked_processes(process);
    }

done:
    return ret;
}

static const char* _syscall_str(long n)
{
    for (size_t i = 0; i < _n_pairs; i++)
    {
        if (n == _pairs[i].num)
            return _pairs[i].str;
    }

    return "unknown";
}

const char* myst_syscall_str(long n)
{
    return _syscall_str(n);
}

__attribute__((format(printf, 2, 3))) static void _strace(
    long n,
    const char* fmt,
    ...)
{
    if (__myst_kernel_args.trace_syscalls)
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
            _syscall_str(n),
            reset,
            buf,
            myst_gettid());

        if (buf != &null_char)
            free(buf);
    }
}

long myst_syscall_unmap_on_exit(
    myst_thread_t* process_thread,
    void* ptr,
    size_t size)
{
    long ret = 0;
    int i = process_thread->main.unmap_on_exit_used++;
    if (i >= MYST_MAX_MUNNAP_ON_EXIT)
    {
        process_thread->main.unmap_on_exit_used--;
        ret = -ENOMEM;
    }
    else
    {
        process_thread->main.unmap_on_exit[i].ptr = ptr;
        process_thread->main.unmap_on_exit[i].size = size;
    }
    return ret;
}

static long _forward_syscall(long n, long params[6])
{
    if (__myst_kernel_args.trace_syscalls)
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
    if (__myst_kernel_args.trace_syscalls)
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
                _syscall_str(n),
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
                _syscall_str(n),
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
        myst_strlcpy(out, "NULL", limit);
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

// Given a dir fd and a pathname, return a concatenated absolute path.
// This function allocates buffer for the concatenated abspath. The
// caller doesn't need to preallocate buffer, but should free the
// abspath buffer after using it.
//
// Caveats:
//
// - Sometimes abspath is set to equal to
//   pathname, in which case no free is needed. The caller should check
//   *abspath_out before free:
//   e.g.
//       if (*abspath_out != pathname)
//           free(*abspath_out)
//
// - If this function hits an error and doesn't return SUCCESS, it will
//   free the abspath buffer by itself. Also, *abspath_out == NULL.
//   Thus, the check above is still valid.
//
// - Some flags allow the pathname to be an empty string. Caller
//   passing in those flags should check when *abspath == '\0'. If
//   true, then the caller should apply the fd version of the syscall
//   using dirfd.
long myst_get_absolute_path_from_dirfd(
    int dirfd,
    const char* pathname,
    int flags,
    char** abspath_out)
{
    long ret = 0;
    char* path_out = NULL;
    struct locals
    {
        char dirname[PATH_MAX];
    }* locals = NULL;

    if (!pathname || !abspath_out)
        ERAISE(-EINVAL);

    /* If pathname is absolute, then ignore dirfd */
    if (*pathname == '/' || dirfd == AT_FDCWD)
    {
        *abspath_out = (char*)pathname;
    }
    else if (*pathname == '\0')
    {
        if (!(flags & AT_EMPTY_PATH))
            ERAISE(-ENOENT);

        if (dirfd < 0)
            ERAISE(-EBADF);

        if (!(path_out = malloc(PATH_MAX)))
            ERAISE(-ENOMEM);

        if (flags & AT_SYMLINK_NOFOLLOW)
        {
            myst_fdtable_t* fdtable = myst_fdtable_current();
            myst_fs_t* fs;
            myst_file_t* file;

            ECHECK(myst_fdtable_get_file(fdtable, dirfd, &fs, &file));
            ECHECK((*fs->fs_realpath)(fs, file, path_out, PATH_MAX));
        }
        else
        {
            *path_out = '\0';
        }
        *abspath_out = path_out;
    }
    else
    {
        if (dirfd < 0)
            ERAISE(-EBADF);

        if (!(path_out = malloc(PATH_MAX)))
            ERAISE(-ENOMEM);

        if (!(locals = malloc(sizeof(struct locals))))
            ERAISE(-ENOMEM);

        myst_fdtable_t* fdtable = myst_fdtable_current();
        myst_fdtable_type_t type;
        void* device = NULL;
        void* object = NULL;
        myst_fs_t* fs;
        myst_file_t* file;

        /* first check dirfd is of file type, e.g. not tty */
        ECHECK(myst_fdtable_get_any(fdtable, dirfd, &type, &device, &object));
        if (type != MYST_FDTABLE_TYPE_FILE)
            ERAISE(-ENOTDIR);

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

        /* construct absolute path of file */
        ECHECK(myst_make_path(path_out, PATH_MAX, locals->dirname, pathname));
        *abspath_out = path_out;
    }

    path_out = NULL;

done:

    if (path_out)
        free(path_out);

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
    char* abspath = NULL;
    struct locals
    {
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (fs_out)
        *fs_out = NULL;

    if (file_out)
        *file_out = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_get_absolute_path_from_dirfd(dirfd, pathname, 0, &abspath));
    if (fs_out && file_out)
    {
        myst_fs_t* fs;

        ECHECK(myst_mount_resolve(abspath, locals->suffix, &fs));
        ECHECK(
            (*fs->fs_open)(fs, locals->suffix, flags, mode, fs_out, file_out));
    }
    else
    {
        ret = myst_syscall_open(abspath, flags, mode);
    }

done:

    if (locals)
        free(locals);

    if (abspath != pathname)
        free(abspath);

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

ssize_t myst_syscall_pwritev2(
    int fd,
    const struct iovec* iov,
    int iovcnt,
    off_t offset,
    int flags)
{
    ssize_t ret = 0;
    void* buf = NULL;
    ssize_t len;
    ssize_t nwritten;

    // ATTN: all flags are ignored since they are hints and have no
    // definitively perceptible effect.
    (void)flags;

    ECHECK(len = myst_iov_gather(iov, iovcnt, &buf));
    ECHECK(nwritten = myst_syscall_pwrite(fd, buf, len, offset));
    ret = nwritten;

done:

    if (buf)
        free(buf);

    return ret;
}

ssize_t myst_syscall_preadv2(
    int fd,
    const struct iovec* iov,
    int iovcnt,
    off_t offset,
    int flags)
{
    ssize_t ret = 0;
    ssize_t len;
    char buf[256];
    void* ptr = NULL;
    ssize_t nread;

    // ATTN: all flags are ignored since they are hints and have no
    // definitively perceptible effect.
    (void)flags;

    ECHECK(len = myst_iov_len(iov, iovcnt));

    if (len == 0)
        goto done;

    if (!(ptr = myst_buf_malloc(buf, sizeof(buf), len)))
        ERAISE(-ENOMEM);

    ECHECK(nread = myst_syscall_pread(fd, ptr, len, offset));
    ECHECK(myst_iov_scatter(iov, iovcnt, ptr, nread));
    ret = nread;

done:

    if (ptr)
        myst_buf_free(buf, ptr);

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

long myst_syscall_mkdirat(int dirfd, const char* pathname, mode_t mode)
{
    char* abspath = NULL;
    long ret = 0;

    if (dirfd == AT_FDCWD)
    {
        ret = myst_syscall_mkdir(pathname, mode);
    }
    else
    {
        ECHECK(myst_get_absolute_path_from_dirfd(dirfd, pathname, 0, &abspath));
        ret = myst_syscall_mkdir(abspath, mode);
    }

done:

    if (abspath != pathname)
        free(abspath);

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

long myst_syscall_unlinkat(int dirfd, const char* pathname, int flags)
{
    char* abspath = NULL;
    long ret = 0;

    (void)flags;

    if (flags & ~AT_REMOVEDIR)
        ERAISE(-EINVAL);

    ECHECK(myst_get_absolute_path_from_dirfd(dirfd, pathname, 0, &abspath));

    if (flags & AT_REMOVEDIR)
    {
        ECHECK(myst_syscall_rmdir(abspath));
    }
    else
    {
        ECHECK(myst_syscall_unlink(abspath));
    }

done:

    if (abspath != pathname)
        free(abspath);

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

long myst_syscall_faccessat(
    int dirfd,
    const char* pathname,
    int mode,
    int flags)
{
    long ret = 0;
    char* abspath = NULL;

    /* ATTN: support AT_ flags */
    (void)flags;

    ECHECK(myst_get_absolute_path_from_dirfd(dirfd, pathname, 0, &abspath));
    ret = myst_syscall_access(abspath, mode);

done:

    if (abspath != pathname)
        free(abspath);

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

long myst_syscall_renameat(
    int olddirfd,
    const char* oldpath,
    int newdirfd,
    const char* newpath)
{
    long ret = 0;
    char* old_abspath = NULL;
    char* new_abspath = NULL;

    ECHECK(
        myst_get_absolute_path_from_dirfd(olddirfd, oldpath, 0, &old_abspath));
    ECHECK(
        myst_get_absolute_path_from_dirfd(newdirfd, newpath, 0, &new_abspath));
    ret = myst_syscall_rename(old_abspath, new_abspath);

done:

    if (old_abspath != oldpath)
        free(old_abspath);

    if (new_abspath != newpath)
        free(new_abspath);

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

long myst_syscall_readlinkat(
    int dirfd,
    const char* pathname,
    char* buf,
    size_t bufsiz)
{
    long ret = 0;
    char* abspath = NULL;

    if (!buf || !bufsiz)
        ERAISE(-EINVAL);

    /*
     * ATTN: Since Linux 2.6.39, pathname can be an empty string, in which
     * case the call operates on the symbolic link referred to by dirfd.
     * But dirfd should have been obtained using open with the O_PATH
     * and O_NOFOLLOW flags. Our existing implementation of ext2_open()
     * dosn't support the O_PATH flag. If the trailing component
     * (i.e., basename) of pathname is a symbolic link, then the open
     * fails, with the error ELOOP.
     * Thus, return "No such file or directory"
     */
    ECHECK(myst_get_absolute_path_from_dirfd(dirfd, pathname, 0, &abspath));
    ret = myst_syscall_readlink(abspath, buf, bufsiz);

done:

    if (abspath != pathname)
        free(abspath);

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

long myst_syscall_symlinkat(
    const char* target,
    int newdirfd,
    const char* linkpath)
{
    long ret = 0;
    char* abspath = NULL;

    ECHECK(myst_get_absolute_path_from_dirfd(newdirfd, linkpath, 0, &abspath));
    ret = myst_syscall_symlink(target, abspath);

done:

    if (abspath != linkpath)
        free(abspath);

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

long myst_syscall_fchdir(int fd)
{
    long ret = 0;
    struct locals
    {
        char realpath[PATH_MAX];
    }* locals = NULL;
    myst_thread_t* thread = myst_thread_self();
    myst_thread_t* process_thread = myst_find_process_thread(thread);
    myst_file_t* file = NULL;
    myst_fs_t* fs = NULL;
    myst_fdtable_t* fdtable = myst_fdtable_current();

    if (fd < 0)
        ERAISE(-EBADF);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_fdtable_get_file(fdtable, fd, &fs, &file));

    /* fail if the directory does not exist */
    {
        struct stat buf;

        if (fs->fs_fstat(fs, file, &buf) != 0 || !S_ISDIR(buf.st_mode))
            ERAISE(-ENOENT);
    }

    /* Get file path */
    ECHECK((*fs->fs_realpath)(
        fs, file, locals->realpath, sizeof(locals->realpath)));

    char* tmp = strdup(locals->realpath);
    if (tmp == NULL)
        ERAISE(-ENOMEM);

    myst_spin_lock(&process_thread->main.cwd_lock);
    free(process_thread->main.cwd);
    process_thread->main.cwd = tmp;

done:

    myst_spin_unlock(&process_thread->main.cwd_lock);

    if (locals)
        free(locals);

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
    long ret = 0;
    myst_fs_t* fs;
    struct locals
    {
        char suffix[PATH_MAX];
        struct stat statbuf;
    }* locals = NULL;
    myst_thread_t* self = myst_thread_self();

    if (!pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(myst_mount_resolve(pathname, locals->suffix, &fs));

    /* Root or owner of file can change mode */
    if (!self->euid == 0)
    {
        ECHECK(fs->fs_stat(fs, locals->suffix, &locals->statbuf));
        if (locals->statbuf.st_uid != self->euid)
            ERAISE(-EPERM);
    }
    ECHECK((*fs->fs_chmod)(fs, locals->suffix, mode));

done:

    if (locals)
        free(locals);

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
        uid_t host_uid;
        gid_t host_gid;
        myst_fdops_t* fdops = device;
        int target_fd = (*fdops->fd_target_fd)(fdops, object);

        if (target_fd < 0)
            ERAISE(-EBADF);

        ECHECK(myst_enc_uid_to_host(myst_syscall_geteuid(), &host_uid));

        ECHECK(myst_enc_gid_to_host(myst_syscall_getegid(), &host_gid));

        long params[6] = {target_fd, mode, host_uid, host_gid};
        ret = _forward_syscall(SYS_fchmod, params);
    }
    else if (type == MYST_FDTABLE_TYPE_FILE)
    {
        myst_fs_t* fs = device;
        myst_thread_t* self = myst_thread_self();
        struct stat statbuf;

        /* Root or owner of file can change mode */
        if (!self->euid == 0)
        {
            ECHECK(fs->fs_fstat(fs, object, &statbuf));
            if (statbuf.st_uid != self->euid)
                ERAISE(-EPERM);
        }

        ECHECK((*fs->fs_fchmod)(fs, object, mode));
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

    if (__myst_kernel_args.trace_syscalls)
        myst_eprintf("pipe2(): [%d:%d]\n", fd0, fd1);

done:
    return ret;
}

long myst_syscall_eventfd(unsigned int initval, int flags)
{
    long ret = 0;
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_EVENTFD;
    myst_eventfddev_t* dev = myst_eventfddev_get();
    myst_eventfd_t* obj = NULL;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    int fd;

    if (!dev)
        ERAISE(-EINVAL);

    ECHECK((*dev->eventfd)(dev, initval, flags, &obj));

    if ((fd = myst_fdtable_assign(fdtable, type, dev, obj)) < 0)
    {
        myst_fdtable_remove(fdtable, fd);
        (*dev->close)(dev, obj);
        ERAISE(fd);
    }

    ret = fd;

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
    long params[6] = {0};
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

    if (resource == RLIMIT_NOFILE)
    {
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
    }
    else if (resource == RLIMIT_STACK)
    {
        if (old_rlim)
        {
            old_rlim->rlim_cur = MYST_PROCESS_INIT_STACK_SIZE;
            old_rlim->rlim_max = MYST_PROCESS_MAX_STACK_SIZE;
        }
    }
    else
    {
        return -EINVAL;
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

    ECHECK(((myst_fs_t*)device)->fs_fsync(device, (myst_file_t*)object));

done:
    return ret;
}

long myst_syscall_fdatasync(int fd)
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

    ECHECK(((myst_fs_t*)device)->fs_fdatasync(device, (myst_file_t*)object));

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

long myst_syscall_arch_prctl(int code, unsigned long* addr)
{
    long ret = 0;

    if (!addr)
        ERAISE(-EFAULT);

    if (code == ARCH_GET_FS)
    {
        *addr = (unsigned long)myst_get_fsbase();
    }
    else if (code == ARCH_GET_GS)
    {
        *addr = (unsigned long)myst_get_gsbase();
    }
    else if (code == ARCH_SET_FS)
    {
        struct myst_td* new = (struct myst_td*)addr;
        const struct myst_td* old = myst_get_fsbase();
        myst_set_fsbase((void*)new);
        new->canary = old->canary;
    }
    else if (code == ARCH_SET_GS)
    {
        ERAISE(-EINVAL);
    }
    else
    {
        ERAISE(-EINVAL);
    }

done:
    return ret;
}

long myst_syscall_mbind(
    void* addr,
    unsigned long len,
    int mode,
    const unsigned long* nodemask,
    unsigned long maxnode,
    unsigned flags)
{
    long ret = 0;

    /* ATTN: stub implementation */

    (void)addr;
    (void)len;
    (void)mode;
    (void)nodemask;
    (void)maxnode;
    (void)flags;
    return ret;
}

long myst_syscall_get_process_thread_stack(void** stack, size_t* stack_size)
{
    long ret = 0;
    myst_thread_t* self = myst_thread_self();

    if (!stack || !stack_size || !self->main.exec_stack)
        ERAISE(-EINVAL);

    // can only be called from process thread
    if (!myst_is_process_thread(self))
        ERAISE(-EINVAL);

    *stack = self->main.exec_stack;
    *stack_size = self->main.exec_stack_size;

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

/* ATTN: optimize _syscall() stack usage later */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
static long _syscall(void* args_)
{
    syscall_args_t* args = (syscall_args_t*)args_;
    long n = args->n;
    long* params = args->params;
    long syscall_ret = 0;
    long x1 = params[0];
    long x2 = params[1];
    long x3 = params[2];
    long x4 = params[3];
    long x5 = params[4];
    long x6 = params[5];
    static bool _set_thread_area_called;
    myst_td_t* target_td = NULL;
    myst_td_t* crt_td = NULL;
    myst_thread_t* thread = NULL;

    myst_times_enter_kernel(n);

    /* resolve the target-thread-descriptor and the crt-thread-descriptor */
    if (_set_thread_area_called)
    {
        /* ---------- running C-runtime thread descriptor ---------- */

        /* get crt_td */
        crt_td = myst_get_fsbase();
        myst_assume(myst_valid_td(crt_td));

        /* get thread */
        myst_assume(myst_tcall_get_tsd((uint64_t*)&thread) == 0);
        myst_assume(myst_valid_thread(thread));

        /* get target_td */
        target_td = thread->target_td;
        myst_assume(myst_valid_td(target_td));

        /* the syscall on the target thread descriptor */
        myst_set_fsbase(target_td);
    }
    else
    {
        /* ---------- running target thread descriptor ---------- */

        /* get target_td */
        target_td = myst_get_fsbase();
        myst_assume(myst_valid_td(target_td));

        /* get thread */
        myst_assume(myst_tcall_get_tsd((uint64_t*)&thread) == 0);
        myst_assume(myst_valid_thread(thread));

        /* crt_td is null */
    }

    // Process signals pending for this thread, if there is any.
    myst_signal_process(thread);

    /* ---------- running target thread descriptor ---------- */

    myst_assume(target_td != NULL);
    myst_assume(thread != NULL);

    switch (n)
    {
        case SYS_myst_trace:
        {
            const char* msg = (const char*)x1;

            _strace(n, "msg=%s", msg);

            BREAK(_return(n, 0));
        }
        case SYS_myst_trace_ptr:
        {
            printf(
                "trace: %s: %lx %ld\n",
                (const char*)params[0],
                params[1],
                params[1]);
            BREAK(_return(n, 0));
        }
        case SYS_myst_dump_stack:
        {
            const void* stack = (void*)x1;

            _strace(n, NULL);

            myst_dump_stack((void*)stack);
            BREAK(_return(n, 0));
        }
        case SYS_myst_dump_ehdr:
        {
            myst_dump_ehdr((void*)params[0]);
            BREAK(_return(n, 0));
        }
        case SYS_myst_dump_argv:
        {
            int argc = (int)x1;
            const char** argv = (const char**)x2;

            printf("=== SYS_myst_dump_argv\n");

            printf("argc=%d\n", argc);
            printf("argv=%p\n", argv);

            for (int i = 0; i < argc; i++)
            {
                printf("argv[%d]=%s\n", i, argv[i]);
            }

            printf("argv[argc]=%p\n", argv[argc]);

            BREAK(_return(n, 0));
        }
        case SYS_myst_add_symbol_file:
        {
            const char* path = (const char*)x1;
            const void* text = (const void*)x2;
            size_t text_size = (size_t)x3;
            long ret = 0;

            _strace(
                n,
                "path=\"%s\" text=%p text_size=%zu\n",
                path,
                text,
                text_size);

            if (__myst_kernel_args.debug_symbols)
                ret = myst_syscall_add_symbol_file(path, text, text_size);

            BREAK(_return(n, ret));
        }
        case SYS_myst_load_symbols:
        {
            long ret = 0;

            _strace(n, NULL);

            if (__myst_kernel_args.debug_symbols)
                ret = myst_syscall_load_symbols();

            BREAK(_return(n, ret));
        }
        case SYS_myst_unload_symbols:
        {
            long ret = 0;

            _strace(n, NULL);

            if (__myst_kernel_args.debug_symbols)
                ret = myst_syscall_unload_symbols();

            BREAK(_return(n, ret));
        }
        case SYS_myst_gen_creds:
        {
            _strace(n, NULL);
            BREAK(_forward_syscall(MYST_TCALL_GEN_CREDS, params));
        }
        case SYS_myst_free_creds:
        {
            _strace(n, NULL);
            BREAK(_forward_syscall(MYST_TCALL_FREE_CREDS, params));
        }
        case SYS_myst_gen_creds_ex:
        {
            _strace(n, NULL);
            BREAK(_forward_syscall(MYST_TCALL_GEN_CREDS_EX, params));
        }
        case SYS_myst_verify_cert:
        {
            _strace(n, NULL);
            BREAK(_forward_syscall(MYST_TCALL_VERIFY_CERT, params));
        }
        case SYS_myst_max_threads:
        {
            _strace(n, NULL);
            BREAK(_return(n, __myst_kernel_args.max_threads));
        }
        case SYS_myst_poll_wake:
        {
            _strace(n, NULL);
            BREAK(_return(n, myst_tcall_poll_wake()));
        }
#ifdef MYST_ENABLE_GCOV
        case SYS_myst_gcov:
        {
            const char* func = (const char*)x1;
            long* gcov_params = (long*)x2;

            _strace(n, "func=%s gcov_params=%p", func, gcov_params);

            long ret = myst_gcov(func, gcov_params);
            BREAK(_return(n, ret));
        }
#endif
        case SYS_myst_unmap_on_exit:
        {
            void* ptr = (void*)x1;
            size_t size = (size_t)x2;
            myst_thread_t* process_thread = myst_find_process_thread(thread);

            _strace(n, "ptr=%p, size=%zu", ptr, size);

            BREAK(_return(
                n, myst_syscall_unmap_on_exit(process_thread, ptr, size)));
        }
        case SYS_get_process_thread_stack:
        {
            _strace(n, NULL);
            void** stack = (void**)x1;
            size_t* stack_size = (size_t*)x2;

            _strace(n, "stack=%p stack_size=%p", stack, stack_size);

            long ret = myst_syscall_get_process_thread_stack(stack, stack_size);
            BREAK(_return(n, ret));
        }
        case SYS_read:
        {
            int fd = (int)x1;
            void* buf = (void*)x2;
            size_t count = (size_t)x3;

            _strace(n, "fd=%d buf=%p count=%zu", fd, buf, count);

            BREAK(_return(n, myst_syscall_read(fd, buf, count)));
        }
        case SYS_write:
        {
            int fd = (int)x1;
            const void* buf = (const void*)x2;
            size_t count = (size_t)x3;

            _strace(n, "fd=%d buf=%p count=%zu", fd, buf, count);

            BREAK(_return(n, myst_syscall_write(fd, buf, count)));
        }
        case SYS_pread64:
        {
            int fd = (int)x1;
            void* buf = (void*)x2;
            size_t count = (size_t)x3;
            off_t offset = (off_t)x4;

            _strace(
                n, "fd=%d buf=%p count=%zu offset=%ld", fd, buf, count, offset);

            BREAK(_return(n, myst_syscall_pread(fd, buf, count, offset)));
        }
        case SYS_pwrite64:
        {
            int fd = (int)x1;
            void* buf = (void*)x2;
            size_t count = (size_t)x3;
            off_t offset = (off_t)x4;

            _strace(
                n, "fd=%d buf=%p count=%zu offset=%ld", fd, buf, count, offset);

            BREAK(_return(n, myst_syscall_pwrite(fd, buf, count, offset)));
        }
        case SYS_open:
        {
            const char* path = (const char*)x1;
            int flags = (int)x2;
            mode_t mode = (mode_t)x3;
            long ret;

            _strace(n, "path=\"%s\" flags=0%o mode=0%o", path, flags, mode);

            ret = myst_syscall_open(path, flags, mode);

            BREAK(_return(n, ret));
        }
        case SYS_close:
        {
            int fd = (int)x1;

            _strace(n, "fd=%d", fd);

            BREAK(_return(n, myst_syscall_close(fd)));
        }
        case SYS_stat:
        {
            const char* pathname = (const char*)x1;
            struct stat* statbuf = (struct stat*)x2;

            _strace(n, "pathname=\"%s\" statbuf=%p", pathname, statbuf);

            BREAK(_return(n, myst_syscall_stat(pathname, statbuf)));
        }
        case SYS_fstat:
        {
            int fd = (int)x1;
            void* statbuf = (void*)x2;

            _strace(n, "fd=%d statbuf=%p", fd, statbuf);

            BREAK(_return(n, myst_syscall_fstat(fd, statbuf)));
        }
        case SYS_lstat:
        {
            /* ATTN: remove this! */
            const char* pathname = (const char*)x1;
            struct stat* statbuf = (struct stat*)x2;

            _strace(n, "pathname=\"%s\" statbuf=%p", pathname, statbuf);

            BREAK(_return(n, myst_syscall_lstat(pathname, statbuf)));
        }
        case SYS_poll:
        {
            struct pollfd* fds = (struct pollfd*)x1;
            nfds_t nfds = (nfds_t)x2;
            int timeout = (int)x3;
            long ret;

            _strace(n, "fds=%p nfds=%ld timeout=%d", fds, nfds, timeout);

            if (__myst_kernel_args.trace_syscalls && fds)
            {
                for (nfds_t i = 0; i < nfds; i++)
                    myst_eprintf("fd=%d\n", fds[i].fd);
            }

            ret = myst_syscall_poll(fds, nfds, timeout);
            BREAK(_return(n, ret));
        }
        case SYS_lseek:
        {
            int fd = (int)x1;
            off_t offset = (off_t)x2;
            int whence = (int)x3;

            _strace(n, "fd=%d offset=%ld whence=%d", fd, offset, whence);

            BREAK(_return(n, myst_syscall_lseek(fd, offset, whence)));
        }
        case SYS_mmap:
        {
            void* addr = (void*)x1;
            size_t length = (size_t)x2;
            int prot = (int)x3;
            int flags = (int)x4;
            int fd = (int)x5;
            off_t offset = (off_t)x6;
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

                if (myst_register_process_mapping(
                        pid,
                        ptr,
                        length,
                        // Linux ignores fd when the MAP_ANONYMOUS flag is
                        // present
                        flags & MAP_ANONYMOUS ? -1 : fd,
                        offset,
                        prot) != 0)
                    myst_panic("failed to register process mapping");

                ret = (long)ptr;
            }

            BREAK(_return(n, ret));
        }
        case SYS_mprotect:
        {
            const void* addr = (void*)x1;
            const size_t length = (size_t)x2;
            const int prot = (int)x3;

            _strace(
                n,
                "addr=%lx length=%zu(%lx) prot=%d",
                (long)addr,
                length,
                length,
                prot);

            BREAK(_return(n, (long)myst_mprotect(addr, length, prot)));
        }
        case SYS_munmap:
        {
            void* addr = (void*)x1;
            size_t length = (size_t)x2;

            _strace(n, "addr=%lx length=%zu(%lx)", (long)addr, length, length);

            // if the ummapped region overlaps the CRT thread descriptor, then
            // postpone the unmap because unmapping now would invalidate the
            // stack canary and would raise __stack_chk_fail(); this occurs
            // when munmap() is called from __unmapself()
            if (crt_td && addr && length)
            {
                const uint8_t* p = (const uint8_t*)crt_td;
                const uint8_t* pend = p + sizeof(myst_td_t);
                const uint8_t* q = (const uint8_t*)addr;
                const uint8_t* qend = q + length;

                if ((p >= q && p < qend) || (pend >= q && pend < qend))
                {
                    myst_thread_t* process_thread =
                        myst_find_process_thread(thread);

                    /* unmap this later when the thread exits */
                    BREAK(_return(
                        n,
                        myst_syscall_unmap_on_exit(
                            process_thread, addr, length)));
                }
            }

            BREAK(_return(n, (long)myst_munmap(addr, length)));
        }
        case SYS_brk:
        {
            void* addr = (void*)x1;

            _strace(n, "addr=%lx", (long)addr);

            BREAK(_return(n, myst_syscall_brk(addr)));
        }
        case SYS_rt_sigaction:
        {
            int signum = (int)x1;
            const posix_sigaction_t* act = (const posix_sigaction_t*)x2;
            posix_sigaction_t* oldact = (posix_sigaction_t*)x3;

            _strace(n, "signum=%d act=%p oldact=%p", signum, act, oldact);

            long ret = myst_signal_sigaction(signum, act, oldact);
            BREAK(_return(n, ret));
        }
        case SYS_rt_sigprocmask:
        {
            int how = (int)x1;
            const sigset_t* set = (sigset_t*)x2;
            sigset_t* oldset = (sigset_t*)x3;

            _strace(n, "how=%d set=%p oldset=%p", how, set, oldset);

            long ret = myst_signal_sigprocmask(how, set, oldset);
            BREAK(_return(n, ret));
        }
        case SYS_rt_sigreturn:
            break;
        case SYS_ioctl:
        {
            int fd = (int)x1;
            unsigned long request = (unsigned long)x2;
            long arg = (long)x3;
            int iarg = -1;

            if (request == FIONBIO && arg)
                iarg = *(int*)arg;

            _strace(
                n,
                "fd=%d request=0x%lx arg=%lx iarg=%d",
                fd,
                request,
                arg,
                iarg);

            BREAK(_return(n, myst_syscall_ioctl(fd, request, arg)));
        }
        case SYS_readv:
        {
            int fd = (int)x1;
            const struct iovec* iov = (const struct iovec*)x2;
            int iovcnt = (int)x3;

            _strace(n, "fd=%d iov=%p iovcnt=%d", fd, iov, iovcnt);

            BREAK(_return(n, myst_syscall_readv(fd, iov, iovcnt)));
        }
        case SYS_writev:
        {
            int fd = (int)x1;
            const struct iovec* iov = (const struct iovec*)x2;
            int iovcnt = (int)x3;

            _strace(n, "fd=%d iov=%p iovcnt=%d", fd, iov, iovcnt);

            BREAK(_return(n, myst_syscall_writev(fd, iov, iovcnt)));
        }
        case SYS_access:
        {
            const char* pathname = (const char*)x1;
            int mode = (int)x2;

            _strace(n, "pathname=\"%s\" mode=%d", pathname, mode);

            BREAK(_return(n, myst_syscall_access(pathname, mode)));
        }
        case SYS_pipe:
        {
            int* pipefd = (int*)x1;

            _strace(n, "pipefd=%p flags=%0o", pipefd, 0);

            BREAK(_return(n, myst_syscall_pipe2(pipefd, 0)));
        }
        case SYS_select:
        {
            int nfds = (int)x1;
            fd_set* rfds = (fd_set*)x2;
            fd_set* wfds = (fd_set*)x3;
            fd_set* efds = (fd_set*)x4;
            struct timeval* timeout = (struct timeval*)x5;
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
            BREAK(_return(n, ret));
        }
        case SYS_sched_yield:
        {
            _strace(n, NULL);

            BREAK(_return(n, myst_syscall_sched_yield()));
        }
        case SYS_mremap:
        {
            void* old_address = (void*)x1;
            size_t old_size = (size_t)x2;
            size_t new_size = (size_t)x3;
            int flags = (int)x4;
            void* new_address = (void*)x5;
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

            ret = (long)myst_mremap(
                old_address, old_size, new_size, flags, new_address);

            BREAK(_return(n, ret));
        }
        case SYS_msync:
        {
            void* addr = (void*)x1;
            size_t length = (size_t)x2;
            int flags = (int)x3;

            _strace(n, "addr=%p length=%zu flags=%d ", addr, length, flags);

            BREAK(_return(n, myst_msync(addr, length, flags)));
        }
        case SYS_mincore:
            /* ATTN: hook up implementation */
            break;
        case SYS_madvise:
        {
            void* addr = (void*)x1;
            size_t length = (size_t)x2;
            int advice = (int)x3;

            _strace(n, "addr=%p length=%zu advice=%d", addr, length, advice);

            BREAK(_return(n, 0));
        }
        case SYS_shmget:
            break;
        case SYS_shmat:
            break;
        case SYS_shmctl:
            break;
        case SYS_dup:
        {
            int oldfd = (int)x1;
            long ret;

            _strace(n, "oldfd=%d", oldfd);

            ret = myst_syscall_dup(oldfd);
            BREAK(_return(n, ret));
        }
        case SYS_dup2:
        {
            int oldfd = (int)x1;
            int newfd = (int)x2;
            long ret;

            _strace(n, "oldfd=%d newfd=%d", oldfd, newfd);

            ret = myst_syscall_dup2(oldfd, newfd);
            BREAK(_return(n, ret));
        }
        case SYS_dup3:
        {
            int oldfd = (int)x1;
            int newfd = (int)x2;
            int flags = (int)x3;
            long ret;

            _strace(n, "oldfd=%d newfd=%d flags=%o", oldfd, newfd, flags);

            ret = myst_syscall_dup3(oldfd, newfd, flags);
            BREAK(_return(n, ret));
        }
        case SYS_pause:
            break;
        case SYS_nanosleep:
        {
            const struct timespec* req = (const struct timespec*)x1;
            struct timespec* rem = (struct timespec*)x2;

            _strace(n, "req=%p rem=%p", req, rem);

            BREAK(_return(n, myst_syscall_nanosleep(req, rem)));
        }
        case SYS_myst_run_itimer:
        {
            _strace(n, NULL);
            BREAK(_return(n, myst_syscall_run_itimer()));
        }
        case SYS_myst_start_shell:
        {
            _strace(n, NULL);

            if (__myst_kernel_args.shell_mode)
                myst_start_shell("\nMystikos shell (syscall)\n");

            BREAK(_return(n, 0));
        }
        case SYS_getitimer:
        {
            int which = (int)x1;
            struct itimerval* curr_value = (void*)x2;

            _strace(n, "which=%d curr_value=%p", which, curr_value);

            BREAK(_return(n, myst_syscall_getitimer(which, curr_value)));
        }
        case SYS_alarm:
            break;
        case SYS_setitimer:
        {
            int which = (int)x1;
            const struct itimerval* new_value = (void*)x2;
            struct itimerval* old_value = (void*)x3;

            _strace(
                n,
                "which=%d new_value=%p old_value=%p",
                which,
                new_value,
                old_value);

            BREAK(_return(
                n, myst_syscall_setitimer(which, new_value, old_value)));
        }
        case SYS_getpid:
        {
            _strace(n, NULL);
            BREAK(_return(n, myst_getpid()));
        }
        case SYS_clone:
        {
            /* unsupported: using SYS_myst_clone instead */
            break;
        }
        case SYS_myst_clone:
        {
            long* args = (long*)x1;
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

            long ret = myst_syscall_clone(
                fn, child_stack, flags, arg, ptid, newtls, ctid);

            if ((flags & CLONE_VFORK))
            {
                // ATTN: give the thread a little time to start to avoid a
                // syncyhronization error. This suppresses a failure in the
                // popen test. This should be investigated later.
                myst_sleep_msec(5);
            }

            BREAK(_return(n, ret));
        }
        case SYS_myst_get_fork_info:
        {
            myst_fork_info_t* arg = (myst_fork_info_t*)x1;

            _strace(n, NULL);

            long ret = myst_syscall_get_fork_info(thread, arg);
            BREAK(_return(n, ret));
        }
        case SYS_fork_wait_exec_exit:
        {
            int ret = 0;
            _strace(n, NULL);
            myst_futex_wait(&thread->fork_exec_futex_wait, 0, NULL);
            BREAK(_return(n, ret));
        }
        case SYS_myst_kill_wait_child_forks:
        {
            long ret = 0;
            myst_thread_t* process = myst_find_process_thread(thread);

            _strace(n, NULL);

            kill_child_fork_processes(process);

            while (myst_have_child_forked_processes(process))
            {
                myst_sleep_msec(100);
            }

            BREAK(_return(n, ret));
        }
        case SYS_fork:
            break;
        case SYS_vfork:
            break;
        case SYS_execve:
        {
            const char* filename = (const char*)x1;
            char** argv = (char**)x2;
            char** envp = (char**)x3;

            _strace(n, "filename=%s argv=%p envp=%p", filename, argv, envp);

            long ret = myst_syscall_execve(filename, argv, envp);
            BREAK(_return(n, ret));
        }
        case SYS_exit:
        {
            const int status = (int)x1;
            myst_thread_t* thread = myst_thread_self();
            myst_thread_t* process = myst_find_process_thread(thread);

            _strace(n, "status=%d", status);

            if (!thread || thread->magic != MYST_THREAD_MAGIC)
                myst_panic("unexpected");

            process->exit_status = status;

            /* the kstack is freed after the long-jump below */
            thread->kstack = args->kstack;

            /* If this process was created as part of a fork() and the parent is
             * running in wait-exec mode, signal that thread for wakeup */
            if (process->clone.flags & CLONE_VFORK)
            {
                myst_fork_exec_futex_wake(thread);
            }

            /* jump back to myst_enter_kernel() */
            myst_longjmp(&thread->jmpbuf, 1);

            /* unreachable */
            break;
        }
        case SYS_wait4:
        {
            pid_t pid = (pid_t)x1;
            int* wstatus = (int*)x2;
            int options = (int)x3;
            struct rusage* rusage = (struct rusage*)x4;
            long ret;

            ret = myst_syscall_wait4(pid, wstatus, options, rusage);
            BREAK(_return(n, ret));
        }
        case SYS_kill:
        {
            int pid = (int)x1;
            int sig = (int)x2;

            _strace(n, "pid=%d sig=%d", pid, sig);

            long ret = myst_syscall_kill(pid, sig);
            BREAK(_return(n, ret));
        }
        case SYS_uname:
        {
            struct utsname* buf = (struct utsname*)x1;

            BREAK(_return(n, myst_syscall_uname(buf)));
        }
        case SYS_semget:
            break;
        case SYS_semop:
            break;
        case SYS_semctl:
            break;
        case SYS_shmdt:
            break;
        case SYS_msgget:
            break;
        case SYS_msgsnd:
            break;
        case SYS_msgrcv:
            break;
        case SYS_msgctl:
            break;
        case SYS_fcntl:
        {
            int fd = (int)x1;
            int cmd = (int)x2;
            long arg = (long)x3;
            long ret;

            const char* cmdstr = _fcntl_cmdstr(cmd);
            _strace(n, "fd=%d cmd=%d(%s) arg=0%lo", fd, cmd, cmdstr, arg);

            ret = myst_syscall_fcntl(fd, cmd, arg);
            BREAK(_return(n, ret));
        }
        case SYS_flock:
        {
            int fd = (int)x1;
            int cmd = (int)x2;

            _strace(n, "fd=%d cmd=%d", fd, cmd);

            BREAK(_return(n, 0));
        }
        case SYS_fsync:
        {
            int fd = (int)x1;

            _strace(n, "fd=%d", fd);

            BREAK(_return(n, myst_syscall_fsync(fd)));
        }
        case SYS_fdatasync:
        {
            int fd = (int)x1;

            _strace(n, "fd=%d", fd);

            BREAK(_return(n, myst_syscall_fdatasync(fd)));
        }
        case SYS_truncate:
        {
            const char* path = (const char*)x1;
            off_t length = (off_t)x2;

            _strace(n, "path=\"%s\" length=%ld", path, length);

            BREAK(_return(n, myst_syscall_truncate(path, length)));
        }
        case SYS_ftruncate:
        {
            int fd = (int)x1;
            off_t length = (off_t)x2;

            _strace(n, "fd=%d length=%ld", fd, length);

            BREAK(_return(n, myst_syscall_ftruncate(fd, length)));
        }
        case SYS_getdents:
            break;
        case SYS_getcwd:
        {
            char* buf = (char*)x1;
            size_t size = (size_t)x2;

            _strace(n, "buf=%p size=%zu", buf, size);

            BREAK(_return(n, myst_syscall_getcwd(buf, size)));
        }
        case SYS_chdir:
        {
            const char* path = (const char*)x1;

            _strace(n, "path=\"%s\"", path);

            BREAK(_return(n, myst_syscall_chdir(path)));
        }
        case SYS_fchdir:
        {
            int fd = (int)x1;

            _strace(n, "fd=%d", fd);

            BREAK(_return(n, myst_syscall_fchdir(fd)));
        }
        case SYS_rename:
        {
            const char* oldpath = (const char*)x1;
            const char* newpath = (const char*)x2;

            _strace(n, "oldpath=\"%s\" newpath=\"%s\"", oldpath, newpath);

            BREAK(_return(n, myst_syscall_rename(oldpath, newpath)));
        }
        case SYS_mkdir:
        {
            const char* pathname = (const char*)x1;
            mode_t mode = (mode_t)x2;

            _strace(n, "pathname=\"%s\" mode=0%o", pathname, mode);

            BREAK(_return(n, myst_syscall_mkdir(pathname, mode)));
        }
        case SYS_rmdir:
        {
            const char* pathname = (const char*)x1;

            _strace(n, "pathname=\"%s\"", pathname);

            BREAK(_return(n, myst_syscall_rmdir(pathname)));
        }
        case SYS_creat:
        {
            const char* pathname = (const char*)x1;
            mode_t mode = (mode_t)x2;

            _strace(n, "pathname=\"%s\" mode=%x", pathname, mode);

            BREAK(_return(n, myst_syscall_creat(pathname, mode)));
        }
        case SYS_link:
        {
            const char* oldpath = (const char*)x1;
            const char* newpath = (const char*)x2;

            _strace(n, "oldpath=\"%s\" newpath=\"%s\"", oldpath, newpath);

            BREAK(_return(n, myst_syscall_link(oldpath, newpath)));
        }
        case SYS_unlink:
        {
            const char* pathname = (const char*)x1;

            _strace(n, "pathname=\"%s\"", pathname);

            BREAK(_return(n, myst_syscall_unlink(pathname)));
        }
        case SYS_symlink:
        {
            const char* target = (const char*)x1;
            const char* linkpath = (const char*)x2;

            _strace(n, "target=\"%s\" linkpath=\"%s\"", target, linkpath);

            BREAK(_return(n, myst_syscall_symlink(target, linkpath)));
        }
        case SYS_readlink:
        {
            const char* pathname = (const char*)x1;
            char* buf = (char*)x2;
            size_t bufsiz = (size_t)x3;

            _strace(
                n, "pathname=\"%s\" buf=%p bufsiz=%zu", pathname, buf, bufsiz);

            BREAK(_return(n, myst_syscall_readlink(pathname, buf, bufsiz)));
        }
        case SYS_chmod:
        {
            const char* pathname = (const char*)x1;
            mode_t mode = (mode_t)x2;

            _strace(n, "pathname=\"%s\" mode=%o", pathname, mode);

            BREAK(_return(n, myst_syscall_chmod(pathname, mode)));
        }
        case SYS_fchmod:
        {
            int fd = (int)x1;
            mode_t mode = (mode_t)x2;

            _strace(n, "fd=%d mode=%o", fd, mode);

            BREAK(_return(n, myst_syscall_fchmod(fd, mode)));
        }
        case SYS_chown:
        {
            const char* pathname = (const char*)x1;
            uid_t owner = (uid_t)x2;
            gid_t group = (gid_t)x3;

            _strace(n, "pathname=%s owner=%u group=%u", pathname, owner, group);

            BREAK(_return(n, myst_syscall_chown(pathname, owner, group)));
        }
        case SYS_fchown:
        {
            int fd = (int)x1;
            uid_t owner = (uid_t)x2;
            gid_t group = (gid_t)x3;

            _strace(n, "fd=%d owner=%u group=%u", fd, owner, group);

            BREAK(_return(n, myst_syscall_fchown(fd, owner, group)));
        }
        case SYS_fchownat:
        {
            int dirfd = (int)x1;
            const char* pathname = (const char*)x2;
            uid_t owner = (uid_t)x3;
            gid_t group = (gid_t)x4;
            int flags = (int)x5;

            _strace(
                n,
                "dirfd=%d pathname=%s owner=%u group=%u flags=%d",
                dirfd,
                pathname,
                owner,
                group,
                flags);

            BREAK(_return(
                n,
                myst_syscall_fchownat(dirfd, pathname, owner, group, flags)));
        }
        case SYS_lchown:
        {
            const char* pathname = (const char*)x1;
            uid_t owner = (uid_t)x2;
            gid_t group = (gid_t)x3;

            _strace(n, "pathname=%s owner=%u group=%u", pathname, owner, group);

            BREAK(_return(n, myst_syscall_lchown(pathname, owner, group)));
        }
        case SYS_umask:
        {
            mode_t mask = (mode_t)x1;

            _strace(n, "mask=%o", mask);

            BREAK(_return(n, myst_syscall_umask(mask)));
        }
        case SYS_gettimeofday:
        {
            struct timeval* tv = (struct timeval*)x1;
            struct timezone* tz = (void*)x2;

            _strace(n, "tv=%p tz=%p", tv, tz);

            long ret = myst_syscall_gettimeofday(tv, tz);
            BREAK(_return(n, ret));
        }
        case SYS_getrlimit:
            break;
        case SYS_getrusage:
        {
            int who = (int)x1;
            struct rusage* usage = (struct rusage*)x2;

            _strace(n, "who=%d usage=%p", who, usage);

            long ret = myst_syscall_getrusage(who, usage);
            BREAK(_return(n, ret));
        }
        case SYS_sysinfo:
        {
            struct sysinfo* info = (struct sysinfo*)x1;
            _strace(n, "info=%p", info);
            long ret = myst_syscall_sysinfo(info);
            BREAK(_return(n, ret));
        }
        case SYS_times:
        {
            struct tms* tm = (struct tms*)x1;
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

            BREAK(_return(n, stime + utime));
        }
        case SYS_ptrace:
            break;
        case SYS_syslog:
        {
            /* Ignore syslog for now */
            BREAK(_return(n, 0));
        }
        case SYS_setpgid:
        {
            pid_t pid = (pid_t)x1;
            pid_t pgid = (pid_t)x2;
            _strace(n, "pid=%u pgid=%u", pid, pgid);
            BREAK(_return(n, myst_syscall_setpgid(pid, pgid, thread)));
        }
        case SYS_getpgid:
        {
            pid_t pid = (pid_t)x1;
            _strace(n, "pid=%u", pid);
            BREAK(_return(n, myst_syscall_getpgid(pid, thread)));
        }
        case SYS_getpgrp:
        {
            _strace(n, NULL);
            BREAK(_return(n, myst_syscall_getpgid(thread->pid, thread)));
        }
        case SYS_getppid:
        {
            _strace(n, NULL);
            BREAK(_return(n, myst_getppid()));
        }
        case SYS_getsid:
        {
            _strace(n, NULL);
            BREAK(_return(n, myst_getsid()));
        }
        case SYS_setsid:
            break;
        case SYS_getgroups:
        {
            size_t size = (size_t)x1;
            gid_t* list = (gid_t*)x2;
            /* return the extra groups on the thread */
            _strace(n, NULL);
            BREAK(_return(n, myst_syscall_getgroups(size, list)));
        }
        case SYS_setgroups:
        {
            int size = (int)x1;
            const gid_t* list = (const gid_t*)x2;

            /* return the extra groups on the thread */
            _strace(n, NULL);
            BREAK(_return(n, myst_syscall_setgroups(size, list)));
        }
        case SYS_getuid:
        {
            /* return the real uid of the thread */
            _strace(n, NULL);
            BREAK(_return(n, myst_syscall_getuid()));
        }
        case SYS_setuid:
        {
            /* Set euid and fsuid to arg1, and if euid is already set to root
             * also set uid and savuid of the thread */
            uid_t uid = (uid_t)x1;
            _strace(n, "uid=%u", uid);

            BREAK(_return(n, myst_syscall_setuid(uid)));
        }
        case SYS_getgid:
        {
            /* return the gid of the thread */
            _strace(n, NULL);
            BREAK(_return(n, myst_syscall_getgid()));
        }
        case SYS_setgid:
        {
            /* set the effective gid (euid) of the thread, unless egid is root
             * in which case set all gids */
            gid_t gid = (gid_t)x1;
            _strace(n, "gid=%u", gid);
            BREAK(_return(n, myst_syscall_setgid(gid)));
        }
        case SYS_geteuid:
        {
            /* return threads effective uid (euid) */
            _strace(n, NULL);
            BREAK(_return(n, myst_syscall_geteuid()));
        }
        case SYS_getegid:
        {
            /* return threads effective gid (egid) */
            _strace(n, NULL);
            BREAK(_return(n, myst_syscall_getegid()));
        }
        case SYS_setreuid:
        {
            /* set the real and effective uid of the thread */
            uid_t ruid = (uid_t)x1;
            uid_t euid = (uid_t)x2;
            _strace(n, "Changing IDs to ruid=%u, euid=%u", ruid, euid);
            BREAK(_return(n, myst_syscall_setreuid(ruid, euid)));
        }
        case SYS_setregid:
        {
            /* set the real and effective uid of the thread */
            gid_t rgid = (gid_t)x1;
            gid_t egid = (gid_t)x2;
            _strace(n, "Changing setting to rgid=%u, egid=%u", rgid, egid);
            BREAK(_return(n, myst_syscall_setregid(rgid, egid)));
        }
        case SYS_setresuid:
        {
            /* set the real and effective uid of the thread */
            uid_t ruid = (uid_t)x1;
            uid_t euid = (uid_t)x2;
            uid_t savuid = (uid_t)x3;
            _strace(
                n,
                "Changing setting to ruid=%u, euid=%u, savuid=%u",
                ruid,
                euid,
                savuid);
            BREAK(_return(n, myst_syscall_setresuid(ruid, euid, savuid)));
        }
        case SYS_getresuid:
        {
            uid_t* ruid = (uid_t*)x1;
            uid_t* euid = (uid_t*)x2;
            uid_t* savuid = (uid_t*)x3;
            _strace(n, NULL);
            BREAK(_return(n, myst_syscall_getresuid(ruid, euid, savuid)));
        }
        case SYS_setresgid:
        {
            /* set the real and effective uid of the thread */
            gid_t rgid = (gid_t)x1;
            gid_t egid = (gid_t)x2;
            gid_t savgid = (gid_t)x3;
            _strace(
                n,
                "Changing setting to rgid=%u, egid=%u, savgid=%u",
                rgid,
                egid,
                savgid);
            BREAK(_return(n, myst_syscall_setresgid(rgid, egid, savgid)));
        }
        case SYS_getresgid:
        {
            gid_t* rgid = (gid_t*)x1;
            gid_t* egid = (gid_t*)x2;
            gid_t* savgid = (gid_t*)x3;
            _strace(n, NULL);
            BREAK(_return(n, myst_syscall_getresgid(rgid, egid, savgid)));
        }
        case SYS_setfsuid:
        {
            uid_t fsuid = (uid_t)x1;
            _strace(n, "fsuid=%u", fsuid);
            BREAK(_return(n, myst_syscall_setfsuid(fsuid)));
        }
        case SYS_setfsgid:
        {
            gid_t fsgid = (gid_t)x1;
            _strace(n, "fsgid=%u", fsgid);
            BREAK(_return(n, myst_syscall_setfsgid(fsgid)));
        }
        case SYS_capget:
            break;
        case SYS_capset:
            break;
        case SYS_rt_sigpending:
        {
            sigset_t* set = (sigset_t*)x1;
            unsigned size = (unsigned)x2;
            BREAK(_return(n, myst_signal_sigpending(set, size)));
        }
        case SYS_rt_sigtimedwait:
            break;
        case SYS_rt_sigqueueinfo:
            break;
        case SYS_rt_sigsuspend:
            break;
        case SYS_sigaltstack:
        {
            /* ATTN: support user space stack for segv handling. */
            BREAK(_return(n, 0));
        }
        case SYS_utime:
            break;
        case SYS_mknod:
        {
            const char* pathname = (const char*)x1;
            mode_t mode = (mode_t)x2;
            dev_t dev = (dev_t)x3;
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

            BREAK(_return(n, ret));
        }
        case SYS_uselib:
            break;
        case SYS_personality:
            break;
        case SYS_ustat:
            break;
        case SYS_statfs:
        {
            const char* path = (const char*)x1;
            struct statfs* buf = (struct statfs*)x2;

            _strace(n, "path=%s buf=%p", path, buf);

            long ret = myst_syscall_statfs(path, buf);

            BREAK(_return(n, ret));
        }
        case SYS_fstatfs:
        {
            int fd = (int)x1;
            struct statfs* buf = (struct statfs*)x2;

            _strace(n, "fd=%d buf=%p", fd, buf);

            long ret = myst_syscall_fstatfs(fd, buf);

            BREAK(_return(n, ret));
        }
        case SYS_sysfs:
            break;
        case SYS_getpriority:
            break;
        case SYS_setpriority:
            break;
        case SYS_sched_setparam:
        {
            /* ATTN: support setting thread priorities. */
            BREAK(_return(n, 0));
        }
        case SYS_sched_getparam:
        {
            pid_t pid = (pid_t)x1;
            struct sched_param* param = (struct sched_param*)x2;

            _strace(n, "pid=%d param=%p", pid, param);

            // ATTN: Return the priority from SYS_sched_setparam.
            if (param != NULL)
            {
                // Only memset the non reserved part of the structure
                // This is to be defensive against different sizes of this
                // struct in musl and glibc.
                memset(param, 0, sizeof(*param) - 40);
            }
            BREAK(_return(n, 0));
        }
        case SYS_sched_setscheduler:
        {
            // ATTN: support different schedules, FIFO, RR, BATCH, etc.
            // The more control we have on threads inside the kernel, the more
            // schedulers we could support.
            BREAK(_return(n, 0));
        }
        case SYS_sched_getscheduler:
        {
            /* ATTN: return the scheduler installed from sched_setscheduler. */
            BREAK(_return(n, SCHED_OTHER));
        }
        case SYS_sched_get_priority_max:
        {
            /* ATTN: support thread priorities */
            BREAK(_return(n, 0));
        }
        case SYS_sched_get_priority_min:
        {
            /* ATTN: support thread priorities */
            BREAK(_return(n, 0));
        }
        case SYS_sched_rr_get_interval:
            break;
        case SYS_mlock:
        {
            const void* addr = (const void*)x1;
            size_t len = (size_t)x2;
            long ret = 0;

            _strace(n, "addr=%p len=%zu\n", addr, len);

            if (!addr)
                ret = -EINVAL;

            // ATTN: forward the request to target.
            // Some targets, such as sgx, probably just ignore it.

            BREAK(_return(n, ret));
        }
        case SYS_munlock:
            break;
        case SYS_mlockall:
            break;
        case SYS_munlockall:
            break;
        case SYS_vhangup:
            break;
        case SYS_modify_ldt:
            break;
        case SYS_pivot_root:
            break;
        case SYS__sysctl:
            break;
        case SYS_prctl:
        {
            int option = (int)x1;
            long ret = 0;

            _strace(n, "option=%d\n", option);

            if (option == PR_GET_NAME)
            {
                char* arg2 = (char*)x2;
                if (!arg2)
                    BREAK(_return(n, -EINVAL));

                // ATTN: Linux requires a 16-byte buffer:
                const size_t n = 16;
                myst_strlcpy(arg2, myst_get_thread_name(myst_thread_self()), n);
            }
            else if (option == PR_SET_NAME)
            {
                char* arg2 = (char*)x2;
                if (!arg2)
                    BREAK(_return(n, -EINVAL));

                ret = myst_set_thread_name(myst_thread_self(), arg2);
            }
            else
            {
                ret = -EINVAL;
            }

            BREAK(_return(n, ret));
        }
        case SYS_arch_prctl:
        {
            /* this is handled in myst_syscall() */
            break;
        }
        case SYS_adjtimex:
            break;
        case SYS_setrlimit:
            break;
        case SYS_chroot:
            break;
        case SYS_sync:
            break;
        case SYS_acct:
            break;
        case SYS_settimeofday:
            break;
        case SYS_mount:
        {
            const char* source = (const char*)x1;
            const char* target = (const char*)x2;
            const char* filesystemtype = (const char*)x3;
            unsigned long mountflags = (unsigned long)x4;
            void* data = (void*)x5;
            long ret;

            _strace(
                n,
                "source=%s target=%s filesystemtype=%s mountflags=%lu data=%p",
                source,
                target,
                filesystemtype,
                mountflags,
                data);

            ret = myst_syscall_mount(
                source, target, filesystemtype, mountflags, data, false);

            BREAK(_return(n, ret));
        }
        case SYS_umount2:
        {
            const char* target = (const char*)x1;
            int flags = (int)x2;
            long ret;

            _strace(n, "target=%p flags=%d", target, flags);

            ret = myst_syscall_umount2(target, flags);

            BREAK(_return(n, ret));
        }
        case SYS_swapon:
            break;
        case SYS_swapoff:
            break;
        case SYS_reboot:
            break;
        case SYS_sethostname:
        {
            const char* name = (const char*)x1;
            size_t len = (size_t)x2;

            _strace(n, "name=\"%s\" len=%zu", name, len);

            BREAK(_return(n, myst_syscall_sethostname(name, len)));
        }
        case SYS_setdomainname:
            break;
        case SYS_iopl:
            break;
        case SYS_ioperm:
            break;
        case SYS_create_module:
            break;
        case SYS_init_module:
            break;
        case SYS_delete_module:
            break;
        case SYS_get_kernel_syms:
            break;
        case SYS_query_module:
            break;
        case SYS_quotactl:
            break;
        case SYS_nfsservctl:
            break;
        case SYS_getpmsg:
            break;
        case SYS_putpmsg:
            break;
        case SYS_afs_syscall:
            break;
        case SYS_tuxcall:
            break;
        case SYS_security:
            break;
        case SYS_gettid:
        {
            _strace(n, NULL);
            BREAK(_return(n, myst_gettid()));
        }
        case SYS_readahead:
            break;
        case SYS_setxattr:
            break;
        case SYS_lsetxattr:
            break;
        case SYS_fsetxattr:
            break;
        case SYS_getxattr:
            break;
        case SYS_lgetxattr:
            break;
        case SYS_fgetxattr:
            break;
        case SYS_listxattr:
            break;
        case SYS_llistxattr:
            break;
        case SYS_flistxattr:
            break;
        case SYS_removexattr:
            break;
        case SYS_lremovexattr:
            break;
        case SYS_fremovexattr:
            break;
        case SYS_tkill:
        {
            int tid = (int)x1;
            int sig = (int)x2;

            _strace(n, "tid=%d sig=%d", tid, sig);

            myst_thread_t* thread = myst_thread_self();
            int tgid = thread->pid;

            long ret = myst_syscall_tgkill(tgid, tid, sig);
            BREAK(_return(n, ret));
        }
        case SYS_time:
        {
            time_t* tloc = (time_t*)x1;

            _strace(n, "tloc=%p", tloc);
            long ret = myst_syscall_time(tloc);
            BREAK(_return(n, ret));
        }
        case SYS_futex:
        {
            int* uaddr = (int*)x1;
            int futex_op = (int)x2;
            int val = (int)x3;
            long arg = (long)x4;
            int* uaddr2 = (int*)x5;
            int val3 = (int)x6;

            _strace(
                n,
                "uaddr=0x%lx(%d) futex_op=%u(%s) val=%d",
                (long)uaddr,
                (uaddr ? *uaddr : -1),
                futex_op,
                _futex_op_str(futex_op),
                val);

            BREAK(_return(
                n,
                myst_syscall_futex(uaddr, futex_op, val, arg, uaddr2, val3)));
        }
        case SYS_sched_setaffinity:
        {
            pid_t pid = (pid_t)x1;
            size_t cpusetsize = (pid_t)x2;
            const cpu_set_t* mask = (const cpu_set_t*)x3;
            long ret;

            _strace(
                n, "pid=%d cpusetsize=%zu mask=%p\n", pid, cpusetsize, mask);

            ret = myst_syscall_sched_setaffinity(pid, cpusetsize, mask);
            BREAK(_return(n, ret));
        }
        case SYS_sched_getaffinity:
        {
            pid_t pid = (pid_t)x1;
            size_t cpusetsize = (pid_t)x2;
            cpu_set_t* mask = (cpu_set_t*)x3;
            long ret;

            _strace(
                n, "pid=%d cpusetsize=%zu mask=%p\n", pid, cpusetsize, mask);

            /* returns the number of bytes in the kernel affinity mask */
            ret = myst_syscall_sched_getaffinity(pid, cpusetsize, mask);

            BREAK(_return(n, ret));
        }
        case SYS_set_thread_area:
        {
            void* tp = (void*)params[0];

            _strace(n, "tp=%p", tp);

            /* ---------- running target thread descriptor ---------- */

#ifdef DISABLE_MULTIPLE_SET_THREAD_AREA_SYSCALLS
            if (_set_thread_area_called)
                myst_panic("SYS_set_thread_area called twice");
#endif

            /* get the C-runtime thread descriptor */
            crt_td = (myst_td_t*)tp;
            assert(myst_valid_td(crt_td));

            /* set the C-runtime thread descriptor for this thread */
            thread->crt_td = crt_td;

            /* propagate the canary from the old thread descriptor */
            crt_td->canary = target_td->canary;

            _set_thread_area_called = true;

            BREAK(_return(n, 0));
        }
        case SYS_io_setup:
            break;
        case SYS_io_destroy:
            break;
        case SYS_io_getevents:
            break;
        case SYS_io_submit:
            break;
        case SYS_io_cancel:
            break;
        case SYS_get_thread_area:
            break;
        case SYS_lookup_dcookie:
            break;
        case SYS_epoll_create:
        {
            int size = (int)x1;

            _strace(n, "size=%d", size);

            if (size <= 0)
                BREAK(_return(n, -EINVAL));

            BREAK(_return(n, myst_syscall_epoll_create1(0)));
        }
        case SYS_epoll_ctl_old:
            break;
        case SYS_epoll_wait_old:
            break;
        case SYS_remap_file_pages:
            break;
        case SYS_getdents64:
        {
            unsigned int fd = (unsigned int)x1;
            struct dirent* dirp = (struct dirent*)x2;
            unsigned int count = (unsigned int)x3;

            _strace(n, "fd=%d dirp=%p count=%u", fd, dirp, count);

            BREAK(_return(n, myst_syscall_getdents64((int)fd, dirp, count)));
        }
        case SYS_set_tid_address:
        {
            int* tidptr = (int*)params[0];

            /* ATTN: unused */

            _strace(n, "tidptr=%p *tidptr=%d", tidptr, tidptr ? *tidptr : -1);

            BREAK(_return(n, myst_getpid()));
        }
        case SYS_restart_syscall:
            break;
        case SYS_semtimedop:
            break;
        case SYS_fadvise64:
        {
            int fd = (int)x1;
            loff_t offset = (loff_t)x2;
            loff_t len = (loff_t)x3;
            int advice = (int)x4;

            _strace(
                n,
                "fd=%d offset=%ld len=%ld advice=%d",
                fd,
                offset,
                len,
                advice);

            /* ATTN: no-op */
            BREAK(_return(n, 0));
        }
        case SYS_timer_create:
            break;
        case SYS_timer_settime:
            break;
        case SYS_timer_gettime:
            break;
        case SYS_timer_getoverrun:
            break;
        case SYS_timer_delete:
            break;
        case SYS_clock_settime:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;

            _strace(n, "clk_id=%u tp=%p", clk_id, tp);

            BREAK(_return(n, myst_syscall_clock_settime(clk_id, tp)));
        }
        case SYS_clock_gettime:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;

            _strace(n, "clk_id=%u tp=%p", clk_id, tp);

            BREAK(_return(n, myst_syscall_clock_gettime(clk_id, tp)));
        }
        case SYS_clock_getres:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* res = (struct timespec*)x2;

            _strace(n, "clk_id=%u tp=%p", clk_id, res);

            BREAK(_return(n, myst_syscall_clock_getres(clk_id, res)));
        }
        case SYS_clock_nanosleep:
            break;
        case SYS_exit_group:
        {
            int status = (int)x1;
            _strace(n, "status=%d", status);

            myst_kill_thread_group();
            BREAK(_return(n, 0));
        }
        case SYS_epoll_wait:
        {
            int epfd = (int)x1;
            struct epoll_event* events = (struct epoll_event*)x2;
            int maxevents = (int)x3;
            int timeout = (int)x4;
            long ret;

            _strace(
                n,
                "edpf=%d events=%p maxevents=%d timeout=%d",
                epfd,
                events,
                maxevents,
                timeout);

            ret = myst_syscall_epoll_wait(epfd, events, maxevents, timeout);
            BREAK(_return(n, ret));
        }
        case SYS_epoll_ctl:
        {
            int epfd = (int)x1;
            int op = (int)x2;
            int fd = (int)x3;
            struct epoll_event* event = (struct epoll_event*)x4;
            long ret;

            _strace(n, "edpf=%d op=%d fd=%d event=%p", epfd, op, fd, event);

            ret = myst_syscall_epoll_ctl(epfd, op, fd, event);
            BREAK(_return(n, ret));
        }
        case SYS_tgkill:
        {
            int tgid = (int)x1;
            int tid = (int)x2;
            int sig = (int)x3;

            _strace(n, "tgid=%d tid=%d sig=%d", tgid, tid, sig);

            long ret = myst_syscall_tgkill(tgid, tid, sig);
            BREAK(_return(n, ret));
        }
        case SYS_utimes:
            break;
        case SYS_vserver:
            break;
        case SYS_mbind:
        {
            void* addr = (void*)x1;
            unsigned long len = (unsigned long)x2;
            int mode = (int)x3;
            const unsigned long* nodemask = (const unsigned long*)x4;
            unsigned long maxnode = (unsigned long)x5;
            unsigned flags = (unsigned)x6;

            _strace(
                n,
                "addr=%p len=%lu mode=%d nodemask=%p maxnode=%lu flags=%u",
                addr,
                len,
                mode,
                nodemask,
                maxnode,
                flags);

            long ret =
                myst_syscall_mbind(addr, len, mode, nodemask, maxnode, flags);
            BREAK(_return(n, ret));
        }
        case SYS_set_mempolicy:
            break;
        case SYS_get_mempolicy:
            break;
        case SYS_mq_open:
            break;
        case SYS_mq_unlink:
            break;
        case SYS_mq_timedsend:
            break;
        case SYS_mq_timedreceive:
            break;
        case SYS_mq_notify:
            break;
        case SYS_mq_getsetattr:
            break;
        case SYS_kexec_load:
            break;
        case SYS_waitid:
            break;
        case SYS_add_key:
            break;
        case SYS_request_key:
            break;
        case SYS_keyctl:
            break;
        case SYS_ioprio_set:
            break;
        case SYS_ioprio_get:
            break;
        case SYS_inotify_init:
        {
            _strace(n, NULL);

            long ret = myst_syscall_inotify_init1(0);
            BREAK(_return(n, ret));
        }
        case SYS_inotify_add_watch:
        {
            int fd = (int)x1;
            const char* pathname = (const char*)x2;
            uint32_t mask = (uint32_t)x3;

            _strace(n, "fd=%d pathname=%s mask=%x", fd, pathname, mask);

            long ret = myst_syscall_inotify_add_watch(fd, pathname, mask);
            BREAK(_return(n, ret));
            break;
        }
        case SYS_inotify_rm_watch:
        {
            int fd = (int)x1;
            int wd = (int)x2;

            _strace(n, "fd=%d wd=%d", fd, wd);

            long ret = myst_syscall_inotify_rm_watch(fd, wd);
            BREAK(_return(n, ret));
            break;
        }
        case SYS_migrate_pages:
            break;
        case SYS_openat:
        {
            int dirfd = (int)x1;
            const char* path = (const char*)x2;
            int flags = (int)x3;
            mode_t mode = (mode_t)x4;
            long ret;

            _strace(
                n,
                "dirfd=%d path=\"%s\" flags=0%o mode=0%o",
                dirfd,
                path,
                flags,
                mode);

            ret = myst_syscall_openat(dirfd, path, flags, mode);

            BREAK(_return(n, ret));
        }
        case SYS_mkdirat:
        {
            int dirfd = (int)x1;
            const char* pathname = (const char*)x2;
            mode_t mode = (mode_t)x3;
            long ret;

            _strace(
                n, "dirfd=%d pathname=\"%s\" mode=0%o", dirfd, pathname, mode);

            ret = myst_syscall_mkdirat(dirfd, pathname, mode);

            BREAK(_return(n, ret));
        }
        case SYS_mknodat:
            break;
        case SYS_futimesat:
        {
            int dirfd = (int)x1;
            const char* pathname = (const char*)x2;
            const struct timeval* times = (const struct timeval*)x3;
            long ret;

            _strace(n, "dirfd=%d pathname=%s times=%p", dirfd, pathname, times);

            ret = myst_syscall_futimesat(dirfd, pathname, times);
            BREAK(_return(n, ret));
        }
        case SYS_newfstatat:
        {
            int dirfd = (int)x1;
            const char* pathname = (const char*)x2;
            struct stat* statbuf = (struct stat*)x3;
            int flags = (int)x4;
            long ret;

            _strace(
                n,
                "dirfd=%d pathname=%s statbuf=%p flags=%d",
                dirfd,
                pathname,
                statbuf,
                flags);

            ret = myst_syscall_fstatat(dirfd, pathname, statbuf, flags);
            BREAK(_return(n, ret));
            break;
        }
        case SYS_unlinkat:
        {
            int dirfd = (int)x1;
            const char* pathname = (const char*)x2;
            int flags = (int)x3;

            _strace(n, "dirfd=%d pathname=%s flags=%d", dirfd, pathname, flags);

            BREAK(_return(n, myst_syscall_unlinkat(dirfd, pathname, flags)));
        }
        case SYS_renameat:
        {
            int olddirfd = (int)x1;
            const char* oldpath = (const char*)x2;
            int newdirfd = (int)x3;
            const char* newpath = (const char*)x4;

            _strace(
                n,
                "olddirfd=%d oldpath=\"%s\" newdirfd=%d newpath=\"%s\"",
                olddirfd,
                oldpath,
                newdirfd,
                newpath);

            BREAK(_return(
                n,
                myst_syscall_renameat(olddirfd, oldpath, newdirfd, newpath)));
        }
        case SYS_linkat:
            break;
        case SYS_symlinkat:
        {
            const char* target = (const char*)x1;
            int newdirfd = (int)x2;
            const char* linkpath = (const char*)x3;

            _strace(
                n,
                "target=%s newdirfd=%d linkpath=%s",
                target,
                newdirfd,
                linkpath);

            BREAK(
                _return(n, myst_syscall_symlinkat(target, newdirfd, linkpath)));
        }
        case SYS_readlinkat:
        {
            int dirfd = (int)x1;
            const char* pathname = (const char*)x2;
            char* buf = (char*)x3;
            size_t bufsiz = (size_t)x4;

            _strace(
                n,
                "dirfd=%d pathname=%s buf=%p bufsize=%ld",
                dirfd,
                pathname,
                buf,
                bufsiz);

            BREAK(_return(
                n, myst_syscall_readlinkat(dirfd, pathname, buf, bufsiz)));
        }
        case SYS_fchmodat:
            break;
        case SYS_faccessat:
        {
            int dirfd = (int)x1;
            const char* pathname = (const char*)x2;
            int mode = (int)x3;
            int flags = (int)x4;

            _strace(
                n,
                "dirfd=%d pathname=%s mode=%d flags=%d",
                dirfd,
                pathname,
                mode,
                flags);

            BREAK(_return(
                n, myst_syscall_faccessat(dirfd, pathname, mode, flags)));
        }
        case SYS_pselect6:
            break;
        case SYS_ppoll:
            break;
        case SYS_unshare:
            break;
        case SYS_set_robust_list:
        {
            struct myst_robust_list_head* head = (void*)x1;
            size_t len = (size_t)x2;
            long ret;

            _strace(n, "head=%p len=%zu", head, len);

            ret = myst_syscall_set_robust_list(head, len);
            BREAK(_return(n, ret));
        }
        case SYS_get_robust_list:
        {
            int pid = (int)x1;
            struct myst_robust_list_head** head_ptr = (void*)x2;
            size_t* len_ptr = (size_t*)x3;
            long ret;

            _strace(n, "pid=%d head=%p len=%p", pid, head_ptr, len_ptr);

            ret = myst_syscall_get_robust_list(pid, head_ptr, len_ptr);
            BREAK(_return(n, ret));
        }
        case SYS_splice:
            break;
        case SYS_tee:
            break;
        case SYS_sync_file_range:
            break;
        case SYS_vmsplice:
            break;
        case SYS_move_pages:
            break;
        case SYS_utimensat:
        {
            int dirfd = (int)x1;
            const char* pathname = (const char*)x2;
            const struct timespec* times = (const struct timespec*)x3;
            int flags = (int)x4;
            long ret;

            _strace(
                n,
                "dirfd=%d pathname=%s times=%p flags=%o",
                dirfd,
                pathname,
                times,
                flags);

            ret = myst_syscall_utimensat(dirfd, pathname, times, flags);
            BREAK(_return(n, ret));
        }
        case SYS_epoll_pwait:
        {
            int epfd = (int)x1;
            struct epoll_event* events = (struct epoll_event*)x2;
            int maxevents = (int)x3;
            int timeout = (int)x4;
            const sigset_t* sigmask = (const sigset_t*)x5;
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
            BREAK(_return(n, ret));
        }
        case SYS_signalfd:
            break;
        case SYS_timerfd_create:
            break;
        case SYS_eventfd:
            break;
        case SYS_fallocate:
        {
            int fd = (int)x1;
            int mode = (int)x2;
            off_t offset = (off_t)x3;
            off_t len = (off_t)x4;

            _strace(
                n, "fd=%d mode=%d offset=%ld len=%ld", fd, mode, offset, len);

            /* ATTN: treated as advisory only */
            BREAK(_return(n, 0));
        }
        case SYS_timerfd_settime:
            break;
        case SYS_timerfd_gettime:
            break;
        case SYS_accept4:
        {
            int sockfd = (int)x1;
            struct sockaddr* addr = (struct sockaddr*)x2;
            socklen_t* addrlen = (socklen_t*)x3;
            int flags = (int)x4;
            long ret;
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
            BREAK(_return(n, ret));
        }
        case SYS_signalfd4:
            break;
        case SYS_eventfd2:
        {
            unsigned int initval = (unsigned int)x1;
            int flags = (int)x2;

            _strace(n, "initval=%u flags=%d", initval, flags);

            long ret = myst_syscall_eventfd(initval, flags);
            BREAK(_return(n, ret));
        }
        case SYS_epoll_create1:
        {
            int flags = (int)x1;

            _strace(n, "flags=%d", flags);
            BREAK(_return(n, myst_syscall_epoll_create1(flags)));
        }
        case SYS_pipe2:
        {
            int* pipefd = (int*)x1;
            int flags = (int)x2;
            long ret;

            _strace(n, "pipefd=%p flags=%0o", pipefd, flags);
            ret = myst_syscall_pipe2(pipefd, flags);

            if (__myst_kernel_args.trace_syscalls)
                myst_eprintf("    pipefd[]=[%d:%d]\n", pipefd[0], pipefd[1]);

            BREAK(_return(n, ret));
        }
        case SYS_inotify_init1:
        {
            int flags = (int)x1;

            _strace(n, "flags=%x", flags);

            long ret = myst_syscall_inotify_init1(flags);
            BREAK(_return(n, ret));
        }
        case SYS_preadv:
        {
            int fd = (int)x1;
            const struct iovec* iov = (const struct iovec*)x2;
            int iovcnt = (int)x3;
            off_t offset = (off_t)x4;

            _strace(
                n,
                "fd=%d iov=%p iovcnt=%d offset=%zu",
                fd,
                iov,
                iovcnt,
                offset);

            long ret = myst_syscall_preadv2(fd, iov, iovcnt, offset, 0);
            BREAK(_return(n, ret));
        }
        case SYS_pwritev:
        {
            int fd = (int)x1;
            const struct iovec* iov = (const struct iovec*)x2;
            int iovcnt = (int)x3;
            off_t offset = (off_t)x4;

            _strace(
                n,
                "fd=%d iov=%p iovcnt=%d offset=%zu",
                fd,
                iov,
                iovcnt,
                offset);

            long ret = myst_syscall_pwritev2(fd, iov, iovcnt, offset, 0);
            BREAK(_return(n, ret));
        }
        case SYS_rt_tgsigqueueinfo:
            break;
        case SYS_perf_event_open:
            break;
        case SYS_recvmmsg:
            break;
        case SYS_fanotify_init:
            break;
        case SYS_fanotify_mark:
            break;
        case SYS_prlimit64:
        {
            int pid = (int)x1;
            int resource = (int)x2;
            struct rlimit* new_rlim = (struct rlimit*)x3;
            struct rlimit* old_rlim = (struct rlimit*)x4;

            _strace(
                n,
                "pid=%d, resource=%d, new_rlim=%p, old_rlim=%p",
                pid,
                resource,
                new_rlim,
                old_rlim);

            int ret = myst_syscall_prlimit64(pid, resource, new_rlim, old_rlim);
            BREAK(_return(n, ret));
        }
        case SYS_name_to_handle_at:
            break;
        case SYS_open_by_handle_at:
            break;
        case SYS_clock_adjtime:
            break;
        case SYS_syncfs:
            break;
        case SYS_sendmmsg:
            break;
        case SYS_setns:
            break;
        case SYS_getcpu:
        {
            unsigned* cpu = (unsigned*)x1;
            unsigned* node = (unsigned*)x2;
            struct getcpu_cache* tcache = (struct getcpu_cache*)x3;
            long ret;

            _strace(n, "cpu=%p node=%p, tcache=%p", cpu, node, tcache);

            /* unused since Linux 2.6.24 */
            (void)tcache;

            ret = myst_syscall_getcpu(cpu, node);
            BREAK(_return(n, ret));
        }
        case SYS_process_vm_readv:
            break;
        case SYS_process_vm_writev:
            break;
        case SYS_kcmp:
            break;
        case SYS_finit_module:
            break;
        case SYS_sched_setattr:
            break;
        case SYS_sched_getattr:
            break;
        case SYS_renameat2:
            break;
        case SYS_seccomp:
            break;
        case SYS_getrandom:
        {
            void* buf = (void*)x1;
            size_t buflen = (size_t)x2;
            unsigned int flags = (unsigned int)x3;

            _strace(n, "buf=%p buflen=%zu flags=%d", buf, buflen, flags);

            BREAK(_return(n, myst_syscall_getrandom(buf, buflen, flags)));
        }
        case SYS_memfd_create:
            break;
        case SYS_kexec_file_load:
            break;
        case SYS_bpf:
            break;
        case SYS_execveat:
            break;
        case SYS_userfaultfd:
            break;
        case SYS_membarrier:
        {
            int cmd = (int)x1;
            int flags = (int)x2;

            _strace(n, "cmd=%d flags=%d", cmd, flags);
            /* membarrier syscall relies on inter-processor-interrupt and the
             * untrusted privileged SW layer such as the hypervisor or bare
             * metal OS to sychronize code execution across CPU cores. Not
             * supported.
             */
            BREAK(_return(n, -ENOSYS));
        }
        case SYS_mlock2:
            break;
        case SYS_copy_file_range:
            break;
        case SYS_preadv2:
        {
            int fd = (int)x1;
            const struct iovec* iov = (const struct iovec*)x2;
            int iovcnt = (int)x3;
            off_t offset = (off_t)x4;
            int flags = (int)x5;

            _strace(
                n,
                "fd=%d iov=%p iovcnt=%d offset=%zu",
                fd,
                iov,
                iovcnt,
                offset);

            long ret = myst_syscall_preadv2(fd, iov, iovcnt, offset, flags);
            BREAK(_return(n, ret));
        }
        case SYS_pwritev2:
        {
            int fd = (int)x1;
            const struct iovec* iov = (const struct iovec*)x2;
            int iovcnt = (int)x3;
            off_t offset = (off_t)x4;
            int flags = (int)x5;

            _strace(
                n,
                "fd=%d iov=%p iovcnt=%d offset=%zu",
                fd,
                iov,
                iovcnt,
                offset);

            long ret = myst_syscall_pwritev2(fd, iov, iovcnt, offset, flags);
            BREAK(_return(n, ret));
        }
        case SYS_pkey_mprotect:
            break;
        case SYS_pkey_alloc:
            break;
        case SYS_pkey_free:
            break;
        case SYS_statx:
            break;
        case SYS_io_pgetevents:
            break;
        case SYS_rseq:
            break;
        case SYS_bind:
        {
            int sockfd = (int)x1;
            const struct sockaddr* addr = (const struct sockaddr*)x2;
            socklen_t addrlen = (socklen_t)x3;
            long ret;
            char addrstr[MAX_IPADDR_LEN];

            ECHECK(_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN));

            _strace(
                n, "sockfd=%d addr=%s addrlen=%u", sockfd, addrstr, addrlen);

            ret = myst_syscall_bind(sockfd, addr, addrlen);
            BREAK(_return(n, ret));
        }
        case SYS_connect:
        {
            /* connect() and bind() have the same parameters */
            int sockfd = (int)x1;
            const struct sockaddr* addr = (const struct sockaddr*)x2;
            socklen_t addrlen = (socklen_t)x3;
            long ret;
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
            BREAK(_return(n, ret));
        }
        case SYS_recvfrom:
        {
            int sockfd = (int)x1;
            void* buf = (void*)x2;
            size_t len = (size_t)x3;
            int flags = (int)x4;
            struct sockaddr* src_addr = (struct sockaddr*)x5;
            socklen_t* addrlen = (socklen_t*)x6;
            long ret = 0;
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
            ret = myst_syscall_recvfrom(
                sockfd, buf, len, flags, src_addr, addrlen);
#else  /* MYST_NO_RECVMSG_WORKAROUND */
            /* ATTN: this mitigation introduces a severe performance penalty */
            // This mitigation works around a problem with a certain
            // application that fails handle EGAIN. This should be removed
            // when possible.
            for (size_t i = 0; i < 10; i++)
            {
                ret = myst_syscall_recvfrom(
                    sockfd, buf, len, flags, src_addr, addrlen);

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
            BREAK(_return(n, ret));
        }
        case SYS_sendto:
        {
            int sockfd = (int)x1;
            void* buf = (void*)x2;
            size_t len = (size_t)x3;
            int flags = (int)x4;
            struct sockaddr* dest_addr = (struct sockaddr*)x5;
            socklen_t addrlen = (socklen_t)x6;
            long ret = 0;
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

            ret = myst_syscall_sendto(
                sockfd, buf, len, flags, dest_addr, addrlen);

            BREAK(_return(n, ret));
        }
        case SYS_socket:
        {
            int domain = (int)x1;
            int type = (int)x2;
            int protocol = (int)x3;
            long ret;

            _strace(n, "domain=%d type=%o protocol=%d", domain, type, protocol);

            ret = myst_syscall_socket(domain, type, protocol);
            BREAK(_return(n, ret));
        }
        case SYS_accept:
        {
            int sockfd = (int)x1;
            struct sockaddr* addr = (struct sockaddr*)x2;
            socklen_t* addrlen = (socklen_t*)x3;
            long ret;
            char addrstr[MAX_IPADDR_LEN];

            ECHECK(_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN));

            _strace(
                n, "sockfd=%d addr=%s addrlen=%p", sockfd, addrstr, addrlen);

            ret = myst_syscall_accept4(sockfd, addr, addrlen, 0);
            BREAK(_return(n, ret));
        }
        case SYS_sendmsg:
        {
            int sockfd = (int)x1;
            const struct msghdr* msg = (const struct msghdr*)x2;
            int flags = (int)x3;
            long ret;

            _strace(n, "sockfd=%d msg=%p flags=%d", sockfd, msg, flags);

            ret = myst_syscall_sendmsg(sockfd, msg, flags);
            BREAK(_return(n, ret));
        }
        case SYS_recvmsg:
        {
            int sockfd = (int)x1;
            struct msghdr* msg = (struct msghdr*)x2;
            int flags = (int)x3;
            long ret;

            _strace(n, "sockfd=%d msg=%p flags=%d", sockfd, msg, flags);

            ret = myst_syscall_recvmsg(sockfd, msg, flags);
            BREAK(_return(n, ret));
        }
        case SYS_shutdown:
        {
            int sockfd = (int)x1;
            int how = (int)x2;
            long ret;

            _strace(n, "sockfd=%d how=%d", sockfd, how);

            if (__myst_kernel_args.perf)
                myst_print_syscall_times("SYS_shutdown", 10);

            ret = myst_syscall_shutdown(sockfd, how);
            BREAK(_return(n, ret));
        }
        case SYS_listen:
        {
            int sockfd = (int)x1;
            int backlog = (int)x2;
            long ret;

            _strace(n, "sockfd=%d backlog=%d", sockfd, backlog);

            if (__myst_kernel_args.perf)
                myst_print_syscall_times("SYS_listen", 10);

            ret = myst_syscall_listen(sockfd, backlog);
            BREAK(_return(n, ret));
        }
        case SYS_getsockname:
        {
            int sockfd = (int)x1;
            struct sockaddr* addr = (struct sockaddr*)x2;
            socklen_t* addrlen = (socklen_t*)x3;
            long ret;
            char addrstr[MAX_IPADDR_LEN];

            ECHECK(_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN));

            _strace(
                n, "sockfd=%d addr=%s addrlen=%p", sockfd, addrstr, addrlen);

            ret = myst_syscall_getsockname(sockfd, addr, addrlen);
            BREAK(_return(n, ret));
        }
        case SYS_getpeername:
        {
            int sockfd = (int)x1;
            struct sockaddr* addr = (struct sockaddr*)x2;
            socklen_t* addrlen = (socklen_t*)x3;
            long ret;
            char addrstr[MAX_IPADDR_LEN];

            ECHECK(_socketaddr_to_str(addr, addrstr, MAX_IPADDR_LEN));

            _strace(
                n, "sockfd=%d addr=%s addrlen=%p", sockfd, addrstr, addrlen);

            ret = myst_syscall_getpeername(sockfd, addr, addrlen);
            BREAK(_return(n, ret));
        }
        case SYS_socketpair:
        {
            int domain = (int)x1;
            int type = (int)x2;
            int protocol = (int)x3;
            int* sv = (int*)x4;
            long ret;

            _strace(
                n,
                "domain=%d type=%d protocol=%d sv=%p",
                domain,
                type,
                protocol,
                sv);

            ret = myst_syscall_socketpair(domain, type, protocol, sv);
            BREAK(_return(n, ret));
        }
        case SYS_setsockopt:
        {
            int sockfd = (int)x1;
            int level = (int)x2;
            int optname = (int)x3;
            const void* optval = (const void*)x4;
            socklen_t optlen = (socklen_t)x5;
            long ret;

            _strace(
                n,
                "sockfd=%d level=%d optname=%d optval=%p optlen=%u",
                sockfd,
                level,
                optname,
                optval,
                optlen);

            ret =
                myst_syscall_setsockopt(sockfd, level, optname, optval, optlen);
            BREAK(_return(n, ret));
        }
        case SYS_getsockopt:
        {
            int sockfd = (int)x1;
            int level = (int)x2;
            int optname = (int)x3;
            void* optval = (void*)x4;
            socklen_t* optlen = (socklen_t*)x5;
            long ret;

            _strace(
                n,
                "sockfd=%d level=%d optname=%d optval=%p optlen=%p",
                sockfd,
                level,
                optname,
                optval,
                optlen);

            ret =
                myst_syscall_getsockopt(sockfd, level, optname, optval, optlen);
            BREAK(_return(n, ret));
        }
        case SYS_sendfile:
        {
            int out_fd = (int)x1;
            int in_fd = (int)x2;
            off_t* offset = (off_t*)x3;
            size_t count = (size_t)x4;
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
            BREAK(_return(n, ret));
            break;
        }
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
            myst_panic("unknown syscall: %s(): %ld", _syscall_str(n), n);
        }
    }

    myst_panic("unhandled syscall: %s()", _syscall_str(n));

done:

    /* ---------- running target thread descriptor ---------- */

    /* the C-runtime must execute on its own thread descriptor */
    if (crt_td)
        myst_set_fsbase(crt_td);

    myst_times_leave_kernel(n);

    // Process signals pending for this thread, if there is any.
    myst_signal_process(thread);

    return syscall_ret;
}
#pragma GCC diagnostic pop

long myst_syscall(long n, long params[6])
{
    long ret;
    myst_kstack_t* kstack;

    // Call myst_syscall_arch_prctl() upfront since it can only be performed
    // on the caller's stack and before the fsbase is changed by the prologue
    // code that follows.
    if (n == SYS_arch_prctl)
    {
        int code = (int)params[0];
        unsigned long* addr = (unsigned long*)params[1];
        return myst_syscall_arch_prctl(code, addr);
    }

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

    /* validate parameter is writable */
    memset(tp, 0, sizeof(*tp));

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

    /* validate parameter is writable */
    memset(tp, 0, sizeof(*tp));

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
    siginfo_t* siginfo;

    if (target == NULL)
        ERAISE(-ESRCH);

    // Only allow a thread to kill other threads in the same group.
    if (tgid != thread->pid)
        ERAISE(-EINVAL);

    if (!(siginfo = calloc(1, sizeof(siginfo_t))))
        ERAISE(-ENOMEM);

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
        siginfo_t* siginfo;

        if (!(siginfo = calloc(1, sizeof(siginfo_t))))
            ERAISE(-ENOMEM);

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
    params[4] = (long)path;

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
