#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>

#include <myst/defs.h>
#include <myst/syscall.h>
#include <myst/syscallext.h>

#define PAIR(SYSCALL)     \
    {                     \
        SYSCALL, #SYSCALL \
    }

static const myst_syscall_pair_t _pairs[] = {
    PAIR(SYS_read),
    PAIR(SYS_write),
    PAIR(SYS_open),
    PAIR(SYS_close),
    PAIR(SYS_stat),
    PAIR(SYS_fstat),
    PAIR(SYS_lstat),
    PAIR(SYS_poll),
    PAIR(SYS_lseek),
    PAIR(SYS_mmap),
    PAIR(SYS_mprotect),
    PAIR(SYS_munmap),
    PAIR(SYS_brk),
    PAIR(SYS_rt_sigaction),
    PAIR(SYS_rt_sigprocmask),
    PAIR(SYS_rt_sigreturn),
    PAIR(SYS_ioctl),
    PAIR(SYS_pread64),
    PAIR(SYS_pwrite64),
    PAIR(SYS_readv),
    PAIR(SYS_writev),
    PAIR(SYS_access),
    PAIR(SYS_pipe),
    PAIR(SYS_select),
    PAIR(SYS_sched_yield),
    PAIR(SYS_mremap),
    PAIR(SYS_msync),
    PAIR(SYS_mincore),
    PAIR(SYS_madvise),
    PAIR(SYS_shmget),
    PAIR(SYS_shmat),
    PAIR(SYS_shmctl),
    PAIR(SYS_dup),
    PAIR(SYS_dup2),
    PAIR(SYS_pause),
    PAIR(SYS_nanosleep),
    PAIR(SYS_getitimer),
    PAIR(SYS_alarm),
    PAIR(SYS_setitimer),
    PAIR(SYS_getpid),
    PAIR(SYS_sendfile),
    PAIR(SYS_socket),
    PAIR(SYS_connect),
    PAIR(SYS_accept),
    PAIR(SYS_sendto),
    PAIR(SYS_recvfrom),
    PAIR(SYS_sendmsg),
    PAIR(SYS_recvmsg),
    PAIR(SYS_shutdown),
    PAIR(SYS_bind),
    PAIR(SYS_listen),
    PAIR(SYS_getsockname),
    PAIR(SYS_getpeername),
    PAIR(SYS_socketpair),
    PAIR(SYS_setsockopt),
    PAIR(SYS_getsockopt),
    PAIR(SYS_clone),
    PAIR(SYS_fork),
    PAIR(SYS_vfork),
    PAIR(SYS_execve),
    PAIR(SYS_exit),
    PAIR(SYS_wait4),
    PAIR(SYS_kill),
    PAIR(SYS_uname),
    PAIR(SYS_semget),
    PAIR(SYS_semop),
    PAIR(SYS_semctl),
    PAIR(SYS_shmdt),
    PAIR(SYS_msgget),
    PAIR(SYS_msgsnd),
    PAIR(SYS_msgrcv),
    PAIR(SYS_msgctl),
    PAIR(SYS_fcntl),
    PAIR(SYS_flock),
    PAIR(SYS_fsync),
    PAIR(SYS_fdatasync),
    PAIR(SYS_truncate),
    PAIR(SYS_ftruncate),
    PAIR(SYS_getdents),
    PAIR(SYS_getcwd),
    PAIR(SYS_chdir),
    PAIR(SYS_fchdir),
    PAIR(SYS_rename),
    PAIR(SYS_mkdir),
    PAIR(SYS_rmdir),
    PAIR(SYS_creat),
    PAIR(SYS_link),
    PAIR(SYS_unlink),
    PAIR(SYS_symlink),
    PAIR(SYS_readlink),
    PAIR(SYS_chmod),
    PAIR(SYS_fchmod),
    PAIR(SYS_chown),
    PAIR(SYS_fchown),
    PAIR(SYS_lchown),
    PAIR(SYS_umask),
    PAIR(SYS_gettimeofday),
    PAIR(SYS_getrlimit),
    PAIR(SYS_getrusage),
    PAIR(SYS_sysinfo),
    PAIR(SYS_times),
    PAIR(SYS_ptrace),
    PAIR(SYS_getuid),
    PAIR(SYS_syslog),
    PAIR(SYS_getgid),
    PAIR(SYS_setuid),
    PAIR(SYS_setgid),
    PAIR(SYS_geteuid),
    PAIR(SYS_getegid),
    PAIR(SYS_setpgid),
    PAIR(SYS_getppid),
    PAIR(SYS_getpgrp),
    PAIR(SYS_setsid),
    PAIR(SYS_setreuid),
    PAIR(SYS_setregid),
    PAIR(SYS_getgroups),
    PAIR(SYS_setgroups),
    PAIR(SYS_setresuid),
    PAIR(SYS_getresuid),
    PAIR(SYS_setresgid),
    PAIR(SYS_getresgid),
    PAIR(SYS_getpgid),
    PAIR(SYS_setfsuid),
    PAIR(SYS_setfsgid),
    PAIR(SYS_getsid),
    PAIR(SYS_capget),
    PAIR(SYS_capset),
    PAIR(SYS_rt_sigpending),
    PAIR(SYS_rt_sigtimedwait),
    PAIR(SYS_rt_sigqueueinfo),
    PAIR(SYS_rt_sigsuspend),
    PAIR(SYS_sigaltstack),
    PAIR(SYS_utime),
    PAIR(SYS_mknod),
    PAIR(SYS_uselib),
    PAIR(SYS_personality),
    PAIR(SYS_ustat),
    PAIR(SYS_statfs),
    PAIR(SYS_fstatfs),
    PAIR(SYS_sysfs),
    PAIR(SYS_getpriority),
    PAIR(SYS_setpriority),
    PAIR(SYS_sched_setparam),
    PAIR(SYS_sched_getparam),
    PAIR(SYS_sched_setscheduler),
    PAIR(SYS_sched_getscheduler),
    PAIR(SYS_sched_get_priority_max),
    PAIR(SYS_sched_get_priority_min),
    PAIR(SYS_sched_rr_get_interval),
    PAIR(SYS_mlock),
    PAIR(SYS_munlock),
    PAIR(SYS_mlockall),
    PAIR(SYS_munlockall),
    PAIR(SYS_vhangup),
    PAIR(SYS_modify_ldt),
    PAIR(SYS_pivot_root),
    PAIR(SYS__sysctl),
    PAIR(SYS_prctl),
    PAIR(SYS_arch_prctl),
    PAIR(SYS_adjtimex),
    PAIR(SYS_setrlimit),
    PAIR(SYS_chroot),
    PAIR(SYS_sync),
    PAIR(SYS_acct),
    PAIR(SYS_settimeofday),
    PAIR(SYS_mount),
    PAIR(SYS_umount2),
    PAIR(SYS_swapon),
    PAIR(SYS_swapoff),
    PAIR(SYS_reboot),
    PAIR(SYS_sethostname),
    PAIR(SYS_setdomainname),
    PAIR(SYS_iopl),
    PAIR(SYS_ioperm),
    PAIR(SYS_create_module),
    PAIR(SYS_init_module),
    PAIR(SYS_delete_module),
    PAIR(SYS_get_kernel_syms),
    PAIR(SYS_query_module),
    PAIR(SYS_quotactl),
    PAIR(SYS_nfsservctl),
    PAIR(SYS_getpmsg),
    PAIR(SYS_putpmsg),
    PAIR(SYS_afs_syscall),
    PAIR(SYS_tuxcall),
    PAIR(SYS_security),
    PAIR(SYS_gettid),
    PAIR(SYS_readahead),
    PAIR(SYS_setxattr),
    PAIR(SYS_lsetxattr),
    PAIR(SYS_fsetxattr),
    PAIR(SYS_getxattr),
    PAIR(SYS_lgetxattr),
    PAIR(SYS_fgetxattr),
    PAIR(SYS_listxattr),
    PAIR(SYS_llistxattr),
    PAIR(SYS_flistxattr),
    PAIR(SYS_removexattr),
    PAIR(SYS_lremovexattr),
    PAIR(SYS_fremovexattr),
    PAIR(SYS_tkill),
    PAIR(SYS_time),
    PAIR(SYS_futex),
    PAIR(SYS_sched_setaffinity),
    PAIR(SYS_sched_getaffinity),
    PAIR(SYS_set_thread_area),
    PAIR(SYS_io_setup),
    PAIR(SYS_io_destroy),
    PAIR(SYS_io_getevents),
    PAIR(SYS_io_submit),
    PAIR(SYS_io_cancel),
    PAIR(SYS_get_thread_area),
    PAIR(SYS_lookup_dcookie),
    PAIR(SYS_epoll_create),
    PAIR(SYS_epoll_ctl_old),
    PAIR(SYS_epoll_wait_old),
    PAIR(SYS_remap_file_pages),
    PAIR(SYS_getdents64),
    PAIR(SYS_set_tid_address),
    PAIR(SYS_restart_syscall),
    PAIR(SYS_semtimedop),
    PAIR(SYS_fadvise64),
    PAIR(SYS_timer_create),
    PAIR(SYS_timer_settime),
    PAIR(SYS_timer_gettime),
    PAIR(SYS_timer_getoverrun),
    PAIR(SYS_timer_delete),
    PAIR(SYS_clock_settime),
    PAIR(SYS_clock_gettime),
    PAIR(SYS_clock_getres),
    PAIR(SYS_clock_nanosleep),
    PAIR(SYS_exit_group),
    PAIR(SYS_epoll_wait),
    PAIR(SYS_epoll_ctl),
    PAIR(SYS_tgkill),
    PAIR(SYS_utimes),
    PAIR(SYS_vserver),
    PAIR(SYS_mbind),
    PAIR(SYS_set_mempolicy),
    PAIR(SYS_get_mempolicy),
    PAIR(SYS_mq_open),
    PAIR(SYS_mq_unlink),
    PAIR(SYS_mq_timedsend),
    PAIR(SYS_mq_timedreceive),
    PAIR(SYS_mq_notify),
    PAIR(SYS_mq_getsetattr),
    PAIR(SYS_kexec_load),
    PAIR(SYS_waitid),
    PAIR(SYS_add_key),
    PAIR(SYS_request_key),
    PAIR(SYS_keyctl),
    PAIR(SYS_ioprio_set),
    PAIR(SYS_ioprio_get),
    PAIR(SYS_inotify_init),
    PAIR(SYS_inotify_add_watch),
    PAIR(SYS_inotify_rm_watch),
    PAIR(SYS_migrate_pages),
    PAIR(SYS_openat),
    PAIR(SYS_mkdirat),
    PAIR(SYS_mknodat),
    PAIR(SYS_fchownat),
    PAIR(SYS_futimesat),
    PAIR(SYS_newfstatat),
    PAIR(SYS_unlinkat),
    PAIR(SYS_renameat),
    PAIR(SYS_linkat),
    PAIR(SYS_symlinkat),
    PAIR(SYS_readlinkat),
    PAIR(SYS_fchmodat),
    PAIR(SYS_faccessat),
    PAIR(SYS_pselect6),
    PAIR(SYS_ppoll),
    PAIR(SYS_unshare),
    PAIR(SYS_set_robust_list),
    PAIR(SYS_get_robust_list),
    PAIR(SYS_splice),
    PAIR(SYS_tee),
    PAIR(SYS_sync_file_range),
    PAIR(SYS_vmsplice),
    PAIR(SYS_move_pages),
    PAIR(SYS_utimensat),
    PAIR(SYS_epoll_pwait),
    PAIR(SYS_signalfd),
    PAIR(SYS_timerfd_create),
    PAIR(SYS_eventfd),
    PAIR(SYS_fallocate),
    PAIR(SYS_timerfd_settime),
    PAIR(SYS_timerfd_gettime),
    PAIR(SYS_accept4),
    PAIR(SYS_signalfd4),
    PAIR(SYS_eventfd2),
    PAIR(SYS_epoll_create1),
    PAIR(SYS_dup3),
    PAIR(SYS_pipe2),
    PAIR(SYS_inotify_init1),
    PAIR(SYS_preadv),
    PAIR(SYS_pwritev),
    PAIR(SYS_rt_tgsigqueueinfo),
    PAIR(SYS_perf_event_open),
    PAIR(SYS_recvmmsg),
    PAIR(SYS_fanotify_init),
    PAIR(SYS_fanotify_mark),
    PAIR(SYS_prlimit64),
    PAIR(SYS_name_to_handle_at),
    PAIR(SYS_open_by_handle_at),
    PAIR(SYS_clock_adjtime),
    PAIR(SYS_syncfs),
    PAIR(SYS_sendmmsg),
    PAIR(SYS_setns),
    PAIR(SYS_getcpu),
    PAIR(SYS_process_vm_readv),
    PAIR(SYS_process_vm_writev),
    PAIR(SYS_kcmp),
    PAIR(SYS_finit_module),
    PAIR(SYS_sched_setattr),
    PAIR(SYS_sched_getattr),
    PAIR(SYS_renameat2),
    PAIR(SYS_seccomp),
    PAIR(SYS_getrandom),
    PAIR(SYS_memfd_create),
    PAIR(SYS_kexec_file_load),
    PAIR(SYS_bpf),
    PAIR(SYS_execveat),
    PAIR(SYS_userfaultfd),
    PAIR(SYS_membarrier),
    PAIR(SYS_mlock2),
    PAIR(SYS_copy_file_range),
    PAIR(SYS_preadv2),
    PAIR(SYS_pwritev2),
    PAIR(SYS_pkey_mprotect),
    PAIR(SYS_pkey_alloc),
    PAIR(SYS_pkey_free),
    PAIR(SYS_statx),
    PAIR(SYS_io_pgetevents),
    PAIR(SYS_rseq),
    PAIR(SYS_pidfd_send_signal),
    PAIR(SYS_io_uring_setup),
    PAIR(SYS_io_uring_enter),
    PAIR(SYS_io_uring_register),
    PAIR(SYS_open_tree),
    PAIR(SYS_move_mount),
    PAIR(SYS_fsopen),
    PAIR(SYS_fsconfig),
    PAIR(SYS_fsmount),
    PAIR(SYS_fspick),
    PAIR(SYS_pidfd_open),
    PAIR(SYS_clone3),
    PAIR(SYS_myst_trace),
    PAIR(SYS_myst_trace_ptr),
    PAIR(SYS_myst_dump_stack),
    PAIR(SYS_myst_dump_ehdr),
    PAIR(SYS_myst_dump_argv),
    PAIR(SYS_myst_add_symbol_file),
    PAIR(SYS_myst_load_symbols),
    PAIR(SYS_myst_unload_symbols),
    PAIR(SYS_myst_clone),
    PAIR(SYS_myst_poll_wake),
    PAIR(SYS_myst_run_itimer),
    PAIR(SYS_myst_gcov),
    PAIR(SYS_myst_unmap_on_exit),
    PAIR(SYS_myst_get_fork_info),
    PAIR(SYS_myst_kill_wait_child_forks),
    PAIR(SYS_myst_get_process_thread_stack),
    PAIR(SYS_myst_fork_wait_exec_exit),
    PAIR(SYS_myst_get_exec_stack_option),
    PAIR(SYS_myst_interrupt_thread),
    PAIR(SYS_myst_pre_launch_hook),
    /* add new entries here! */
    /* NOTE: when you add a new syscall here, add it to its corresponding group
       below as well! */
    {0, NULL},
};

const myst_syscall_group_t _groups[] = {
    {"desc",
     98,
     {SYS_read,
      SYS_write,
      SYS_open,
      SYS_close,
      SYS_fstat,
      SYS_poll,
      SYS_lseek,
      SYS_mmap,
      SYS_ioctl,
      SYS_pread64,
      SYS_pwrite64,
      SYS_readv,
      SYS_writev,
      SYS_pipe,
      SYS_select,
      SYS_dup,
      SYS_dup2,
      SYS_sendfile,
      SYS_fcntl,
      SYS_flock,
      SYS_fsync,
      SYS_fdatasync,
      SYS_ftruncate,
      SYS_getdents,
      SYS_fchdir,
      SYS_creat,
      SYS_fchmod,
      SYS_fchown,
      SYS_fstatfs,
      SYS_readahead,
      SYS_fsetxattr,
      SYS_fgetxattr,
      SYS_flistxattr,
      SYS_fremovexattr,
      SYS_epoll_create,
      SYS_getdents64,
      SYS_fadvise64,
      SYS_epoll_wait,
      SYS_epoll_ctl,
      SYS_mq_open,
      //   SYS_q_timedsend,
      //   SYS_q_timedreceive,
      SYS_mq_notify,
      SYS_mq_getsetattr,
      SYS_inotify_init,
      SYS_inotify_add_watch,
      SYS_inotify_rm_watch,
      SYS_openat,
      SYS_mkdirat,
      SYS_mknodat,
      SYS_fchownat,
      SYS_futimesat,
      SYS_newfstatat,
      SYS_unlinkat,
      SYS_renameat,
      SYS_linkat,
      SYS_symlinkat,
      SYS_readlinkat,
      SYS_fchmodat,
      SYS_faccessat,
      SYS_pselect6,
      SYS_ppoll,
      SYS_splice,
      SYS_tee,
      SYS_sync_file_range,
      SYS_vmsplice,
      SYS_utimensat,
      SYS_epoll_pwait,
      SYS_signalfd,
      SYS_timerfd_create,
      SYS_eventfd,
      SYS_fallocate,
      SYS_timerfd_settime,
      SYS_timerfd_gettime,
      SYS_signalfd4,
      SYS_eventfd2,
      SYS_epoll_create1,
      SYS_dup3,
      SYS_pipe2,
      SYS_inotify_init1,
      SYS_preadv,
      SYS_pwritev,
      SYS_perf_event_open,
      SYS_fanotify_init,
      SYS_fanotify_mark,
      SYS_name_to_handle_at,
      SYS_open_by_handle_at,
      SYS_syncfs,
      SYS_setns,
      SYS_finit_module,
      SYS_renameat2,
      SYS_memfd_create,
      SYS_kexec_file_load,
      SYS_bpf,
      SYS_execveat,
      SYS_userfaultfd,
      SYS_copy_file_range,
      SYS_preadv2,
      SYS_pwritev2,
      SYS_statx}},
    {"file",
     60,
     {SYS_stat,
      SYS_open,
      SYS_lstat,
      SYS_access,
      SYS_execve,
      SYS_truncate,
      SYS_getcwd,
      SYS_chdir,
      SYS_rename,
      SYS_mkdir,
      SYS_rmdir,
      SYS_creat,
      SYS_link,
      SYS_unlink,
      SYS_symlink,
      SYS_readlink,
      SYS_chmod,
      SYS_chown,
      SYS_lchown,
      SYS_utime,
      SYS_mknod,
      SYS_uselib,
      SYS_statfs,
      SYS_pivot_root,
      SYS_chroot,
      SYS_acct,
      SYS_mount,
      SYS_umount2,
      SYS_swapon,
      SYS_swapoff,
      SYS_quotactl,
      SYS_setxattr,
      SYS_lsetxattr,
      SYS_getxattr,
      SYS_lgetxattr,
      SYS_listxattr,
      SYS_llistxattr,
      SYS_removexattr,
      SYS_lremovexattr,
      SYS_utimes,
      SYS_inotify_add_watch,
      SYS_openat,
      SYS_mkdirat,
      SYS_mknodat,
      SYS_fchownat,
      SYS_futimesat,
      SYS_newfstatat,
      SYS_unlinkat,
      SYS_renameat,
      SYS_linkat,
      SYS_symlinkat,
      SYS_readlinkat,
      SYS_fchmodat,
      SYS_faccessat,
      SYS_utimensat,
      SYS_fanotify_mark,
      SYS_name_to_handle_at,
      SYS_renameat2,
      SYS_execveat,
      SYS_statx}},
    {"ipc",
     12,
     {SYS_shmget,
      SYS_shmat,
      SYS_shmctl,
      SYS_semget,
      SYS_semop,
      SYS_semctl,
      SYS_shmdt,
      SYS_msgget,
      SYS_msgsnd,
      SYS_msgrcv,
      SYS_msgctl,
      SYS_semtimedop}},
    {"network", 21, {SYS_sendfile,    SYS_socket,     SYS_connect,
                     SYS_accept,      SYS_sendto,     SYS_recvfrom,
                     SYS_sendmsg,     SYS_recvmsg,    SYS_shutdown,
                     SYS_bind,        SYS_listen,     SYS_getsockname,
                     SYS_getpeername, SYS_socketpair, SYS_setsockopt,
                     SYS_getsockopt,  SYS_getpmsg,    SYS_putpmsg,
                     SYS_accept4,     SYS_recvmmsg,   SYS_sendmmsg}},
    {"process",
     14,
     {SYS_clone,
      SYS_fork,
      SYS_vfork,
      SYS_execve,
      SYS_exit,
      SYS_wait4,
      SYS_kill,
      SYS_rt_sigqueueinfo,
      SYS_tkill,
      SYS_exit_group,
      SYS_tgkill,
      SYS_waitid,
      SYS_rt_tgsigqueueinfo,
      SYS_execveat}},
    {"signal",
     14,
     {SYS_rt_sigaction,
      SYS_rt_sigprocmask,
      SYS_rt_sigreturn,
      SYS_pause,
      SYS_kill,
      SYS_rt_sigpending,
      //   SYS_t_sigtimedwait,
      SYS_rt_sigqueueinfo,
      SYS_rt_sigsuspend,
      SYS_sigaltstack,
      SYS_tkill,
      SYS_tgkill,
      SYS_signalfd,
      SYS_signalfd4,
      SYS_rt_tgsigqueueinfo}},
    {"memory",
     24,
     {SYS_mmap,
      SYS_mprotect,
      SYS_munmap,
      SYS_brk,
      SYS_mremap,
      SYS_msync,
      SYS_mincore,
      SYS_madvise,
      SYS_shmat,
      SYS_shmdt,
      SYS_mlock,
      SYS_munlock,
      SYS_mlockall,
      SYS_munlockall,
      SYS_io_setup,
      SYS_io_destroy,
      SYS_remap_file_pages,
      SYS_mbind,
      SYS_set_mempolicy,
      SYS_get_mempolicy,
      SYS_migrate_pages,
      SYS_move_pages,
      SYS_mlock2,
      SYS_pkey_mprotect}},
    {"stat", 1, {SYS_stat}},
    {"lstat", 1, {SYS_lstat}},
    {"fstat", 3, {SYS_fstat, SYS_newfstatat, SYS_statx}},
    {"stat_like",
     5,
     {SYS_stat, SYS_fstat, SYS_lstat, SYS_newfstatat, SYS_statx}},
    {"statfs", 1, {SYS_statfs}},
    {"fstatfs", 1, {SYS_fstatfs}},
    {"statfs_like", 3, {SYS_ustat, SYS_statfs, SYS_fstatfs}},
    {"pure",
     8,
     {SYS_getpid,
      SYS_getuid,
      SYS_getgid,
      SYS_geteuid,
      SYS_getegid,
      SYS_getppid,
      SYS_getpgrp,
      SYS_gettid}},
    {"syscall_never_fails",
     12,
     {SYS_getpid,
      SYS_umask,
      SYS_getuid,
      SYS_getgid,
      SYS_geteuid,
      SYS_getegid,
      SYS_getppid,
      SYS_getpgrp,
      SYS_setfsuid,
      SYS_setfsgid,
      SYS_personality,
      SYS_gettid}},
    {"max_args", 0, {}},
    {"memory_mapping_change",
     11,
     {SYS_mmap,
      SYS_mprotect,
      SYS_munmap,
      SYS_brk,
      SYS_mremap,
      SYS_shmat,
      SYS_execve,
      SYS_shmdt,
      SYS_remap_file_pages,
      SYS_execveat,
      SYS_pkey_mprotect}},
    {"stackcapture_on_enter",
     4,
     {SYS_execve, SYS_exit, SYS_exit_group, SYS_execveat}},
    {"compat_syscall_types", 0, {}},
    {"seccomp_default", 2, {SYS_execve, SYS_execveat}},
    {"creds",
     19,
     {SYS_getuid,
      SYS_getgid,
      SYS_setuid,
      SYS_setgid,
      SYS_geteuid,
      SYS_getegid,
      SYS_setreuid,
      SYS_setregid,
      SYS_getgroups,
      SYS_setgroups,
      SYS_setresuid,
      SYS_getresuid,
      SYS_setresgid,
      SYS_getresgid,
      SYS_setfsuid,
      SYS_setfsgid,
      SYS_capget,
      SYS_capset,
      SYS_prctl}},
    {"clock",
     7,
     {SYS_gettimeofday,
      SYS_adjtimex,
      SYS_settimeofday,
      SYS_time,
      SYS_clock_settime,
      SYS_clock_gettime,
      //   SYS_lock_getres,
      SYS_clock_adjtime}},
    {"comm_change", 3, {SYS_execve, SYS_prctl, SYS_execveat}},
    {NULL, 0, {}},
};

__attribute__((__unused__)) static void _check_myst_syscalls(void)
{
    myst_syscall_t msyscall = SYS_myst_trace;

    /* Please add new entries to the _pairs[] array above as well */
    switch (msyscall)
    {
        case SYS_myst_trace:
        case SYS_myst_trace_ptr:
        case SYS_myst_dump_stack:
        case SYS_myst_dump_ehdr:
        case SYS_myst_dump_argv:
        case SYS_myst_add_symbol_file:
        case SYS_myst_load_symbols:
        case SYS_myst_unload_symbols:
        case SYS_myst_clone:
        case SYS_myst_poll_wake:
        case SYS_myst_run_itimer:
        case SYS_myst_gcov:
        case SYS_myst_unmap_on_exit:
        case SYS_myst_get_fork_info:
        case SYS_myst_kill_wait_child_forks:
        case SYS_myst_get_process_thread_stack:
        case SYS_myst_fork_wait_exec_exit:
        case SYS_myst_get_exec_stack_option:
        case SYS_myst_interrupt_thread:
        case SYS_myst_pre_launch_hook:
            break;
    }
}

const char* myst_syscall_name(long num)
{
    for (size_t i = 0; _pairs[i].name; i++)
    {
        if (_pairs[i].num == num)
            return _pairs[i].name;
    }

    /* not found */
    return NULL;
}

long myst_syscall_num(const char* name)
{
    for (size_t i = 0; _pairs[i].name; i++)
    {
        if (strcmp(_pairs[i].name, name) == 0)
            return _pairs[i].num;
    }

    /* not found */
    return -ENOENT;
}

const int* myst_syscall_group(const char* name)
{
    for (size_t i = 0; _groups[i].name; i++)
    {
        if (strcmp(_groups[i].name, name) == 0)
            return _groups[i].syscalls;
    }

    /* not found */
    return NULL;
}

size_t myst_syscall_group_size(const char* name)
{
    for (size_t i = 0; _groups[i].name; i++)
    {
        if (strcmp(_groups[i].name, name) == 0)
            return _groups[i].group_size;
    }

    /* not found */
    return -ENOENT;
}

const myst_syscall_pair_t* myst_syscall_pairs(void)
{
    return _pairs;
}
