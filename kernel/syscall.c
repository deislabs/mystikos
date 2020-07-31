#include <stdio.h>
#include <libos/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <setjmp.h>
#include <sys/uio.h>
#include <libos/syscall.h>
#include <libos/elfutils.h>
#include <libos/mmanutils.h>

jmp_buf _exit_jmp_buf;

static bool _trace;

static char _rootfs[PATH_MAX];

void libos_set_rootfs(const char* path)
{
    snprintf(_rootfs, sizeof(_rootfs), "%s", path);
}

static const char* _fullpath(char buf[PATH_MAX], const char* path)
{
    if (strlcpy(buf, _rootfs, PATH_MAX) >= PATH_MAX)
        return NULL;

    if (strlcat(buf, "/", PATH_MAX) >= PATH_MAX)
        return NULL;

    if (strlcat(buf, path, PATH_MAX) >= PATH_MAX)
        return NULL;

    return buf;
}

typedef struct _pair
{
    long num;
    const char* str;
}
pair_t;

static pair_t _pairs[] =
{
    { SYS_read, "SYS_read" },
    { SYS_write, "SYS_write" },
    { SYS_open, "SYS_open" },
    { SYS_close, "SYS_close" },
    { SYS_stat, "SYS_stat" },
    { SYS_fstat, "SYS_fstat" },
    { SYS_lstat, "SYS_lstat" },
    { SYS_poll, "SYS_poll" },
    { SYS_lseek, "SYS_lseek" },
    { SYS_mmap, "SYS_mmap" },
    { SYS_mprotect, "SYS_mprotect" },
    { SYS_munmap, "SYS_munmap" },
    { SYS_brk, "SYS_brk" },
    { SYS_rt_sigaction, "SYS_rt_sigaction" },
    { SYS_rt_sigprocmask, "SYS_rt_sigprocmask" },
    { SYS_rt_sigreturn, "SYS_rt_sigreturn" },
    { SYS_ioctl, "SYS_ioctl" },
    { SYS_pread64, "SYS_pread64" },
    { SYS_pwrite64, "SYS_pwrite64" },
    { SYS_readv, "SYS_readv" },
    { SYS_writev, "SYS_writev" },
    { SYS_access, "SYS_access" },
    { SYS_pipe, "SYS_pipe" },
    { SYS_select, "SYS_select" },
    { SYS_sched_yield, "SYS_sched_yield" },
    { SYS_mremap, "SYS_mremap" },
    { SYS_msync, "SYS_msync" },
    { SYS_mincore, "SYS_mincore" },
    { SYS_madvise, "SYS_madvise" },
    { SYS_shmget, "SYS_shmget" },
    { SYS_shmat, "SYS_shmat" },
    { SYS_shmctl, "SYS_shmctl" },
    { SYS_dup, "SYS_dup" },
    { SYS_dup2, "SYS_dup2" },
    { SYS_pause, "SYS_pause" },
    { SYS_nanosleep, "SYS_nanosleep" },
    { SYS_getitimer, "SYS_getitimer" },
    { SYS_alarm, "SYS_alarm" },
    { SYS_setitimer, "SYS_setitimer" },
    { SYS_getpid, "SYS_getpid" },
    { SYS_sendfile, "SYS_sendfile" },
    { SYS_socket, "SYS_socket" },
    { SYS_connect, "SYS_connect" },
    { SYS_accept, "SYS_accept" },
    { SYS_sendto, "SYS_sendto" },
    { SYS_recvfrom, "SYS_recvfrom" },
    { SYS_sendmsg, "SYS_sendmsg" },
    { SYS_recvmsg, "SYS_recvmsg" },
    { SYS_shutdown, "SYS_shutdown" },
    { SYS_bind, "SYS_bind" },
    { SYS_listen, "SYS_listen" },
    { SYS_getsockname, "SYS_getsockname" },
    { SYS_getpeername, "SYS_getpeername" },
    { SYS_socketpair, "SYS_socketpair" },
    { SYS_setsockopt, "SYS_setsockopt" },
    { SYS_getsockopt, "SYS_getsockopt" },
    { SYS_clone, "SYS_clone" },
    { SYS_fork, "SYS_fork" },
    { SYS_vfork, "SYS_vfork" },
    { SYS_execve, "SYS_execve" },
    { SYS_exit, "SYS_exit" },
    { SYS_wait4, "SYS_wait4" },
    { SYS_kill, "SYS_kill" },
    { SYS_uname, "SYS_uname" },
    { SYS_semget, "SYS_semget" },
    { SYS_semop, "SYS_semop" },
    { SYS_semctl, "SYS_semctl" },
    { SYS_shmdt, "SYS_shmdt" },
    { SYS_msgget, "SYS_msgget" },
    { SYS_msgsnd, "SYS_msgsnd" },
    { SYS_msgrcv, "SYS_msgrcv" },
    { SYS_msgctl, "SYS_msgctl" },
    { SYS_fcntl, "SYS_fcntl" },
    { SYS_flock, "SYS_flock" },
    { SYS_fsync, "SYS_fsync" },
    { SYS_fdatasync, "SYS_fdatasync" },
    { SYS_truncate, "SYS_truncate" },
    { SYS_ftruncate, "SYS_ftruncate" },
    { SYS_getdents, "SYS_getdents" },
    { SYS_getcwd, "SYS_getcwd" },
    { SYS_chdir, "SYS_chdir" },
    { SYS_fchdir, "SYS_fchdir" },
    { SYS_rename, "SYS_rename" },
    { SYS_mkdir, "SYS_mkdir" },
    { SYS_rmdir, "SYS_rmdir" },
    { SYS_creat, "SYS_creat" },
    { SYS_link, "SYS_link" },
    { SYS_unlink, "SYS_unlink" },
    { SYS_symlink, "SYS_symlink" },
    { SYS_readlink, "SYS_readlink" },
    { SYS_chmod, "SYS_chmod" },
    { SYS_fchmod, "SYS_fchmod" },
    { SYS_chown, "SYS_chown" },
    { SYS_fchown, "SYS_fchown" },
    { SYS_lchown, "SYS_lchown" },
    { SYS_umask, "SYS_umask" },
    { SYS_gettimeofday, "SYS_gettimeofday" },
    { SYS_getrlimit, "SYS_getrlimit" },
    { SYS_getrusage, "SYS_getrusage" },
    { SYS_sysinfo, "SYS_sysinfo" },
    { SYS_times, "SYS_times" },
    { SYS_ptrace, "SYS_ptrace" },
    { SYS_getuid, "SYS_getuid" },
    { SYS_syslog, "SYS_syslog" },
    { SYS_getgid, "SYS_getgid" },
    { SYS_setuid, "SYS_setuid" },
    { SYS_setgid, "SYS_setgid" },
    { SYS_geteuid, "SYS_geteuid" },
    { SYS_getegid, "SYS_getegid" },
    { SYS_setpgid, "SYS_setpgid" },
    { SYS_getppid, "SYS_getppid" },
    { SYS_getpgrp, "SYS_getpgrp" },
    { SYS_setsid, "SYS_setsid" },
    { SYS_setreuid, "SYS_setreuid" },
    { SYS_setregid, "SYS_setregid" },
    { SYS_getgroups, "SYS_getgroups" },
    { SYS_setgroups, "SYS_setgroups" },
    { SYS_setresuid, "SYS_setresuid" },
    { SYS_getresuid, "SYS_getresuid" },
    { SYS_setresgid, "SYS_setresgid" },
    { SYS_getresgid, "SYS_getresgid" },
    { SYS_getpgid, "SYS_getpgid" },
    { SYS_setfsuid, "SYS_setfsuid" },
    { SYS_setfsgid, "SYS_setfsgid" },
    { SYS_getsid, "SYS_getsid" },
    { SYS_capget, "SYS_capget" },
    { SYS_capset, "SYS_capset" },
    { SYS_rt_sigpending, "SYS_rt_sigpending" },
    { SYS_rt_sigtimedwait, "SYS_rt_sigtimedwait" },
    { SYS_rt_sigqueueinfo, "SYS_rt_sigqueueinfo" },
    { SYS_rt_sigsuspend, "SYS_rt_sigsuspend" },
    { SYS_sigaltstack, "SYS_sigaltstack" },
    { SYS_utime, "SYS_utime" },
    { SYS_mknod, "SYS_mknod" },
    { SYS_uselib, "SYS_uselib" },
    { SYS_personality, "SYS_personality" },
    { SYS_ustat, "SYS_ustat" },
    { SYS_statfs, "SYS_statfs" },
    { SYS_fstatfs, "SYS_fstatfs" },
    { SYS_sysfs, "SYS_sysfs" },
    { SYS_getpriority, "SYS_getpriority" },
    { SYS_setpriority, "SYS_setpriority" },
    { SYS_sched_setparam, "SYS_sched_setparam" },
    { SYS_sched_getparam, "SYS_sched_getparam" },
    { SYS_sched_setscheduler, "SYS_sched_setscheduler" },
    { SYS_sched_getscheduler, "SYS_sched_getscheduler" },
    { SYS_sched_get_priority_max, "SYS_sched_get_priority_max" },
    { SYS_sched_get_priority_min, "SYS_sched_get_priority_min" },
    { SYS_sched_rr_get_interval, "SYS_sched_rr_get_interval" },
    { SYS_mlock, "SYS_mlock" },
    { SYS_munlock, "SYS_munlock" },
    { SYS_mlockall, "SYS_mlockall" },
    { SYS_munlockall, "SYS_munlockall" },
    { SYS_vhangup, "SYS_vhangup" },
    { SYS_modify_ldt, "SYS_modify_ldt" },
    { SYS_pivot_root, "SYS_pivot_root" },
    { SYS__sysctl, "SYS__sysctl" },
    { SYS_prctl, "SYS_prctl" },
    { SYS_arch_prctl, "SYS_arch_prctl" },
    { SYS_adjtimex, "SYS_adjtimex" },
    { SYS_setrlimit, "SYS_setrlimit" },
    { SYS_chroot, "SYS_chroot" },
    { SYS_sync, "SYS_sync" },
    { SYS_acct, "SYS_acct" },
    { SYS_settimeofday, "SYS_settimeofday" },
    { SYS_mount, "SYS_mount" },
    { SYS_umount2, "SYS_umount2" },
    { SYS_swapon, "SYS_swapon" },
    { SYS_swapoff, "SYS_swapoff" },
    { SYS_reboot, "SYS_reboot" },
    { SYS_sethostname, "SYS_sethostname" },
    { SYS_setdomainname, "SYS_setdomainname" },
    { SYS_iopl, "SYS_iopl" },
    { SYS_ioperm, "SYS_ioperm" },
    { SYS_create_module, "SYS_create_module" },
    { SYS_init_module, "SYS_init_module" },
    { SYS_delete_module, "SYS_delete_module" },
    { SYS_get_kernel_syms, "SYS_get_kernel_syms" },
    { SYS_query_module, "SYS_query_module" },
    { SYS_quotactl, "SYS_quotactl" },
    { SYS_nfsservctl, "SYS_nfsservctl" },
    { SYS_getpmsg, "SYS_getpmsg" },
    { SYS_putpmsg, "SYS_putpmsg" },
    { SYS_afs_syscall, "SYS_afs_syscall" },
    { SYS_tuxcall, "SYS_tuxcall" },
    { SYS_security, "SYS_security" },
    { SYS_gettid, "SYS_gettid" },
    { SYS_readahead, "SYS_readahead" },
    { SYS_setxattr, "SYS_setxattr" },
    { SYS_lsetxattr, "SYS_lsetxattr" },
    { SYS_fsetxattr, "SYS_fsetxattr" },
    { SYS_getxattr, "SYS_getxattr" },
    { SYS_lgetxattr, "SYS_lgetxattr" },
    { SYS_fgetxattr, "SYS_fgetxattr" },
    { SYS_listxattr, "SYS_listxattr" },
    { SYS_llistxattr, "SYS_llistxattr" },
    { SYS_flistxattr, "SYS_flistxattr" },
    { SYS_removexattr, "SYS_removexattr" },
    { SYS_lremovexattr, "SYS_lremovexattr" },
    { SYS_fremovexattr, "SYS_fremovexattr" },
    { SYS_tkill, "SYS_tkill" },
    { SYS_time, "SYS_time" },
    { SYS_futex, "SYS_futex" },
    { SYS_sched_setaffinity, "SYS_sched_setaffinity" },
    { SYS_sched_getaffinity, "SYS_sched_getaffinity" },
    { SYS_set_thread_area, "SYS_set_thread_area" },
    { SYS_io_setup, "SYS_io_setup" },
    { SYS_io_destroy, "SYS_io_destroy" },
    { SYS_io_getevents, "SYS_io_getevents" },
    { SYS_io_submit, "SYS_io_submit" },
    { SYS_io_cancel, "SYS_io_cancel" },
    { SYS_get_thread_area, "SYS_get_thread_area" },
    { SYS_lookup_dcookie, "SYS_lookup_dcookie" },
    { SYS_epoll_create, "SYS_epoll_create" },
    { SYS_epoll_ctl_old, "SYS_epoll_ctl_old" },
    { SYS_epoll_wait_old, "SYS_epoll_wait_old" },
    { SYS_remap_file_pages, "SYS_remap_file_pages" },
    { SYS_getdents64, "SYS_getdents64" },
    { SYS_set_tid_address, "SYS_set_tid_address" },
    { SYS_restart_syscall, "SYS_restart_syscall" },
    { SYS_semtimedop, "SYS_semtimedop" },
    { SYS_fadvise64, "SYS_fadvise64" },
    { SYS_timer_create, "SYS_timer_create" },
    { SYS_timer_settime, "SYS_timer_settime" },
    { SYS_timer_gettime, "SYS_timer_gettime" },
    { SYS_timer_getoverrun, "SYS_timer_getoverrun" },
    { SYS_timer_delete, "SYS_timer_delete" },
    { SYS_clock_settime, "SYS_clock_settime" },
    { SYS_clock_gettime, "SYS_clock_gettime" },
    { SYS_clock_getres, "SYS_clock_getres" },
    { SYS_clock_nanosleep, "SYS_clock_nanosleep" },
    { SYS_exit_group, "SYS_exit_group" },
    { SYS_epoll_wait, "SYS_epoll_wait" },
    { SYS_epoll_ctl, "SYS_epoll_ctl" },
    { SYS_tgkill, "SYS_tgkill" },
    { SYS_utimes, "SYS_utimes" },
    { SYS_vserver, "SYS_vserver" },
    { SYS_mbind, "SYS_mbind" },
    { SYS_set_mempolicy, "SYS_set_mempolicy" },
    { SYS_get_mempolicy, "SYS_get_mempolicy" },
    { SYS_mq_open, "SYS_mq_open" },
    { SYS_mq_unlink, "SYS_mq_unlink" },
    { SYS_mq_timedsend, "SYS_mq_timedsend" },
    { SYS_mq_timedreceive, "SYS_mq_timedreceive" },
    { SYS_mq_notify, "SYS_mq_notify" },
    { SYS_mq_getsetattr, "SYS_mq_getsetattr" },
    { SYS_kexec_load, "SYS_kexec_load" },
    { SYS_waitid, "SYS_waitid" },
    { SYS_add_key, "SYS_add_key" },
    { SYS_request_key, "SYS_request_key" },
    { SYS_keyctl, "SYS_keyctl" },
    { SYS_ioprio_set, "SYS_ioprio_set" },
    { SYS_ioprio_get, "SYS_ioprio_get" },
    { SYS_inotify_init, "SYS_inotify_init" },
    { SYS_inotify_add_watch, "SYS_inotify_add_watch" },
    { SYS_inotify_rm_watch, "SYS_inotify_rm_watch" },
    { SYS_migrate_pages, "SYS_migrate_pages" },
    { SYS_openat, "SYS_openat" },
    { SYS_mkdirat, "SYS_mkdirat" },
    { SYS_mknodat, "SYS_mknodat" },
    { SYS_fchownat, "SYS_fchownat" },
    { SYS_futimesat, "SYS_futimesat" },
    { SYS_newfstatat, "SYS_newfstatat" },
    { SYS_unlinkat, "SYS_unlinkat" },
    { SYS_renameat, "SYS_renameat" },
    { SYS_linkat, "SYS_linkat" },
    { SYS_symlinkat, "SYS_symlinkat" },
    { SYS_readlinkat, "SYS_readlinkat" },
    { SYS_fchmodat, "SYS_fchmodat" },
    { SYS_faccessat, "SYS_faccessat" },
    { SYS_pselect6, "SYS_pselect6" },
    { SYS_ppoll, "SYS_ppoll" },
    { SYS_unshare, "SYS_unshare" },
    { SYS_set_robust_list, "SYS_set_robust_list" },
    { SYS_get_robust_list, "SYS_get_robust_list" },
    { SYS_splice, "SYS_splice" },
    { SYS_tee, "SYS_tee" },
    { SYS_sync_file_range, "SYS_sync_file_range" },
    { SYS_vmsplice, "SYS_vmsplice" },
    { SYS_move_pages, "SYS_move_pages" },
    { SYS_utimensat, "SYS_utimensat" },
    { SYS_epoll_pwait, "SYS_epoll_pwait" },
    { SYS_signalfd, "SYS_signalfd" },
    { SYS_timerfd_create, "SYS_timerfd_create" },
    { SYS_eventfd, "SYS_eventfd" },
    { SYS_fallocate, "SYS_fallocate" },
    { SYS_timerfd_settime, "SYS_timerfd_settime" },
    { SYS_timerfd_gettime, "SYS_timerfd_gettime" },
    { SYS_accept4, "SYS_accept4" },
    { SYS_signalfd4, "SYS_signalfd4" },
    { SYS_eventfd2, "SYS_eventfd2" },
    { SYS_epoll_create1, "SYS_epoll_create1" },
    { SYS_dup3, "SYS_dup3" },
    { SYS_pipe2, "SYS_pipe2" },
    { SYS_inotify_init1, "SYS_inotify_init1" },
    { SYS_preadv, "SYS_preadv" },
    { SYS_pwritev, "SYS_pwritev" },
    { SYS_rt_tgsigqueueinfo, "SYS_rt_tgsigqueueinfo" },
    { SYS_perf_event_open, "SYS_perf_event_open" },
    { SYS_recvmmsg, "SYS_recvmmsg" },
    { SYS_fanotify_init, "SYS_fanotify_init" },
    { SYS_fanotify_mark, "SYS_fanotify_mark" },
    { SYS_prlimit64, "SYS_prlimit64" },
    { SYS_name_to_handle_at, "SYS_name_to_handle_at" },
    { SYS_open_by_handle_at, "SYS_open_by_handle_at" },
    { SYS_clock_adjtime, "SYS_clock_adjtime" },
    { SYS_syncfs, "SYS_syncfs" },
    { SYS_sendmmsg, "SYS_sendmmsg" },
    { SYS_setns, "SYS_setns" },
    { SYS_getcpu, "SYS_getcpu" },
    { SYS_process_vm_readv, "SYS_process_vm_readv" },
    { SYS_process_vm_writev, "SYS_process_vm_writev" },
    { SYS_kcmp, "SYS_kcmp" },
    { SYS_finit_module, "SYS_finit_module" },
    { SYS_sched_setattr, "SYS_sched_setattr" },
    { SYS_sched_getattr, "SYS_sched_getattr" },
    { SYS_renameat2, "SYS_renameat2" },
    { SYS_seccomp, "SYS_seccomp" },
    { SYS_getrandom, "SYS_getrandom" },
    { SYS_memfd_create, "SYS_memfd_create" },
    { SYS_kexec_file_load, "SYS_kexec_file_load" },
    { SYS_bpf, "SYS_bpf" },
    { SYS_execveat, "SYS_execveat" },
    { SYS_userfaultfd, "SYS_userfaultfd" },
    { SYS_membarrier, "SYS_membarrier" },
    { SYS_mlock2, "SYS_mlock2" },
    { SYS_copy_file_range, "SYS_copy_file_range" },
    { SYS_preadv2, "SYS_preadv2" },
    { SYS_pwritev2, "SYS_pwritev2" },
    { SYS_pkey_mprotect, "SYS_pkey_mprotect" },
    { SYS_pkey_alloc, "SYS_pkey_alloc" },
    { SYS_pkey_free, "SYS_pkey_free" },
    { SYS_statx, "SYS_statx" },
    { SYS_io_pgetevents, "SYS_io_pgetevents" },
    { SYS_rseq, "SYS_rseq" },
};

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

static int _exit_status;

int libos_get_exit_status(void)
{
    return _exit_status;
}

static const void* _original_fs_base;

static void _set_fs_base(const void* p)
{
    __asm__ volatile("wrfsbase %0" ::"r"(p));
}

static void* _get_fs_base(void)
{
    void* p;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(p));
    return p;
}

static long _forward_syscall(long n, long params[6])
{
    extern long oe_syscall(long n, long x1, long x2, long x3, long x4,
        long x5, long x6);
    long x1 = params[0];
    long x2 = params[1];
    long x3 = params[2];
    long x4 = params[3];
    long x5 = params[4];
    long x6 = params[5];

    return oe_syscall(n, x1, x2, x3, x4, x5, x6);
}

typedef struct fd_entry
{
    int fd;
    char path[PATH_MAX];
}
fd_entry_t;

/* ATTN:MEB: replace this later */
static fd_entry_t _fd_entries[1024];
static size_t _fd_entries_size = sizeof(_fd_entries) / sizeof(_fd_entries[0]);

static long _return(long n, long ret)
{
    if (_trace)
    {
        fprintf(stderr, "    %s(): return=%ld\n", syscall_str(n), ret);
    }

    return ret;
}

long libos_syscall(long n, long params[6])
{
    long x1 = params[0];
    long x2 = params[1];
    long x3 = params[2];
    long x4 = params[3];
    long x5 = params[4];
    long x6 = params[5];

    if (n == LIBOS_SYS_trace)
    {
        printf("trace: %s\n", (const char*)params[0]);
        return _return(n, 0);
    }
    else if (n == LIBOS_SYS_trace_ptr)
    {
        printf("trace: %s: %lX %ld\n",
            (const char*)params[0], params[1], params[1]);
        return _return(n, 0);
    }
    else if (n == LIBOS_SYS_dump_stack)
    {
        elf_dump_stack((void*)params[0]);
        return _return(n, 0);
    }
    else if (n == LIBOS_SYS_dump_ehdr)
    {
        elf_dump_ehdr((void*)params[0]);
        return _return(n, 0);
    }
    else if (n == SYS_set_thread_area)
    {
        const void* tp = (void*)params[0];

        if (_trace)
        {
            fprintf(stderr, "=== %s(tp=%p)\n", syscall_str(n), tp);
        }

        if (!_original_fs_base)
            _original_fs_base = _get_fs_base();

        _set_fs_base(tp);

        return _return(n, 0);
    }
    else if (n == SYS_set_tid_address)
    {
        const void* tidptr = (const void*)params[0];

        if (_trace)
        {
            fprintf(stderr, "=== %s(tidptr=%p)\n", syscall_str(n), tidptr);
        }

        return _return(n, 0);
    }
    else if (n == SYS_open)
    {
        const char* path = (const char*)x1;
        int flags = (int)x2;
        int mode = (int)x3;
        char buf[PATH_MAX];
        long ret;

        if (_trace)
        {
            fprintf(stderr, "=== %s(path=%s flags=%d mode=%03o)\n",
                syscall_str(n), path, flags, mode);
        }

        params[0] = (long)_fullpath(buf, path);

        ret = _forward_syscall(n, params);

        if (ret >= 0 && ret < (long)_fd_entries_size)
            strlcpy(_fd_entries[ret].path, path, PATH_MAX);

        return _return(n, ret);
    }
    else if (n == SYS_read)
    {
        if (_trace)
        {
            fprintf(stderr, "=== %s()\n", syscall_str(n));
        }

        return _return(n, _forward_syscall(n, params));
    }
    else if (n == SYS_writev)
    {
        if (_trace)
        {
            fprintf(stderr, "=== %s()\n", syscall_str(n));
        }

        return _return(n, _forward_syscall(n, params));
    }
    else if (n == SYS_close)
    {
        int fd = (int)x1;

        if (_trace)
        {
            fprintf(stderr, "=== %s()\n", syscall_str(n));
        }

        if (fd >= 0 && fd < (long)_fd_entries_size)
        {
            _fd_entries[fd].path[0] = '\0';
        }

        return _return(n, _forward_syscall(n, params));
    }
    else if (n == SYS_mmap)
    {
        void* addr = (void*)x1;
        size_t length = (size_t)x2;
        int prot = (int)x3;
        int flags = (int)x4;
        int fd = (int)x5;
        off_t offset = (off_t)x6;

        if (_trace)
        {
            fprintf(stderr, "=== %s"
                "(addr=%lX length=%lu prot=%d flags=%d fd=%d offset=%lu)\n",
                syscall_str(n), (long)addr, length, prot, flags, fd, offset);
        }

        long ret = (long)libos_mmap(addr, length, prot, flags, fd, offset);

        return _return(n, ret);
    }
    else if (n == SYS_mprotect)
    {
        const void* addr = (void*)x1;
        const size_t length = (size_t)x2;
        const int prot = (int)x3;

        if (_trace)
        {
            fprintf(stderr, "=== %s(addr=%lX length=%zu prot=%d)\n",
                syscall_str(n), (uint64_t)addr, length, prot);
        }

        return _return(n, 0);
    }
    else if (n == SYS_exit)
    {
        const int status = (int)x1;

        /* restore original fs base, else stack smashing will be detected */
        _set_fs_base(_original_fs_base);

        if (_trace)
        {
            printf("=== %s(status=%d)\n", syscall_str(n), status);
        }

        _exit_status = status;
        longjmp(_exit_jmp_buf, 1);

        /* Unreachable! */
        assert("unreachable" == NULL);
    }
    else if (n == SYS_ioctl)
    {
        int fd = (int)x1;
        /* Note: 0x5413 is TIOCGWINSZ  */
        unsigned long request = (unsigned long)x2;

        if (_trace)
        {
            fprintf(stderr, "=== %s(fd=%d request=%lx)\n",
                syscall_str(n), fd, request);
        }

        return _return(n, _forward_syscall(n, params));
    }
    else if (n == SYS_exit_group)
    {
        int status = (int)x1;

        if (_trace)
        {
            fprintf(stderr, "=== %s(status=%d)\n", syscall_str(n), status);
        }

        return 0;
    }
    else if (n == SYS_fstat)
    {
        int fd = (int)x1;
        void* statbuf = (void*)x2;
        char buf[PATH_MAX];

        if (_trace)
        {
            fprintf(stderr, "=== syscall: %s(fd=%d statbuf=%p)\n",
                syscall_str(n), fd, statbuf);
        }

        long new_params[6] = { 0 };
        new_params[0] = (long)_fullpath(buf, _fd_entries[fd].path);
        new_params[1] = params[1];

        return _return(n, _forward_syscall(SYS_stat, new_params));
    }
    else
    {
        if (_trace)
        {
            fprintf(stderr, "=== syscall: %s()\n", syscall_str(n));
        }

        return _return(n, _forward_syscall(n, params));
    }

    assert("panic" == NULL);
    return 0;
}

int libos_set_exit_jump(void)
{
    return setjmp(_exit_jmp_buf);
}

void libos_trace_syscalls(bool flag)
{
    _trace = flag;
}
