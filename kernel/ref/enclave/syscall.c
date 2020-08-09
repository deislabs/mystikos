#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/assert.h>
#include "pthread_impl.h"
#include "posix_syscall.h"
#include "posix_mman.h"
#include "posix_io.h"
#include "posix_thread.h"
#include "posix_trace.h"
#include "posix_ocalls.h"
#include "posix_futex.h"
#include "posix_time.h"
#include "posix_trace.h"
#include "posix_signal.h"
#include "futex.h"

#include "posix_warnings.h"

static const char* _syscall_name(long n)
{
    typedef struct _pair
    {
        long number;
        const char* name;
    }
    pair_t;

    static const pair_t _pairs[] =
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
        { SYS_pidfd_send_signal, "SYS_pidfd_send_signal" },
        { SYS_io_uring_setup, "SYS_io_uring_setup" },
        { SYS_io_uring_enter, "SYS_io_uring_enter" },
        { SYS_io_uring_register, "SYS_io_uring_register" },
        { SYS_open_tree, "SYS_open_tree" },
        { SYS_move_mount, "SYS_move_mount" },
        { SYS_fsopen, "SYS_fsopen" },
        { SYS_fsconfig, "SYS_fsconfig" },
        { SYS_fsmount, "SYS_fsmount" },
        { SYS_fspick, "SYS_fspick" },
    };

    static size_t _npairs = sizeof(_pairs) / sizeof(_pairs[0]);

    for (size_t i = 0; i < _npairs; i++)
    {
        if (_pairs[i].number == n)
            return _pairs[i].name;
    }

    return "unknown";
}

static int _ioctl_tiocgwinsz(int fd, unsigned long request, long arg)
{
    (void)fd;
    (void)request;

    struct winsize
    {
        unsigned short int ws_row;
        unsigned short int ws_col;
        unsigned short int ws_xpixel;
        unsigned short int ws_ypixel;
    };
    struct winsize* p;

    if (!(p = (struct winsize*)arg))
        return -EINVAL;

    p->ws_row = 24;
    p->ws_col = 80;
    p->ws_xpixel = 0;
    p->ws_ypixel = 0;

    return 0;
}

#define TIOCGWINSZ 0x5413

long posix_syscall(long n, ...)
{
    va_list ap;

    va_start(ap, n);
    long x1 = va_arg(ap, long);
    long x2 = va_arg(ap, long);
    long x3 = va_arg(ap, long);
    long x4 = va_arg(ap, long);
    long x5 = va_arg(ap, long);
    long x6 = va_arg(ap, long);
    va_end(ap);

    (void)x1;
    (void)x2;
    (void)x3;
    (void)x4;
    (void)x5;
    (void)x6;

#if 0
    posix_printf("SYSCALL{%s}\n", _syscall_name(n));
    //posix_printf("SYSCALL{%s}: tid=%d\n", _syscall_name(n), posix_gettid());
#endif

    switch (n)
    {
        case SYS_exit:
        {
            int status = (int)x1;
            posix_exit(status);
            return -1;
        }
        case SYS_exit_group:
        {
            int status = (int)x1;
            posix_exit(status);
            return -1;
        }
        case SYS_read:
        {
            break;
        }
        case SYS_write:
        {
            int fd = (int)x1;

            if (fd == STDOUT_FILENO || fd == STDERR_FILENO)
            {
                const void* buf = (const void*)x2;
                size_t count = (size_t)x3;

                if (fd == STDOUT_FILENO || fd == STDERR_FILENO)
                {
                    return (long)posix_write(fd, buf, count);
                }
            }

            break;
        }
        case SYS_writev:
        {
            int fd = (int)x1;
            const struct iovec *iov = (const struct iovec*)x2;
            int iovcnt = (int)x3;

            if (fd == STDOUT_FILENO || fd == STDERR_FILENO)
            {
                return (long)posix_writev(fd, iov, iovcnt);
            }

            break;
        }
        case SYS_ioctl:
        {
            int fd = (int)x1;
            unsigned long request = (unsigned long)x2;

            if (fd == STDOUT_FILENO && request == TIOCGWINSZ)
                return _ioctl_tiocgwinsz(fd, request, x3);

            break;
        }
        case SYS_set_tid_address:
        {
            int* tidptr = (int*)x1;
            return posix_set_tid_address(tidptr);
        }
        case SYS_brk:
        {
            void* new_brk = (void*)x1;
            return (long)posix_brk(new_brk);
        }
        case SYS_tkill:
        {
            int tid = (int)x1;
            int sig = (int)x2;
            int r = posix_tkill(tid, sig);
            return (long)r;
        }
        case SYS_rt_sigaction:
        {
            int signum = (int)x1;
            const struct posix_sigaction* act = (void*)x2;
            struct posix_sigaction* oldact = (void*)x3;
            size_t sigsetsize = (size_t)x4;
            return posix_rt_sigaction(signum, act, oldact, sigsetsize);
        }
        case SYS_rt_sigprocmask:
        {
            errno = 0;
            int how = (int)x1;
            const sigset_t* set = (void*)x2;
            sigset_t* oldset = (void*)x3;
            size_t sigsetsize = (size_t)x4;
            return posix_rt_sigprocmask(how, set, oldset, sigsetsize);
        }
        case SYS_mprotect:
        {
            void* addr = (void*)x1;
            size_t len = (size_t)x2;
            int prot = (int)x3;

            if (addr && len && (prot & (PROT_READ|PROT_WRITE)))
                return 0;

            return 0;

            break;
        }
        case SYS_mmap:
        {
            void* addr = (void*)x1;
            size_t length = (size_t)x2;
            int prot = (int)x3;
            int flags = (int)x4;
            int fd = (int)x5;
            off_t offset = (int)x6;
            const int FLAGS = MAP_PRIVATE | MAP_ANON;

            (void)prot;

            if (!addr && fd == -1 && !offset && flags == FLAGS)
            {
                uint8_t* ptr;

                if (!(ptr = oe_memalign(4096, length)))
                {
                    oe_assert("oe_memalign() failed" == NULL);
                    return -ENOMEM;
                }

                memset(ptr, 0, length);
                return (long)ptr;
            }

            break;
        }
        case SYS_munmap:
        {
            void* addr = (void*)x1;
            size_t length = (size_t)x2;

posix_printf("SYS_munmap: tid=%d\n", posix_gettid());

            if (addr && length)
            {
                memset(addr, 0, length);
                oe_free(addr);
                return 0;
            }

            break;
        }
        case SYS_futex:
        {
            int* uaddr = (int*)x1;
            int op = (int)x2;
            int val = (int)x3;

            if (op == FUTEX_WAIT || op == (FUTEX_WAIT|FUTEX_PRIVATE))
            {
                const struct timespec* timeout = (const struct timespec*)x4;
                return posix_futex_wait(uaddr, op, val, timeout);
            }
            else if (op == FUTEX_WAKE || op == (FUTEX_WAKE|FUTEX_PRIVATE))
            {
                return posix_futex_wake(uaddr, op, val);
            }
            else if (op == FUTEX_REQUEUE || op == (FUTEX_REQUEUE|FUTEX_PRIVATE))
            {
                int val2 = (int)x4;
                int* uaddr2 = (int*)x5;
                return posix_futex_requeue(uaddr, op, val, val2, uaddr2);
            }
            else
            {
                posix_printf("unhandled futex op: %d\n", op);
                posix_print_backtrace();
                assert(false);
            }

            break;
        }
        case SYS_set_thread_area:
        {
            return posix_set_thread_area((void*)x1);
        }
        case SYS_membarrier:
        {
            break;
        }
        case SYS_nanosleep:
        {
            const struct timespec* req = (const struct timespec*)x1;
            struct timespec* rem = (struct timespec*)x2;
            return posix_nanosleep(req, rem);
        }
        case SYS_clock_gettime:
        {
            clockid_t clk_id = (clockid_t)x1;
            struct timespec* tp = (struct timespec*)x2;
            /* ATTN: Why is this necesswary? */
            errno = 0;
            return posix_clock_gettime(clk_id, tp);
        }
        case SYS_sigaltstack:
        {
            break;
        }
        case SYS_get_robust_list:
        {
            int pid = (int)x1;
            struct posix_robust_list_head** head_ptr = (void*)x2;
            size_t* len_ptr = (size_t*)x3;
            return posix_get_robust_list(pid, head_ptr, len_ptr);
        }
        case SYS_set_robust_list:
        {
            struct posix_robust_list_head* head = (void*)x1;
            size_t len = (size_t)x2;
            return posix_set_robust_list(head, len);
        }
        case SYS_getpid:
        {
            return (long)posix_getpid();
        }
    }

    posix_printf("unhandled syscall: %s\n", _syscall_name(n));
    assert(false);
    return -1;
}
