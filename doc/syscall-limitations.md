# Notable limitation of system call support in Mystikos

System calls are contracts between user applications and the kernel.
We consider several factors when deciding whether, when, or how complete
we implement a particular system call in Mystikos kernel:

1. The hardware limitations. Some limitations are are outlined in
[this](kernel-limitations.md).
1. Applicability. Whether the syscall is applicable in a TEE context.
1. Popularity. The more applications uses the syscall, the higher
priority it is to us.
1. Complexity. If all other factors equal, the more complex the syscall
support is, the longer it takes to design, implement and validate the
support.

Out of the system calls that are not fully supported yet, we have three
compatibility levels compared to Linux kernel:

* **Unsupported**: the syscall is not supported by Mystikos, in the
current implementation. Any invocation, directly, or indirectly, from
the application, results in a crash.
* **Stub only**: In the current implementation, Mystikos does nothing
more than making an acknowledgement to the caller. This no-op could
satisfy the application most times, unless
the application has a hard dependency on the `effects` of the syscall.
* **Partial**: In the current implementation, the kernel only handles
some cases or aspects of the syscall.

The following lists of system call support limitation are by no means
exhaustive. The lists may seem long, but keep in mind that many of them
are not applicable to a TEE context or rarely used by typical applications.
The current implementation of Mystikos has already unlocked a large set of
user applications with these incompatibilities. And we are actively working
on lowering the incompatibilities to enable more applications.

## Process/IPC-related system calls


| Syscall names        | Description           |  Compatibility |
| -------------------- |-----------------| ---------------|
| SYS_shmget / SYS_shmctl / SYS_shmat / SYS_shmdt | System V shared memory | Unsupported |
| SYS_msgget / SYS_msgsnd / SYS_msgrcv / SYS_msgctl | System V message queue | Unsupported |
| SYS_mq_open / SYS_mq_unlink/ SYS_mq_timedsend / SYS_mq_timedreceive / SYS_mq_notify / SYS_mq_getsetattr | Posix message queue | Unsupported |
| SYS_semop / SYS_semctl / SYS_semget / SYS_semtimedop | System V semaphore | Unsupported |
| SYS_fork / SYS_vfork | fork a child process  | Experimental. See [here](design/fork.md) for details |
| SYS_unshare  | unshare states between parent and child processes | Unsupported |
| SYS_process_vm_readv / SYS_process_vm_writev | read/write memory from another process | Unsupported |
| SYS_kcmp | check if two processes share kernel resources | Unsupported |
| SYS_getpriority / SYS_setpriority | get/set scheduling priority of process | Unsupported |
| SYS_sched_rr_get_interval | get interval of the round-robin scheduler of process | Unsupported |
| SYS_sched_setparam / SYS_sched_getparam | get/set the scheduling parameters of process | Stub only |
| SYS_sched_setscheduler / SYS_sched_getscheduler | get/set the scheduling policy and params of process | Stub only |
| SYS_sched_setattr / SYS_sched_getattr  | get/set scheduling policy and attributes of process | Stub only |
| SYS_sched_get_priority_max / SYS_sched_get_priority_min  | get min/max priority levels of a policy | Stub only |

## System calls related to user/group identity or identity-based permissions


| Syscall names        | Description             | Compatibility |
| -------------------- |-------------------| --------------|
| SYS_getpgrp / SYS_setpgrp / SYS_getpgid / SYS_setpgid / SYS_getregid / SYS_setregid / SYS_getresgid / SYS_setresgid | get/set process's group ID | Partial |
| SYS_getgroups / SYS_setgroups | get/set group IDs the process belongs to | Partial |
| SYS_setsid / SYS_getsid | Create-and-set or get a session ID | Partial |
| SYS_setreuid / SYS_setresuid/ SYS_getresuid | get/set process's user ID | Partial |
| SYS_setfsuid  / SYS_setfsgid | set process's File System user/group identity | Partial |

## System calls related to reporting or modifying resources including time

| Syscall names        | Description             | Compatibility |
| -------------------- |-------------------| --------------|
| SYS_getrlimit / SYS_setrlimit | get/set system resource limits | Unsupported |
| SYS_getrusage                 | get system resource usages | Partial |
| SYS_sysinfo                   | get statistics of system memory/cpu load | Partial |
| SYS_times                     | get times used by kernel and user spaces | Partial |
| SYS_capget / SYS_capset       | get/set thread capabilities | Unsupported |
| SYS_utime / SYS_utimes        | set access/modify time of a file | Unsupported |
| SYS_prctl / SYS_arch_prctl    | modify behaviors of calling thread/process | Partial |
| SYS_clock_settime / SYS_clock_gettime | get/set nano resolution time from/to various system clocks | Partial |
| SYS_adjtimex / SYS_clock_adjtime / SYS_settimeofday | Set properties/values of system clocks | Unsupported |
| SYS_setdomainname             | set NIS domain name | Unsupported |
| SYS_prlimit64                 | set resource limits | Partial |

##  Signal/timer related system calls

| Syscall names        | Description             | Compatibility |
| -------------------- |-------------------| --------------|
| SYS_timer_create / SYS_timer_settime / SYS_timer_gettime / SYS_timer_getoverrun / SYS_timer_delete | Posix timers | Unsupported |
| SYS_eventfd / SYS_signalfd / SYS_signalfd4 / SYS_timerfd_create / SYS_timerfd_settime / SYS_timerfd_gettime              | deliver signal/timer events to a file descriptor | Unsupported |
| SYS_rt_sigtimedwait            | synchronously wait for a signal with timeout | Unsupported |
| SYS_rt_sigqueueinfo / SYS_rt_tgsigqueueinfo | deliver a signal with siginfo | Unhanlded |
| SYS_rt_sigsuspend              | replace the signal mask and wait for a signal | Unsupported |
| SYS_sigaltstack                | Install an alternative stack for certain signal handlings | Stub only |

## System calls related to file or file system operations

| Syscall names        | Description             | Compatibility |
| -------------------- |-------------------| --------------|
| SYS_fcntl | File descriptor operations | Partial |
| SYS_mknod | Create a file system node  | Partial |
| SYS_mknodat / SYS_renameat2 / SYS_linkat / SYS_fchmodat | File system operation relative to a directory file descriptor | Unsupported |
| SYS_lsetxattr / SYS_fsetxattr / SYS_getxattr / SYS_lgetxattr / SYS_fgetxattr / SYS_listxattr / SYS_llistxattr / SYS_flistxattr / SYS_removexattr / SYS_lremovexattr/ SYS_fremovexattr | get/set/remove extended file attributes | Unsupported |
| SYS_inotify_add_watch | Monitor file system changes | Partial |
| SYS_fanotify_init / SYS_fanotify_mark | Monitor file system changes | Unsupported |
| SYS_statx | get extended file status | Unsupported |
| SYS_memfd_create | create anonymous file descriptor | Unsupported |
| SYS_chroot | change root directory | Unsupported |
| SYS_statfs / SYS_fstatfs | get file system status | Partial |
| SYS_sync / SYS_syncfs | commit filesystem caches to disk | Unsupported |

## System calls related to low level memory management

| Syscall names        | Description             | Compatibility |
| -------------------- |-------------------| --------------|
| SYS_mmap                | allocate memory pages | Partial |
| SYS_msync               | flush mmaped files | Partial |
| SYS_mlock               | lock pages in memory | Stub only |
| SYS_mlock2 / SYS_munlock / SYS_mlockall / SYS_munlockall | lock/unlock pages in memory | Unsupported |
| SYS_pkey_mprotect / SYS_pkey_alloc / SYS_pkey_free | MPK based page protection | Unsupported |
| SYS_mincore             | get memory residency status of pages | Unsupported |
| SYS_mbind / SYS_set_mempolicy / SYS_get_mempolicy | get/set NUMA policy for memory pages | Unsupported |
| SYS_migrate_pages / SYS_move_pages | Move memory pages across nodes | Unsupported |


## Miscellaneous system calls

| Syscall names        | Description             | Compatibility |
| -------------------- |-------------------| --------------|
| SYS_syslog              | read and/or clear kernel message ring buffer | Unsupported |
| SYS_futex               | futex operations | Partial |
| SYS_get_thread_area     | get thread-local storage | Unsupported |
| SYS_clock_nanosleep     | high-resolution sleep | Unsupported |
| SYS_bpf                 | Berkeley Packet Filters operations | Unsupported |
| SYS_seccomp             | Secure Computing filters | Unsupported |
| SYS_iopl / SYS_ioperm / io_setup / SYS_io_destroy / SYS_io_getevents / SYS_io_submit SYS_io_cancel / SYS_ioprio_set / SYS_ioprio_get | I/O operations | Unsupported |
| SYS_reboot / YS_kexec_load / SYS_kexec_file_load | System-wide operations | Unsupported |
| SYS_init_module / SYS_finit_module / SYS_delete_module / SYS_query_module | kernel module operations | Unsupported |

