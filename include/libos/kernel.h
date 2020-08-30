#ifndef _LIBOS_KERNEL_H
#define _LIBOS_KERNEL_H

#include <libos/types.h>
#include <libos/tcall.h>

typedef struct libos_kernel_args
{
    /* The arguments passed to libos */
    size_t argc;
    const char** argv;

    /* The environment*/
    size_t envc;
    const char** envp;

    /* The read-write-execute memory management pages */
    void* mman_data;
    size_t mman_size;

    /* The CPIO root file system image */
    void* rootfs_data;
    size_t rootfs_size;

    /* The C runtime image */
    void* crt_data;
    size_t crt_size;

    /* Tracing options */
    bool trace_syscalls;
    bool real_syscalls;

    /* The parent process identifer from the target */
    pid_t ppid;

    /* The process identifer from the target */
    pid_t pid;

    /* The event object for the main thread */
    uint64_t event;

    /* Callback for making target-calls */
    libos_tcall_t tcall;
}
libos_kernel_args_t;

typedef int (*libos_kernel_entry_t)(libos_kernel_args_t* args);

int libos_enter_kernel(libos_kernel_args_t* args);

#endif /* _LIBOS_KERNEL_H */
