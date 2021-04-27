// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_KERNEL_H
#define _MYST_KERNEL_H

#include <limits.h>

#include <myst/tcall.h>
#include <myst/types.h>

typedef struct _myst_host_enc_id_mapping
{
    uid_t host_uid;
    gid_t host_gid;
    uid_t enc_uid;
    gid_t enc_gid;
} myst_host_enc_id_mapping;

/* Information used for a specific automatic mount point that is mounted on
 * start. flags, public_keys and roothash are currently not used, but are
 * available in the configuration parser for when we start using them. Target is
 * the mount point inside the TEE, source is the what is mounted from outside
 * the TEE.
 */
typedef struct myst_mount_point_config
{
    char* target;
    char* source;
    char* fs_type;
    char** flags;
    size_t flags_count;
    char* public_key;
    char* roothash;
} myst_mount_point_config_t;

/* This is the configuration used to automatically mount drives on start-up.
 * The configuration is passed in from the target.
 * For TEE targets, the configuration will be measured with the exception of hte
 * source information. The source configuration for each mount is passed in from
 * the command line to map the source which is outside the TEE to the target
 * path that is used in the TEE
 * */
typedef struct myst_mounts_config
{
    myst_mount_point_config_t* mounts;
    size_t mounts_count;
} myst_mounts_config_t;

typedef struct myst_kernel_args
{
    /* The image that contains the kernel and crt etc. */
    const void* image_data;
    size_t image_size;

    /* The loaded kernel ELF image (ELF header start here) */
    const void* kernel_data;
    size_t kernel_size;

    /* Kernel relocation entries */
    const void* reloc_data;
    size_t reloc_size;

    /* The symbol table (.symtab) section from the kernel ELF image */
    const void* symtab_data;
    size_t symtab_size;

    /* The symbol table (.dynsym) section from the kernel ELF image */
    const void* dynsym_data;
    size_t dynsym_size;

    /* The string table (.strtab) section from the kernel ELF image */
    const void* strtab_data;
    size_t strtab_size;

    /* The string table (.dynstr) section from the kernel ELF image */
    const void* dynstr_data;
    size_t dynstr_size;

    /* The arguments passed to myst */
    size_t argc;
    const char** argv;

    /* The environment*/
    size_t envc;
    const char** envp;

    /* current working directory for app */
    char cwd_buffer[PATH_MAX];
    const char* cwd;

    /* enclave to host uid/gid identity mapping when calling out of the enclave
       to the host. This is only done for APIs that implement identity
       propagation. Currently we only support a single mapping which would
       typically only map from the enclave identity (root) to whatever identity
       of the host application.
      */
    myst_host_enc_id_mapping host_enc_id_mapping;

    /* This is only used as the kernel initialized and the lifetime is handled
     * in the target where the pointer came from. */
    myst_mounts_config_t* mounts;

    /* configure hostname in kernel */
    char hostname_buffer[1024];
    const char* hostname;

    /* The read-write-execute memory management pages */
    void* mman_data;
    size_t mman_size;

    /* The CPIO root file system image */
    char rootfs[PATH_MAX];
    void* rootfs_data;
    size_t rootfs_size;

    /* The CPIO archive image */
    void* archive_data;
    size_t archive_size;

    /* The C runtime image */
    void* crt_data;
    size_t crt_size;

    /* CRT relocation entries */
    const void* crt_reloc_data;
    size_t crt_reloc_size;

    /* The number of threads that can be created (including the main thread) */
    size_t max_threads;

    /* Tracing options */
    bool trace_errors;
    bool trace_syscalls;
    bool have_syscall_instruction;
    bool export_ramfs;

    /* The event object for the main thread */
    uint64_t event;

    /* whether this TEE is in debug mode */
    bool tee_debug_mode;

    /* true if --shell option present */
    bool shell_mode;

    /* true if --memcheck option present */
    bool memcheck;

    /* Callback for making target-calls */
    myst_tcall_t tcall;

    /* pointer to myst_syscall() that is set by myst_enter_kernel() */
    long (*myst_syscall)(long n, long params[6]);

} myst_kernel_args_t;

typedef int (*myst_kernel_entry_t)(myst_kernel_args_t* args);

int myst_enter_kernel(myst_kernel_args_t* args);

extern myst_kernel_args_t __myst_kernel_args;

typedef struct myst_malloc_stats
{
    size_t usage;
    size_t peak_usage;
} myst_malloc_stats_t;

int myst_get_malloc_stats(myst_malloc_stats_t* stats);

int myst_find_leaks(void);

void myst_start_shell(const char* msg);

#endif /* _MYST_KERNEL_H */
