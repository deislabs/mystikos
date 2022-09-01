// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_KERNEL_H
#define _MYST_KERNEL_H

#include <limits.h>
#include <myst/kstack.h>
#include <myst/syscallext.h>
#include <myst/tcall.h>
#include <myst/types.h>
#include <myst/uid_gid.h>
#include <signal.h>

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

typedef struct _wanted_secret
{
    const char* id;
    const char* srs_addr;
    const char* srs_api_ver;
    const char* local_path;
    const char* clientlib;
    unsigned int verbose;
} myst_wanted_secret_t;

typedef struct _myst_wanted_secrets_config
{
    myst_wanted_secret_t* secrets;
    size_t secrets_count;
} myst_wanted_secrets_t;

typedef struct myst_crt_args
{
    myst_wanted_secrets_t* wanted_secrets;
} myst_crt_args_t;

typedef struct _myst_strace_config
{
    /* Is tracing enabled or not */
    bool trace_syscalls;

    /* Should failing syscalls be traced or not*/
    bool trace_failing;

    /* Is filtering enabled or not */
    bool filter;

    /*
        If filter is enabled, should the given syscall be traced or not.
        Note: ausyscall --dump shows that maximum syscall value on Ubuntu 18.04
              is 332 statx.
              MYST_MAX_SYSCALLS value is much higher (3000).
    */
    bool trace[MYST_MAX_SYSCALLS];

    /* If the tid filter is enabled, this will store the number of tids to
     * filter by */
    int tid_filter_num;

    /*
        If tid filter is enabled, stores the list of tids to include.
    */
    pid_t tid_trace[MYST_MAX_IDS];

    /* If the pid filter is enabled, this will store the number of pids to
     * filter by */
    int pid_filter_num;

    /*
        If pid filter is enabled, stores the list of pids to include.
    */
    pid_t pid_trace[MYST_MAX_IDS];

} myst_strace_config_t;

typedef struct myst_kernel_args
{
    /* The image that contains the kernel and crt etc. */
    const void* image_data;
    size_t image_size;

    /* The stack used to enter the kernel */
    const void* enter_stack;
    size_t enter_stack_size;

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
    myst_host_enc_uid_gid_mappings host_enc_uid_gid_mappings;

    /* This is only used as the kernel initialized and the lifetime is handled
     * in the target where the pointer came from. */
    myst_mounts_config_t* mounts;

    /* configure hostname in kernel */
    char hostname_buffer[1024];
    const char* hostname;

    /* The read-write-execute memory management pages */
    void* mman_data;
    size_t mman_size;

    /* The pids[] vector for the memory management pages */
    void* mman_pids_data;
    size_t mman_pids_size;

    /* The fdmappings[] vector for fd-mman mappings */
    void* fdmappings_data;
    size_t fdmappings_size;

    /* The CPIO root file system image */
    char rootfs[PATH_MAX];
    void* rootfs_data;
    size_t rootfs_size;

    /* The pubkeys region */
    void* pubkeys_data;
    size_t pubkeys_size;

    /* The roothashes region */
    void* roothashes_data;
    size_t roothashes_size;

    /* The C runtime image */
    void* crt_data;
    size_t crt_size;

    /* CRT relocation entries */
    const void* crt_reloc_data;
    size_t crt_reloc_size;

    /* The number of threads that can be created (including the main thread) */
    size_t max_threads;

    /* The tid/pid of the main thread passed from the host */
    pid_t target_tid;

    /* The start time passed in from the host */
    uint64_t start_time_sec;
    uint64_t start_time_nsec;

    /* Tracing options */
    bool trace_errors;
    myst_strace_config_t strace_config;
    bool trace_times;

    /* Whether the target supports the SYSCALL instruction */
    bool have_syscall_instruction;

    /* Whether the target supports the WRFSBASE and WRGSBASE instructions */
    bool have_fsgsbase_instructions;

    /* The event object for the main thread */
    uint64_t event;

    /* whether this TEE is in debug mode */
    bool tee_debug_mode;

    /* perform syslog when level is less than or equal to this */
    int syslog_level;

    /* whether debug symbols are needed */
    bool debug_symbols;

    /* true if --memcheck option present */
    bool memcheck;

    /* true if --nobrk option is present (if so brk syscall returns -ENOTSUP */
    bool nobrk;

    /* true if --exec_stack option is present -- allows trampolines. */
    bool exec_stack;

    /* true if --perf option present -- print performance statistics */
    bool perf;

    /* true if --report-native-tids is present */
    bool report_native_tids;

    /* true if --host-uds on command line or HostUDS in json config */
    bool host_uds;

    // From the --main-stack-size=<size> option.
    size_t main_stack_size;

    // From the --thread-stack-size=<size> option.
    size_t thread_stack_size;

    // From the --max-affinity-cpus=<num> option. This setting limits the
    // CPUs reported by sched_getaffinity().
    size_t max_affinity_cpus;

    // mode the fork implementation uses.
    // selection between a fork/exec model,
    // or a more traditional fork model with limits
    myst_fork_mode_t fork_mode;

    /* Callback for making target-calls */
    myst_tcall_t tcall;

    /* pointer to myst_syscall() that is set by myst_enter_kernel() */
    long (*myst_syscall)(long n, long params[6]);

    /* pointer to myst_handle_host_signal(). Set by myst_enter_kernel */
    void (*myst_handle_host_signal)(siginfo_t* siginfo, mcontext_t* context);

    /* pointer to myst_signal_restore_mask(). Set by myst_enter_kernel */
    void (*myst_signal_restore_mask)(void);

    /* boolean indicating whether to terminate on unhandled syscall or return
     * ENOSYS
     */
    bool unhandled_syscall_enosys;

    /* List of secrets we want the kernel to retrieve on behalf of the app */
    myst_wanted_secrets_t* wanted_secrets;

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

const char* myst_syscall_str(long n);

MYST_INLINE bool myst_is_addr_within_kernel(const void* ptr)
{
    const uint64_t base = (uint64_t)__myst_kernel_args.image_data;
    const uint64_t end = base + __myst_kernel_args.image_size;

    if ((uint64_t)ptr < base || (uint64_t)ptr >= end)
        return false;

    return true;
}

#endif /* _MYST_KERNEL_H */
