// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <linux/futex.h>
#include <myst/elf.h>
#include <myst/strings.h>
#include <myst/tcall.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>

#include <myst/buf.h>
#include <myst/cpio.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/fssig.h>
#include <myst/getopt.h>
#include <myst/options.h>
#include <myst/round.h>
#include <myst/shm.h>
#include <openenclave/bits/properties.h>
#include <openenclave/bits/sgx/sgxproperties.h>
#include <openenclave/host.h>

#include "../shared.h"
#include "archive.h"
#include "exec.h"
#include "myst_u.h"
#include "regions.h"
#include "utils.h"

// This is a default enclave configuration that we use when overriding the
// unsigned configuration
#undef OE_INFO_SECTION_BEGIN
#define OE_INFO_SECTION_BEGIN
#undef OE_INFO_SECTION_END
#define OE_INFO_SECTION_END

/* How many nanoseconds between two clock ticks */
/* TODO: Make it configurable through json */
#define CLOCK_TICK 1000

static struct myst_shm shared_memory = {0};

static size_t _count_args(const char* args[])
{
    size_t n = 0;

    for (size_t i = 0; args[i]; i++)
        n++;

    return n;
}

static oe_enclave_t* _enclave;

/* the address of this is eventually passed to futex (uaddr argument) */
static __thread int _thread_event;

static void* _thread_func(void* arg)
{
    uint64_t cookie = (uint64_t)arg;
    uint64_t event = (uint64_t)&_thread_event;
    pid_t target_tid = (int)syscall(SYS_gettid);
    oe_result_t res;
    long retval = -1;

    res = myst_run_thread_ecall(_enclave, &retval, cookie, event, target_tid);

    if (res != OE_OK || retval != 0)
    {
        fprintf(
            stderr,
            "myst_run_thread_ecall(): failed: res=%u retval=%ld\n",
            res,
            retval);
        fflush(stdout);
        abort();
    }

    return NULL;
}

long myst_create_thread_ocall(uint64_t cookie)
{
    pthread_t t;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    long ret = -pthread_create(&t, &attr, _thread_func, (void*)cookie);
    pthread_attr_destroy(&attr);

    return ret;
}

long myst_wait_ocall(uint64_t event, const struct myst_timespec* timeout)
{
    const struct timespec* ts = (const struct timespec*)timeout;
    return myst_tcall_wait(event, ts);
}

long myst_wake_ocall(uint64_t event)
{
    return myst_tcall_wake(event);
}

long myst_wake_wait_ocall(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct myst_timespec* timeout)
{
    const struct timespec* ts = (const struct timespec*)timeout;
    return myst_tcall_wake_wait(waiter_event, self_event, ts);
}

long myst_export_file_ocall(const char* path, const void* data, size_t size)
{
    return myst_tcall_export_file(path, data, size);
}

int exec_launch_enclave(
    const char* enc_path,
    oe_enclave_type_t type,
    uint32_t flags,
    const char* argv[],
    const char* envp[],
    struct myst_options* options)
{
    oe_result_t r;
    int retval;
    static int _event; /* the main-thread event (used by futex: uaddr) */
    myst_buf_t argv_buf = MYST_BUF_INITIALIZER;
    myst_buf_t envp_buf = MYST_BUF_INITIALIZER;
    pid_t target_tid = (pid_t)syscall(SYS_gettid);

    /* Load the enclave: calls oe_load_extra_enclave_data_hook() */
    r = oe_create_myst_enclave(enc_path, type, flags, NULL, 0, &_enclave);

    if (r != OE_OK)
        _err("failed to load enclave: result=%s", oe_result_str(r));

    /* Serialize the argv[] strings */
    if (myst_buf_pack_strings(&argv_buf, argv, _count_args(argv)) != 0)
        _err("failed to serialize argv stings");

    /* Serialize the argv[] strings */
    if (myst_buf_pack_strings(&envp_buf, envp, _count_args(envp)) != 0)
        _err("failed to serialize envp stings");

    /* Get clock times right before entering the enclave */
    shm_create_clock(&shared_memory, CLOCK_TICK);

    /* Enter the enclave and run the program */
    r = myst_enter_ecall(
        _enclave,
        &retval,
        options,
        &shared_memory,
        argv_buf.data,
        argv_buf.size,
        envp_buf.data,
        envp_buf.size,
        (uint64_t)&_event,
        target_tid);
    if (r != OE_OK)
        _err("failed to enter enclave: result=%s", oe_result_str(r));

    /* Terminate the enclave */
    r = oe_terminate_enclave(_enclave);
    if (r != OE_OK)
        _err("failed to terminate enclave: result=%s", oe_result_str(r));

    shm_free_clock(&shared_memory);

    free(argv_buf.data);
    free(envp_buf.data);

    return retval;
}

#define USAGE_FORMAT \
    "\n\
\n\
Usage: %s exec-sgx [options] <rootfs> <application> <args...>\n\
\n\
Where:\n\
    exec-sgx             -- execute an application within <rootfs> in a\n\
                            trusted SGX environment\n\
    <rootfs>             -- the root file system containing the application\n\
                            (CPIO or EXT2)\n\
    <application>        -- the path of the executable program within\n\
                            <rootfs> that will be executed\n\
    <args>               -- arguments to passed through to the <application>\n\
\n\
Options:\n\
    --help               -- this message\n\
    --memory-size <size> -- the memory size required by the Mystikos kernel\n\
                            and application, where <size> may have a\n\
                            multiplier suffix: k 1024, m 1024*1024, or\n\
                            g 1024*1024*1024\n\
    --app-config-path <json> -- specifies the configuration json file for\n\
                                running an unsigned binary. The file can be\n\
                                the same one used for the signing process.\n\
\n"

int exec_action(int argc, const char* argv[], const char* envp[])
{
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    struct myst_options options;
    static const size_t max_pubkeys = 128;
    const char* pubkeys[max_pubkeys];
    size_t num_pubkeys = 0;
    static const size_t max_roothashes = 128;
    const char* roothashes[max_roothashes];
    size_t num_roothashes = 0;
    const region_details* details;
    int return_status;
    char archive_path[PATH_MAX];
    char rootfs_path[] = "/tmp/mystXXXXXX";
    uint64_t heap_size = 0;
    const char* commandline_config = NULL;

    assert(strcmp(argv[1], "exec") == 0 || strcmp(argv[1], "exec-sgx") == 0);

    memset(&options, 0, sizeof(options));

    /* Get options */
    {
        // process ID mapping options
        cli_get_mapping_opts(&argc, argv, &options.host_enc_id_mapping);

        // retrieve mount mapping options
        cli_get_mount_mapping_opts(&argc, argv, &options.mount_mapping);

        /* Get --trace-syscalls option */
        if (cli_getopt(&argc, argv, "--trace-syscalls", NULL) == 0 ||
            cli_getopt(&argc, argv, "--strace", NULL) == 0)
        {
            options.trace_syscalls = true;
        }

        /* Get --trace option */
        if (cli_getopt(&argc, argv, "--trace-errors", NULL) == 0 ||
            cli_getopt(&argc, argv, "--etrace", NULL) == 0)
        {
            options.trace_errors = true;
        }

        /* Get --shell option */
        if (cli_getopt(&argc, argv, "--shell", NULL) == 0)
            options.shell_mode = true;

        /* Get --memcheck option */
        if (cli_getopt(&argc, argv, "--memcheck", NULL) == 0)
            options.memcheck = true;

        /* Get --export-ramfs option */
        if (cli_getopt(&argc, argv, "--export-ramfs", NULL) == 0)
            options.export_ramfs = true;

        /* Get --memory-size or --user-mem-size option */
        {
            const char* opt;
            const char* arg = NULL;

            if ((cli_getopt(&argc, argv, "--memory-size", &arg) == 0))
            {
                opt = "--memory-size";
            }

            if (!arg && cli_getopt(&argc, argv, "--user-mem-size", &arg) == 0)
            {
                /* legacy option (kept for backwards compatibility) */
                opt = "--user-mem-size";
            }

            if (arg)
            {
                if ((myst_expand_size_string_to_ulong(arg, &heap_size) != 0) ||
                    (myst_round_up(heap_size, PAGE_SIZE, &heap_size) != 0))
                {
                    _err("%s <size> -- bad suffix (must be k, m, or g)\n", opt);
                }
            }
        }

        /* Get --app-config option if it exists, otherwise we use default values
         */
        cli_getopt(&argc, argv, "--app-config-path", &commandline_config);

        /* Get --help option */
        if ((cli_getopt(&argc, argv, "--help", NULL) == 0) ||
            (cli_getopt(&argc, argv, "-h", NULL) == 0))
        {
            fprintf(stderr, USAGE_FORMAT, argv[0]);
            return 1;
        }

        /* Set export_ramfs option based on MYST_ENABLE_GCOV env variable */
        {
            const char* val;

            if ((val = getenv("MYST_ENABLE_GCOV")) && strcmp(val, "1") == 0)
                options.export_ramfs = true;
        }

        /* Get --pubkey=filename and --roothash=filename options */
        get_archive_options(
            &argc,
            argv,
            pubkeys,
            max_pubkeys,
            &num_pubkeys,
            roothashes,
            max_roothashes,
            &num_roothashes);
    }

    if (argc < 4)
    {
        fprintf(stderr, USAGE_FORMAT, argv[0]);
        return 1;
    }

    const char* rootfs = argv[2];
    const char* program = argv[3];
    create_archive(
        pubkeys, num_pubkeys, roothashes, num_roothashes, archive_path);

    /* copy the rootfs path to the options */
    if (myst_strlcpy(options.rootfs, rootfs, sizeof(options.rootfs)) >=
        sizeof(options.rootfs))
    {
        _err("<rootfs> command line argument is too long: %s", rootfs);
    }

    /* if not a CPIO archive, create a zero-filled file with one page */
    if (myst_cpio_test(rootfs) == -ENOTSUP)
    {
        int fd;
        uint8_t page[PAGE_SIZE];

        if ((fd = mkstemp(rootfs_path)) < 0)
            _err("failed to create temporary file");

        memset(page, 0, sizeof(page));

        if (write(fd, page, sizeof(page)) != sizeof(page))
            _err("failed to create file");

        close(fd);
        rootfs = rootfs_path;
    }

    // we may  or may not have config passed in through the commandline.
    // If the enclave is signed that config will take precedence over
    // this version
    if ((details = create_region_details_from_files(
             program, rootfs, archive_path, commandline_config, heap_size)) ==
        NULL)
    {
        _err("Creating region data failed.");
    }

    unlink(archive_path);

    return_status = exec_launch_enclave(
        details->enc.path, type, flags, argv + 3, envp, &options);

    free_mount_mapping_opts(&options.mount_mapping);

    free_region_details();

    if (rootfs == rootfs_path)
        unlink(rootfs_path);

    return return_status;
}

OE_STATIC_ASSERT((sizeof(struct myst_stat) % 8) == 0);
OE_STATIC_ASSERT(sizeof(struct myst_stat) == 120);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_dev) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_ino) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_nlink) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_mode) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_uid) == 28);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_gid) == 32);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_rdev) == 40);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_size) == 48);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_blksize) == 56);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_blocks) == 64);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_atim.tv_sec) == 72);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_atim.tv_nsec) == 80);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_mtim.tv_sec) == 88);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_mtim.tv_nsec) == 96);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_ctim.tv_sec) == 104);
OE_STATIC_ASSERT(OE_OFFSETOF(struct myst_stat, st_ctim.tv_nsec) == 112);

long myst_fstat_ocall(int fd, struct myst_stat* statbuf)
{
    if (fstat(fd, (struct stat*)statbuf) != 0)
        return -errno;

    return 0;
}

long myst_sched_yield_ocall(void)
{
    return (sched_yield() == 0) ? 0 : -errno;
}

long myst_fchmod_ocall(int fd, uint32_t mode)
{
    if (fchmod(fd, mode) != 0)
        return -errno;

    return 0;
}

long myst_poll_wake_ocall(void)
{
    extern long myst_tcall_poll_wake();

    return myst_tcall_poll_wake();
}

long myst_poll_ocall(struct pollfd* fds, unsigned long nfds, int timeout)
{
    extern long myst_tcall_poll(
        struct pollfd * lfds, unsigned long nfds, int timeout);

    return myst_tcall_poll(fds, nfds, timeout);
}

int myst_load_fssig_ocall(const char* path, myst_fssig_t* fssig)
{
    return myst_load_fssig(path, fssig);
}
