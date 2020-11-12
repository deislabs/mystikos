// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <libos/elf.h>
#include <libos/strings.h>
#include <libos/tcall.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

#include <libos/buf.h>
#include <libos/eraise.h>
#include <libos/file.h>
#include <libos/getopt.h>
#include <libos/shm.h>
#include <openenclave/host.h>

#include "libos_u.h"
#include "regions.h"
#include "utils.h"

/* How many nanoseconds between two clock ticks */
/* TODO: Make it configurable through json */
#define CLOCK_TICK 1000

static struct libos_shm shared_memory = {0};

static size_t _count_args(const char* args[])
{
    size_t n = 0;

    for (size_t i = 0; args[i]; i++)
        n++;

    return n;
}

static int _getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    char err[128];
    int ret;

    ret = libos_getopt(argc, argv, opt, optarg, err, sizeof(err));

    if (ret < 0)
        _err("%s", err);

    return ret;
}

static oe_enclave_t* _enclave;

/* the address of this is eventually passed to futex (uaddr argument) */
static __thread int _thread_event;

static void* _thread_func(void* arg)
{
    long r = -1;
    uint64_t cookie = (uint64_t)arg;
    uint64_t event = (uint64_t)&_thread_event;

    if (libos_run_thread_ecall(_enclave, &r, cookie, event) != OE_OK || r != 0)
    {
        fprintf(stderr, "libos_run_thread_ecall(): failed: retval=%ld\n", r);
        fflush(stdout);
        abort();
    }

    return NULL;
}

long libos_create_thread_ocall(uint64_t cookie)
{
    long ret = 0;
    pthread_t t;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&t, &attr, _thread_func, (void*)cookie) != 0)
    {
        ret = -EINVAL;
        goto done;
    }

done:
    pthread_attr_destroy(&attr);
    return ret;
}

long libos_wait_ocall(uint64_t event, const struct libos_timespec* timeout)
{
    const struct timespec* ts = (const struct timespec*)timeout;
    return libos_tcall_wait(event, ts);
}

long libos_wake_ocall(uint64_t event)
{
    return libos_tcall_wake(event);
}

long libos_wake_wait_ocall(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct libos_timespec* timeout)
{
    const struct timespec* ts = (const struct timespec*)timeout;
    return libos_tcall_wake_wait(waiter_event, self_event, ts);
}

long libos_export_file_ocall(const char* path, const void* data, size_t size)
{
    return libos_tcall_export_file(path, data, size);
}

int exec_launch_enclave(
    const char* enc_path,
    oe_enclave_type_t type,
    uint32_t flags,
    const char* argv[],
    const char* envp[],
    struct libos_options* options)
{
    oe_result_t r;
    int retval;
    static int _event; /* the main-thread event (used by futex: uaddr) */
    libos_buf_t argv_buf = LIBOS_BUF_INITIALIZER;
    libos_buf_t envp_buf = LIBOS_BUF_INITIALIZER;

    /* Load the enclave: calls oe_region_add_regions() */
    {
        r = oe_create_libos_enclave(enc_path, type, flags, NULL, 0, &_enclave);

        if (r != OE_OK)
            _err("failed to load enclave: result=%s", oe_result_str(r));
    }

    /* Serialize the argv[] strings */
    if (libos_buf_pack_strings(&argv_buf, argv, _count_args(argv)) != 0)
        _err("failed to serialize argv stings");

    /* Serialize the argv[] strings */
    if (libos_buf_pack_strings(&envp_buf, envp, _count_args(envp)) != 0)
        _err("failed to serialize envp stings");

    /* Get clock times right before entering the enclave */
    shm_create_clock(&shared_memory, CLOCK_TICK);

    /* Enter the enclave and run the program */
    r = libos_enter_ecall(
        _enclave,
        &retval,
        options,
        &shared_memory,
        argv_buf.data,
        argv_buf.size,
        envp_buf.data,
        envp_buf.size,
        (uint64_t)&_event);
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

int exec_action(int argc, const char* argv[], const char* envp[])
{
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    struct libos_options options;
    const region_details* details;
    int return_status;

    assert(strcmp(argv[1], "exec") == 0 || strcmp(argv[1], "exec-sgx") == 0);

    memset(&options, 0, sizeof(options));

    /* Get options */
    {
        /* Get --trace-syscalls option */
        if (_getopt(&argc, argv, "--trace-syscalls", NULL) == 0 ||
            _getopt(&argc, argv, "--strace", NULL) == 0)
        {
            options.trace_syscalls = true;
        }

        /* Get --export-ramfs option */
        if (_getopt(&argc, argv, "--export-ramfs", NULL) == 0)
            options.export_ramfs = true;

        /* Set export_ramfs option based on LIBOS_ENABLE_GCOV env variable */
        {
            const char* val;

            if ((val = getenv("LIBOS_ENABLE_GCOV")) && strcmp(val, "1") == 0)
                options.export_ramfs = true;
        }
    }

    if (argc < 4)
    {
        fprintf(
            stderr,
            "Usage: %s %s <rootfs> <program> <args...>\n",
            argv[0],
            argv[1]);
        return 1;
    }

    const char* rootfs = argv[2];
    const char* program = argv[3];

    // note... we have no config, but this call will go looking in the enclave
    // if it is signed.
    if ((details = create_region_details_from_files(
             program, rootfs, NULL, 0)) == NULL)
    {
        _err("Creating region data failed.");
    }

    return_status = exec_launch_enclave(
        details->enc.path, type, flags, argv + 3, envp, &options);

    free_region_details();

    return return_status;
}

OE_STATIC_ASSERT((sizeof(struct libos_stat) % 8) == 0);
OE_STATIC_ASSERT(sizeof(struct libos_stat) == 120);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_dev) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_ino) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_nlink) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_mode) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_uid) == 28);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_gid) == 32);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_rdev) == 40);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_size) == 48);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_blksize) == 56);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_blocks) == 64);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_atim.tv_sec) == 72);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_atim.tv_nsec) == 80);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_mtim.tv_sec) == 88);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_mtim.tv_nsec) == 96);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_ctim.tv_sec) == 104);
OE_STATIC_ASSERT(OE_OFFSETOF(struct libos_stat, st_ctim.tv_nsec) == 112);

long libos_fstat_ocall(long fd, struct libos_stat* statbuf)
{
    if (fd > INT_MAX)
        return -EINVAL;

    if (fstat((int)fd, (struct stat*)statbuf) != 0)
        return -errno;

    return 0;
}

long libos_sched_yield_ocall(void)
{
    return (sched_yield() == 0) ? 0 : -errno;
}

long libos_fchmod_ocall(int fd, uint32_t mode)
{
    return fchmod(fd, mode);
}
