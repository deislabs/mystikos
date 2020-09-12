// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <assert.h>
#include <errno.h>
#include <libgen.h>
#include <libos/elf.h>
#include <libos/strings.h>
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

#include <libos/eraise.h>
#include <libos/file.h>
#include <libos/getopt.h>
#include <openenclave/host.h>

#include "libos_u.h"
#include "regions.h"
#include "utils.h"

static int _serialize_args(
    const char* argv[],
    void** args_out,
    size_t* args_size_out)
{
    int ret = -1;
    void* args = NULL;
    size_t args_size = 0;

    if (args_out)
        *args_out = NULL;

    if (args_size_out)
        *args_size_out = 0;

    if (!argv || !args_out || !args_size_out)
        goto done;

    /* Determine the size of the output buffer */
    for (size_t i = 0; argv[i]; i++)
        args_size += strlen(argv[i]) + 1;

    if (!(args = malloc(args_size)))
        goto done;

    memset(args, 0, args_size);

    /* Copy the strings */
    {
        uint8_t* p = args;

        for (size_t i = 0; argv[i]; i++)
        {
            size_t n = strlen(argv[i]) + 1;

            memcpy(p, argv[i], n);
            p += n;
        }
    }

    *args_out = args;
    args = NULL;
    *args_size_out = args_size;
    ret = 0;

done:

    if (args)
        free(args);

    return ret;
}

int exec_get_opt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    char err[128];
    int ret;

    ret = libos_get_opt(argc, argv, opt, optarg, err, sizeof(err));

    if (ret < 0)
        _err("%s", err);

    return ret;
}

static oe_enclave_t* _enclave;

/* the address of this is eventually passed to futex (uaddr argument) */
static __thread int _thread_event;

static pid_t _gettid(void)
{
    return (pid_t)syscall(SYS_gettid);
}

static void* _thread_func(void* arg)
{
    long r = -1;
    uint64_t cookie = (uint64_t)arg;
    uint64_t event = (uint64_t)&_thread_event;
    pid_t tid = _gettid();

    if (libos_run_thread_ecall(_enclave, &r, cookie, tid, event) != OE_OK ||
        r != 0)
    {
        fprintf(stderr, "libos_run_thread_ecall(): failed: retval=%ld\n", r);
        fflush(stdout);
        abort();
    }

    return NULL;
}

long libos_create_host_thread_ocall(uint64_t cookie)
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
    int* uaddr = (int*)event;

    /* if *uaddr == 0 */
    if (__sync_fetch_and_add(uaddr, -1) == 0)
    {
        do
        {
            long ret;

            /* wait while *uaddr == -1 */
            ret = syscall(
                SYS_futex,
                (int*)event,
                FUTEX_WAIT_PRIVATE,
                -1,
                timeout,
                NULL,
                0);

            if (ret != 0 && errno == ETIMEDOUT)
            {
                return ETIMEDOUT;
            }
        } while (*uaddr == -1);
    }

    return 0;
}

long libos_wake_ocall(uint64_t event)
{
    long ret = 0;

    if (__sync_fetch_and_add((int*)event, 1) != 0)
    {
        ret = syscall(
            SYS_futex, (int*)event, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);

        if (ret != 0)
            ret = -errno;
    }

    return ret;
}

long libos_wake_wait_ocall(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct libos_timespec* timeout)
{
    long ret;

    if ((ret = libos_wake_ocall(waiter_event)) != 0)
        return ret;

    if ((ret = libos_wait_ocall(self_event, timeout)) != 0)
        return ret;

    return 0;
}

long libos_export_file_ocall(const char* path, const void* data, size_t size)
{
    long ret = 0;
    char cwd[PATH_MAX];
    char file[PATH_MAX];
    char dir[PATH_MAX];
    char* p;

    if (!path || (!data && size))
        ERAISE(-EINVAL);

    if (!(getcwd(cwd, sizeof(cwd))))
        ERAISE(-errno);

    if (snprintf(file, sizeof(file), "%s/ramfs/%s", cwd, path) >= sizeof(file))
        ERAISE(-ENAMETOOLONG);

    if (libos_strlcpy(dir, file, sizeof(dir)) >= sizeof(dir))
        ERAISE(-ENAMETOOLONG);

    /* Chop off the final component */
    if ((p = strrchr(dir, '/')))
        *p = '\0';
    else
        ERAISE(-EINVAL);

    ECHECK(libos_mkdirhier(dir, 0777));
    ECHECK(libos_write_file(file, data, size));

done:
    return ret;
}

int exec_launch_enclave(
    const char* enc_path,
    oe_enclave_type_t type,
    uint32_t flags,
    const char* argv[],
    struct libos_options* options)
{
    oe_result_t r;
    int retval;
    static int _event; /* the main-thread event (used by futex: uaddr) */
    void* args = NULL;
    size_t args_size = 0;

    /* Load the enclave: calls oe_region_add_regions() */
    {
        r = oe_create_libos_enclave(enc_path, type, flags, NULL, 0, &_enclave);

        if (r != OE_OK)
            _err("failed to load enclave: result=%s", oe_result_str(r));
    }

    /* Serialize the argv[] strings */
    if (_serialize_args(argv, &args, &args_size) != 0)
        _err("failed to serialize argv stings");

    const char env[] = "PATH=/bin\0HOME=/root";

    /* Enter the enclave and run the program */
    r = libos_enter_ecall(
        _enclave,
        &retval,
        options,
        args,
        args_size,
        env,
        sizeof(env),
        getppid(),
        getpid(),
        (uint64_t)&_event);
    if (r != OE_OK)
        _err("failed to enter enclave: result=%s", oe_result_str(r));

    /* Terminate the enclave */
    r = oe_terminate_enclave(_enclave);
    if (r != OE_OK)
        _err("failed to terminate enclave: result=%s", oe_result_str(r));

    free(args);

    return retval;
}

int _exec(int argc, const char* argv[])
{
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    struct libos_options options;
    const region_details* details;

    assert(strcmp(argv[1], "exec") == 0);

    memset(&options, 0, sizeof(options));

    /* Get options */
    {
        /* Get --trace-syscalls option */
        if (exec_get_opt(&argc, argv, "--trace-syscalls", NULL) == 0 ||
            exec_get_opt(&argc, argv, "--strace", NULL) == 0)
        {
            options.trace_syscalls = true;
        }

        /* Get --real-syscalls option */
        if (exec_get_opt(&argc, argv, "--real-syscalls", NULL) == 0)
            options.real_syscalls = true;

        /* Get --export-ramfs option */
        if (exec_get_opt(&argc, argv, "--export-ramfs", NULL) == 0)
            options.export_ramfs = true;

        /* Set export_ramfs option based on LIBOS_ENABLE_GCOV env variable */
        {
            const char* val;

            if ((val = getenv("LIBOS_ENABLE_GCOV")) && strcmp(val, "1") == 0)
                options.export_ramfs = true;
        }
    }

    if (options.real_syscalls)
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
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

    if (exec_launch_enclave(
            details->enc.path, type, flags, argv + 3, &options) != 0)
    {
        _err("Failed to run enclave %s", details->enc.path);
    }

    free_region_details();

    return 0;
}
