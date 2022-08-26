// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
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
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <syscall.h>
#include <unistd.h>

#include <myst/args.h>
#include <myst/buf.h>
#include <myst/cpio.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/fssig.h>
#include <myst/getopt.h>
#include <myst/hex.h>
#include <myst/options.h>
#include <myst/round.h>
#include <myst/sha256.h>
#include <myst/shm.h>
#include <myst/thread.h>
#include <openenclave/bits/properties.h>
#include <openenclave/bits/sgx/sgxproperties.h>
#include <openenclave/host.h>

#include "../shared.h"
#include "exec.h"
#include "fsgsbase.h"
#include "myst_u.h"
#include "process.h"
#include "pubkeys.h"
#include "regions.h"
#include "roothash.h"
#include "strace.h"
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

/* forward declarations of the OE data type and internal API */
typedef oe_result_t (
    *oe_load_extra_enclave_data_hook_t)(void* arg, uint64_t baseaddr);

void oe_register_load_extra_enclave_data_hook(
    oe_load_extra_enclave_data_hook_t hook);

/* forward declaration of the hook implemented in regions_sgx.c */
oe_result_t myst_load_extra_enclave_data_hook(void* arg, uint64_t baseaddr);

static struct myst_shm shared_memory = {0};

/* wait for so many milliseconds */
static void _sleep_msec(uint64_t msec)
{
    struct timespec ts;
    const struct timespec* req = &ts;
    struct timespec rem = {0, 0};
    static const uint64_t _SEC_TO_MSEC = 1000UL;
    static const uint64_t _MSEC_TO_NSEC = 1000000UL;

    ts.tv_sec = (time_t)(msec / _SEC_TO_MSEC);
    ts.tv_nsec = (long)((msec % _SEC_TO_MSEC) * _MSEC_TO_NSEC);

    while (nanosleep(req, &rem) != 0 && errno == EINTR)
        req = &rem;
}

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

/* the number of enclave threads (excluding the main thread) */
static _Atomic(size_t) _num_child_enclave_threads;

static void* _thread_func(void* arg)
{
    uint64_t cookie = (uint64_t)arg;
    uint64_t event = (uint64_t)&_thread_event;
    pid_t target_tid = (pid_t)syscall(SYS_gettid);
    oe_result_t res;
    long retval = -1;

    /* block MYST_INTERRUPT_THREAD_SIGNAL when inside the enclave */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, MYST_INTERRUPT_THREAD_SIGNAL);
    sigprocmask(SIG_BLOCK, &set, NULL);

    res = myst_run_thread_ecall(_enclave, &retval, cookie, event, target_tid);

    /* unblock MYST_INTERRUPT_THREAD_SIGNAL when outside the enclave */
    sigprocmask(SIG_UNBLOCK, &set, NULL);

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

    _num_child_enclave_threads--;
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

    if (ret == 0)
        _num_child_enclave_threads++;

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

static void _interrupt_thread_signal_handler(int sig)
{
    /* no-op */
    (void)sig;
}

/* Wait for child enclave threads to exit or fail trying */
static void _wait_on_child_threads(void)
{
    uint64_t msec_per_sec = 1000;
    uint64_t msec = 1;
    const size_t max_retries = 5;
    size_t num_retries = 0;

    while (_num_child_enclave_threads)
    {
        if (msec < msec_per_sec)
        {
            _sleep_msec(msec);
            msec *= 2;
        }
        else
        {
            if (num_retries == max_retries)
            {
                fprintf(stderr, "myst: child threads failed to exit\n");
                fflush(stdout);
                abort();
            }

            fprintf(stderr, "myst: waiting for child threads to exit\n");
            fflush(stdout);
            _sleep_msec(msec_per_sec);
            num_retries++;
        }
    }
}

int exec_launch_enclave(
    const char* enc_path,
    oe_enclave_type_t type,
    uint32_t flags,
    const char* argv[],
    const char* envp[],
    const myst_args_t* mount_mappings,
    struct myst_options* options)
{
    oe_result_t r;
    int retval;
    static int _event; /* the main-thread event (used by futex: uaddr) */
    myst_buf_t argv_buf = MYST_BUF_INITIALIZER;
    myst_buf_t envp_buf = MYST_BUF_INITIALIZER;
    myst_buf_t mount_mappings_buf = MYST_BUF_INITIALIZER;
    pid_t target_tid = (pid_t)syscall(SYS_gettid);
    struct timespec start_time;
    oe_enclave_setting_context_switchless_t switchless_setting = {0, 0};
    oe_enclave_setting_t settings[8];
    size_t num_settings = 0;
    sighandler_t old_sighandler;

    /* get the start time and pass it into the kernel */
    if (clock_gettime(CLOCK_REALTIME, &start_time) != 0)
        _err("clock_gettime() failed");

    // Initialize the switchless setting; this applies to ocalls with the
    // transition_using_threads attribute.
    {
        switchless_setting.max_enclave_workers = 0;
        switchless_setting.max_host_workers = 4;

        // clang-format off
        oe_enclave_setting_t setting =
        {
            .setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS,
            .u.context_switchless_setting = &switchless_setting
        };
        // clang-format on

        settings[num_settings++] = setting;
    }

    /* Register the hook */
    oe_register_load_extra_enclave_data_hook(myst_load_extra_enclave_data_hook);

    /* Load the enclave: calls oe_load_extra_enclave_data_hook() */
#ifndef SUPPRESS_SWITCHLESS
    r = oe_create_myst_enclave(
        enc_path, type, flags, settings, num_settings, &_enclave);
#else
    r = oe_create_myst_enclave(enc_path, type, flags, NULL, 0, &_enclave);
    (void)settings;
#endif

    if (r != OE_OK)
        _err("failed to load enclave: result=%s", oe_result_str(r));

    /* Serialize the argv[] strings */
    if (myst_buf_pack_strings(&argv_buf, argv, _count_args(argv)) != 0)
        _err("failed to serialize argv stings");

    /* Serialize the argv[] strings */
    if (myst_buf_pack_strings(&envp_buf, envp, _count_args(envp)) != 0)
        _err("failed to serialize envp stings");

    /* Serialize the argv[] strings */
    if (mount_mappings->data)
    {
        if (myst_buf_pack_strings(
                &mount_mappings_buf,
                mount_mappings->data,
                mount_mappings->size) != 0)
            _err("failed to serialize mapping parameter stings");
    }

    /* Get clock times right before entering the enclave */
    shm_create_clock(&shared_memory, CLOCK_TICK);

    /* Set a MYST_INTERRUPT_THREAD_SIGNAL handler */
    old_sighandler =
        sigset(MYST_INTERRUPT_THREAD_SIGNAL, _interrupt_thread_signal_handler);

    /* block MYST_INTERRUPT_THREAD_SIGNAL when inside the enclave */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, MYST_INTERRUPT_THREAD_SIGNAL);
    sigprocmask(SIG_BLOCK, &set, NULL);

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
        mount_mappings_buf.data,
        mount_mappings_buf.size,
        (uint64_t)&_event,
        target_tid,
        start_time.tv_sec,
        start_time.tv_nsec);
    if (r != OE_OK)
        _err("failed to enter enclave: result=%s", oe_result_str(r));

    /* unblock MYST_INTERRUPT_THREAD_SIGNAL when outside the enclave */
    sigprocmask(SIG_UNBLOCK, &set, NULL);

    /* restore the old MYST_INTERRUPT_THREAD_SIGNAL handler */
    sigset(MYST_INTERRUPT_THREAD_SIGNAL, old_sighandler);

    // Wait for child enclave threads to exit before attempting to terminate
    // the enclave. Otherwise, oe_query_enclave_instance() may fail during
    // termination.
    _wait_on_child_threads();

    /* Terminate the enclave */
    r = oe_terminate_enclave(_enclave);
    if (r != OE_OK)
        _err("failed to terminate enclave: result=%s", oe_result_str(r));

    shm_free_clock(&shared_memory);

    free(argv_buf.data);
    free(envp_buf.data);
    free(mount_mappings_buf.data);

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
    --main-stack-size <size>\n\
                         -- the stack size required by the Mystikos application's\n\
                            main thread, where <size> may have a\n\
                            multiplier suffix: k 1024, m 1024*1024, or\n\
                            g 1024*1024*1024\n\
    --app-config-path <json>\n\
                         -- specifies the configuration json file for\n\
                            running an unsigned binary. The file can be\n\
                            the same one used for the signing process.\n\
    --host-to-enc-uid-map <host-uid:enc-uid[,host-uid2:enc-uid2,...]>\n\
                         -- comma separated list of uid mappings between\n\
                            the host and the enclave\n\
    --host-to-enc-gid-map <host-gid:enc-gid[,host-gid2:enc-gid2,...]>\n\
                         -- comma separated list of gid mappings between\n\
                            the host and the enclave\n\
    --unhandled-syscall-enosys <true/false>\n\
                         -- flag indicating if the app must exit when\n\
                            it encounters an unimplemented syscall\n\
                            'true' implies the syscall would not terminate\n\
                            and instead return ENOSYS.\n\
    --strace            \n\
                         -- Use this option to display the system call traces of \n\
                            the execution\n\
    --strace-failing\n\
                         -- When specified, all syscalls that fail will be logged.\n\
                            Other syscalls will not be logged, unless specified via \n\
                            filter (see below). Set a breakpoint in _strace_failure_hook \n\
                            to stop execution whenever a syscall fails. Use breakpoint \n\
                            conditions to control the behavior of the breakpoint.\n\
                            E.g: Use syscall number as a condition in the breakpoint\n\
    --strace-filter 'SYS_name1:group1:SYS_name2:...'\n\
                         -- Specify the set of syscalls or groups to be traced. When filters \n\
                            are specified, only those syscalls/groups specified in the filter \n\
                            will be traced, in addition to failing syscalls if\n\
                            specified as described above. Any combination of syscalls and groups \n\
                            can be used. For a list of all the groups and their consituents check\n\
                            out 'man strace' \n\
                            E.g: To trace open and mprotect syscalls, and 'desc' group of \n\
                            syscalls (file descriptor related group), specify \n\
                            --strace-filter 'SYS_open:SYS_mprotect:desc'\n\
    --strace-exclude-filter 'SYS_name1:SYS_name2:group1...'\n\
                         -- Specify a set of syscalls or groups to exclude from the strace log. \n\
                            All other syscalls will be logged in the strace. Failing syscalls, even \n\
                            if excluded, will also be logged if --strace-failing is specified. Any \n\
                            combination of syscalls and groups can be used.  For a list of all the \n\
                            groups and their consituents check out 'man strace' \n\
                            E.g: To exclude open and mprotect syscalls and the group of \n\
                            file syscalls, specify\n\
                            --strace-exclude-filter='SYS_open:SYS_mprotect:file'\n\
\n"

int exec_action(int argc, const char* argv[], const char* envp[])
{
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG_AUTO;
    struct myst_options options;
    static const size_t max_pubkeys = 128;
    const char* pubkeys[max_pubkeys];
    size_t num_pubkeys = 0;
    const region_details* details;
    int return_status;
    char pubkeys_path[PATH_MAX];
    char roothashes_path[PATH_MAX];
    char rootfs_path[] = "/tmp/mystXXXXXX";
    uint64_t heap_size = 0;
    const char* commandline_config = NULL;
    myst_args_t mount_mapping = {0};
    myst_buf_t roothash_buf = MYST_BUF_INITIALIZER;

    assert(strcmp(argv[1], "exec") == 0 || strcmp(argv[1], "exec-sgx") == 0);

    memset(&options, 0, sizeof(options));

    (void)pubkeys;
    (void)num_pubkeys;

    /* Get options */
    {
        // process ID mapping options
        cli_get_mapping_opts(&argc, argv, &options.host_enc_uid_gid_mappings);

        // retrieve mount mapping options
        cli_get_mount_mapping_opts(&argc, argv, &mount_mapping);

        /* Get --trace-syscalls option */
        if (cli_getopt(&argc, argv, "--trace-syscalls", NULL) == 0 ||
            cli_getopt(&argc, argv, "--strace", NULL) == 0)
        {
            options.strace_config.trace_syscalls = true;
        }

        if (myst_strace_parse_config(&argc, argv, &options.strace_config) == 0)
        {
            options.strace_config.trace_syscalls = true;
        }

        /* Get --trace option */
        if (cli_getopt(&argc, argv, "--trace-errors", NULL) == 0 ||
            cli_getopt(&argc, argv, "--etrace", NULL) == 0)
        {
            options.trace_errors = true;
        }

        /* Get --trace-times option */
        if (cli_getopt(&argc, argv, "--trace-times", NULL) == 0 ||
            cli_getopt(&argc, argv, "--ttrace", NULL) == 0)
        {
            options.trace_times = true;
        }

        /* Get --memcheck option */
        if (cli_getopt(&argc, argv, "--memcheck", NULL) == 0)
            options.memcheck = true;

        /* Get --nobrk option */
        if (cli_getopt(&argc, argv, "--nobrk", NULL) == 0)
            options.nobrk = true;

        /* Get --exec-stack option */
        if (cli_getopt(&argc, argv, "--exec-stack", NULL) == 0)
            options.exec_stack = true;

        /* Get --perf option */
        if (cli_getopt(&argc, argv, "--perf", NULL) == 0)
            options.perf = true;

        /* Get --report-native-tids option */
        if (cli_getopt(&argc, argv, "--report-native-tids", NULL) == 0)
            options.report_native_tids = true;

        /* Get --host-uds option */
        if (cli_getopt(&argc, argv, "--host-uds", NULL) == 0)
            options.host_uds = true;

        /* Get --max-affinity-cpus */
        {
            const char* arg = NULL;

            if ((cli_getopt(&argc, argv, "--max-affinity-cpus", &arg) == 0))
            {
                char* end = NULL;
                size_t val = strtoull(arg, &end, 10);

                if (!end || *end != '\0')
                {
                    fprintf(
                        stderr,
                        "%s: bad --max-affinity-cpus=%s option\n",
                        argv[0],
                        arg);
                    return 1;
                }

                options.max_affinity_cpus = val;
            }
        }

        if (get_fork_mode_opts(&argc, argv, &options.fork_mode) != 0)
        {
            fprintf(
                stderr,
                "%s: invalid --fork-mode option. Only \"none\", "
                "\"pseudo\" and \"pseudo_wait_for_exit_exec\" are currently "
                "supported\n",
                argv[0]);
            return 1;
        }

        /* Get MYST_MEMCHECK environment variable */
        {
            const char* env;
            if ((env = getenv("MYST_MEMCHECK")) && strcmp(env, "1") == 0)
                options.memcheck = true;
        }

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

        /* Get --main-stack-size */
        {
            const char* opt = "--main-stack-size";
            const char* arg = NULL;

            if (cli_getopt(&argc, argv, opt, &arg) == 0)
            {
                if (arg)
                {
                    if ((myst_expand_size_string_to_ulong(
                             arg, &options.main_stack_size) != 0) ||
                        (myst_round_up(
                             options.main_stack_size,
                             PAGE_SIZE,
                             &options.main_stack_size) != 0))
                    {
                        _err(
                            "%s <size> -- bad suffix (must be k, m, or g)\n",
                            opt);
                    }
                }
            }
        }

        /* Get --thread-stack-size */
        {
            const char* opt = "--thread-stack-size";
            const char* arg = NULL;

            if (cli_getopt(&argc, argv, opt, &arg) == 0)
            {
                if (arg)
                {
                    if ((myst_expand_size_string_to_ulong(
                             arg, &options.thread_stack_size) != 0) ||
                        (myst_round_up(
                             options.thread_stack_size,
                             PAGE_SIZE,
                             &options.thread_stack_size) != 0))
                    {
                        _err(
                            "%s <size> -- bad suffix (must be k, m, or g)\n",
                            opt);
                    }
                }
            }
        }

        /* Get --app-config option if it exists, otherwise we use default values
         */
        cli_getopt(&argc, argv, "--app-config-path", &commandline_config);

        /* Get option deciding how to handle unimplemented syscalls */
        /* Get --unhandled-syscall-enosys */
        {
            const char* arg = NULL;

            if ((cli_getopt(&argc, argv, "--unhandled-syscall-enosys", &arg) ==
                 0))
            {
                if (strcmp(arg, "true") == 0)
                {
                    options.unhandled_syscall_enosys = true;
                }
                else if (strcmp(arg, "false") == 0)
                {
                    options.unhandled_syscall_enosys = false;
                }
                else
                {
                    fprintf(
                        stderr,
                        "%s: bad --unhandled-syscall-enosys=%s option. "
                        "Must be 'true' or 'false'\n",
                        argv[0],
                        arg);
                    return 1;
                }
            }
        }

        /* Get --help option */
        if ((cli_getopt(&argc, argv, "--help", NULL) == 0) ||
            (cli_getopt(&argc, argv, "-h", NULL) == 0))
        {
            fprintf(stderr, USAGE_FORMAT, argv[0]);
            return 1;
        }

        /* Get --pubkey=filename options */
        get_pubkeys_options(&argc, argv, pubkeys, max_pubkeys, &num_pubkeys);

        /* Get --roothash=filename options */
        get_roothash_options(&argc, argv, &roothash_buf);

        /* determine whether debug symbols are needed */
        {
            int r;

            if ((r = process_is_being_traced()) < 0)
            {
                fprintf(
                    stderr,
                    "%s: process_is_being_traced() failed: %d",
                    argv[0],
                    r);
                return 1;
            }

            options.debug_symbols = (bool)r;
        }
    }

    if (argc < 4)
    {
        fprintf(stderr, USAGE_FORMAT, argv[0]);
        return 1;
    }

    const char* rootfs = argv[2];
    const char* program = argv[3];

    /* check whether FSGSBASE instructions are supported */
    if (test_user_space_fsgsbase() == 0)
        options.have_fsgsbase_instructions = true;

    assert(myst_validate_file_path(commandline_config));
    if (extract_roothashes_from_ext2_images(
            rootfs, &mount_mapping, &roothash_buf) != 0)
    {
        _err("failed to extract roothashes from EXT2 images");
    }

    create_pubkeys_file(pubkeys, num_pubkeys, pubkeys_path);

    if (create_roothashes_file(&roothash_buf, roothashes_path) != 0)
        _err("failed to create roothashes file");

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

    // we may or may not have config passed in through the commandline.
    // If the enclave is signed that config will take precedence over
    // this version
    if ((details = create_region_details_from_files(
             program,
             rootfs,
             pubkeys_path,
             roothashes_path,
             commandline_config,
             heap_size)) == NULL)
    {
        _err("Creating region data failed.");
    }

    unlink(pubkeys_path);
    unlink(roothashes_path);

    return_status = exec_launch_enclave(
        details->enc.path,
        type,
        flags,
        argv + 3,
        envp,
        &mount_mapping,
        &options);
    myst_args_release(&mount_mapping);

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

long myst_poll_wake_ocall(void)
{
    return myst_tcall_poll_wake();
}

long myst_poll_ocall(struct pollfd* fds, unsigned long nfds, int timeout)
{
    return myst_tcall_poll(fds, nfds, timeout);
}

int myst_load_fssig_ocall(const char* path, myst_fssig_t* fssig)
{
    return myst_load_fssig(path, fssig);
}

int myst_mprotect_ocall(void* addr, size_t len, int prot)
{
    return mprotect(addr, len, prot);
}

long myst_interrupt_thread_ocall(pid_t tid)
{
    return myst_tcall_interrupt_thread(tid);
}

long myst_write_console_ocall(int fd, const void* buf, size_t count)
{
    long ret = 0;
    FILE* stream = NULL;

    if (!buf)
        ERAISE(-EINVAL);

    if (fd == STDOUT_FILENO)
        stream = stdout;
    else if (fd == STDERR_FILENO)
        stream = stderr;
    else
        ERAISE(-EINVAL);

    if (fwrite(buf, 1, count, stream) != count)
        ERAISE(-EIO);

    ret = count;

done:
    return ret;
}
