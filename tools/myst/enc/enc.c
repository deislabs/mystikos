// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

#include <openenclave/enclave.h>

#include <elf.h>
#include <myst/args.h>
#include <myst/buf.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/kernel.h>
#include <myst/mmanutils.h>
#include <myst/mount.h>
#include <myst/ramfs.h>
#include <myst/regions.h>
#include <myst/reloc.h>
#include <myst/shm.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>
#include <myst/trace.h>

#include "../config.h"
#include "../kargs.h"
#include "../shared.h"
#include "myst_t.h"

#define IRETFRAME_Rip 0
#define IRETFRAME_SegCs IRETFRAME_Rip + 8
#define IRETFRAME_EFlags IRETFRAME_SegCs + 8
#define IRETFRAME_Rsp IRETFRAME_EFlags + 8

static myst_kernel_args_t kargs;

long _exception_handler_syscall(long n, long params[6])
{
    return (*kargs.myst_syscall)(n, params);
}

extern volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx;

static size_t _get_num_tcs(void)
{
    return oe_enclave_properties_sgx.header.size_settings.num_tcs;
}

int myst_setup_clock(struct clock_ctrl*);

/* Handle illegal SGX instructions */
static uint64_t _vectored_handler(oe_exception_record_t* er)
{
#define RDTSC_OPCODE 0x310F
#define CPUID_OPCODE 0xA20F
#define IRETQ_OPCODE 0xCF48
#define SYSCALL_OPCODE 0x050F

    const uint16_t opcode = *((uint16_t*)er->context->rip);

    if (er->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        switch (opcode)
        {
            case RDTSC_OPCODE:
            {
                uint32_t rax = 0;
                uint32_t rdx = 0;

                /* Ask host to execute RDTSC instruction */
                if (myst_rdtsc_ocall(&rax, &rdx) != OE_OK)
                {
                    fprintf(stderr, "myst_rdtsc_ocall() failed\n");
                    assert(false);
                    return OE_EXCEPTION_CONTINUE_SEARCH;
                }

                er->context->rax = rax;
                er->context->rdx = rdx;

                /* Skip over the illegal instruction. */
                er->context->rip += 2;

                return OE_EXCEPTION_CONTINUE_EXECUTION;
                break;
            }
            case CPUID_OPCODE:
            {
                uint32_t rax = 0xaa;
                uint32_t rbx = 0xbb;
                uint32_t rcx = 0xcc;
                uint32_t rdx = 0xdd;

                if (er->context->rax != 0xff)
                {
                    myst_cpuid_ocall(
                        (uint32_t)er->context->rax, /* leaf */
                        (uint32_t)er->context->rcx, /* subleaf */
                        &rax,
                        &rbx,
                        &rcx,
                        &rdx);
                }

                er->context->rax = rax;
                er->context->rbx = rbx;
                er->context->rcx = rcx;
                er->context->rdx = rdx;

                return OE_EXCEPTION_CONTINUE_EXECUTION;
                break;
            }
            case IRETQ_OPCODE:
            {
                // Restore RSP, RIP, EFLAGS from the stack. CS and SS are not
                // applicable for sgx applications, and restoring them triggers
                // #UD.

                er->context->flags =
                    *(uint64_t*)(er->context->rsp + IRETFRAME_EFlags);
                er->context->rip =
                    *(uint64_t*)(er->context->rsp + IRETFRAME_Rip);
                er->context->rsp =
                    *(uint64_t*)(er->context->rsp + IRETFRAME_Rsp);

                return OE_EXCEPTION_CONTINUE_EXECUTION;
                break;
            }
            case SYSCALL_OPCODE:
            {
                long params[6] = {0};

                // SYSCALL saves RIP (next instruction after SYSCALL) to RCX and
                // SYSRET restors the RIP from RCX
                er->context->rcx = er->context->rip + 2;
                er->context->rip = er->context->rcx;
                // SYSCALL saves RFLAGS into R11 and clears in RFLAGS every bit
                // corresponding to a bit that is set in the IA32_FMASK MSR, for
                // CPU operations. No need to emulate RFLAGS value here.
                // SYSRET loads (r11 & 0x3C7FD7) | 2 to RFLAG
                er->context->r11 = er->context->flags;
                er->context->flags = (er->context->r11 & 0x3C7FD7) | 2;

                params[0] = (long)er->context->rdi;
                params[1] = (long)er->context->rsi;
                params[2] = (long)er->context->rdx;
                params[3] = (long)er->context->r10;
                params[4] = (long)er->context->r8;
                params[5] = (long)er->context->r9;

                // syscall number is in RAX. SYSRET sets RAX.
                er->context->rax = (uint64_t)_exception_handler_syscall(
                    (long)er->context->rax, params);

                // If the specific syscall is not supported in Mystikos, the
                // exception handler will cause abort.
                return OE_EXCEPTION_CONTINUE_EXECUTION;
                break;
            }
            default:
                break;
        }
    }

    return OE_EXCEPTION_CONTINUE_SEARCH;
}

static bool _is_allowed_env_variable(
    const config_parsed_data_t* config,
    const char* env)
{
    for (size_t i = 0; i < config->host_environment_variables_count; i++)
    {
        const char* allowed = config->host_environment_variables[i];
        size_t len = strlen(allowed);

        if (strncmp(env, allowed, len) == 0 && env[len] == '=')
            return true;
    }

    return false;
}

const void* __oe_get_enclave_base(void);
size_t __oe_get_enclave_size(void);

volatile int myst_enter_ecall_lock = 0;

/* return 0 if OE is in SGX debug mode (else return -1) */
static int _test_oe_debug_mode(void)
{
    int ret = -1;
    uint8_t* buf = NULL;
    size_t buf_size;
    oe_report_t report;

    if (oe_get_report_v2(0, NULL, 0, NULL, 0, &buf, &buf_size) != OE_OK)
        goto done;

    if (oe_parse_report(buf, buf_size, &report) != OE_OK)
        goto done;

    if (!(report.identity.attributes & OE_REPORT_ATTRIBUTES_DEBUG))
        goto done;

    ret = 0;

done:

    if (buf)
        oe_free_report(buf);

    return ret;
}

struct enter_arg
{
    struct myst_options* options;
    struct myst_shm* shared_memory;
    const void* argv_data;
    size_t argv_size;
    const void* envp_data;
    size_t envp_size;
    uint64_t event;
};

static long _enter(void* arg_)
{
    long ret = -1;
    struct enter_arg* arg = (struct enter_arg*)arg_;
    struct myst_options* options = arg->options;
    struct myst_shm* shared_memory = arg->shared_memory;
    const void* argv_data = arg->argv_data;
    size_t argv_size = arg->argv_size;
    const void* envp_data = arg->envp_data;
    size_t envp_size = arg->envp_size;
    uint64_t event = arg->event;
    bool trace_errors = false;
    bool trace_syscalls = false;
    bool shell_mode = false;
    bool memcheck = false;
    bool export_ramfs = false;
    const char* rootfs = NULL;
    config_parsed_data_t parsed_config;
    bool have_config = false;
    myst_args_t args;
    myst_args_t env;
    const char* cwd = "/";       // default to root dir
    const char* hostname = NULL; // kernel has a default
    const uint8_t* enclave_base;
    size_t enclave_size;
    const Elf64_Ehdr* ehdr;
    const char target[] = "MYST_TARGET=sgx";

    memset(&parsed_config, 0, sizeof(parsed_config));

    if (!argv_data || !argv_size || !envp_data || !envp_size)
        goto done;

    memset(&args, 0, sizeof(args));
    memset(&env, 0, sizeof(env));

    /* Get the enclave base address */
    if (!(enclave_base = __oe_get_enclave_base()))
    {
        fprintf(stderr, "__oe_get_enclave_base() failed\n");
        assert(0);
    }

    /* Get the enclave size */
    enclave_size = __oe_get_enclave_size();

    /* Get the config region */
    {
        myst_region_t r;
        extern const void* __oe_get_heap_base(void);
        const void* regions = __oe_get_heap_base();

        if (myst_region_find(regions, MYST_REGION_CONFIG, &r) == 0)
        {
            if (parse_config_from_buffer(r.data, r.size, &parsed_config) != 0)
            {
                fprintf(stderr, "failed to parse configuration\n");
                assert(0);
            }
            have_config = true;
        }
    }

    if (have_config && !parsed_config.allow_host_parameters)
    {
        if (myst_args_init(&args) != 0)
            goto done;

        if (myst_args_append1(&args, parsed_config.application_path) != 0)
            goto done;

        if (myst_args_append(
                &args,
                (const char**)parsed_config.application_parameters,
                parsed_config.application_parameters_count) != 0)
        {
            goto done;
        }
    }
    else
    {
        if (myst_args_unpack(&args, argv_data, argv_size) != 0)
            goto done;
    }

    // Need to handle config to environment
    // in the mean time we will just pull from the host
    if (have_config)
    {
        myst_args_init(&env);

        // append all enclave-side environment variables first
        if (myst_args_append(
                &env,
                (const char**)parsed_config.enclave_environment_variables,
                parsed_config.enclave_environment_variables_count) != 0)
        {
            goto done;
        }

        // now include host-side environment variables that are allowed
        if (parsed_config.host_environment_variables &&
            parsed_config.host_environment_variables_count)
        {
            myst_args_t tmp;

            if (myst_args_unpack(&tmp, envp_data, envp_size) != 0)
                goto done;

            for (size_t i = 0; i < tmp.size; i++)
            {
                if (_is_allowed_env_variable(&parsed_config, tmp.data[i]))
                {
                    if (myst_args_append1(&env, tmp.data[i]) != 0)
                    {
                        free(tmp.data);
                        goto done;
                    }
                }
            }

            free(tmp.data);
        }
    }
    else
    {
        if (myst_args_unpack(&env, envp_data, envp_size) != 0)
            goto done;
    }

    // Override current working directory if present in config
    if (have_config && parsed_config.cwd)
    {
        cwd = parsed_config.cwd;
    }

    // Override current working directory if present in config
    if (have_config && parsed_config.hostname)
    {
        hostname = parsed_config.hostname;
    }

    /* Inject the MYST_TARGET environment variable */
    {
        const char val[] = "MYST_TARGET=";

        for (size_t i = 0; i < env.size; i++)
        {
            if (strncmp(env.data[i], val, sizeof(val) - 1) == 0)
            {
                fprintf(stderr, "environment already contains %s", val);
                goto done;
            }
        }

        myst_args_append1(&env, "MYST_TARGET=sgx");
    }

    if (options)
    {
        trace_errors = options->trace_errors;
        trace_syscalls = options->trace_syscalls;
        shell_mode = options->shell_mode;
        memcheck = options->memcheck;
        export_ramfs = options->export_ramfs;

        if (strlen(options->rootfs) >= PATH_MAX)
        {
            fprintf(stderr, "rootfs path too long (> %u)\n", PATH_MAX);
            goto done;
        }

        rootfs = options->rootfs;
    }

    /* Setup the vectored exception handler */
    if (oe_add_vectored_exception_handler(true, _vectored_handler) != OE_OK)
    {
        fprintf(stderr, "oe_add_vectored_exception_handler() failed\n");
        assert(0);
    }

    if (myst_setup_clock(shared_memory->clock))
    {
        fprintf(stderr, "myst_setup_clock() failed\n");
        assert(0);
    }

    /* Enter the kernel image */
    {
        myst_kernel_args_t kargs;
        myst_kernel_entry_t entry;
        extern const void* __oe_get_heap_base(void);
        const void* regions_end = __oe_get_heap_base();
        const bool tee_debug_mode = _test_oe_debug_mode() == 0;
        char err[256];

        init_kernel_args(
            &kargs,
            target,
            (int)args.size,
            args.data,
            (int)env.size,
            env.data,
            cwd,
            hostname,
            regions_end,
            enclave_base,   /* image_data */
            enclave_size,   /* image_size */
            _get_num_tcs(), /* max threads */
            trace_errors,
            trace_syscalls,
            export_ramfs,
            false, /* have_syscall_instruction */
            tee_debug_mode,
            event, /* thread_event */
            myst_tcall,
            rootfs,
            err,
            sizeof(err));

        kargs.shell_mode = shell_mode;
        kargs.memcheck = memcheck;

        /* set ehdr and verify that the kernel is an ELF image */
        {
            ehdr = (const Elf64_Ehdr*)kargs.kernel_data;
            const uint8_t ident[] = {0x7f, 'E', 'L', 'F'};

            if (memcmp(ehdr->e_ident, ident, sizeof(ident)) != 0)
            {
                fprintf(stderr, "bad kernel image\n");
                assert(0);
            }
        }

        /* Resolve the the kernel entry point */
        entry =
            (myst_kernel_entry_t)((uint8_t*)kargs.kernel_data + ehdr->e_entry);

        if ((uint8_t*)entry < (uint8_t*)kargs.kernel_data ||
            (uint8_t*)entry >= (uint8_t*)kargs.kernel_data + kargs.kernel_size)
        {
            fprintf(stderr, "kernel entry point is out of bounds\n");
            assert(0);
        }

        ret = (*entry)(&kargs);
    }

done:

    if (args.data)
        free(args.data);

    if (env.data)
        free(env.data);

    free_config(&parsed_config);

    printf("enclave: exiting: ret=%ld\n", ret);
    return ret;
}

/* The size of the stack for entering the kernel */
#define ENTER_STACK_SIZE (512 * 1024)

int myst_enter_ecall(
    struct myst_options* options,
    struct myst_shm* shared_memory,
    const void* argv_data,
    size_t argv_size,
    const void* envp_data,
    size_t envp_size,
    uint64_t event)
{
    /* WARNING: ecalls are invoked on a very small stack (see
     * ENCLAVE_STACK_SIZE) */
    int ret = 0;
    struct enter_arg arg = {
        .options = options,
        .shared_memory = shared_memory,
        .argv_data = argv_data,
        .argv_size = argv_size,
        .envp_data = envp_data,
        .envp_size = envp_size,
        .event = event,
    };
    MYST_ALIGN(16) static uint8_t _stack[ENTER_STACK_SIZE];

    /* prevent this function from being called more than once */
    if (__sync_fetch_and_add(&myst_enter_ecall_lock, 1) != 0)
    {
        myst_enter_ecall_lock = 1; // stop this from wrapping
        ret = -1;
        goto done;
    }

    /* avoid using the tiny TCS stack */
    ret = (int)myst_call_on_stack(_stack + ENTER_STACK_SIZE, _enter, &arg);

done:
    return ret;
}

long myst_run_thread_ecall(uint64_t cookie, uint64_t event)
{
    /* WARNING: ecalls are invoked on a very small stack (see
     * ENCLAVE_STACK_SIZE) */
    return myst_run_thread(cookie, event);
}

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_add_symbol_file(
    const void* file_data,
    size_t file_size,
    const void* text,
    size_t text_size)
{
    long ret = 0;
    int retval;

    if (!text || !text_size)
        ERAISE(-EINVAL);

    if (myst_add_symbol_file_ocall(
            &retval, file_data, file_size, text, text_size) != OE_OK)
    {
        ERAISE(-EINVAL);
    }

done:

    return ret;
}

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_load_symbols(void)
{
    long ret = 0;
    int retval;

    if (myst_load_symbols_ocall(&retval) != OE_OK || retval != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_unload_symbols(void)
{
    long ret = 0;
    int retval;

    if (myst_unload_symbols_ocall(&retval) != OE_OK || retval != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_isatty(int fd)
{
    long ret;

    if (myst_syscall_isatty_ocall(&ret, fd) != OE_OK)
        return -EINVAL;

    return (long)ret;
}

long myst_tcall_create_thread(uint64_t cookie)
{
    long ret;

    if (myst_create_thread_ocall(&ret, cookie) != OE_OK)
        return -EINVAL;

    return (long)ret;
}

long myst_tcall_wait(uint64_t event, const struct timespec* timeout)
{
    long retval = -EINVAL;
    const struct myst_timespec* to = (const struct myst_timespec*)timeout;

    if (myst_wait_ocall(&retval, event, to) != OE_OK)
        return -EINVAL;

    return retval;
}

long myst_tcall_wake(uint64_t event)
{
    long retval = -EINVAL;

    if (myst_wake_ocall(&retval, event) != OE_OK)
        return -EINVAL;

    return retval;
}

long myst_tcall_wake_wait(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct timespec* timeout)
{
    long retval = -EINVAL;
    const struct myst_timespec* to = (const struct myst_timespec*)timeout;

    if (myst_wake_wait_ocall(&retval, waiter_event, self_event, to) != OE_OK)
        return -EINVAL;

    return retval;
}

long myst_tcall_export_file(const char* path, const void* data, size_t size)
{
    long retval = -1;

    if (myst_export_file_ocall(&retval, path, data, size) != OE_OK)
        return -EINVAL;

    return retval;
}

long myst_tcall_poll_wake(void)
{
    long r;

    if (myst_poll_wake_ocall(&r) != OE_OK)
        return -EINVAL;

    return r;
}

int myst_tcall_open_block_device(const char* path, bool read_only)
{
    int retval;

    if (myst_open_block_device_ocall(&retval, path, read_only) != OE_OK)
        return -EINVAL;

    return retval;
}

int myst_tcall_close_block_device(int blkdev)
{
    int retval;

    if (myst_close_block_device_ocall(&retval, blkdev) != OE_OK)
        return -EINVAL;

    return retval;
}

int myst_tcall_read_block_device(
    int blkdev,
    uint64_t blkno,
    struct myst_block* blocks,
    size_t num_blocks)
{
    int retval;

    if (myst_read_block_device_ocall(
            &retval, blkdev, blkno, blocks, num_blocks) != OE_OK)
    {
        return -EINVAL;
    }

    return retval;
}

int myst_tcall_write_block_device(
    int blkdev,
    uint64_t blkno,
    const struct myst_block* blocks,
    size_t num_blocks)
{
    int retval;

    if (myst_write_block_device_ocall(
            &retval, blkdev, blkno, blocks, num_blocks) != OE_OK)
    {
        return -EINVAL;
    }

    return retval;
}

int myst_load_fssig(const char* path, myst_fssig_t* fssig)
{
    int retval;

    if (!path || !fssig)
        return -EINVAL;

    if (myst_load_fssig_ocall(&retval, path, fssig) != OE_OK)
        return -EINVAL;

    if (fssig->signature_size > sizeof(fssig->signature))
    {
        memset(fssig, 0, sizeof(myst_fssig_t));
        return -EPERM;
    }

    return retval;
}

#define ENCLAVE_PRODUCT_ID 1
#define ENCLAVE_SECURITY_VERSION 1
#define ENCLAVE_DEBUG true
#define ENCLAVE_HEAP_SIZE 131072
#define ENCLAVE_STACK_SIZE 8192

OE_SET_ENCLAVE_SGX(
    ENCLAVE_PRODUCT_ID,
    ENCLAVE_SECURITY_VERSION,
    ENCLAVE_DEBUG,
    ENCLAVE_HEAP_SIZE / OE_PAGE_SIZE,
    ENCLAVE_STACK_SIZE / OE_PAGE_SIZE,
    ENCLAVE_MAX_THREADS);
