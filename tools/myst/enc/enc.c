// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
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
#include <myst/kstack.h>
#include <myst/mmanutils.h>
#include <myst/mount.h>
#include <myst/process.h>
#include <myst/ramfs.h>
#include <myst/regions.h>
#include <myst/reloc.h>
#include <myst/shm.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>
#include <myst/trace.h>
#include <signal.h>

#include "../config.h"
#include "../kargs.h"
#include "../shared.h"
#include "myst_t.h"

#define IRETFRAME_Rip 0
#define IRETFRAME_SegCs IRETFRAME_Rip + 8
#define IRETFRAME_EFlags IRETFRAME_SegCs + 8
#define IRETFRAME_Rsp IRETFRAME_EFlags + 8

static myst_kernel_args_t _kargs;

struct myst_final_options final_options = {0};

extern const void* __oe_get_heap_base(void);

long myst_tcall_isatty(int fd);

long _exception_handler_syscall(long n, long params[6])
{
    return (*_kargs.myst_syscall)(n, params);
}

static void _oe_context_to_mcontext(oe_context_t* oe_context, mcontext_t* mc)
{
    mc->gregs[REG_R8] = (int64_t)(oe_context->r8);
    mc->gregs[REG_R9] = (int64_t)(oe_context->r9);
    mc->gregs[REG_R10] = (int64_t)(oe_context->r10);
    mc->gregs[REG_R11] = (int64_t)(oe_context->r11);
    mc->gregs[REG_R12] = (int64_t)(oe_context->r12);
    mc->gregs[REG_R13] = (int64_t)(oe_context->r13);
    mc->gregs[REG_R14] = (int64_t)(oe_context->r14);
    mc->gregs[REG_R15] = (int64_t)(oe_context->r15);

    mc->gregs[REG_RSI] = (int64_t)(oe_context->rsi);
    mc->gregs[REG_RDI] = (int64_t)(oe_context->rdi);
    mc->gregs[REG_RBP] = (int64_t)(oe_context->rbp);
    mc->gregs[REG_RSP] = (int64_t)(oe_context->rsp);
    mc->gregs[REG_RIP] = (int64_t)(oe_context->rip);

    mc->gregs[REG_RAX] = (int64_t)(oe_context->rax);
    mc->gregs[REG_RBX] = (int64_t)(oe_context->rbx);
    mc->gregs[REG_RCX] = (int64_t)(oe_context->rcx);
    mc->gregs[REG_RDX] = (int64_t)(oe_context->rdx);

    mc->gregs[REG_EFL] = (int64_t)(oe_context->flags);

    // Ensure the definitions between musl and OE are aligned
    assert(sizeof(struct _fpstate) == sizeof(oe_basic_xstate_t));

    memcpy(mc->fpregs, &(oe_context->basic_xstate), sizeof(struct _fpstate));
}

static uint64_t _forward_exception_as_signal_to_kernel(
    oe_exception_record_t* oe_exception_record)
{
    uint32_t oe_exception_code = oe_exception_record->code;
    oe_context_t* oe_context = oe_exception_record->context;
    mcontext_t mcontext = {0};
    struct _fpstate fpregs __attribute__((aligned(16))) = {0};
    siginfo_t siginfo = {0};
    bool supported_code = false;

    mcontext.fpregs = &fpregs;

    _oe_context_to_mcontext(oe_context, &mcontext);

    // Kernel should be the ultimate handler of #PF, #GP, #MF, and #UD.
    // If we are still alive after kernel handling, it means kernel
    // wanted the execution to continue.
    if (oe_exception_code == OE_EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        siginfo.si_code = SI_KERNEL;
        siginfo.si_signo = SIGILL;
        supported_code = true;
    }
    else if (oe_exception_code == OE_EXCEPTION_PAGE_FAULT)
    {
        // ATTN: Use the following rule to determine the si_code, which
        // may be different from the behavior of the Linux kernel.
        if (oe_exception_record->error_code & OE_SGX_PAGE_FAULT_PK_FLAG)
            siginfo.si_code = SEGV_PKUERR;
        else if (oe_exception_record->error_code & OE_SGX_PAGE_FAULT_P_FLAG)
            siginfo.si_code = SEGV_ACCERR;
        else
            siginfo.si_code = SEGV_MAPERR;
        siginfo.si_signo = SIGSEGV;
        // The faulting address is only avaiable on icelake. The
        // mystikos-specific OE runtime also simulates the #PF on
        // coffeelake when the enclave is in debug mode.
        // Note that the si_addr in the simulated #PF always has the
        // lower 12 bits cleared.
        siginfo.si_addr = (void*)oe_exception_record->faulting_address;
        supported_code = true;
    }
    else if (oe_exception_code == OE_EXCEPTION_ACCESS_VIOLATION)
    {
        // #GP can only be delivered on icelake.
        siginfo.si_code = SEGV_ACCERR;
        siginfo.si_signo = SIGSEGV;
        // `si_addr` is always null for #GP.
        siginfo.si_addr = NULL;
        supported_code = true;
    }
    else if (oe_exception_code == OE_EXCEPTION_X87_FLOAT_POINT)
    {
        // ATTN: Consider implementing accurate si-code for
        // OE_EXCEPTION_X87_FLOAT_POINT
        siginfo.si_code = FPE_FLTINV;
        siginfo.si_signo = SIGFPE;
        supported_code = true;
    }
    else if (oe_exception_code == OE_EXCEPTION_DIVIDE_BY_ZERO)
    {
        siginfo.si_code = FPE_INTDIV;
        siginfo.si_signo = SIGFPE;
        supported_code = true;
    }

    if (supported_code)
    {
        /* The OE layer hardware exception handling scheme requires
         * any registered handler call to return such that the OE
         * can clean up internal states after the handler finishes.
         * However, invoking a signal handler of the programming
         * language or the application does not always meet the
         * requirement as the handler might not return. Therefore,
         * we set up the oe_context and return to OE layer with
         * OE_EXCEPTION_CONTINUE_EXECUTION. After OE performs
         * necessary cleanup, the execution will "jump to"
         * myst_handle_host_signal using Mystikos stack.
         */

        uint64_t rsp;
        uint64_t rbp;

        asm volatile("mov %%rsp, %0" : "=r"(rsp));
        asm volatile("mov %%rbp, %0" : "=r"(rbp));

        oe_context->rip =
            (__typeof(oe_context->rip))_kargs.myst_handle_host_signal;
        // Update the rsp so that the myst_handle_host_signal can continue
        // from the current stack frame on which siginfo and mcontext are
        // saved. Also, make rsp 16-byte aligned and mimic the behavior of
        // call (i.e., substract 8 bytes) to conform the x86-64 calling
        // convention as myst_handle_host_signal is expected to be called
        oe_context->rsp = (rsp & -16) - 8;
        oe_context->rbp = rbp;
        oe_context->rdi = (__typeof(oe_context->rdi)) & siginfo;
        oe_context->rsi = (__typeof(oe_context->rsi)) & mcontext;

        return OE_EXCEPTION_CONTINUE_EXECUTION;
    }

    // ATTN: Consider forwarding OE_EXCEPTION_BOUND_OUT_OF_RANGE,
    // OE_EXCEPTION_ACCESS_VIOLATION, OE_EXCEPTION_MISALIGNMENT,
    // OE_EXCEPTION_SIMD_FLOAT_POINT as signal.
    // Delegate unhandled hardware exceptions to other vector handlers.
    return OE_EXCEPTION_CONTINUE_SEARCH;
}

extern volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx;

static size_t _get_num_tcs(void)
{
    return oe_enclave_properties_sgx.header.size_settings.num_tcs;
}

int myst_setup_clock(struct clock_ctrl*);

static void _sanitize_xsave_area_fields(uint64_t* rbx, uint64_t* rcx)
{
    assert(rbx && rcx);
    /* replace XSAVE/XRSTOR save area size with fixed large value of 4096,
    to protect against spoofing attacks from untrusted host.
    If host returns smaller xsave area than required, this can cause a buffer
    overflow at context switch time.
    We believe value of 4096 should be sufficient for forseeable future. */
    if (*rbx < 4096)
        *rbx = 4096;
    if (*rcx < 4096)
        *rcx = 4096;
}

#define COLOR_GREEN "\e[32m"
#define COLOR_RESET "\e[0m"

#define RDTSC_OPCODE 0x310F
#define CPUID_OPCODE 0xA20F
#define IRETQ_OPCODE 0xCF48
#define SYSCALL_OPCODE 0x050F

typedef struct _opcode_pair
{
    long opcode;
    const char* str;
} opcode_pair_t;

static opcode_pair_t _opcode_pairs[] = {
    {RDTSC_OPCODE, "rdtsc"},
    {CPUID_OPCODE, "cpuid"},
    {IRETQ_OPCODE, "iretq"},
    {SYSCALL_OPCODE, "syscall"},
};

static size_t _n_pairs = sizeof(_opcode_pairs) / sizeof(_opcode_pairs[0]);
const char* opcode_str(long n)
{
    for (size_t i = 0; i < _n_pairs; i++)
    {
        if (n == _opcode_pairs[i].opcode)
            return _opcode_pairs[i].str;
    }

    return "unknown";
}

__attribute__((format(printf, 2, 3))) static void _exception_handler_strace(
    long n,
    const char* fmt,
    ...)
{
    if (final_options.base.strace_config.trace_syscalls)
    {
        char null_char = '\0';
        char* buf = &null_char;
        const bool isatty = myst_tcall_isatty(STDERR_FILENO) == 1l;
        const char* green = isatty ? COLOR_GREEN : "";
        const char* reset = isatty ? COLOR_RESET : "";

        if (fmt)
        {
            const size_t buf_size = 1024;

            if (!(buf = malloc(buf_size)))
            {
                fprintf(stderr, "out of memory\n");
                assert(0);
            }
            va_list ap;
            va_start(ap, fmt);
            vsnprintf(buf, buf_size, fmt, ap);
            va_end(ap);
        }

        fprintf(
            stderr,
            "[exception handler] %s%s%s(%s)\n",
            green,
            opcode_str(n),
            reset,
            buf);

        if (buf != &null_char)
            free(buf);
    }
}

/* Handle illegal SGX instructions */
static uint64_t _vectored_handler(oe_exception_record_t* er)
{
    const uint16_t opcode = *((uint16_t*)er->context->rip);
    void* saved_fs = NULL;
    void* fsbase;
    void* gsbase;

    /* restore FS to OE's default value so that we can make ocalls */
    asm volatile("mov %%fs:0, %0" : "=r"(fsbase));
    asm volatile("mov %%gs:0, %0" : "=r"(gsbase));

    if (fsbase != gsbase)
    {
        asm volatile("wrfsbase %0" ::"r"(gsbase));
        saved_fs = fsbase;
    }

    if (er->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        _exception_handler_strace(opcode, NULL);
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

                /* Restore FS if needed */
                if (saved_fs)
                    asm volatile("wrfsbase %0" ::"r"(saved_fs));

                return OE_EXCEPTION_CONTINUE_EXECUTION;
                break;
            }
            case CPUID_OPCODE:
            {
                uint32_t rax = 0xaa;
                uint32_t rbx = 0xbb;
                uint32_t rcx = 0xcc;
                uint32_t rdx = 0xdd;
                bool is_xsave_subleaf_zero =
                    (er->context->rax == 0xd && er->context->rcx == 0);

                if (er->context->rax != 0xff)
                {
                    _exception_handler_strace(
                        opcode,
                        "rax= 0x%lx rcx= 0x%lx",
                        er->context->rax,
                        er->context->rcx);
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

                if (is_xsave_subleaf_zero)
                    _sanitize_xsave_area_fields(
                        &er->context->rbx, &er->context->rcx);

                /* Skip over the illegal instruction. */
                er->context->rip += 2;

                /* Restore FS if needed */
                if (saved_fs)
                    asm volatile("wrfsbase %0" ::"r"(saved_fs));

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

                /* Always restore signal mask on iretq. For the case of
                 * returning from signal handling, doing so recovers
                 * the mask that is temporarily set by _handle_one_signal.
                 * For other cases, this function does not have any
                 * effectiveness. */
                (*_kargs.myst_signal_restore_mask)();

                /* Restore FS if needed */
                if (saved_fs)
                    asm volatile("wrfsbase %0" ::"r"(saved_fs));

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

                /* Restore FS if needed */
                if (saved_fs)
                    asm volatile("wrfsbase %0" ::"r"(saved_fs));

                // If the specific syscall is not supported in Mystikos, the
                // exception handler will cause abort.
                return OE_EXCEPTION_CONTINUE_EXECUTION;
                break;
            }
            default:
                break;
        }
    }

    /* Restore FS if needed */
    if (saved_fs)
        asm volatile("wrfsbase %0" ::"r"(saved_fs));

    return _forward_exception_as_signal_to_kernel(er);
}

const void* __oe_get_enclave_start_address(void);
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

    fprintf(stderr, "_test_oe_debug_mode: %d\n", ret);

    return ret;
}

static bool _validate_wanted_secrets(myst_wanted_secrets_t* secrets)
{
    if (secrets != NULL)
    {
        for (size_t i = 0; i < secrets->secrets_count; i++)
        {
            myst_wanted_secret_t* tmp = &secrets->secrets[i];
            if (tmp->id == NULL || tmp->srs_addr == NULL ||
                tmp->local_path == NULL || tmp->clientlib == NULL)
            {
                fprintf(
                    stderr,
                    "Warning: incomplete entries for wanted secret "
                    "{id: %s, Srs Address: %s, Local Path: %s, ClientLib: %s}. "
                    "All wanted secrets are ignored.\n",
                    tmp->id,
                    tmp->srs_addr,
                    tmp->local_path,
                    tmp->clientlib);
                return false;
            }
        }
    }
    return true;
}

struct enter_arg
{
    struct myst_options* options;
    struct myst_shm* shared_memory;
    const void* argv_data;
    size_t argv_size;
    const void* envp_data;
    size_t envp_size;
    const void* mount_mappings_data;
    size_t mount_mappings_size;
    uint64_t event;
    pid_t target_tid;
    uint64_t start_time_sec;
    uint64_t start_time_nsec;
    const void* enter_stack;
    size_t enter_stack_size;
};

static long _enter(void* arg_)
{
    long ret = -1;
    struct enter_arg* arg = (struct enter_arg*)arg_;
    struct myst_options* host_options = arg->options;
    struct myst_shm* shared_memory = arg->shared_memory;
    const void* argv_data = arg->argv_data;
    size_t argv_size = arg->argv_size;
    const void* envp_data = arg->envp_data;
    size_t envp_size = arg->envp_size;
    uint64_t event = arg->event;
    pid_t target_tid = arg->target_tid;
    config_parsed_data_t parsed_config;
    bool have_config = false;
    const uint8_t* enclave_image_base;
    size_t enclave_image_size;
    const Elf64_Ehdr* ehdr;
    const char target[] = "MYST_TARGET=sgx";
    const bool tee_debug_mode = (_test_oe_debug_mode() == 0);
    myst_args_t mount_mappings;
    myst_args_t args;
    myst_args_t env;
    myst_wanted_secrets_t* wanted_secrets = NULL;

    memset(&parsed_config, 0, sizeof(parsed_config));
    memset(&mount_mappings, 0, sizeof(mount_mappings));

    if (!argv_data || !argv_size || !envp_data || !envp_size)
        goto done;

    /* Get the enclave base address */
    if (!(enclave_image_base = __oe_get_enclave_start_address()))
    {
        fprintf(stderr, "__oe_get_enclave_start_address() failed\n");
        assert(0);
    }

    /* Get the enclave size */
    enclave_image_size = __oe_get_enclave_size();

    /* Get the config region */
    {
        myst_region_t r;
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

    if (myst_args_unpack(&args, argv_data, argv_size) != 0)
        goto done;
    if (myst_args_unpack(&env, envp_data, envp_size) != 0)
        goto done;
    if (myst_args_unpack(
            &mount_mappings,
            arg->mount_mappings_data,
            arg->mount_mappings_size) != 0)
        goto done;

    if (have_config)
    {
        wanted_secrets = &parsed_config.wanted_secrets;
        if (!_validate_wanted_secrets(wanted_secrets))
            wanted_secrets = NULL;
    }

    if (determine_final_options(
            host_options,
            &final_options,
            &args,
            &env,
            &parsed_config,
            have_config,
            tee_debug_mode,
            target,
            &mount_mappings) != 0)
    {
        fprintf(stderr, "Failed to determine final options\n");
        assert(0);
    }

    myst_args_release(&args);
    myst_args_release(&env);
    myst_args_release(&mount_mappings);

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
        myst_kernel_entry_t entry;
        const void* regions_end = __oe_get_heap_base();
        char err[256];

        if (init_kernel_args(
                &_kargs,
                target,
                (int)final_options.args.size,
                final_options.args.data,
                (int)final_options.env.size,
                final_options.env.data,
                final_options.cwd,
                &final_options.base.host_enc_uid_gid_mappings,
                &parsed_config.mounts,
                wanted_secrets,
                final_options.hostname,
                regions_end,
                enclave_image_base, /* image_data */
                enclave_image_size, /* image_size */
                _get_num_tcs(),     /* max threads */
                final_options.base.trace_errors,
                final_options.base.trace_times,
                &final_options.base.strace_config,
                false, /* have_syscall_instruction */
                tee_debug_mode,
                event, /* thread_event */
                target_tid,
                final_options.base.max_affinity_cpus,
                final_options.base.fork_mode,
                myst_tcall,
                final_options.base.rootfs,
                err,
                final_options.base.unhandled_syscall_enosys,
                sizeof(err)) != 0)
        {
            fprintf(stderr, "init_kernel_args() failed\n");
            assert(0);
        }

        _kargs.debug_symbols = final_options.base.debug_symbols;
        _kargs.memcheck = final_options.base.memcheck;
        _kargs.nobrk = final_options.base.nobrk;
        _kargs.exec_stack = final_options.base.exec_stack;
        _kargs.perf = final_options.base.perf;
        _kargs.start_time_sec = arg->start_time_sec;
        _kargs.start_time_nsec = arg->start_time_nsec;
        _kargs.report_native_tids = final_options.base.report_native_tids;
        _kargs.enter_stack = arg->enter_stack;
        _kargs.enter_stack_size = arg->enter_stack_size;
        _kargs.main_stack_size = final_options.base.main_stack_size
                                     ? final_options.base.main_stack_size
                                     : MYST_PROCESS_INIT_STACK_SIZE;
        _kargs.thread_stack_size = final_options.base.thread_stack_size;
        _kargs.host_uds = final_options.base.host_uds;

        /* whether user-space FSGSBASE instructions are supported */
        _kargs.have_fsgsbase_instructions =
            final_options.base.have_fsgsbase_instructions;

        /* set ehdr and verify that the kernel is an ELF image */
        {
            ehdr = (const Elf64_Ehdr*)_kargs.kernel_data;
            const uint8_t ident[] = {0x7f, 'E', 'L', 'F'};

            if (memcmp(ehdr->e_ident, ident, sizeof(ident)) != 0)
            {
                fprintf(stderr, "bad kernel image\n");
                assert(0);
            }
        }

        /* Resolve the the kernel entry point */
        entry =
            (myst_kernel_entry_t)((uint8_t*)_kargs.kernel_data + ehdr->e_entry);

        if ((uint8_t*)entry < (uint8_t*)_kargs.kernel_data ||
            (uint8_t*)entry >=
                (uint8_t*)_kargs.kernel_data + _kargs.kernel_size)
        {
            fprintf(stderr, "kernel entry point is out of bounds\n");
            assert(0);
        }

        ret = (*entry)(&_kargs);
    }

done:

    if (final_options.args.data)
        free(final_options.args.data);
    if (final_options.env.data)
        free(final_options.env.data);

    free_config(&parsed_config);
    return ret;
}

int myst_enter_ecall(
    struct myst_options* options,
    struct myst_shm* shared_memory,
    const void* argv_data,
    size_t argv_size,
    const void* envp_data,
    size_t envp_size,
    const void* mount_mappings,
    size_t mount_mappings_size,
    uint64_t event,
    pid_t target_tid,
    uint64_t start_time_sec,
    uint64_t start_time_nsec)
{
    struct enter_arg arg = {
        .options = options,
        .shared_memory = shared_memory,
        .argv_data = argv_data,
        .argv_size = argv_size,
        .envp_data = envp_data,
        .envp_size = envp_size,
        .mount_mappings_data = mount_mappings,
        .mount_mappings_size = mount_mappings_size,
        .event = event,
        .target_tid = target_tid,
        .start_time_sec = start_time_sec,
        .start_time_nsec = start_time_nsec,
    };

    /* prevent this function from being called more than once */
    if (__sync_fetch_and_add(&myst_enter_ecall_lock, 1) != 0)
    {
        myst_enter_ecall_lock = 1; // stop this from wrapping
        return -1;
    }

    const void* regions = __oe_get_heap_base();
    myst_region_t reg;

    /* find the stack for entering the kernel */
    if (myst_region_find(regions, MYST_REGION_KERNEL_ENTER_STACK, &reg) != 0)
        return -1;

    uint8_t* stack = (uint8_t*)reg.data + reg.size;

    arg.enter_stack = reg.data;
    arg.enter_stack_size = reg.size;

    /* avoid using the tiny TCS stack */
    return (int)myst_call_on_stack(stack, _enter, &arg);
}

long myst_run_thread_ecall(uint64_t cookie, uint64_t event, pid_t target_tid)
{
    return myst_run_thread(cookie, event, target_tid);
}

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_add_symbol_file(
    const void* file_data,
    size_t file_size,
    const void* text,
    size_t text_size,
    const char* enclave_rootfs_path)
{
    long ret = 0;
    int retval;

    if (!text || !text_size)
        ERAISE(-EINVAL);

    if (myst_add_symbol_file_ocall(
            &retval,
            file_data,
            file_size,
            text,
            text_size,
            enclave_rootfs_path) != OE_OK)
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

ssize_t myst_tcall_read_block_device(
    int blkdev,
    uint64_t blkno,
    struct myst_block* blocks,
    size_t num_blocks)
{
    ssize_t retval;

    if (myst_read_block_device_ocall(
            &retval, blkdev, blkno, blocks, num_blocks) != OE_OK)
    {
        return -EINVAL;
    }
    /* guard against host setting the return value greater than num_blocks */
    if (retval > (ssize_t)num_blocks)
    {
        retval = -EINVAL;
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
    /* guard against host setting the return value greater than num_blocks */
    if (retval > (ssize_t)num_blocks)
    {
        retval = -EINVAL;
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

long myst_tcall_interrupt_thread(pid_t tid)
{
    long retval = 0;

    if (myst_interrupt_thread_ocall(&retval, tid) != OE_OK)
        return -ENOSYS;

    return retval;
}

long myst_tcall_write_console(int fd, const void* buf, size_t count)
{
    long ret = 0;
    long retval = 0;

    if (fd != STDOUT_FILENO && fd != STDERR_FILENO)
        ERAISE(-EINVAL);

    if (myst_write_console_ocall(&retval, fd, buf, count) != OE_OK)
        ERAISE(-EIO);

    if (retval != count)
        ERAISE(-EIO);

    ret = count;

done:
    return ret;
}

OE_SET_ENCLAVE_SGX2(
    ENCLAVE_PRODUCT_ID,
    ENCLAVE_SECURITY_VERSION,
    ENCLAVE_EXTENDED_PRODUCT_ID,
    ENCLAVE_FAMILY_ID,
    ENCLAVE_DEBUG,
    ENCLAVE_CAPTURE_PF_GP_EXCEPTIONS,
    ENCLAVE_REQUIRE_KSS,
    ENCLAVE_CREATE_ZERO_BASE_ENCLAVE,
    ENCLAVE_START_ADDRESS,
    ENCLAVE_HEAP_SIZE / OE_PAGE_SIZE,
    ENCLAVE_STACK_SIZE / OE_PAGE_SIZE,
    ENCLAVE_MAX_THREADS);
