// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include "./syscall.h"
#include "./mmanutils.h"
#include <sys/mount.h>
#include "run_t.h"
#include "elfutils.h"
#include <oel/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <lthread.h>
#include <setjmp.h>

extern jmp_buf _exit_jmp_buf;

typedef long (*syscall_callback_t)(long n, long params[6]);

#define ARGV0 "/root/oe-libos/build/bin/samples/split/main"

static void _setup_hostfs(void)
{
    if (oe_load_module_host_file_system() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_file_system() failed\n");
        assert(false);
    }

    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        assert(false);
    }
}

static void _teardown_hostfs(void)
{
    if (umount("/") != 0)
    {
        fprintf(stderr, "umount() failed\n");
        assert(false);
    }
}

typedef void (*enter_t)(
    void* stack, void* dynv, syscall_callback_t callback);

typedef struct entry_args
{
    enter_t enter;
    void* stack;
    uint64_t* dynv;
    long (*syscall)(long n, long params[6]);
}
entry_args_t;

#define USE_LTHREADS

void _entry_thread(void* args_)
{
#ifdef USE_LTHREADS
    lthread_detach();
#endif

    /* jumps here from _syscall() on SYS_exit */
    if (setjmp(_exit_jmp_buf) != 0)
    {
#ifdef USE_LTHREADS
        lthread_exit(NULL);
#endif
        return;
    }

#if 0
    long params[6] = { 0 };
    _syscall(SYS_exit, params);
#endif

    entry_args_t* args = (entry_args_t*)args_;
    (*args->enter)(args->stack, args->dynv, args->syscall);
}

static int _enter_crt(void)
{
    extern void* __oe_get_isolated_image_entry_point(void);
    extern const void* __oe_get_isolated_image_base();

    enter_t enter = __oe_get_isolated_image_entry_point();
    assert(enter);

    const void* base = __oe_get_isolated_image_base();
    const Elf64_Ehdr* ehdr = base;
    void* stack;
    void* sp = NULL;
    const size_t stack_size = 64 * PAGE_SIZE;

    /* Extract program-header related info */
    const uint8_t* phdr = (const uint8_t*)base + ehdr->e_phoff;
    size_t phnum = ehdr->e_phnum;
    size_t phentsize = ehdr->e_phentsize;

    const char* argv[] = { "arg0", ARGV0, "arg2", NULL };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    const char* envp[] = { "ENV0=zero", "ENV1=one", "ENV2=two", NULL };
    size_t envc = sizeof(envp) / sizeof(envp[0]) - 1;

    if (!(stack = elf_make_stack(argc, argv, envc, envp,
        stack_size, base, ehdr, phdr, phnum, phentsize,
        enter, &sp)))
    {
        fprintf(stderr, "_make_stack() failed\n");
        assert(false);
    }

    assert(elf_check_stack(stack, stack_size) == 0);

    /* Find the dynamic vector */
    uint64_t* dynv = NULL;
    {
        const uint8_t* p = phdr;

        for (int i = 0; i < phnum; i++)
        {
            const Elf64_Phdr* ph = (const Elf64_Phdr*)p;

            if (ph->p_type == PT_DYNAMIC)
            {
                dynv = (uint64_t*)((uint8_t*)base + ph->p_vaddr);
                break;
            }

            p += phentsize;
        }
    }

    if (!dynv)
    {
        printf("dynv not found\n");
        assert(false);
    }

    assert(elf_check_stack(stack, stack_size) == 0);

    /* Run the main program */
    {
        static entry_args_t args;
        args.enter = enter;
        args.stack = sp;
        args.dynv = dynv;
        args.syscall = oel_syscall;

#ifdef USE_LTHREADS
        lthread_t* lt;
        lthread_create(&lt, _entry_thread, &args);
        lthread_run();
#else
        _entry_thread(&args);
#endif
    }

    assert(elf_check_stack(stack, stack_size) == 0);
    free(stack);

    return oel_get_exit_status();
}

int run_ecall(void)
{
    const size_t MMAN_SIZE = 16 * 1024 * 1024;

    if (oel_setup_mman(MMAN_SIZE) != 0)
    {
        fprintf(stderr, "_setup_mman() failed\n");
        assert(false);
    }

    _setup_hostfs();

    int ret = _enter_crt();

    _teardown_hostfs();
    oel_teardown_mman();

    printf("ret=%d\n", ret);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    4);   /* NumTCS */
