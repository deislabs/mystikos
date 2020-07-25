// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
    AT_SYSINFO_EHDR=7ffebe5c8000
    AT_HWCAP=bfebfbff
    AT_PAGESZ=1000
    AT_CLKTCK=64
    AT_PHDR=560102ecb040
    AT_PHENT=38
    AT_PHNUM=9
    AT_BASE=7fd6d9d47000
    AT_FLAGS=0
    AT_ENTRY=560102ecb930
    AT_UID=0
    AT_EUID=0
    AT_GID=0
    AT_EGID=0
    AT_SECURE=0
    AT_RANDOM=7ffebe5aa159
    AT_HWCAP2=0
    AT_EXECFN=7ffebe5abff1
    AT_PLATFORM=7ffebe5aa169
*/

#include <openenclave/enclave.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "syscallutils.h"
#include <sys/mount.h>
#include "run_t.h"
#include "elfutils.h"

typedef long (*syscall_callback_t)(long n, long params[6]);

#define ARGV0 "/root/sgx-lkl/samples/basic/helloworld/app/helloworld"

static void* _make_stack(
    size_t stack_size,
    const void* base,
    const void* ehdr,
    const void* phdr,
    size_t phnum,
    size_t phentsize,
    const void* entry)
{
    void* ret = NULL;
    void* stack = NULL;

    if (!(stack = memalign(16, stack_size)))
        goto done;

    const char* argv[] = { ARGV0, ARGV0, "arg2", NULL };
    int argc = sizeof(argv) / sizeof(argv[0]) - 1;
    const char* envp[] = { "ENV0=zero", "ENV1=one", "ENV2=two", NULL };
    size_t envc = sizeof(envp) / sizeof(envp[0]) - 1;
    const Elf64_auxv_t auxv[] =
    {
        {
            .a_type = AT_BASE,
            .a_un.a_val = (uint64_t)base,
        },
        {
            .a_type = AT_SYSINFO_EHDR,
            .a_un.a_val = (uint64_t)ehdr,
        },
        {
            .a_type = AT_PHDR,
            .a_un.a_val = (uint64_t)phdr,
        },
        {
            .a_type = AT_PHNUM,
            .a_un.a_val = (uint64_t)phnum,
        },
        {
            .a_type = AT_PHENT,
            .a_un.a_val = (uint64_t)phentsize,
        },
        {
            .a_type = AT_ENTRY,
            .a_un.a_val = (uint64_t)entry,
        },
        {
            .a_type = AT_PAGESZ,
            .a_un.a_val = 4096,
        },
        {
            .a_type = AT_NULL,
            .a_un.a_val = 0,
        },
    };
    size_t auxc = sizeof(auxv) / sizeof(auxv[0]) - 1;

    if (elf_init_stack(
        argc, argv, envc, envp, auxc, auxv, stack, stack_size) != 0)
    {
        goto done;
    }

    ret = stack;
    stack = NULL;

done:

    if (stack)
        free(stack);

    return ret;
}

static long _forward_syscall(long n, long params[6])
{
    extern long oe_syscall(long n, long x1, long x2, long x3, long x4,
        long x5, long x6);
    long x1 = params[0];
    long x2 = params[1];
    long x3 = params[2];
    long x4 = params[3];
    long x5 = params[4];
    long x6 = params[5];
    long ret;

    return oe_syscall(n, x1, x2, x3, x4, x5, x6);
}

static long _syscall(long n, long params[6])
{
    long x1 = params[0];
    long x2 = params[1];
    long x3 = params[2];
    long x4 = params[3];
    long x5 = params[4];
    long x6 = params[5];

    if (n == 1000)
    {
        printf("trace: %s\n", (const char*)params[0]);
    }
    else if (n == 1001)
    {
        printf("trace: %s: %p %ld\n",
            (const char*)params[0], (void*)params[1], params[1]);
    }
    else if (n == SYS_set_thread_area)
    {
        void* p = (void*)params[0];
        __asm__ volatile("wrfsbase %0" ::"r"(p));
        return 0;
    }
    else if (n == SYS_set_tid_address)
    {
        return 0;
    }
    else if (n == SYS_open)
    {
        printf("open(%s)\n", (char*)x1);

        long ret = _forward_syscall(n, params);

        printf("open.ret=%ld\n", ret);

        return ret;
    }
    else if (n == SYS_read)
    {
        printf("read(fd=%ld, buf=%p, count=%ld)\n", x1, (void*)x2, x3);

        long ret = _forward_syscall(n, params);

        printf("ret=%ld\n", ret);

        return ret;
    }
    else if (n == SYS_close)
    {
        printf("close(%ld)\n", x1);

        long ret = _forward_syscall(n, params);

        printf("ret=%ld\n", ret);

        return ret;
    }
    else
    {
        printf("********** uknown syscall: %s\n", syscall_str(n));

        long ret = _forward_syscall(n, params);

        printf("********** ret=%ld\n", ret);

        return ret;
    }
}

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

static void _enter_crt(void)
{
    extern void* __oe_get_isolated_image_entry_point(void);
    extern const void* __oe_get_isolated_image_base();
    typedef void (*enter_t)(
        void* stack, void* dynv, syscall_callback_t callback);

    enter_t enter = __oe_get_isolated_image_entry_point();
    assert(enter);

    _setup_hostfs();

    const void* base = __oe_get_isolated_image_base();
    const Elf64_Ehdr* ehdr = base;
    void* stack;
    const size_t stack_size = 256 * 1024;

    /* Extract program-header related info */
    const uint8_t* phdr = (const uint8_t*)base + ehdr->e_phoff;
    size_t phnum = ehdr->e_phnum;
    size_t phentsize = ehdr->e_phentsize;

    if (!(stack = _make_stack(stack_size, base, ehdr, phdr, phnum, phentsize,
        enter)))
    {
        printf("_make_stack() failed\n");
        assert(false);
    }

    elf_dump_stack(stack);

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

    (*enter)(stack, dynv, _syscall);

    free(stack);
}

int run_ecall(void)
{
    _enter_crt();
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    2);   /* NumTCS */
