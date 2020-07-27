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
#include <limits.h>
#include "./syscall.h"
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

#define MMAN_SIZE (16 * 1024 * 1024)

typedef long (*syscall_callback_t)(long n, long params[6]);

extern oel_mman_t g_oel_mman;

extern void* _mman_start;
extern void* _mman_end;

//#define ARGV0 "/root/sgx-lkl/samples/basic/helloworld/app/helloworld"
#define ARGV0 "/root/oe-libos/build/bin/samples/split/main"

static uint8_t GUARD_CHAR = 0xAA;

static int _check_guard(const void* p)
{
    for (size_t i = 0; i < PAGE_SIZE; i++)
    {
        if (((uint8_t*)p)[i] != GUARD_CHAR)
            return -1;
    }

    return 0;
}

static void _dump(uint8_t* p, size_t n)
{
    while (n--)
        printf("%02X", *p++);

    printf("\n");
}

#if 0
static void _write_file(const char* path, const void* data, size_t size)
{
    int fd;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;
    ssize_t n;

    if ((fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0666)) < 0)
    {
        fprintf(stderr, "open failed: %s\n", path);
        exit(1);
    }

    while ((n = write(fd, p, r)) > 0)
    {
        p += n;
        r -= n;
    }

    if (r != 0)
    {
        fprintf(stderr, "write failed: %s\n", path);
        exit(1);
    }

    close(fd);
}
#endif

extern jmp_buf _exit_jmp_buf;
extern int _exit_status;

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

    return _exit_status;
}

static int _setup_mman(oel_mman_t* mman, size_t size)
{
    int ret = -1;
    void* base;
    void* ptr;

    /* Allocate aligned pages */
    if (!(ptr = memalign(OE_PAGE_SIZE, PAGE_SIZE + size + PAGE_SIZE)))
        goto done;

    base = ptr + PAGE_SIZE;

    _mman_start = base;
    _mman_end = base + size;

    /* Set the guard pages */
    memset(_mman_start - PAGE_SIZE, GUARD_CHAR, PAGE_SIZE);
    memset(_mman_end, GUARD_CHAR, PAGE_SIZE);

    if (oel_mman_init(mman, (uintptr_t)base, size) != OE_OK)
        goto done;

    mman->scrub = true;

    oel_mman_set_sanity(mman, true);

    ret = 0;

done:
    return ret;
}

static int _teardown_mman(oel_mman_t* mman)
{
    assert(oel_mman_is_sane(&g_oel_mman));

    /* Check the start guard page */
    if (_check_guard(_mman_start - PAGE_SIZE) != 0)
    {
        fprintf(stderr, "bad mman start guard page\n");
        _dump(_mman_start - PAGE_SIZE, PAGE_SIZE);
        assert(false);
    }

    /* Check the end guard page */
    if (_check_guard(_mman_end) != 0)
    {
        fprintf(stderr, "bad mman end guard page\n");
        _dump(_mman_end, PAGE_SIZE);
        assert(false);
    }

    free((void*)mman->base - PAGE_SIZE);
}

int run_ecall(void)
{
    if (_setup_mman(&g_oel_mman, MMAN_SIZE) != 0)
    {
        fprintf(stderr, "_setup_mman() failed\n");
        assert(false);
    }

    _setup_hostfs();

    int ret = _enter_crt();

    _teardown_hostfs();
    _teardown_mman(&g_oel_mman);

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
