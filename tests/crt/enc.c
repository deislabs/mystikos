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
#include <oel/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <lthread.h>

#define MMAN_SIZE (16 * 1024 * 1024)

typedef long (*syscall_callback_t)(long n, long params[6]);

static oel_mman_t _mman;

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

    if (!(stack = memalign(4096, stack_size)))
        goto done;

    const char* argv[] = { "arg0", ARGV0, "arg2", NULL };
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

static ssize_t _map_file_onto_memory(int fd, void* data, size_t size)
{
    ssize_t ret = -1;
    ssize_t bytes_read = 0;
    off_t save_pos;

    if (fd < 0 || !data || !size)
        goto done;

    /* save the current file position */
    if ((save_pos = lseek(fd, 0, SEEK_CUR)) == (off_t)-1)
        goto done;

    /* seek start of file */
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
        goto done;

    /* read file onto memory */
    {
        char buf[BUFSIZ];
        ssize_t n;
        uint8_t* p = data;
        size_t r = size;

        while ((n = read(fd, buf, sizeof buf)) > 0)
        {
            /* if copy would write past end of data */
            if (r < n)
                goto done;

            memcpy(p, buf, n);
            p += n;
            bytes_read += n;
        }
    }

    /* restore the file position */
    if (lseek(fd, save_pos, SEEK_SET) == (off_t)-1)
        goto done;

    ret = bytes_read;

done:
    return ret;
}

static long _syscall(long n, long params[6])
{
    long x1 = params[0];
    long x2 = params[1];
    long x3 = params[2];
    long x4 = params[3];
    long x5 = params[4];
    long x6 = params[5];

    if (n == OEL_SYS_trace)
    {
        printf("trace: %s\n", (const char*)params[0]);
    }
    else if (n == OEL_SYS_trace_ptr)
    {
        printf("trace: %s: %lX %ld\n",
            (const char*)params[0], params[1], params[1]);
    }
    else if (n == OEL_SYS_dump_stack)
    {
        printf("syscall: OEL_SYS_dump_stack\n");

        elf_dump_stack((void*)params[0]);
    }
    else if (n == OEL_SYS_dump_ehdr)
    {
        printf("syscall: OEL_SYS_dump_ehdr\n");

        elf_dump_ehdr((void*)params[0]);
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
        printf("open(path=%s flags=%d mode=%03o)\n",
            (char*)x1, (int)x2, (int)x3);
        long ret = _forward_syscall(n, params);
        printf("open.ret=%ld\n", ret);

        return ret;
    }
    else if (n == SYS_read)
    {
        // printf("read(fd=%ld, buf=%p, count=%ld)\n", x1, (void*)x2, x3);
        long ret = _forward_syscall(n, params);
        // printf("ret=%ld\n", ret);

        return ret;
    }
    else if (n == SYS_writev)
    {
        return _forward_syscall(n, params);
    }
    else if (n == SYS_close)
    {
        // printf("close(%ld)\n", x1);
        long ret = _forward_syscall(n, params);
        // printf("ret=%ld\n", ret);

        return ret;
    }
    else if (n == SYS_mmap)
    {
        void* addr = (void*)x1;
        size_t length = (size_t)x2;
        int prot = (int)x3;
        int flags = (int)x4;
        int fd = (int)x5;
        off_t offset = (off_t)x6;
        void* ptr = (void*)-1;

        printf("=== SYS_mmap:\n");
        printf("addr=%lX\n", (long)addr);
        printf("length=%lu\n", length);
        printf("prot=%d\n", prot);
        printf("flags=%d\n", flags);
        printf("fd=%d\n", fd);
        printf("offset=%lu\n", offset);

        if (fd >= 0 && addr)
        {
            ssize_t n;

            if ((n = _map_file_onto_memory(fd, addr, length)) < 0)
                return -1L;

            return (long)addr;
        }

        int tflags = OEL_MAP_ANONYMOUS | OEL_MAP_PRIVATE;

        if (oel_mman_map(&_mman, addr, length, prot, tflags, &ptr) != 0)
        {
            printf("oel_mman_map: error: %s\n", _mman.err);
            return -1L;
        }

        if (fd >= 0 && !addr)
        {
            ssize_t n;

            if ((n = _map_file_onto_memory(fd, ptr, length)) < 0)
            {
                return -1L;
            }
        }

        return (long)ptr;
    }
    else if (n == SYS_mprotect)
    {
#if 0
        void* addr = (void*)x1;
        size_t length = (size_t)x2;
        int prot = (int)x3;

        printf("=== SYS_mprotect:\n");
        printf("addr=%p\n", addr);
        printf("length=%lu\n", length);
        printf("prot=%d\n", prot);
#endif
        return 0;
    }
    else
    {
        // fprintf(stderr, "********** uknown syscall: %s\n", syscall_str(n));

        long ret = _forward_syscall(n, params);

        // fprintf(stderr, "********** ret=%ld\n", ret);

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

void _entry_thread(void* args_)
{
    entry_args_t* args = (entry_args_t*)args_;

    (*args->enter)(args->stack, args->dynv, args->syscall);
}

static void _enter_crt(void)
{
    extern void* __oe_get_isolated_image_entry_point(void);
    extern const void* __oe_get_isolated_image_base();

    enter_t enter = __oe_get_isolated_image_entry_point();
    assert(enter);

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

#if 1
    elf_dump_stack(stack);
#endif

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

    static entry_args_t args;
    args.enter = enter;
    args.stack = stack;
    args.dynv = dynv;
    args.syscall = _syscall;

#if 1
    (*enter)(stack, dynv, _syscall);
#else
    lthread_t* lt;
    lthread_create(&lt, _entry_thread, &args);
    lthread_run();
#endif

    free(stack);
}

static int _setup_mman(oel_mman_t* mman, size_t size)
{
    int ret = -1;
    void* base;

    /* Allocate aligned pages */
    if (!(base = memalign(OE_PAGE_SIZE, size)))
        goto done;

    if (oel_mman_init(mman, (uintptr_t)base, size) != OE_OK)
        goto done;

    mman->scrub = true;

    oel_mman_set_sanity(mman, true);

    ret = 0;

done:
    return ret;
}

int run_ecall(void)
{
    if (_setup_mman(&_mman, MMAN_SIZE) != 0)
    {
        fprintf(stderr, "_setup_mman() failed\n");
        assert(false);
    }

    _setup_hostfs();
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
