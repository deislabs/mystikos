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
#include <setjmp.h>

#define MMAN_SIZE (16 * 1024 * 1024)

typedef long (*syscall_callback_t)(long n, long params[6]);

static oel_mman_t _mman;

static void* _mman_start;
static void* _mman_end;

//#define ARGV0 "/root/sgx-lkl/samples/basic/helloworld/app/helloworld"
#define ARGV0 "/root/oe-libos/build/bin/samples/split/main"

static void _set_fs_base(const void* p)
{
    __asm__ volatile("wrfsbase %0" ::"r"(p));
}

static void* _get_fs_base(void)
{
    void* p;
    __asm__ volatile("mov %%fs:0, %0" : "=r"(p));
    return p;
}

static const void* _original_fs_base;

static void _dump(uint8_t* p, size_t n)
{
    while (n--)
        printf("%02X", *p++);

    printf("\n");
}

static void* _make_stack(
    size_t stack_size,
    const void* base,
    const void* ehdr,
    const void* phdr,
    size_t phnum,
    size_t phentsize,
    const void* entry,
    void** sp)
{
    void* ret = NULL;
    void* stack = NULL;

    if (sp)
        *sp = NULL;

    /* The stack must be a multiple of the page size */
    if (stack_size % PAGE_SIZE)
        goto done;

    if (!(stack = memalign(PAGE_SIZE, stack_size)))
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
            .a_un.a_val = PAGE_SIZE,
        },
        {
            .a_type = AT_NULL,
            .a_un.a_val = 0,
        },
    };
    size_t auxc = sizeof(auxv) / sizeof(auxv[0]) - 1;

    if (elf_init_stack(
        argc, argv, envc, envp, auxc, auxv, stack, stack_size, sp) != 0)
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

static jmp_buf _exit_jmp_buf;
static int _exit_status;

#define TRACE_SYSCALLS

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
        elf_dump_stack((void*)params[0]);
    }
    else if (n == OEL_SYS_dump_ehdr)
    {
        elf_dump_ehdr((void*)params[0]);
    }
    else if (n == SYS_set_thread_area)
    {
        if (!_original_fs_base)
            _original_fs_base = _get_fs_base();

        _set_fs_base((void*)params[0]);

        return 0;
    }
    else if (n == SYS_set_tid_address)
    {
        return 0;
    }
    else if (n == SYS_open)
    {
#ifdef TRACE_SYSCALLS
        const char* path = (const char*)x1;
        int flags = (int)x2;
        int mode = (int)x3;

        fprintf(stderr,
            "=== %s(path=%s flags=%d mode=%03o)\n",
            syscall_str(n), path, flags, mode);
#endif

        return _forward_syscall(n, params);
    }
    else if (n == SYS_read)
    {
        return _forward_syscall(n, params);
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

#ifdef TRACE_SYSCALLS
        fprintf(
            stderr,
            "=== %s(addr=%lX length=%lu prot=%d flags=%d fd=%d offset=%lu)\n",
            syscall_str(n), (long)addr, length, prot, flags, fd, offset);
#endif

        if (fd >= 0 && addr)
        {
            ssize_t n;

            if ((n = _map_file_onto_memory(fd, addr, length)) < 0)
                return -1L;

            void* end = addr + length;
            assert(addr >= _mman_start && addr <= _mman_end);
            assert(end >= _mman_start && end <= _mman_end);

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

        void* end = ptr + length;
        assert(ptr >= _mman_start && ptr <= _mman_end);
        assert(end >= _mman_start && end <= _mman_end);
        return (long)ptr;
    }
    else if (n == SYS_mprotect)
    {
#ifdef TRACE_SYSCALLS
        const void* addr = (void*)x1;
        const size_t length = (size_t)x2;
        const int prot = (int)x3;

        fprintf(stderr,
            "=== %s(addr=%lX length=%zu prot=%d)\n",
            syscall_str(n), (uint64_t)addr, length, prot);
#endif

        return 0;
    }
    else if (n == SYS_exit)
    {
        const int status = (int)x1;

        /* restore original fs base, else stack smashing will be detected */
        _set_fs_base(_original_fs_base);

#ifdef TRACE_SYSCALLS
        printf("=== SYS_exit(status=%d)\n", status);
#endif

        _exit_status = status;
        longjmp(_exit_jmp_buf, 1);
    }
    else
    {
        return _forward_syscall(n, params);
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

    if (!(stack = _make_stack(stack_size, base, ehdr, phdr, phnum, phentsize,
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
        args.syscall = _syscall;

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

    memset(ptr, 0x6E, PAGE_SIZE);

    base = ptr + PAGE_SIZE;

    _mman_start = base;
    _mman_end = base + size;

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
    assert(oel_mman_is_sane(&_mman));

#if 0
    _dump((void*)mman->base - PAGE_SIZE, PAGE_SIZE);
#endif

    free((void*)mman->base - PAGE_SIZE);
}

int run_ecall(void)
{
    if (_setup_mman(&_mman, MMAN_SIZE) != 0)
    {
        fprintf(stderr, "_setup_mman() failed\n");
        assert(false);
    }

    _setup_hostfs();

    int ret = _enter_crt();

    _teardown_hostfs();
    _teardown_mman(&_mman);

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
