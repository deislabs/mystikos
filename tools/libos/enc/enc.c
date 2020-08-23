// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/bits/sgx/region.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/mount.h>
#include <libos/syscall.h>
#include <stdlib.h>
#include <libos/mmanutils.h>
#include <libos/eraise.h>
#include <libos/elfutils.h>
#include <libos/ramfs.h>
#include <libos/mount.h>
#include <libos/file.h>
#include <libos/cpio.h>
#include <libos/trace.h>
#include "libos_t.h"
#include "../shared.h"

extern int oe_host_printf(const char* fmt, ...);

static int _deserialize_args(
    const void* args,
    size_t args_size,
    const char* argv[],
    size_t argv_size)
{
    int ret = -1;
    size_t n = 0;
    const char* p = (const char*)args;
    const char* end = (const char*)args + args_size;

    while (p != end)
    {
        if (n == argv_size)
            goto done;

        argv[n++] = p;
        p += strlen(p) + 1;
    }

    argv[n] = NULL;
    ret = 0;

done:
    return ret;
}

static size_t _count_args(const char* args[])
{
    size_t n = 0;

    for (size_t i = 0; args[i]; i++)
        n++;

    return n;
}

#if 0
static void _dump_args(const char* args[])
{
    printf("args=%p\n", args);
    for (int i = 0; args[i]; i++)
        printf("args[%d]=%s\n", i, args[i]);
}
#endif

static libos_fs_t* _fs;

static void _setup_ramfs(void)
{
    if (libos_init_ramfs(&_fs) != 0)
    {
        fprintf(stderr, "failed to initialize the ramfs\n");
        abort();
    }

    if (libos_mount(_fs, "/") != 0)
    {
        fprintf(stderr, "failed to mount ramfs\n");
        abort();
    }

    if (libos_mkdir("/tmp", 777) != 0)
    {
        fprintf(stderr, "failed create the /tmp directory\n");
        abort();
    }

    if (libos_mkdirhier("/proc/self/fd", 777) != 0)
    {
        fprintf(stderr, "failed create the /proc/self/fd directory\n");
        abort();
    }

    if (libos_mkdirhier("/usr/local/etc", 777) != 0)
    {
        fprintf(stderr, "failed create the /usr/local/etc directory\n");
        abort();
    }
}

static void _teardown_ramfs(void)
{
    if ((*_fs->fs_release)(_fs) != 0)
    {
        fprintf(stderr, "failed to release ramfs\n");
        abort();
    }
}

static void _setup_sockets(void)
{
    if (oe_load_module_host_socket_interface() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_socket_interface() failed\n");
        assert(0);
    }
}

ssize_t _writen(int fd, const void* data, size_t size)
{
    int ret = -1;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n;

        if ((n = libos_write(fd, p, r)) <= 0)
        {
            goto done;
        }

        p += n;
        r -= (size_t)n;
    }

    ret = 0;

done:
    return ret;
}

static int _create_cpio_file(const char* path, const char* data, size_t size)
{
    int ret = -1;
    int fd = -1;

    if (!path || !data || !size)
        goto done;

    if ((fd = libos_open(path, O_WRONLY | O_CREAT, 0666)) < 0)
        goto done;

    if (_writen(fd, data, size) != 0)
        goto done;

    ret = 0;

done:

    if (fd >= 0)
        libos_close(fd);

    return ret;
}

static void _apply_relocations(
    const void* image_base,
    size_t image_size,
    const void* reloc_base,
    size_t reloc_size)
{
    const Elf64_Rela* relocs = (const Elf64_Rela*)reloc_base;
    size_t nrelocs = reloc_size / sizeof(Elf64_Rela);
    const uint8_t* baseaddr = (const uint8_t*)image_base;

    for (size_t i = 0; i < nrelocs; i++)
    {
        const Elf64_Rela* p = &relocs[i];

        /* If zero-padded bytes reached */
        if (p->r_offset == 0)
            break;

        assert(p->r_offset > 0);
        assert(p->r_offset <= image_size);

        /* Compute address of reference to be relocated */
        uint64_t* dest = (uint64_t*)(baseaddr + p->r_offset);

        uint64_t reloc_type = ELF64_R_TYPE(p->r_info);

        /* Relocate the reference */
        if (reloc_type == R_X86_64_RELATIVE)
        {
            *dest = (uint64_t)(baseaddr + p->r_addend);
        }
    }
}

/* Handle illegal SGX instructions */
static uint64_t _vectored_handler(oe_exception_record_t* er)
{
    const uint16_t RDTSC_OPCODE = 0x310F;
    const uint16_t opcode = *((uint16_t*)er->context->rip);

    if (er->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION && opcode == RDTSC_OPCODE)
    {
        uint32_t rax = 0;
        uint32_t rdx = 0;

        /* Ask host to execute RDTSC instruction */
        if (libos_rdtsc_ocall(&rax, &rdx) != OE_OK)
        {
            fprintf(stderr, "libos_rdtsc_ocall() failed\n");
            assert(false);
            return OE_EXCEPTION_CONTINUE_SEARCH;
        }

        er->context->rax = rax;
        er->context->rdx = rdx;

        /* Skip over the illegal instruction. */
        er->context->rip += 2;

        return OE_EXCEPTION_CONTINUE_EXECUTION;
    }

    return OE_EXCEPTION_CONTINUE_SEARCH;
}

int libos_enter_ecall(
    struct libos_options* options,
    const void* args,
    size_t args_size,
    const void* env,
    size_t env_size)
{
    int ret = -1;
    const char* argv[64];
    size_t argv_size = sizeof(argv) / sizeof(argv[0]);
    const char* envp[64];
    size_t envp_size = sizeof(envp) / sizeof(envp[0]);
    const char rootfs_path[] = "/tmp/rootfs.cpio";
    const void* crt_image_base;
    size_t crt_image_size;
    const void* rootfs_data;
    size_t rootfs_size;

    if (!args || !args_size || !env || !env_size)
        goto done;

    if (_deserialize_args(args, args_size, argv + 1, argv_size - 1) != 0)
        goto done;

    if (_deserialize_args(env, env_size, envp, envp_size) != 0)
        goto done;

    argv[0] = "libosenc.so";

    if (options)
    {
        libos_trace_syscalls(options->trace_syscalls);
        libos_real_syscalls(options->real_syscalls);
    }

#ifdef TRACE
    _dump_args(argv);
    _dump_args(envp);
#endif

    /* Setup the memory manager */
    {
        void* mman_data;
        size_t mman_size;
        {
            extern const void* __oe_get_enclave_base(void);
            oe_region_t region;
            const uint8_t* enclave_base;

            if (!(enclave_base = __oe_get_enclave_base()))
            {
                fprintf(stderr, "__oe_get_enclave_base() failed\n");
                assert(0);
            }

            if (oe_region_get(MMAN_REGION_ID, &region) != OE_OK)
            {
                fprintf(stderr, "failed to get crt region\n");
                assert(0);
            }

            mman_data = (void*)(enclave_base + region.vaddr);
            mman_size = region.size;
        }

        if (libos_setup_mman(mman_data, mman_size) != 0)
        {
            fprintf(stderr, "_setup_mman() failed\n");
            assert(0);
        }
    }

    /* Setup the vectored exception handler */
    if (oe_add_vectored_exception_handler(true, _vectored_handler) != OE_OK)
    {
        fprintf(stderr, "oe_add_vectored_exception_handler() failed\n");
        assert(0);
    }

    /* Setup the RAM file system */
    _setup_ramfs();

    /* Fetch the rootfs image */
    {
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

        if (oe_region_get(ROOTFS_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        rootfs_data = enclave_base + region.vaddr;
        rootfs_size = region.size;
    }

    if (_create_cpio_file(rootfs_path, rootfs_data, rootfs_size) != 0)
    {
        fprintf(stderr, "failed to create %s\n", rootfs_path);
        assert(0);
    }

    assert(libos_access(rootfs_path, R_OK) == 0);

    /* unpack the cpio archive */
    {
        const bool trace = libos_get_trace();

        libos_set_trace(false);

        if (libos_cpio_unpack(rootfs_path, "/") != 0)
        {
            fprintf(stderr, "failed to unpack: %s\n", rootfs_path);
            assert(0);
        }

        libos_set_trace(trace);
    }

    /* Set up the standard directories (some may already exist) */
    {
        libos_set_trace(false);
        libos_mkdir("/tmp", 777);
        libos_mkdir("/proc", 777);
        libos_mkdir("/proc/self", 777);
        libos_mkdir("/proc/self/fd", 777);
        libos_set_trace(true);
    }

    _setup_sockets();

    /* Find the base address of the C runtime ELF image */
    {
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

        if (oe_region_get(CRT_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        crt_image_base = enclave_base + region.vaddr;
        crt_image_size = region.size;
    }

    /* Apply relocations to the crt image */
    {
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

        if (oe_region_get(CRT_RELOC_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        _apply_relocations(
            crt_image_base,
            crt_image_size,
            enclave_base + region.vaddr,
            region.size);
    }

    const size_t argc = _count_args(argv);
    const size_t envc = _count_args(envp);
    ret = elf_enter_crt(crt_image_base, argc, argv, envc, envp);

    _teardown_ramfs();
    libos_teardown_mman();

done:
    return ret;
}

_Static_assert(sizeof(struct libos_timespec) == sizeof(struct timespec), "");

/* ATTN: replace this with clock ticks implementation */
/* This overrides the weak version in liboskernel.a */
long libos_syscall_clock_gettime(clockid_t clk_id, struct timespec* tp_)
{
    int retval = -1;
    struct libos_timespec* tp = (struct libos_timespec*)tp_;

    if (libos_clock_gettime_ocall(&retval, clk_id, tp) != OE_OK)
        return -EINVAL;

    return (long)retval;
}

/* This overrides the weak version in liboskernel.a */
long libos_syscall_add_symbol_file(
    const char* path,
    const void* text,
    size_t text_size)
{
    long ret = 0;
    void* file_data = NULL;
    size_t file_size;
    int retval;

    if (!path || !text || !text_size)
        ERAISE(-EINVAL);

    ECHECK(libos_load_file(path, &file_data, &file_size));

    if (libos_add_symbol_file_ocall(&retval, file_data, file_size, text,
        text_size) != OE_OK)
    {
        ERAISE(-EINVAL);
    }

done:

    if (file_data)
        free(file_data);

    return ret;
}

/* This overrides the weak version in liboskernel.a */
long libos_syscall_load_symbols(void)
{
    long ret = 0;
    int retval;

    if (libos_load_symbols_ocall(&retval) != OE_OK || retval != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

/* This overrides the weak version in liboskernel.a */
long libos_syscall_unload_symbols(void)
{
    long ret = 0;
    int retval;

    if (libos_unload_symbols_ocall(&retval) != OE_OK || retval != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

/* This overrides the weak version in liboskernel.a */
long libos_syscall_isatty(int fd)
{
    long ret;

    if (libos_syscall_isatty_ocall(&ret, fd) != OE_OK)
        return -EINVAL;

    return (long)ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    8*4096, /* NumHeapPages */
    1024, /* NumStackPages */
    4);   /* NumTCS */
