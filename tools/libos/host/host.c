// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/bits/sgx/region.h>
#include <libos/elf.h>
#include <libos/round.h>
#include <libos/trace.h>
#include <libos/eraise.h>
#include <libos/round.h>
#include <libos/strings.h>
#include <stdio.h>
#include <libgen.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <cpuid.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libos/cpio.h>
#include "libos_u.h"
#include "../shared.h"
#include "debug_image.h"

static char _arg0[PATH_MAX];

#define MEGABYTE (1024UL * 1024UL)

static size_t _mman_size = (64 * MEGABYTE);

__attribute__((format(printf, 1, 2)))
static void _err(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", _arg0);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    exit(1);
}

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

static int _which(const char* program, char buf[PATH_MAX])
{
    int ret = -1;
    char path[PATH_MAX];

    if (buf)
        *buf = '\0';

    if (!program || !buf)
        goto done;

    /* If the program has slashes the use realpath */
    if (strchr(program, '/'))
    {
        char current[PATH_MAX];

        if (!realpath(program, current))
            goto done;

        if (access(current, X_OK) == 0)
        {
            strcpy(buf, current);
            ret = 0;
            goto done;
        }

        goto done;
    }

    /* Get the PATH environment variable */
    {
        const char* p;

        if (!(p = getenv("PATH")) || strlen(p) >= PATH_MAX)
            goto done;

        strcpy(path, p);
    }

    /* Search the PATH for the program */
    {
        char* p;
        char* save;

        for (p = strtok_r(path, ":", &save); p; p = strtok_r(NULL, ":", &save))
        {
            char current[PATH_MAX];
            int n;

            n = snprintf(current, sizeof(current), "%s/%s", p, program);
            if (n >= sizeof(current))
                goto done;

            if (access(current, X_OK) == 0)
            {
                strcpy(buf, current);
                ret = 0;
                goto done;
            }
        }
    }

    /* not found */

done:
    return ret;
}

static int _load_file(const char* path, void** data_out, size_t* size_out)
{
    int ret = -1;
    FILE* is = NULL;
    void* data = NULL;
    size_t size;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    /* Check parameters */
    if (!path || !data_out || !size_out)
        goto done;

    /* Get size of this file */
    {
        struct stat buf;

        if (stat(path, &buf) != 0)
            goto done;

        size = buf.st_size;
    }

    /* Allocate memory */
    if (!(data = malloc(size)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(data, 1, size, is) != size)
        goto done;

    *size_out = size;
    *data_out = data;
    data = NULL;
    ret = 0;

done:

    if (data)
        free(data);

    if (is)
        fclose(is);

    return ret;
}

static int _get_opt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    size_t olen = strlen(opt);

    if (optarg)
        *optarg = NULL;

    if (!opt)
        _err("unexpected");


    for (int i = 0; i < *argc; )
    {
        if (strcmp(argv[i], opt) == 0)
        {
            if (optarg)
            {
                if (i + 1 == *argc)
                    _err("%s: missing option argument", opt);

                *optarg = argv[i+1];
                memmove(&argv[i], &argv[i+2], (*argc - i - 1) * sizeof(char*));
                (*argc) -= 2;
                return 0;
            }
            else
            {
                memmove(&argv[i], &argv[i+1], (*argc - i) * sizeof(char*));
                (*argc)--;
                return 0;
            }
        }
        else if (strncmp(argv[i], opt, olen) == 0 && argv[i][olen] == '=')
        {
            if (!optarg)
                _err("%s: extraneous '='", opt);

            *optarg = &argv[i][olen + 1];
            memmove(&argv[i], &argv[i+1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return 0;
        }
        else
        {
            i++;
        }
    }

    /* Not found! */
    return -1;
}

static elf_image_t _crt_image;
static char _crt_path[PATH_MAX];

static void* _rootfs_data = NULL;
static size_t _rootfs_size;

static int _exec(int argc, const char* argv[])
{
    oe_result_t r;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    oe_enclave_t* enclave;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    int retval;
    char dir[PATH_MAX];
    char libosenc[PATH_MAX];
    char liboscrt[PATH_MAX];
    void* args = NULL;
    size_t args_size;
    struct libos_options options;

    assert(strcmp(argv[1], "exec") == 0);

    /* Get options */
    {
        /* Get --trace-syscalls option */
        if (_get_opt(&argc, argv, "--trace-syscalls", NULL) == 0 ||
            _get_opt(&argc, argv, "--strace", NULL) == 0)
        {
            options.trace_syscalls = true;
        }

        /* Get --real-syscalls option */
        if (_get_opt(&argc, argv, "--real-syscalls", NULL) == 0)
            options.real_syscalls = true;
    }

    if (options.real_syscalls)
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s %s <rootfs> <program> <args...>\n",
            argv[0], argv[1]);
        return 1;
    }

    const char* rootfs = argv[2];
    const char* program = argv[3];

    if (_load_file(rootfs, &_rootfs_data, &_rootfs_size) != 0)
        _err("failed to load load rootfs: %s", rootfs);

    if (program[0] != '/')
        _err("program must be an absolute path: %s", program);

    /* Get the directory that contains argv[0] */
    strcpy(dir, _arg0);
    dirname(dir);

    /* Find libosenc.so and liboscrt.so */
    {
        int n;

        n = snprintf(libosenc, sizeof(libosenc), "%s/enc/libosenc.so", dir);
        if (n >= sizeof libosenc)
            _err("buffer overflow when forming libosenc.so path");

        n = snprintf(liboscrt, sizeof(liboscrt), "%s/enc/liboscrt.so", dir);
        if (n >= sizeof liboscrt)
            _err("buffer overflow when forming liboscrt.so path");

        if (access(libosenc, R_OK) != 0)
            _err("cannot find: %s", libosenc);

        if (access(liboscrt, R_OK) != 0)
            _err("cannot find: %s", liboscrt);
    }

    /* Load the C runtime ELF image into memory */
    if (elf_image_load(liboscrt, &_crt_image) != 0)
        _err("failed to load C runtime image: %s", liboscrt);

    if (LIBOS_STRLCPY(_crt_path, liboscrt) >= sizeof(_crt_path))
        _err("path is too long: %s", liboscrt);

    /* Load the enclave: calls oe_region_add_regions() */
    r = oe_create_libos_enclave(libosenc, type, flags, NULL, 0, &enclave);
    if (r != OE_OK)
        _err("failed to load enclave: result=%s", oe_result_str(r));

    /* Serialize the argv[] strings */
    if (_serialize_args(argv + 3, &args, &args_size) != 0)
        _err("failed to serialize argv srings");

    const char env[] = "PATH=/bin\0HOME=/root";

    /* Enter the enclave and run the program */
    r = libos_enter_ecall(
        enclave,
        &retval,
        &options,
        args,
        args_size,
        env,
        sizeof(env));
    if (r != OE_OK)
        _err("failed to enter enclave: result=%s", oe_result_str(r));

    /* Terminate the enclave */
    r = oe_terminate_enclave(enclave);
    if (r != OE_OK)
        _err("failed to terminate enclave: reuslt=%s", oe_result_str(r));

    free(args);
    free(_rootfs_data);
    elf_image_free(&_crt_image);

    return retval;
}

static int _mkcpio(int argc, const char* argv[])
{
    assert(strcmp(argv[1], "mkcpio") == 0);

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s %s <directory> <cpioarchive>\n",
            argv[0], argv[1]);
        return 1;
    }

    const char* directory = argv[2];
    const char* cpioarchive = argv[3];

    if (libos_cpio_pack(directory, cpioarchive) != 0)
    {
        _err("failed to create CPIO archive from %s: %s", directory, cpioarchive);
        return 1;
    }

    return 0;
}

static int _excpio(int argc, const char* argv[])
{
    assert(strcmp(argv[1], "excpio") == 0);

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s %s <cpioarchive> <directory>\n",
            argv[0], argv[1]);
        return 1;
    }

    const char* cpioarchive = argv[2];
    const char* directory = argv[3];

    if (libos_cpio_unpack(cpioarchive, directory) != 0)
    {
        _err("failed to extract CPIO archive to %s: %s", directory, cpioarchive);
        return 1;
    }

    return 0;
}

_Static_assert(sizeof(struct libos_timespec) == sizeof(struct timespec), "");

int libos_clock_gettime_ocall(int clk_id, struct libos_timespec* tp)
{
    if (clock_gettime(clk_id, (struct timespec*)tp) != 0)
        return -errno;

    return 0;
}

long libos_syscall_isatty_ocall(int fd)
{
    if (isatty(fd) != 1)
        return -errno;

    return 1;
}

void libos_rdtsc_ocall(uint32_t* rax, uint32_t* rdx)
{
    uint32_t hi;
    uint32_t lo;

    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));

    *rax = lo;
    *rdx = hi;
}

void libos_cpuid_ocall(
    uint32_t leaf,
    uint32_t subleaf,
    uint32_t* rax,
    uint32_t* rbx,
    uint32_t* rcx,
    uint32_t* rdx)
{
    if (rax)
        *rax = 0;

    if (rbx)
        *rbx = 0;

    if (rcx)
        *rcx = 0;

    if (rdx)
        *rdx = 0;

    __cpuid_count(leaf, subleaf, *rax, *rbx, *rcx, *rdx);
}

static int _write_file(int fd, const void* data, size_t size)
{
    int ret = 0;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;
    ssize_t n;

    if (fd < 0 || !data)
        ERAISE(-EINVAL);

    while (r > 0)
    {
        if ((n = write(fd, p, r)) == 0)
            break;

        if (n < 0)
            ERAISE(-errno);

        p += n;
        r -= (size_t)n;
    }

    if (r != 0)
        ERAISE(-EIO);

done:
    return ret;
}

#define MAX_DEBUG_IMAGES 256

static oe_debug_image_t _debug_images[MAX_DEBUG_IMAGES];
static bool _debug_images_loaded[MAX_DEBUG_IMAGES];
static size_t _num_debug_images;

int libos_add_symbol_file_ocall(
    const void* file_data,
    size_t file_size,
    const void* text_data,
    size_t text_size)
{
    int ret = -1;
    int fd = -1;
    char template[] = "/tmp/libosXXXXXX";
    oe_debug_image_t di;

    if (!file_data || !file_size || !text_data || !text_size)
        ERAISE(-EINVAL);

    /* Create a file containing the data */
    {
        if ((fd = mkstemp(template)) <  0)
            goto done;

        ECHECK(_write_file(fd, file_data, file_size));

        close(fd);
        fd = -1;
    }

    /* Add new debug image to the table */
    {
        if (_num_debug_images == MAX_DEBUG_IMAGES)
            ERAISE(-ENOMEM);

        if (!(di.path = strdup(template)))
            ERAISE(-ENOMEM);

        di.magic = OE_DEBUG_IMAGE_MAGIC;
        di.version = 1;
        di.path_length = strlen(di.path);
        di.base_address = (uint64_t)text_data;
        di.size = text_size;
        _debug_images[_num_debug_images++] = di;
    }

    ret = 0;

done:

    if (fd > 0)
        close(fd);

    return ret;
}

OE_EXPORT
OE_NEVER_INLINE
void oe_notify_debugger_library_load(oe_debug_image_t* image)
{
    OE_UNUSED(image);
}

OE_EXPORT
OE_NEVER_INLINE
void oe_notify_debugger_library_unload(oe_debug_image_t* image)
{
    OE_UNUSED(image);
}

oe_result_t oe_debug_notify_library_loaded(oe_debug_image_t* image)
{
    oe_notify_debugger_library_load(image);
    return OE_OK;
}

oe_result_t oe_debug_notify_library_unloaded(oe_debug_image_t* image)
{
    oe_notify_debugger_library_unload(image);
    return OE_OK;
}

int libos_load_symbols_ocall(void)
{
    int ret = 0;

    for (size_t i = 0; i < _num_debug_images; i++)
    {
        if (!_debug_images_loaded[i])
        {
            oe_debug_image_t* di = &_debug_images[i];
            oe_debug_notify_library_loaded(di);
            _debug_images_loaded[i] = true;
        }
    }

    return ret;
}

int libos_unload_symbols_ocall(void)
{
    int ret = 0;

    for (size_t i = 0; i < _num_debug_images; i++)
    {
        oe_debug_image_t* di = &_debug_images[i];
        oe_debug_notify_library_unloaded(di);
        unlink(di->path);
        free(di->path);
    }

    return ret;
}

#define USAGE "\
\n\
Usage: %s <action> [options] ...\n\
\n\
Where <action> is one of:\n\
    exec   -- execute an application within the libos\n\
    mkcpio -- create a CPIO archive from a directory\n\
    excpio -- extract the CPIO archive into a directory\n\
\n\
"

int main(int argc, const char* argv[])
{
    if (argc <  2)
    {
        fprintf(stderr, USAGE, argv[0]);
        return 1;
    }

    /* Get the full path of argv[0] */
    if (_which(argv[0], _arg0) != 0)
    {
        fprintf(stderr, "%s: failed to get full path of argv[0]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "exec") == 0)
    {
        return _exec(argc, argv);
    }
    else if (strcmp(argv[1], "mkcpio") == 0)
    {
        return _mkcpio(argc, argv);
    }
    else if (strcmp(argv[1], "excpio") == 0)
    {
        return _excpio(argc, argv);
    }
    else
    {
        _err("unknown action: %s", argv[1]);
        return 1;
    }
}

/* ATTN: use common header */
#define PAGE_SIZE 4096

static int _add_segment_pages(
    oe_region_context_t* context,
    const elf_segment_t* segment,
    const void* image_base,
    uint64_t vaddr)
{
    int ret = 0;
    uint64_t page_vaddr = libos_round_down_to_page_size(segment->vaddr);
    uint64_t segment_end = segment->vaddr + segment->memsz;

    for (; page_vaddr < segment_end; page_vaddr += PAGE_SIZE)
    {
        const uint64_t dest_vaddr = vaddr + page_vaddr;
        const void* page = (uint8_t*)image_base + page_vaddr;
        uint64_t flags = SGX_SECINFO_REG;
        const bool extend = true;

        if (segment->flags & PF_R)
            flags |= SGX_SECINFO_R;

        if (segment->flags & PF_W)
            flags |= SGX_SECINFO_W;

        if (segment->flags & PF_X)
            flags |= SGX_SECINFO_X;

        if (oe_region_add_page(
            context,
            dest_vaddr,
            page,
            flags,
            extend) != OE_OK)
        {
            ERAISE(-EINVAL);
        }
    }

    ret = 0;

done:
    return ret;
}

static int _load_crt_pages(
    oe_region_context_t* context,
    elf_image_t* image,
    uint64_t vaddr)
{
    int ret = 0;

    if (!context || !image)
        ERAISE(-EINVAL);

    assert((image->image_size & (PAGE_SIZE - 1)) == 0);

    /* Add the program segments first */
    for (size_t i = 0; i < image->num_segments; i++)
    {
        ECHECK(_add_segment_pages(
            context,
            &image->segments[i],
            image->image_data,
            vaddr));
    }

    ret = 0;

done:
    return ret;
}

static int _add_crt_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    assert(_crt_image.image_data != NULL);
    assert(_crt_image.image_size != 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, CRT_REGION_ID, true, _crt_path) != OE_OK)
        ERAISE(-EINVAL);

    ECHECK(_load_crt_pages(context, &_crt_image, *vaddr));

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

    *vaddr += libos_round_up_to_page_size(_crt_image.image_size);

done:
    return ret;
}

static int _add_crt_reloc_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const bool is_elf = true;
    assert(_crt_image.reloc_data != NULL);
    assert(_crt_image.reloc_size != 0);
    assert((_crt_image.reloc_size % PAGE_SIZE) == 0);

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, CRT_RELOC_REGION_ID, is_elf, NULL) != OE_OK)
        ERAISE(-EINVAL);

    /* Add the pages */
    {
        const uint8_t* page = (const uint8_t*)_crt_image.reloc_data;
        size_t npages = _crt_image.reloc_size / PAGE_SIZE;

        for (size_t i = 0; i < npages; i++)
        {
            const bool extend = true;

            if (oe_region_add_page(
                context,
                *vaddr,
                page,
                SGX_SECINFO_REG | SGX_SECINFO_R,
                extend) != OE_OK)
            {
                ERAISE(-EINVAL);
            }

            page += PAGE_SIZE;
            (*vaddr) += PAGE_SIZE;
        }
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _add_rootfs_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    const uint8_t* p = _rootfs_data;
    size_t n = _rootfs_size;
    size_t r = n;

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    assert(_rootfs_data != NULL);
    assert(_rootfs_size != 0);

    if (oe_region_start(context, ROOTFS_REGION_ID, false, NULL) != OE_OK)
        ERAISE(-EINVAL);

    while (r)
    {
        __attribute__((__aligned__(4096)))
        uint8_t page[LIBOS_PAGE_SIZE];
        const bool extend = true;
        const size_t min = (r < sizeof(page)) ? r : sizeof(page);

        memcpy(page, p, min);

        if (min < sizeof(page))
            memset(page + r, 0, sizeof(page) - r);

        if (oe_region_add_page(
            context,
            *vaddr,
            page,
            SGX_SECINFO_REG | SGX_SECINFO_R,
            extend) != OE_OK)
        {
            ERAISE(-EINVAL);
        }

        *vaddr += sizeof(page);
        p += min;
        r -= min;
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

static int _add_mman_region(oe_region_context_t* context, uint64_t* vaddr)
{
    int ret = 0;
    __attribute__((__aligned__(4096)))
    uint8_t page[LIBOS_PAGE_SIZE];
    const size_t mman_pages = _mman_size / LIBOS_PAGE_SIZE;

    if (!context || !vaddr)
        ERAISE(-EINVAL);

    if (oe_region_start(context, MMAN_REGION_ID, false, NULL) != OE_OK)
        ERAISE(-EINVAL);

    memset(page, 0, sizeof(page));

    /* Add the leading guard page */
    {
        const bool extend = true;

        if (oe_region_add_page(
            context,
            *vaddr,
            page,
            SGX_SECINFO_REG,
            extend) != OE_OK)
        {
            ERAISE(-EINVAL);
        }

        *vaddr += sizeof(page);
    }

    for (size_t i = 0; i < mman_pages; i++)
    {
        const bool extend = false;

        if (oe_region_add_page(
            context,
            *vaddr,
            page,
            SGX_SECINFO_REG|SGX_SECINFO_R|SGX_SECINFO_W|SGX_SECINFO_X,
            extend) != OE_OK)
        {
            ERAISE(-EINVAL);
        }

        *vaddr += sizeof(page);
    }

    /* Add the trailing guard page */
    {
        const bool extend = true;

        if (oe_region_add_page(
            context,
            *vaddr,
            page,
            SGX_SECINFO_REG,
            extend) != OE_OK)
        {
            ERAISE(-EINVAL);
        }

        *vaddr += sizeof(page);
    }

    if (oe_region_end(context) != OE_OK)
        ERAISE(-EINVAL);

done:
    return ret;
}

oe_result_t oe_region_add_regions(oe_region_context_t* context, uint64_t vaddr)
{
    if (_add_crt_region(context, &vaddr) != 0)
        _err("_add_crt_region() failed");

    if (_add_crt_reloc_region(context, &vaddr) != 0)
        _err("_add_crt_reloc_region() failed");

    if (_add_rootfs_region(context, &vaddr) != 0)
        _err("_add_rootfs_region() failed");

    if (_add_mman_region(context, &vaddr) != 0)
        _err("_add_mman_region() failed");

    return OE_OK;
}
