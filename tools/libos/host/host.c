// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <cpuid.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <libos/cpio.h>
#include <libos/elf.h>
#include <libos/eraise.h>
#include <libos/file.h>
#include <libos/getopt.h>
#include <libos/round.h>
#include <libos/strings.h>
#include <libos/tcall.h>
#include <libos/trace.h>
#include <openenclave/bits/sgx/region.h>
#include <openenclave/host.h>

#include "../shared.h"
#include "cpio.h"
#include "debug_image.h"
#include "exec.h"
#include "exec_linux.h"
#include "libos_u.h"
#include "package.h"
#include "sign.h"
#include "utils.h"

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

#define MAX_DEBUG_IMAGES 256

static oe_debug_image_t _debug_images[MAX_DEBUG_IMAGES];
static bool _debug_images_loaded[MAX_DEBUG_IMAGES];
static size_t _num_debug_images;

long libos_tcall_add_symbol_file(
    const void* file_data,
    size_t file_size,
    const void* text_data,
    size_t text_size)
{
    long ret = -1;
    int fd = -1;
    char template[] = "/tmp/libosXXXXXX";
    oe_debug_image_t di;

    if (!file_data || !file_size || !text_data || !text_size)
        ERAISE(-EINVAL);

    /* Create a file containing the data */
    {
        if ((fd = mkstemp(template)) < 0)
            goto done;

        ECHECK(libos_write_file_fd(fd, file_data, file_size));

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

int libos_add_symbol_file_ocall(
    const void* file_data,
    size_t file_size,
    const void* text_data,
    size_t text_size)
{
    return (int)libos_tcall_add_symbol_file(
        file_data, file_size, text_data, text_size);
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

long libos_tcall_load_symbols(void)
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

int libos_load_symbols_ocall(void)
{
    return libos_tcall_load_symbols();
}

long libos_tcall_unload_symbols(void)
{
    long ret = 0;

    for (size_t i = 0; i < _num_debug_images; i++)
    {
        oe_debug_image_t* di = &_debug_images[i];
        oe_debug_notify_library_unloaded(di);
        unlink(di->path);
        free(di->path);
    }

    return ret;
}

int libos_unload_symbols_ocall(void)
{
    return libos_tcall_unload_symbols();
}

#define USAGE \
    "\
\n\
Usage: %s <action> [options] ...\n\
\n\
Where <action> is one of:\n\
    exec   -- execute an application within the libos\n\
    mkcpio -- create a CPIO archive from a directory\n\
    excpio -- extract the CPIO archive into a directory\n\
    sign   -- sign the platform application and root filesystem\n\
\n\
"

int main(int argc, const char* argv[], const char* envp[])
{
    if (set_program_file(argv[0]) == NULL)
    {
        fprintf(stderr, "%s: failed to get full path of argv[0]\n", argv[0]);
        return 1;
    }

    setenv("AZDCAP_DEBUG_LOG_LEVEL", "0", 1);

    // First check to see if we are executing a packaged process
    const char* executable;
    executable = strrchr(argv[0], '/');
    if (executable == NULL)
    {
        executable = argv[0];
    }
    if (*executable == '/')
    {
        executable++;
    }
    if (strcmp(executable, "libos") != 0)
    {
        return _exec_package(argc, argv, envp);
    }

    if (argc < 2)
    {
        fprintf(stderr, USAGE, argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "exec") == 0 || strcmp(argv[1], "exec-sgx") == 0)
    {
        return exec_action(argc, argv, envp);
    }
    else if (strcmp(argv[1], "exec-linux") == 0)
    {
        return exec_linux_action(argc, argv, envp);
    }
    else if (strcmp(argv[1], "mkcpio") == 0)
    {
        return _mkcpio(argc, argv);
    }
    else if (strcmp(argv[1], "excpio") == 0)
    {
        return _excpio(argc, argv);
    }
    else if (strcmp(argv[1], "sign") == 0)
    {
        return _sign(argc, argv);
    }
    else if (strcmp(argv[1], "package") == 0)
    {
        return _package(argc, argv, envp);
    }
    else
    {
        _err("unknown action: %s", argv[1]);
        return 1;
    }
}
