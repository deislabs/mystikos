// Copyright (c) Microsoft Corporation.
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

#include <myst/cpio.h>
#include <myst/elf.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/getopt.h>
#include <myst/round.h>
#include <myst/strings.h>
#include <myst/tcall.h>
#include <myst/trace.h>
#include <openenclave/bits/sgx/region.h>
#include <openenclave/host.h>

#include "../shared.h"
#include "cpio.h"
#include "debug_image.h"
#include "dump.h"
#include "exec.h"
#include "exec_linux.h"
#include "myst_u.h"
#include "package.h"
#include "regions.h"
#include "sign.h"
#include "utils.h"

_Static_assert(sizeof(struct myst_timespec) == sizeof(struct timespec), "");

typedef struct debug_image debug_image_t;

struct debug_image
{
    oe_debug_image_t base;
    debug_image_t* next;
    char buf[PATH_MAX];
    bool loaded;
};

static debug_image_t* _debug_images;

long myst_syscall_isatty_ocall(int fd)
{
    if (isatty(fd) != 1)
        return -errno;

    return 1;
}

void myst_rdtsc_ocall(uint32_t* rax, uint32_t* rdx)
{
    uint32_t hi;
    uint32_t lo;

    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));

    *rax = lo;
    *rdx = hi;
}

void myst_cpuid_ocall(
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

long myst_tcall_add_symbol_file(
    const void* file_data,
    size_t file_size,
    const void* text_data,
    size_t text_size)
{
    long ret = 0;
    int fd = -1;
    char tmp[] = "/tmp/mystXXXXXX";
    debug_image_t* di = NULL;
    void* data = NULL;
    bool notify = false;

    if (!text_data || !text_size || (!file_data && file_size))
        ERAISE(-EINVAL);

    /* assume libmystcrt if no file data */
    if (!file_data)
    {
        char path[PATH_MAX];

        ECHECK(format_libmystcrt(path, sizeof path));

        if (access(path, R_OK) == 0)
        {
            ECHECK(myst_load_file(path, &data, &file_size));
            file_data = data;
        }
        else
        {
            const region_details* rd = get_region_details();
            file_data = rd->crt.buffer;
            file_size = rd->crt.buffer_size;
        }

        notify = true;
    }

    /* Create a file containing the data */
    {
        if ((fd = mkstemp(tmp)) < 0)
            goto done;

        ECHECK(myst_write_file_fd(fd, file_data, file_size));

        close(fd);
        fd = -1;
    }

    /* Add new debug image to the table */
    {
        if (!(di = calloc(1, sizeof(debug_image_t))))
            ERAISE(-ENOMEM);

        if (myst_strlcpy(di->buf, tmp, sizeof(di->buf)) >= sizeof(di->buf))
            ERAISE(-ENAMETOOLONG);

        di->base.magic = OE_DEBUG_IMAGE_MAGIC;
        di->base.version = 1;
        di->base.path = di->buf;
        di->base.path_length = strlen(di->base.path);
        di->base.base_address = (uint64_t)text_data;
        di->base.size = text_size;

        if (notify)
        {
            /* notify gdb to load the symbols */
            oe_debug_notify_library_loaded(&di->base);
            di->loaded = true;
        }

        /* add to the front of the list */
        di->next = _debug_images;
        _debug_images = di;
        di = NULL;
    }

done:

    if (di)
        free(di);

    if (data)
        free(data);

    if (fd > 0)
        close(fd);

    return ret;
}

int myst_add_symbol_file_ocall(
    const void* file_data,
    size_t file_size,
    const void* text_data,
    size_t text_size)
{
    return (int)myst_tcall_add_symbol_file(
        file_data, file_size, text_data, text_size);

    return 0;
}

long myst_tcall_load_symbols(void)
{
    int ret = 0;

    for (debug_image_t* p = _debug_images; p; p = p->next)
    {
        if (!p->loaded)
        {
            oe_debug_notify_library_loaded(&p->base);
            p->loaded = true;
        }
    }

    return ret;
}

int myst_load_symbols_ocall(void)
{
    return myst_tcall_load_symbols();
}

long myst_tcall_unload_symbols(void)
{
    long ret = 0;

    for (debug_image_t* p = _debug_images; p;)
    {
        debug_image_t* next = p->next;

        oe_debug_notify_library_unloaded(&p->base);
        unlink(p->base.path);
        free(p);

        p = next;
    }

    return ret;
}

int myst_unload_symbols_ocall(void)
{
    return myst_tcall_unload_symbols();
}

#define USAGE \
    "\
\n\
Usage: %s <action> [options] ...\n\
\n\
Where <action> is one of:\n\
    exec-sgx      -- execute an application from within the CPIO\n\
                     archive inside an SGX enclave\n\
    exec-linux    -- execute an application within the CPIO archive in a none\n\
                     trusted environment environment (Linux)\n\
    mkcpio        -- create a CPIO archive from an application directory\n\
    excpio        -- extract the CPIO archive into an application directory\n\
    sign-sgx      -- sign the CPIO archive along with configuration and system\n\
                     files into a directory for the SGX platform\n\
    package-sgx   -- create an executable package to run on the SGX platform\n\
                     from an application directory, package configuration and\n\
                     system files, signing and measuring all enclave resident\n\
                     pieces during in the process\n\
    dump-sgx      -- dump the SGX enclave configuration along with the\n\
                     packaging configuration from an SGX packaged executable\n\
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
    if (strcmp(executable, "myst") != 0)
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
    else if (strcmp(argv[1], "dump") == 0 || strcmp(argv[1], "dump-sgx") == 0)
    {
        return dump_action(argc, argv, envp);
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
    else if (
        (strcmp(argv[1], "sign") == 0) || (strcmp(argv[1], "sign-sgx") == 0))
    {
        return _sign(argc, argv);
    }
    else if (
        (strcmp(argv[1], "package") == 0) ||
        (strcmp(argv[1], "package-sgx") == 0))
    {
        return _package(argc, argv, envp);
    }
    else if (strcmp(argv[1], "mkext2") == 0)
    {
        extern int mkext2_action(int argc, const char* argv[]);
        return mkext2_action(argc, argv);
    }
    else if (strcmp(argv[1], "fssig") == 0)
    {
        extern int fssig_action(int argc, const char* argv[]);
        return fssig_action(argc, argv);
    }
    else
    {
        fprintf(stderr, USAGE, argv[0]);
        return 1;
    }
}

size_t oe_get_num_stack_pages_hook(size_t tcs_index)
{
    const size_t num_main_stack_pages = 16;
    const size_t num_child_stack_pages = 2;

    if (tcs_index == 0)
        return num_main_stack_pages;
    else
        return num_child_stack_pages;
}
