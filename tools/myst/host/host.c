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
#include <myst/paths.h>
#include <myst/round.h>
#include <myst/spinlock.h>
#include <myst/strings.h>
#include <myst/tcall.h>
#include <myst/trace.h>
#include <openenclave/host.h>

#include "../shared.h"
#include "cpio.h"
#include "dump.h"
#include "exec.h"
#include "exec_linux.h"
#include "myst_u.h"
#include "oe_debug_module.h"
#include "package.h"
#include "regions.h"
#include "sign.h"
#include "utils.h"

/* forward declarations of OE internal APIs */
void oe_debug_module_loaded_hook(oe_debug_module_t* module);
void oe_debug_module_unloaded_hook(oe_debug_module_t* module);

_Static_assert(sizeof(struct myst_timespec) == sizeof(struct timespec), "");

typedef struct debug_module
{
    oe_debug_module_t base;
    struct debug_module* next;
    char __buf[PATH_MAX];
} debug_module_t;

/* Modules that have been registered with the debugger. Each time a module is
   registered, it is added to the front of the list. This list is maintained
   in the same order that the debugger receives notifications. This allows the
   debugger to efficiently sync in case _debug_modules and the debugger's own
   list go out of sync.  */
static debug_module_t* _debug_modules;

/* List of modules yet to be registered with the debugger. The modules in this
   list are removed one by one and then registered with the debugger and
   prepended to the _debug_modules list.  */
static debug_module_t* _debug_modules_pending;
static myst_spinlock_t _modules_lock;

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

oe_result_t oe_debug_notify_library_loaded(oe_debug_module_t* module)
{
    oe_debug_module_loaded_hook(module);
    return OE_OK;
}

oe_result_t oe_debug_notify_library_unloaded(oe_debug_module_t* module)
{
    oe_debug_module_unloaded_hook(module);
    return OE_OK;
}

long myst_add_symbol_file_by_path(
    const char* path,
    const void* text_data,
    size_t text_size)
{
    long ret = 0;
    debug_module_t* di = NULL;
    void* data = NULL;
    bool notify = true;

    myst_spin_lock(&_modules_lock);
    if (!path || !text_data || !text_size)
        ERAISE(-EINVAL);

    /* Add new debug image to the table */
    {
        if (!(di = calloc(1, sizeof(debug_module_t))))
            ERAISE(-ENOMEM);

        if (myst_strlcpy(di->__buf, path, sizeof(di->__buf)) >=
            sizeof(di->__buf))
            ERAISE(-ENAMETOOLONG);

        di->base.magic = OE_DEBUG_MODULE_MAGIC;
        di->base.version = 1;
        di->base.path = di->__buf;
        di->base.path_length = strlen(di->base.path);
        di->base.base_address = text_data;
        di->base.size = text_size;

        if (notify)
        {
            /* notify gdb to load the symbols */
            oe_debug_notify_library_loaded(&di->base);

            /* add to the front of the list */
            di->next = _debug_modules;
            _debug_modules = di;
        }
        else
        {
            /* add to the front of the pending list */
            di->next = _debug_modules_pending;
            _debug_modules_pending = di;
        }

        di = NULL;
    }

done:
    myst_spin_unlock(&_modules_lock);
    if (di)
        free(di);

    if (data)
        free(data);

    return ret;
}

long init_symbol_file_tmpdir(char* tmpdir)
{
    long ret = 0;

    if (!mkdtemp(tmpdir))
        ERAISE(errno);
    ECHECK(chmod(tmpdir, 0750));

done:
    return ret;
}

long myst_tcall_add_symbol_file(
    const void* file_data,
    size_t file_size,
    const void* text_data,
    size_t text_size,
    const char* enclave_rootfs_path)
{
    long ret = 0;
    int fd = -1;
    static char tmpdir[PATH_MAX] = "/tmp/mystXXXXXX";
    static int tmpdir_init = 0;
    char tmp[PATH_MAX];
    debug_module_t* di = NULL;
    void* data = NULL;
    bool notify = false;

    myst_spin_lock(&_modules_lock);
    if (!text_data || !text_size || (!file_data && file_size))
        ERAISE(-EINVAL);

    if (!tmpdir_init)
    {
        ECHECK(init_symbol_file_tmpdir(tmpdir));
        tmpdir_init = 1;
    }

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

        /* Create a file containing the data */
        {
            if (snprintf(tmp, PATH_MAX, "%s/%s", tmpdir, "libmystcrt") >=
                PATH_MAX)
            {
                ERAISE(-ENAMETOOLONG);
            }
            if ((fd = creat(tmp, 0750)) < 0)
                goto done;
        }
    }
    else
    {
        /* Preserve file name from enclave rootfs */
        char dirname[PATH_MAX];
        char imagename[PATH_MAX];
        myst_split_path(
            enclave_rootfs_path, dirname, PATH_MAX, imagename, PATH_MAX);
        if (snprintf(tmp, PATH_MAX, "%s/%s", tmpdir, imagename) >= PATH_MAX)
        {
            ERAISE(-ENAMETOOLONG);
        }

        if ((fd = creat(tmp, 0750)) < 0)
            goto done;
    }

    /* Write the contents of the image to file */
    {
        ECHECK(myst_write_file_fd(fd, file_data, file_size));

        close(fd);
        fd = -1;
    }

    /* Add new debug image to the table */
    {
        if (!(di = calloc(1, sizeof(debug_module_t))))
            ERAISE(-ENOMEM);

        if (myst_strlcpy(di->__buf, tmp, sizeof(di->__buf)) >=
            sizeof(di->__buf))
            ERAISE(-ENAMETOOLONG);

        di->base.magic = OE_DEBUG_MODULE_MAGIC;
        di->base.version = 1;
        di->base.path = di->__buf;
        di->base.path_length = strlen(di->base.path);
        di->base.base_address = (const void*)text_data;
        di->base.size = text_size;

        if (notify)
        {
            /* notify gdb to load the symbols */
            oe_debug_notify_library_loaded(&di->base);

            /* add to the front of the list */
            di->next = _debug_modules;
            _debug_modules = di;
        }
        else
        {
            /* add to the front of the pending list */
            di->next = _debug_modules_pending;
            _debug_modules_pending = di;
        }

        di = NULL;
    }

done:
    myst_spin_unlock(&_modules_lock);

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
    size_t text_size,
    const char* enclave_rootfs_path)
{
    return (int)myst_tcall_add_symbol_file(
        file_data, file_size, text_data, text_size, enclave_rootfs_path);

    return 0;
}

long myst_tcall_load_symbols(void)
{
    int ret = 0;

    myst_spin_lock(&_modules_lock);

    debug_module_t* next;
    for (debug_module_t* p = _debug_modules_pending; p; p = next)
    {
        next = p->next;

        oe_debug_notify_library_loaded(&p->base);

        p->next = _debug_modules;
        _debug_modules = p;
    }
    _debug_modules_pending = NULL;

    myst_spin_unlock(&_modules_lock);

    return ret;
}

int myst_load_symbols_ocall(void)
{
    return myst_tcall_load_symbols();
}

long myst_tcall_unload_symbols(void)
{
    long ret = 0;

    myst_spin_lock(&_modules_lock);

    for (debug_module_t* p = _debug_modules; p;)
    {
        debug_module_t* next = p->next;

        oe_debug_notify_library_unloaded(&p->base);

        /* avoid unloading libmystkernel.so */
        if (strncmp(p->base.path, "/tmp/", 5) == 0)
            unlink(p->base.path);

        free(p);

        p = next;
    }

    myst_spin_unlock(&_modules_lock);
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
    exec-sgx      -- execute an application from within a root file system\n\
                     inside an SGX enclave\n\
    exec-linux    -- execute an application from within a root file system\n\
                     in a untrusted environment environment (Linux)\n\
    mkcpio        -- create a CPIO archive from an application directory\n\
    mkext2        -- create an EXT2 image from an application directory\n\
    fssig         -- dump the file system signature of an EXT2 image\n\
    excpio        -- extract the CPIO archive into an application directory\n\
    sign-sgx      -- sign the CPIO archive along with configuration and\n\
                     system files into a directory for the SGX platform\n\
    package-sgx   -- create an executable package to run on the SGX platform\n\
                     from an application directory, package configuration and\n\
                     system files, signing and measuring all enclave resident\n\
                     pieces during in the process\n\
    dump-sgx      -- dump the SGX enclave configuration along with the\n\
                     packaging configuration from an SGX packaged executable\n\
    fsgsbase      -- tests whether the FSGSBASE instructions are supported\n\
\n\
"

static int _main(int argc, const char* argv[], const char* envp[])
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
    else if (strcmp(argv[1], "fsgsbase") == 0)
    {
        extern int fsgsbase_action(int argc, const char* argv[]);
        return fsgsbase_action(argc, argv);
    }
    else
    {
        fprintf(stderr, USAGE, argv[0]);
        return 1;
    }
}

int main(int argc, const char* argv[], const char* envp[])
{
#ifdef MYST_ENABLE_GCOV
    const char* uid_str = getenv("SUDO_UID");
    const char* gid_str = getenv("SUDO_GID");
    uid_t uid = UINT_MAX;
    gid_t gid = UINT_MAX;

    /* if running as SUDO, then save the uid and gid */
    if (uid_str && gid_str)
    {
        uid = atoi(uid_str);
        gid = atoi(gid_str);
    }
#endif

    int ec = _main(argc, argv, envp);

#ifdef MYST_ENABLE_GCOV
    /* if running as SUDO, then restore uid and gid for gcov */
    if (uid_str && gid_str)
    {
        setgid(gid);
        setegid(gid);
        setuid(uid);
        seteuid(uid);
    }
#endif

    return ec;
}
