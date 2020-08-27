#include <libos/kernel.h>
#include <libos/crash.h>
#include <libos/syscall.h>
#include <libos/mmanutils.h>
#include <libos/assert.h>
#include <libos/eraise.h>
#include <libos/errno.h>
#include <libos/strings.h>
#include <libos/ramfs.h>
#include <libos/mount.h>
#include <libos/file.h>
#include <libos/cpio.h>
#include <libos/elfutils.h>
#include <libos/malloc.h>
#include <libos/crash.h>

static libos_kernel_args_t* _args;

static libos_fs_t* _fs;

long libos_tcall(long n, long params[6])
{
    return (*_args->tcall)(n, params);
}

static int _setup_ramfs(void)
{
    int ret = 0;

    if (libos_init_ramfs(&_fs) != 0)
    {
        libos_eprintf("failed initialize the RAM files system\n");
        ERAISE(-EINVAL);
    }

    if (libos_mount(_fs, "/") != 0)
    {
        libos_eprintf("failed create the / directory\n");
        ERAISE(-EINVAL);
    }

    if (libos_mkdir("/tmp", 777) != 0)
    {
        libos_eprintf("failed create the /tmp directory\n");
        ERAISE(-EINVAL);
    }

    if (libos_mkdirhier("/proc/self/fd", 777) != 0)
    {
        libos_eprintf("failed create the /proc/self/fd directory\n");
        ERAISE(-EINVAL);
    }

    if (libos_mkdirhier("/usr/local/etc", 777) != 0)
    {
        libos_eprintf("failed create the /usr/local/etc directory\n");
        ERAISE(-EINVAL);
    }

done:
    return ret;
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
    int ret = 0;
    int fd = -1;

    if (!path || !data || !size)
        ERAISE(-EINVAL);

    if ((fd = libos_open(path, O_WRONLY | O_CREAT, 0444)) < 0)
        ERAISE(-EINVAL);

    ECHECK(libos_ramfs_set_buf(_fs, path, data, size));

    ret = 0;

done:

    if (fd >= 0)
        libos_close(fd);

    return ret;
}

static int _teardown_ramfs(void)
{
    if ((*_fs->fs_release)(_fs) != 0)
    {
        libos_eprintf("failed to release ramfs\n");
        return -1;
    }

    return 0;
}

int libos_enter_kernel(libos_kernel_args_t* args)
{
    int ret = 0;
    const char rootfs_path[] = "/tmp/rootfs.cpio";

    /* Check arguments */
    {
        if (!args)
        {
            libos_eprintf("kernel: bad args\n");
            ERAISE(-EINVAL);
        }

        if (!args->argc || !args->argv)
        {
            libos_eprintf("kernel: bad argc/argv arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->envc || !args->envp)
        {
            libos_eprintf("kernel: bad envc/envp arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->mman_data || !args->mman_size)
        {
            libos_eprintf("kernel: bad mman arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->rootfs_data || !args->rootfs_size)
        {
            libos_eprintf("kernel: bad rootfs arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->crt_data || !args->crt_size)
        {
            libos_eprintf("kernel: bad crt arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->tcall)
        {
            libos_eprintf("kernel: bad tcall argument\n");
            ERAISE(-EINVAL);
        }
    }

    /* Save the aguments */
    _args = args;

    /* Set the tracing flags */
    libos_trace_syscalls(args->trace_syscalls);
    libos_real_syscalls(args->real_syscalls);

    /* Setup the memory manager */
    if (libos_setup_mman(args->mman_data, args->mman_size) != 0)
    {
        libos_eprintf("kernel: memory manageger setup failed\n");
        ERAISE(-EINVAL);
    }

    /* Setup the RAM file system */
    if (_setup_ramfs() != 0)
    {
        ERAISE(-EINVAL);
    }

    /* Create a temporary file containing the root file system */
    {
        if (_create_cpio_file(
            rootfs_path,
            args->rootfs_data,
            args->rootfs_size) != 0)
        {
            libos_eprintf("kernel: failed to create: %s\n", rootfs_path);
            ERAISE(-EINVAL);
        }

        if (libos_access(rootfs_path, R_OK) != 0)
        {
            libos_eprintf("kernel: failed to create: %s\n", rootfs_path);
            ERAISE(-EINVAL);
        }
    }

    /* Unpack the root file system */
    if (libos_cpio_unpack(rootfs_path, "/") != 0)
    {
        libos_eprintf("failed to unpack: %s\n", rootfs_path);
        ERAISE(-EINVAL);
    }

    /* Enter the C runtime (which enters the application) */
    ret = elf_enter_crt(
        args->crt_data,
        args->argc,
        args->argv,
        args->envc,
        args->envp);

    /* Tear down the RAM file system */
    _teardown_ramfs();

    /* Check for memory leaks */
    if (libos_find_leaks() != 0)
        libos_crash();

done:
    return ret;
}
