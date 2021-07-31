// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <myst/tcall.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

ssize_t myst_tcall_get_file_size(const char* pathname)
{
    ssize_t ret = 0;
    int fd = -1;
    size_t size = 0;
    char buf[1024];

    if (!pathname)
        return -EINVAL;

    /* try to obtain size with stat() (virtual files will show as zero-sized) */
    {
        struct stat statbuf;

        if (stat(pathname, &statbuf) != 0)
            return -errno;

        if (statbuf.st_size != 0)
        {
            ret = statbuf.st_size;
            goto done;
        }
    }

    /* open the virtual file */
    if ((fd = open(pathname, O_RDONLY)) < 0)
    {
        ret = -errno;
        goto done;
    }

    // Determine the size of a virtual file by reading it. If it is not
    // a virtual file, then read() will return zero the first time, indicating
    // a zero-sized file.
    for (;;)
    {
        ssize_t n = read(fd, buf, sizeof(buf));

        if (n == 0)
            break;

        if (n < 0)
        {
            ret = -errno;
            goto done;
        }

        size += n;
    }

    ret = size;

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

int myst_tcall_read_file(const char* pathname, char* buf, size_t size)
{
    int ret = 0;
    int fd = -1;
    char* ptr = buf;
    size_t rem = size;

    if (!pathname || !buf)
    {
        ret = -EINVAL;
        goto done;
    }

    if ((fd = open(pathname, O_RDONLY)) <= 0)
    {
        ret = -errno;
        goto done;
    }

    while (rem > 0)
    {
        ssize_t n = read(fd, ptr, rem);

        if (n <= 0)
        {
            ret = -errno;
            goto done;
        }

        ptr += n;
        rem -= (size_t)n;
    }

done:

    return ret;
}
