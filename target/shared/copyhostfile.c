// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <myst/tcall.h>
#include <string.h>
#include <sys/stat.h>

ssize_t myst_tcall_get_file_size(const char* pathname)
{
    struct stat statbuf;

    if (!pathname)
        return -EINVAL;

    if (stat(pathname, &statbuf) != 0)
        return -errno;

    return (ssize_t)statbuf.st_size;
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

    if (fd >= 0)
        close(fd);

    return ret;
}
