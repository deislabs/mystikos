// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <myst/tcall.h>
#include <string.h>

int myst_tcall_cpuinfo_size()
{
    int fd, nbytes, size = 0;
    char buf[1024];

    fd = open("/proc/cpuinfo", O_RDONLY);
    if (fd < 0)
        return errno;

    while ((nbytes = read(fd, buf, sizeof(buf))))
        size += nbytes;
    close(fd);

    return size;
}

int myst_tcall_get_cpuinfo(char* buf, size_t size)
{
    int fd = open("/proc/cpuinfo", O_RDONLY);

    if (fd < 0)
        return errno;

    read(fd, buf, size);
    close(fd);

    return 0;
}