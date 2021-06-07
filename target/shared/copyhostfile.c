// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <fcntl.h>
#include <myst/tcall.h>
#include <string.h>

int myst_tcall_get_file_size(const char* pathname)
{
    int fd, nbytes, size = 0;
    char buf[1024];

    fd = open(pathname, O_RDONLY);
    if (fd < 0)
        return errno;

    while ((nbytes = read(fd, buf, sizeof(buf))))
        size += nbytes;
    close(fd);

    return size;
}

int myst_tcall_read_file(const char* pathname, char* buf, size_t size)
{
    int fd = open(pathname, O_RDONLY);

    if (fd < 0)
        return errno;

    read(fd, buf, size);
    close(fd);

    return 0;
}