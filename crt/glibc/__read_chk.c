// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <unistd.h>

ssize_t __read_chk(int fd, void* buf, size_t nbytes, size_t buflen)
{
    return read(fd, buf, buflen);
}
