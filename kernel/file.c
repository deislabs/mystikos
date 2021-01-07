// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <stdlib.h>

#include <myst/buf.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/trace.h>

int myst_getdents64(int fd, struct dirent* dirp, size_t count)
{
    return (int)myst_syscall_ret(myst_syscall_getdents64(fd, dirp, count));
}
