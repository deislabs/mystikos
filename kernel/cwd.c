// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/eraise.h>
#include <myst/syscall.h>

int myst_chdir(const char* path)
{
    return (int)myst_syscall_ret(myst_syscall_chdir(path));
}

char* myst_getcwd(char* buf, size_t size)
{
    return (char*)myst_syscall_ret(myst_syscall_getcwd(buf, size));
}
