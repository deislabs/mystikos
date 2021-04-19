// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdlib.h>

#include <myst/cwd.h>
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

int myst_getcwd2(char** buf_out)
{
    long ret = 0;
    char* buf = NULL;

    if (!buf_out)
        ERAISE(-EINVAL);

    if (!(buf = malloc(PATH_MAX)))
        ERAISE(-ENOMEM);

    ECHECK(myst_syscall_getcwd(buf, PATH_MAX));
    *buf_out = buf;
    buf = NULL;

done:

    if (buf)
        free(buf);

    return ret;
}
