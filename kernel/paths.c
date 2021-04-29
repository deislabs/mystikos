// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/paths.h>
#include <myst/strings.h>
#include <myst/syscall.h>

int myst_path_absolute_cwd(
    const char* cwd,
    const char* path,
    char* buf,
    size_t size)
{
    int ret = 0;

    if (buf)
        *buf = '\0';

    if (!path || !buf || !size)
        ERAISE(-EINVAL);

    if (path[0] == '/')
    {
        if (myst_strlcpy(buf, path, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        size_t cwd_len;

        if (myst_strlcpy(buf, cwd, size) >= size)
            ERAISE(-ENAMETOOLONG);

        if ((cwd_len = strlen(cwd)) == 0)
            ERAISE(-EINVAL);

        if (cwd[cwd_len - 1] != '/')
        {
            if (myst_strlcat(buf, "/", size) >= size)
                ERAISE(-ENAMETOOLONG);
        }

        if (myst_strlcat(buf, path, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }

done:
    return ret;
}

int myst_path_absolute(const char* path, char* buf, size_t size)
{
    int ret = 0;
    struct vars
    {
        char cwd[PATH_MAX];
    };
    struct vars* v = NULL;

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    if (buf)
        *buf = '\0';

    if (!path || !buf || !size)
        ERAISE(-EINVAL);

    if (path[0] == '/')
    {
        if (myst_strlcpy(buf, path, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        long r;

        if ((r = myst_syscall_getcwd(v->cwd, sizeof(v->cwd))) < 0)
            ERAISE((int)r);

        ERAISE(myst_path_absolute_cwd(v->cwd, path, buf, size));
    }

done:

    if (v)
        free(v);

    return ret;
}

int myst_make_path(
    char* buf,
    size_t size,
    const char* dirname,
    const char* basename)
{
    int ret = 0;

    if (!buf || !dirname || !basename)
        ERAISE(-EINVAL);

    size_t dirname_len = strlen(dirname);
    size_t basename_len = strlen(basename);

    if (dirname_len + 1 + basename_len >= size)
        ERAISE(-ENAMETOOLONG);

    memcpy(buf, dirname, dirname_len);
    buf[dirname_len] = '/';
    memcpy(buf + dirname_len + 1, basename, basename_len + 1);

done:
    return ret;
}
