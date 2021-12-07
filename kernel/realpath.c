// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/cwd.h>
#include <myst/eraise.h>
#include <myst/realpath.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/types.h>
#include <stdlib.h>
#include <string.h>

int myst_realpath(const char* path, myst_path_t* resolved_path)
{
    int ret = 0;
    struct locals
    {
        char buf[PATH_MAX];
        const char* in[PATH_MAX];
        const char* out[PATH_MAX];
        char cwd[PATH_MAX];
    };
    struct locals* locals = NULL;
    size_t nin = 0;
    size_t nout = 0;

    if (resolved_path)
        *resolved_path->buf = '\0';

    if (!path || !resolved_path)
        ERAISE(-EINVAL);

    if (*path == 0)
        ERAISE(-ENOENT);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    memset(locals, 0, sizeof(struct locals));

    if (path[0] == '/')
    {
        if (myst_strlcpy(locals->buf, path, sizeof(locals->buf)) >=
            sizeof(locals->buf))
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        long r;

        if ((r = myst_syscall_getcwd(locals->cwd, sizeof(locals->cwd))) < 0)
            ERAISE((int)r);

        if (myst_strlcpy(locals->buf, locals->cwd, sizeof(locals->buf)) >=
            sizeof(locals->buf))
            ERAISE(-ENAMETOOLONG);

        if (myst_strlcat(locals->buf, "/", sizeof(locals->buf)) >=
            sizeof(locals->buf))
            ERAISE(-ENAMETOOLONG);

        if (myst_strlcat(locals->buf, path, sizeof(locals->buf)) >=
            sizeof(locals->buf))
            ERAISE(-ENAMETOOLONG);
    }

    /* Split the path into elements. */
    {
        char* p;
        char* save;

        locals->in[nin++] = "/";

        for (p = strtok_r(locals->buf, "/", &save); p;
             p = strtok_r(NULL, "/", &save))
        {
            locals->in[nin++] = p;
        }

        /* if the path ends in '/' and not root then add '.' */
        {
            size_t len = strlen(path);

            if (len > 1 && path[len - 1] == '/')
                locals->in[nin++] = ".";
        }
    }

    /* Normalize the path. */
    for (size_t i = 0; i < nin; i++)
    {
        /* Skip "." elements. */
        if (i + 1 != nin && strcmp(locals->in[i], ".") == 0)
            continue;

        /* If "..", remove previous element. */
        if (strcmp(locals->in[i], "..") == 0)
        {
            if (nout > 1)
                nout--;
            continue;
        }

        locals->out[nout++] = locals->in[i];
    }

    /* Build the resolved path. */
    {
        const size_t n = sizeof(myst_path_t);
        *resolved_path->buf = '\0';

        for (size_t i = 0; i < nout; i++)
        {
            if (myst_strlcat(resolved_path->buf, locals->out[i], n) >= n)
                ERAISE(-ENAMETOOLONG);

            if (i != 0 && i + 1 != nout)
            {
                if (myst_strlcat(resolved_path->buf, "/", n) >= n)
                    ERAISE(-ENAMETOOLONG);
            }
        }
    }

done:

    if (locals)
        free(locals);

    return ret;
}
