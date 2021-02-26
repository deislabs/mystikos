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
    typedef struct _variables
    {
        char buf[PATH_MAX];
        const char* in[PATH_MAX];
        const char* out[PATH_MAX];
    } variables_t;
    variables_t* v = NULL;
    size_t nin = 0;
    size_t nout = 0;

    if (resolved_path)
        *resolved_path->buf = '\0';

    if (!path || !resolved_path)
        ERAISE(-EINVAL);

    /* Allocate variables on the heap since too big for the stack. */
    if (!(v = calloc(1, sizeof(variables_t))))
        ERAISE(-ENOMEM);

    if (path[0] == '/')
    {
        if (myst_strlcpy(v->buf, path, sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        char cwd[PATH_MAX];
        long r;

        if ((r = myst_syscall_getcwd(cwd, sizeof(cwd))) < 0)
            ERAISE((int)r);

        if (myst_strlcpy(v->buf, cwd, sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(-ENAMETOOLONG);

        if (myst_strlcat(v->buf, "/", sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(-ENAMETOOLONG);

        if (myst_strlcat(v->buf, path, sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(-ENAMETOOLONG);
    }

    /* Split the path into elements. */
    {
        char* p;
        char* save;

        v->in[nin++] = "/";

        for (p = strtok_r(v->buf, "/", &save); p;
             p = strtok_r(NULL, "/", &save))
        {
            v->in[nin++] = p;
        }

        /* if the path ends in '/' and not root then add '.' */
        {
            size_t len = strlen(path);

            if (len > 1 && path[len-1] == '/')
                v->in[nin++] = ".";
        }
    }

    /* Normalize the path. */
    for (size_t i = 0; i < nin; i++)
    {
        /* Skip "." elements. */
        if (i + 1 != nin && strcmp(v->in[i], ".") == 0)
            continue;

        /* If "..", remove previous element. */
        if (strcmp(v->in[i], "..") == 0)
        {
            if (nout > 1)
                nout--;
            continue;
        }

        v->out[nout++] = v->in[i];
    }

    /* Build the resolved path. */
    {
        const size_t n = sizeof(myst_path_t);
        *resolved_path->buf = '\0';

        for (size_t i = 0; i < nout; i++)
        {
            if (myst_strlcat(resolved_path->buf, v->out[i], n) >= n)
                ERAISE(-ENAMETOOLONG);

            if (i != 0 && i + 1 != nout)
            {
                if (myst_strlcat(resolved_path->buf, "/", n) >= n)
                    ERAISE(-ENAMETOOLONG);
            }
        }
    }

done:

    if (v)
        free(v);

    return ret;
}
