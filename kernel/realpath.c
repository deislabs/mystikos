#include <string.h>
#include <stdlib.h>
#include <libos/types.h>
#include <libos/eraise.h>
#include <libos/cwd.h>
#include <libos/realpath.h>
#include <libos/cwd.h>
#include <libos/syscall.h>
#include "common.h"

int libos_realpath(const char* path, libos_path_t* resolved_path)
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
    if (!(v = libos_calloc(1, sizeof(variables_t))))
        ERAISE(-ENOMEM);

    if (path[0] == '/')
    {
        if (libos_strlcpy(v->buf, path, sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        char cwd[PATH_MAX];
        long r;

        if ((r = libos_syscall_getcwd(cwd, sizeof(cwd))) < 0)
            ERAISE((int)r);

        if (libos_strlcpy(v->buf, cwd, sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(-ENAMETOOLONG);

        if (libos_strlcat(v->buf, "/", sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(-ENAMETOOLONG);

        if (libos_strlcat(v->buf, path, sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(-ENAMETOOLONG);
    }

    /* Split the path into elements. */
    {
        char* p;
        char* save;

        v->in[nin++] = "/";

        for (p = libos_strtok_r(v->buf, "/", &save); p;
             p = libos_strtok_r(NULL, "/", &save))
        {
            v->in[nin++] = p;
        }
    }

    /* Normalize the path. */
    for (size_t i = 0; i < nin; i++)
    {
        /* Skip "." elements. */
        if (libos_strcmp(v->in[i], ".") == 0)
            continue;

        /* If "..", remove previous element. */
        if (libos_strcmp(v->in[i], "..") == 0)
        {
            if (nout > 1)
                nout--;
            continue;
        }

        v->out[nout++] = v->in[i];
    }

    /* Build the resolved path. */
    {
        const size_t n = sizeof(libos_path_t);
        *resolved_path->buf = '\0';

        for (size_t i = 0; i < nout; i++)
        {
            if (libos_strlcat(resolved_path->buf, v->out[i], n) >= n)
                ERAISE(-ENAMETOOLONG);

            if (i != 0 && i + 1 != nout)
            {
                if (libos_strlcat(resolved_path->buf, "/", n) >= n)
                    ERAISE(-ENAMETOOLONG);
            }
        }
    }

done:

    if (v)
        libos_free(v);

    return ret;
}
