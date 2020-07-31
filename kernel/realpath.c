#include <string.h>
#include <stdlib.h>
#include <libos/types.h>
#include "eraise.h"
#include <libos/cwd.h>
#include <libos/realpath.h>
#include <libos/cwd.h>

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
        ERAISE(EINVAL);

    /* Allocate variables on the heap since too big for the stack. */
    if (!(v = calloc(1, sizeof(variables_t))))
        ERAISE(ENOMEM);

    if (path[0] == '/')
    {
        if (strlcpy(v->buf, path, sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(ENAMETOOLONG);
    }
    else
    {
        libos_path_t cwd;

        ECHECK(libos_getcwd(&cwd));

        if (strlcpy(v->buf, cwd.buf, sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(ENAMETOOLONG);

        if (strlcat(v->buf, "/", sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(ENAMETOOLONG);

        if (strlcat(v->buf, path, sizeof(v->buf)) >= sizeof(v->buf))
            ERAISE(ENAMETOOLONG);
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
    }

    /* Normalize the path. */
    for (size_t i = 0; i < nin; i++)
    {
        /* Skip "." elements. */
        if (strcmp(v->in[i], ".") == 0)
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
        const size_t n = sizeof(libos_path_t);
        *resolved_path->buf = '\0';

        for (size_t i = 0; i < nout; i++)
        {
            if (strlcat(resolved_path->buf, v->out[i], n) >= n)
                ERAISE(ENAMETOOLONG);

            if (i != 0 && i + 1 != nout)
            {
                if (strlcat(resolved_path->buf, "/", n) >= n)
                    ERAISE(ENAMETOOLONG);
            }
        }
    }

done:

    if (v)
        free(v);

    return ret;
}
