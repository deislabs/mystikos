// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/getopt.h>

#include <myst/eraise.h>
#include <string.h>

int myst_getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg,
    char* err,
    size_t err_size)
{
    int ret = 0;
    size_t olen = strlen(opt);

    if (optarg)
        *optarg = NULL;

    if (!argv || !opt || !err)
    {
        snprintf(err, err_size, "bad argument");
        ERAISE(-EINVAL);
    }

    for (int i = 0; i < *argc;)
    {
        if (strcmp(argv[i], opt) == 0)
        {
            if (optarg)
            {
                if (i + 1 == *argc)
                {
                    snprintf(err, err_size, "%s: missing option argument", opt);
                    ERAISE(-EINVAL);
                }

                *optarg = argv[i + 1];
                memmove(
                    &argv[i], &argv[i + 2], (*argc - i - 1) * sizeof(char*));
                (*argc) -= 2;
                goto done;
            }
            else
            {
                memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
                (*argc)--;
                goto done;
            }
        }
        else if (strncmp(argv[i], opt, olen) == 0 && argv[i][olen] == '=')
        {
            if (!optarg)
            {
                snprintf(err, err_size, "%s: extraneous '='", opt);
                ERAISE(-EINVAL);
            }

            *optarg = &argv[i][olen + 1];
            memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
            (*argc)--;
            goto done;
        }
        else
        {
            i++;
        }
    }

    /* Not found! */
    ret = 1;

done:
    return ret;
}
