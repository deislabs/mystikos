// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include "utils.h"

static int _which(const char* program, char buf[PATH_MAX])
{
    int ret = -1;
    char path[PATH_MAX];

    if (buf)
        *buf = '\0';

    if (!program || !buf)
        goto done;

    /* If the program has slashes the use realpath */
    if (strchr(program, '/'))
    {
        char current[PATH_MAX];

        if (!realpath(program, current))
            goto done;

        if (access(current, X_OK) == 0)
        {
            strcpy(buf, current);
            ret = 0;
            goto done;
        }

        goto done;
    }

    /* Get the PATH environment variable */
    {
        const char* p;

        if (!(p = getenv("PATH")) || strlen(p) >= PATH_MAX)
            goto done;

        strcpy(path, p);
    }

    /* Search the PATH for the program */
    {
        char* p;
        char* save;

        for (p = strtok_r(path, ":", &save); p; p = strtok_r(NULL, ":", &save))
        {
            char current[PATH_MAX];
            int n;

            n = snprintf(current, sizeof(current), "%s/%s", p, program);
            if (n >= sizeof(current))
                goto done;

            if (access(current, X_OK) == 0)
            {
                strcpy(buf, current);
                ret = 0;
                goto done;
            }
        }
    }

    /* not found */

done:
    return ret;
}

char _program[PATH_MAX];

const char *set_program_file(const char *program)
{
    if (_which(program, _program) != 0)
    {
        return NULL;
    }
    else
    {
        return _program;
    }
    
}

const char *get_program_file()
{
    return _program;
}

__attribute__((format(printf, 1, 2)))
void _err(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", get_program_file());
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    exit(1);
}
