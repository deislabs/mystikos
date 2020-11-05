// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#define _XOPEN_SOURCE 500
#include <errno.h>
#include <ftw.h>
#include <libgen.h>
#include <libos/strings.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

const char* set_program_file(const char* program)
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

const char* get_program_file()
{
    return _program;
}

static const int _format_lib(char* path, size_t size, const char* suffix)
{
    int ret = 0;
    char buf[PATH_MAX];
    char* dir1;
    char* dir2;
    int n;

    if (!path || !size || !suffix)
    {
        ret = -EINVAL;
        goto done;
    }

    if (libos_strlcpy(buf, _program, sizeof(buf)) >= sizeof(buf))
    {
        ret = -ENAMETOOLONG;
        goto done;
    }

    if (!(dir1 = dirname(buf)) || !(dir2 = dirname(dir1)))
    {
        ret = -EINVAL;
        goto done;
    }

    if ((n = snprintf(path, size, "%s/%s", dir2, suffix)) >= size)
    {
        ret = -ENAMETOOLONG;
        goto done;
    }

done:
    return ret;
}

const int format_libosenc(char* path, size_t size)
{
    return _format_lib(path, size, "lib/openenclave/libosenc.so");
}

const int format_liboscrt(char* path, size_t size)
{
    return _format_lib(path, size, "lib/liboscrt.so");
}

const int format_liboskernel(char* path, size_t size)
{
    return _format_lib(path, size, "lib/liboskernel.so");
}

__attribute__((format(printf, 1, 2))) void _err(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", get_program_file());
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    exit(1);
}

int unlink_cb(
    const char* fpath,
    const struct stat* sb,
    int typeflag,
    struct FTW* ftwbuf)
{
    int rv = remove(fpath);

    if (rv)
        perror(fpath);

    return rv;
}

// delete a directory and anything in it
// NOTE: this is not thread safe!
int remove_recursive(const char* path)
{
    return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}
