// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <libos/eraise.h>
#include <libos/paths.h>
#include <libos/strings.h>
#include <libos/syscall.h>

int libos_tok_normalize(const char* toks[])
{
    int ret = 0;
    size_t start = (size_t)-1;
    size_t size = 0;

    if (!toks)
        ERAISE(-EINVAL);

    /* Determine the size of the toks array, including the null terminator */
    size = libos_tokslen(toks) + 1;
    assert(toks[size - 1] == NULL);

    /* Find the index of the last "/" token */
    for (size_t i = 0; toks[i]; i++)
    {
        if (strcmp(toks[i], "/") == 0)
        {
            start = i;
            break;
        }
    }

    /* Remove everything up to the last "/" token */
    if (start != (size_t)-1)
    {
        ECHECK(libos_memremove_u64(toks, size, 0, start));
        size -= start;
    }

    for (size_t i = 0; toks[i];)
    {
        /* Skip "." elements */
        if (strcmp(toks[i], ".") == 0)
        {
            ECHECK(libos_memremove_u64(toks, size, i, 1));
            size--;
            assert(toks[size - 1] == NULL);
            continue;
        }

        /* If "..", remove previous element. */
        if (strcmp(toks[i], "..") == 0)
        {
            /* Remove this element */
            ECHECK(libos_memremove_u64(toks, size, i, 1));
            size--;
            assert(toks[size - 1] == NULL);

            if (i > 0)
            {
                /* Remove previous element */
                ECHECK(libos_memremove_u64(toks, size, i - 1, 1));
                size--;
                assert(toks[size - 1] == NULL);
                i--;
            }

            if (i >= size)
                break;

            continue;
        }

        i++;
    }

done:
    return ret;
}

int libos_normalize(const char* path, char* buf, size_t size)
{
    int ret = 0;
    char** toks = NULL;
    size_t ntoks;
    char* str = NULL;

    if (!path)
        ERAISE(-EINVAL);

    ECHECK(libos_strsplit(path, "/", &toks, &ntoks));
    ECHECK(libos_tok_normalize((const char**)toks));
    ntoks = libos_tokslen((const char**)toks);
    ECHECK(libos_strjoin((const char**)toks, ntoks, "/", "/", NULL, &str));

    if (libos_strlcpy(buf, str, size) >= size)
        ERAISE(-ERANGE);

done:

    if (toks)
        free(toks);

    if (str)
        free(str);

    return ret;
}

#if 0
int libos_path_expand(const char* toks[], const char* buf[], size_t size)
{
    int ret = 0;
    size_t n = 0;
    char* path = NULL;
    struct stat st;
    char** split = NULL;

    if (!toks || !buf || !size)
        ERAISE(-EINVAL);

    for (size_t i = 0; toks[i]; i++)
    {
        if (i == 0 && strcmp(toks[i], "/") == 0)
        {
            buf[n++] = toks[i];
            continue;
        }

        /* Add the next component */
        {
            if (n == size)
                ERAISE(-ENAMETOOLONG);

            buf[n++] = toks[i];
        }

        /* Build a path out of what we have so far */
        ECHECK(libos_strjoin(buf, n, "/", "/", NULL, &path));

        /* Stat the path */
        ECHECK(libos_syscall_lstat(path, &st));

        /* If it's a link, then inject all elements of the target */
        if (S_ISLNK(st.st_mode))
        {
            char target[PATH_MAX];
            size_t nsplit;

            ECHECK(libos_syscall_readlink(path, target, sizeof(target)));

            ECHECK(libos_strsplit(target, "/", &split, &nsplit));

            /* remove the link name */
            n--;

            /* append the target elements */
            for (size_t j = 0; j < nsplit; j++)
            {
                if (n == size)
                    ERAISE(-ENAMETOOLONG);

                buf[n++] = split[j];
            }

            free(split);
            split = NULL;
        }

        free(path);
        path = NULL;
    }

    buf[n] = NULL;

done:

    if (path)
        free(path);

    if (split)
        free(split);

    return ret;
}
#endif
