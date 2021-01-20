// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <myst/eraise.h>
#include <myst/paths.h>
#include <myst/strings.h>
#include <myst/syscall.h>

int myst_tok_normalize(const char* toks[])
{
    int ret = 0;
    size_t start = (size_t)-1;
    size_t size = 0;

    if (!toks)
        ERAISE(-EINVAL);

    /* Determine the size of the toks array, including the null terminator */
    size = myst_tokslen(toks) + 1;
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
        ECHECK(myst_memremove_u64(toks, size, 0, start));
        size -= start;
    }

    for (size_t i = 0; toks[i];)
    {
        /* Skip "." elements */
        if (strcmp(toks[i], ".") == 0)
        {
            ECHECK(myst_memremove_u64(toks, size, i, 1));
            size--;
            assert(toks[size - 1] == NULL);
            continue;
        }

        /* If "..", remove previous element. */
        if (strcmp(toks[i], "..") == 0)
        {
            /* Remove this element */
            ECHECK(myst_memremove_u64(toks, size, i, 1));
            size--;
            assert(toks[size - 1] == NULL);

            if (i > 0)
            {
                /* Remove previous element */
                ECHECK(myst_memremove_u64(toks, size, i - 1, 1));
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

int myst_normalize(const char* path, char* buf, size_t size)
{
    int ret = 0;
    char** toks = NULL;
    size_t ntoks;
    char* str = NULL;

    if (!path)
        ERAISE(-EINVAL);

    ECHECK(myst_strsplit(path, "/", &toks, &ntoks));
    ECHECK(myst_tok_normalize((const char**)toks));
    ntoks = myst_tokslen((const char**)toks);
    ECHECK(myst_strjoin((const char**)toks, ntoks, "/", "/", NULL, &str));

    if (myst_strlcpy(buf, str, size) >= size)
        ERAISE(-ERANGE);

done:

    if (toks)
        free(toks);

    if (str)
        free(str);

    return ret;
}

int myst_split_path(
    const char* path,
    char dirname[PATH_MAX],
    char basename[PATH_MAX])
{
    int ret = 0;
    char* slash;

    /* Reject paths that are too long. */
    if (strlen(path) >= PATH_MAX)
        ERAISE(-EINVAL);

    /* Reject paths that are not absolute */
    if (path[0] != '/')
        ERAISE(-EINVAL);

    /* Handle root directory up front */
    if (strcmp(path, "/") == 0)
    {
        myst_strlcpy(dirname, "/", PATH_MAX);
        myst_strlcpy(basename, "/", PATH_MAX);
        goto done;
    }

    /* This cannot fail (prechecked) */
    if (!(slash = strrchr(path, '/')))
        ERAISE(-EINVAL);

    /* If path ends with '/' character */
    if (!slash[1])
        ERAISE(-EINVAL);

    /* Split the path */
    {
        if (slash == path)
        {
            myst_strlcpy(dirname, "/", PATH_MAX);
        }
        else
        {
            size_t index = (size_t)(slash - path);
            myst_strlcpy(dirname, path, PATH_MAX);

            if (index < PATH_MAX)
                dirname[index] = '\0';
            else
                dirname[PATH_MAX - 1] = '\0';
        }

        myst_strlcpy(basename, slash + 1, PATH_MAX);
    }

done:
    return ret;
}

#if 0
int myst_path_expand(const char* toks[], const char* buf[], size_t size)
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
        ECHECK(myst_strjoin(buf, n, "/", "/", NULL, &path));

        /* Stat the path */
        ECHECK(myst_syscall_lstat(path, &st));

        /* If it's a link, then inject all elements of the target */
        if (S_ISLNK(st.st_mode))
        {
            char target[PATH_MAX];
            size_t nsplit;

            ECHECK(myst_syscall_readlink(path, target, sizeof(target)));

            ECHECK(myst_strsplit(target, "/", &split, &nsplit));

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
