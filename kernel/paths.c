#include <errno.h>
#include <libos/assert.h>
#include <libos/deprecated.h>
#include <libos/eraise.h>
#include <libos/malloc.h>
#include <libos/paths.h>
#include <libos/strings.h>
#include <libos/syscall.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "trace.h"

int libos_path_absolute_cwd(
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
        if (libos_strlcpy(buf, path, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        size_t cwd_len;

        if (libos_strlcpy(buf, cwd, size) >= size)
            ERAISE(-ENAMETOOLONG);

        if ((cwd_len = libos_strlen(cwd)) == 0)
            ERAISE(-EINVAL);

        if (cwd[cwd_len - 1] != '/')
        {
            if (libos_strlcat(buf, "/", size) >= size)
                ERAISE(-ENAMETOOLONG);
        }

        if (libos_strlcat(buf, path, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }

done:
    return ret;
}

int libos_path_absolute(const char* path, char* buf, size_t size)
{
    int ret = 0;

    if (buf)
        *buf = '\0';

    if (!path || !buf || !size)
        ERAISE(-EINVAL);

    if (path[0] == '/')
    {
        if (libos_strlcpy(buf, path, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        long r;
        char cwd[PATH_MAX];

        if ((r = libos_syscall_getcwd(cwd, sizeof(cwd))) < 0)
            ERAISE((int)r);

        ERAISE(libos_path_absolute_cwd(cwd, path, buf, size));
    }

done:
    return ret;
}

int libos_tok_normalize(const char* toks[])
{
    int ret = 0;
    size_t start = (size_t)-1;
    size_t size = 0;

    if (!toks)
        ERAISE(-EINVAL);

    /* Determine the size of the toks array, including the null terminator */
    size = libos_tokslen(toks) + 1;
    libos_assert(toks[size - 1] == NULL);

    /* Find the index of the last "/" token */
    for (size_t i = 0; toks[i]; i++)
    {
        if (libos_strcmp(toks[i], "/") == 0)
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
        if (libos_strcmp(toks[i], ".") == 0)
        {
            ECHECK(libos_memremove_u64(toks, size, i, 1));
            size--;
            libos_assert(toks[size - 1] == NULL);
            continue;
        }

        /* If "..", remove previous element. */
        if (libos_strcmp(toks[i], "..") == 0)
        {
            /* Remove this element */
            ECHECK(libos_memremove_u64(toks, size, i, 1));
            size--;
            libos_assert(toks[size - 1] == NULL);

            if (i > 0)
            {
                /* Remove previous element */
                ECHECK(libos_memremove_u64(toks, size, i - 1, 1));
                size--;
                libos_assert(toks[size - 1] == NULL);
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
        libos_free(toks);

    if (str)
        libos_free(str);

    return ret;
}

/* TODO: test this next */
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
        if (i == 0 && libos_strcmp(toks[i], "/") == 0)
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

            libos_free(split);
            split = NULL;
        }

        libos_free(path);
        path = NULL;
    }

    buf[n] = NULL;

done:

    if (path)
        libos_free(path);

    if (split)
        libos_free(split);

    return ret;
}
