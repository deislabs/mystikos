#include <errno.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <libos/syscall.h>
#include <libos/strings.h>
#include <sys/stat.h>
#include <libos/paths.h>
#include "eraise.h"
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
        if (strlcpy(buf, path, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        size_t cwd_len;

        if (strlcpy(buf, cwd, size) >= size)
            ERAISE(-ENAMETOOLONG);

        if ((cwd_len = strlen(cwd)) == 0)
            ERAISE(-EINVAL);

        if (cwd[cwd_len-1] != '/')
        {
            if (strlcat(buf, "/", size) >= size)
                ERAISE(-ENAMETOOLONG);
        }

        if (strlcat(buf, path, size) >= size)
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
        if (strlcpy(buf, path, size) >= size)
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

#if 0
int libos_path_absolute(const char* path, char* buf, size_t size)
{
    int ret = 0;

    if (buf)
        *buf = '\0';

    if (!path || !buf || !size)
        ERAISE(-EINVAL);

    if (path[0] == '/')
    {
        if (strlcpy(buf, path, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }
    else
    {
        char cwd[PATH_MAX];
        size_t cwd_len;
        long r;

        if ((r = libos_syscall_getcwd(cwd, sizeof(cwd))) < 0)
            ERAISE((int)r);

        if (strlcpy(buf, cwd, size) >= size)
            ERAISE(-ENAMETOOLONG);

        if ((cwd_len = strlen(cwd)) == 0)
            ERAISE(-EINVAL);

        if (cwd[cwd_len-1] != '/')
        {
            if (strlcat(buf, "/", size) >= size)
                ERAISE(-ENAMETOOLONG);
        }

        if (strlcat(buf, path, size) >= size)
            ERAISE(-ENAMETOOLONG);
    }

done:
    return ret;
}
#endif

int libos_tok_normalize(const char* toks[])
{
    int ret = 0;
    size_t start = (size_t)-1;
    size_t size = 0;

    if (!toks)
        ERAISE(-EINVAL);

    /* Determine the size of the toks array, including the null terminator */
    size = libos_tokslen(toks) + 1;
    assert(toks[size-1] == NULL);

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

    for (size_t i = 0; toks[i]; )
    {
        /* Skip "." elements */
        if (strcmp(toks[i], ".") == 0)
        {
            ECHECK(libos_memremove_u64(toks, size, i, 1));
            size--;
            assert(toks[size-1] == NULL);
            continue;
        }

        /* If "..", remove previous element. */
        if (strcmp(toks[i], "..") == 0)
        {
            /* Remove this element */
            ECHECK(libos_memremove_u64(toks, size, i, 1));
            size--;
            assert(toks[size-1] == NULL);

            if (i > 0)
            {
                /* Remove previous element */
                ECHECK(libos_memremove_u64(toks, size, i - 1, 1));
                size--;
                assert(toks[size-1] == NULL);
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

    if (strlcpy(buf, str, size) >= size)
        ERAISE(-ERANGE);

done:

    if (toks)
        free(toks);

    if (str)
        free(str);

    return ret;
}

#if 0

int libos_path_expand(
    const libos_components_t* in,
    libos_components_t* out)
{
    int ret = 0;
    char path[PATH_MAX];
    char target[PATH_MAX];
    struct stat buf;
    libos_components_t split;

    if (!in || !out)
        ERAISE(-EINVAL);

    for (size_t i = 0; i < in->size; i++)
    {
        if (i == 0 && strcmp(in->data[i], "/") == 0)
        {
            out->data[out->size++] = in->data[i];
            continue;
        }

        /* Add the next component */
        {
            if (out->size == LIBOS_PATH_MAX_COMPONENTS)
                ERAISE(-ENAMETOOLONG);

            out->data[out->size++] = in->data[i];
        }

        /* Build a path out of what we have so far */
        ECHECK(libos_path_join(out, path, sizeof(path)));

        /* Stat the path */
        ECHECK((int)libos_syscall_lstat(path, &buf));

        /* If it's a link, then inject all elements of the target */
        if (S_ISLNK(buf.st_mode))
        {
            ECHECK((int)libos_syscall_readlink(path, target, sizeof(target)));

            ECHECK(libos_path_split(target, &split));

            /* remove the link name */
            out->size--;

            /* append the target elements */
            for (size_t j = 0; j < split.size; j++)
            {
                if (out->size == LIBOS_PATH_MAX_COMPONENTS)
                    ERAISE(-ENAMETOOLONG);

                out->data[out->size++] = split.data[j];
            }
        }
    }

done:
    return ret;
}

#endif
