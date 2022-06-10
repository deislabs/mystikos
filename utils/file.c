// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/printf.h>
#include <myst/strings.h>
#include <myst/types.h>

int myst_load_file(const char* path, void** data_out, size_t* size_out)
{
    int ret = 0;
    ssize_t n;
    struct stat st;
    int fd = -1;
    void* data = NULL;
    uint8_t* p;
    struct locals
    {
        char block[512];
    };
    struct locals* locals = NULL;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    if (!path || !data_out || !size_out)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if ((fd = open(path, O_RDONLY, 0)) < 0)
        ERAISE(-ENOENT);

    if (fstat(fd, &st) != 0)
        ERAISE(-EINVAL);

    /* Allocate an extra byte for null termination */
    if (!(data = malloc((size_t)(st.st_size + 1))))
        ERAISE(-ENOMEM);

    p = data;

    /* Null-terminate the data */
    p[st.st_size] = '\0';

    while ((n = read(fd, locals->block, sizeof(locals->block))) > 0)
    {
        memcpy(p, locals->block, (size_t)n);
        p += n;
    }

    *data_out = data;
    data = NULL;
    *size_out = (size_t)st.st_size;

done:

    if (locals)
        free(locals);

    if (fd >= 0)
        close(fd);

    if (data)
        free(data);

    return ret;
}

int myst_write_file_fd(int fd, const void* data, size_t size)
{
    int ret = 0;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;
    ssize_t n;

    if (fd < 0 || (!data && size > 0))
        ERAISE(-EINVAL);

    while (r > 0)
    {
        if ((n = write(fd, p, r)) == 0)
            break;

        if (n < 0)
            ERAISE(n);

        p += n;
        r -= (size_t)n;
    }

    if (r != 0)
        ERAISE(-EIO);

done:
    return ret;
}

int myst_copy_file_fd(char* oldpath, int newfd)
{
    int ret = 0;
    int oldfd = -1;
    ssize_t n;
    struct stat st;
    struct locals
    {
        char buf[512];
    };
    struct locals* locals = NULL;

    if (!oldpath || newfd < 0)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if ((oldfd = open(oldpath, O_RDONLY, 0)) < 0)
        ERAISE(oldfd);

    if (fstat(oldfd, &st) != 0)
        ERAISE(-EINVAL);

    while ((n = read(oldfd, locals->buf, sizeof(locals->buf))) > 0)
    {
        ECHECK(myst_write_file_fd(newfd, locals->buf, (size_t)n));
    }

    if (n < 0)
        ERAISE((int)n);

done:

    if (locals)
        free(locals);

    if (oldfd >= 0)
        close(oldfd);

    return ret;
}

int myst_copy_file(const char* oldpath, const char* newpath)
{
    int ret = 0;
    int oldfd = -1;
    int newfd = -1;
    ssize_t n;
    mode_t mode;
    struct locals
    {
        char buf[512];
        struct stat st;
    };
    struct locals* locals = NULL;

    if (!oldpath || !newpath)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if ((oldfd = open(oldpath, O_RDONLY, 0)) < 0)
        ERAISE(oldfd);

    if (fstat(oldfd, &locals->st) != 0)
        ERAISE(-EINVAL);

    mode = (locals->st.st_mode & (mode_t)(~S_IFMT));

    if ((newfd = open(newpath, O_WRONLY | O_CREAT | O_TRUNC, mode)) < 0)
        ERAISE(newfd);

    while ((n = read(oldfd, locals->buf, sizeof(locals->buf))) > 0)
    {
        ECHECK(myst_write_file_fd(newfd, locals->buf, (size_t)n));
    }

    if (n < 0)
        ERAISE((int)n);

done:

    if (locals)
        free(locals);

    if (oldfd >= 0)
        close(oldfd);

    if (newfd >= 0)
        close(newfd);

    return ret;
}

const char* myst_basename(const char* path)
{
    char* p;

    if ((p = strrchr(path, '/')))
        return p + 1;

    return path;
}

int myst_mkdirhier(const char* pathname, mode_t mode)
{
    int ret = 0;
    char** toks = NULL;
    size_t ntoks;
    struct stat buf;
    struct locals
    {
        char path[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!pathname)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* If the directory already exists, stop here */
    if (stat(pathname, &buf) == 0 && S_ISDIR(buf.st_mode))
        goto done;

    ECHECK(myst_strsplit(pathname, "/", &toks, &ntoks));

    *locals->path = '\0';

    for (size_t i = 0; i < ntoks; i++)
    {
        if (MYST_STRLCAT(locals->path, "/") >= PATH_MAX)
            ERAISE(-ENAMETOOLONG);

        if (MYST_STRLCAT(locals->path, toks[i]) >= PATH_MAX)
            ERAISE(-ENAMETOOLONG);

        if (stat(locals->path, &buf) == 0)
        {
            if (!S_ISDIR(buf.st_mode))
                ERAISE(-ENOTDIR);
        }
        else
        {
            ECHECK(mkdir(locals->path, mode));
            /* To override umask effect on hostfs */
            ECHECK(chmod(locals->path, mode));
        }
    }

    if (stat(pathname, &buf) != 0 || !S_ISDIR(buf.st_mode))
        ERAISE(-EPERM);

done:

    if (locals)
        free(locals);

    if (toks)
        free(toks);

    return ret;
}

int myst_validate_file_path(const char* path)
{
    struct stat st;
    if (path == NULL ||
        (stat(path, &st) == 0 && (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))))
        return 1;
    myst_eprintf("The input path %s is invalid\n", path);
    return 0;
}
