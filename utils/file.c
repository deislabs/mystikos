// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/strings.h>
#include <myst/types.h>

int myst_load_file(const char* path, void** data_out, size_t* size_out)
{
    int ret = 0;
    ssize_t n;
    struct stat st;
    char block[512];
    int fd = -1;
    void* data = NULL;
    uint8_t* p;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    if (!path || !data_out || !size_out)
        ERAISE(-EINVAL);

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

    while ((n = read(fd, block, sizeof(block))) > 0)
    {
        memcpy(p, block, (size_t)n);
        p += n;
    }

    *data_out = data;
    data = NULL;
    *size_out = (size_t)st.st_size;

done:

    if (fd >= 0)
        close(fd);

    if (data)
        free(data);

    return ret;
}

ssize_t myst_writen(int fd, const void* data, size_t size)
{
    ssize_t ret = 0;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n = write(fd, p, r);

        if (n == 0)
            break;
        else if (n < 0)
            ERAISE(n);

        p += n;
        r -= (size_t)n;
    }

done:

    return ret;
}

int myst_copy_file_fd(const char* oldpath, int newfd)
{
    int ret = 0;
    int oldfd = -1;
    char buf[512];
    ssize_t n;
    struct stat st;

    if (!oldpath || newfd < 0)
        ERAISE(-EINVAL);

    if ((oldfd = open(oldpath, O_RDONLY, 0)) < 0)
        ERAISE(oldfd);

    if (fstat(oldfd, &st) != 0)
        ERAISE(-EINVAL);

    while ((n = read(oldfd, buf, sizeof(buf))) > 0)
    {
        ECHECK(myst_writen(newfd, buf, (size_t)n));
    }

    if (n < 0)
        ERAISE((int)n);

done:

    if (oldfd >= 0)
        close(oldfd);

    return ret;
}

int myst_copy_file(const char* oldpath, const char* newpath)
{
    int ret = 0;
    int oldfd = -1;
    int newfd = -1;
    char buf[512];
    ssize_t n;
    struct stat st;
    mode_t mode;

    if (!oldpath || !newpath)
        ERAISE(-EINVAL);

    if ((oldfd = open(oldpath, O_RDONLY, 0)) < 0)
        ERAISE(oldfd);

    if (fstat(oldfd, &st) != 0)
        ERAISE(-EINVAL);

    mode = (st.st_mode & (mode_t)(~S_IFMT));

    if ((newfd = open(newpath, O_WRONLY | O_CREAT | O_TRUNC, mode)) < 0)
        ERAISE(newfd);

    while ((n = read(oldfd, buf, sizeof(buf))) > 0)
    {
        ECHECK(myst_writen(newfd, buf, (size_t)n));
    }

    if (n < 0)
        ERAISE((int)n);

done:

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
    char path[PATH_MAX];
    struct stat buf;

    if (!pathname)
        ERAISE(-EINVAL);

    /* If the directory already exists, stop here */
    if (stat(pathname, &buf) == 0 && S_ISDIR(buf.st_mode))
        goto done;

    ECHECK(myst_strsplit(pathname, "/", &toks, &ntoks));

    *path = '\0';

    for (size_t i = 0; i < ntoks; i++)
    {
        if (MYST_STRLCAT(path, "/") >= PATH_MAX)
            ERAISE(-ENAMETOOLONG);

        if (MYST_STRLCAT(path, toks[i]) >= PATH_MAX)
            ERAISE(-ENAMETOOLONG);

        if (stat(path, &buf) == 0)
        {
            if (!S_ISDIR(buf.st_mode))
                ERAISE(-ENOTDIR);
        }
        else
        {
            ECHECK(mkdir(path, mode));
        }
    }

    if (stat(pathname, &buf) != 0 || !S_ISDIR(buf.st_mode))
        ERAISE(-EPERM);

done:

    if (toks)
        free(toks);

    return ret;
}
