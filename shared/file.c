#include <libos/eraise.h>
#include <libos/file.h>
#include <libos/malloc.h>
#include <libos/strings.h>
#include <libos/types.h>

int libos_load_file(const char* path, void** data_out, size_t* size_out)
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

    if ((fd = libos_open(path, O_RDONLY, 0)) < 0)
        ERAISE(-ENOENT);

    if (libos_fstat(fd, &st) != 0)
        ERAISE(-EINVAL);

    /* Allocate an extra byte for null termination */
    if (!(data = libos_malloc((size_t)(st.st_size + 1))))
        ERAISE(-ENOMEM);

    p = data;

    /* Null-terminate the data */
    p[st.st_size] = '\0';

    while ((n = libos_read(fd, block, sizeof(block))) > 0)
    {
        libos_memcpy(p, block, (size_t)n);
        p += n;
    }

    *data_out = data;
    data = NULL;
    *size_out = (size_t)st.st_size;

done:

    if (fd >= 0)
        libos_close(fd);

    if (data)
        libos_free(data);

    return ret;
}

ssize_t libos_writen(int fd, const void* data, size_t size)
{
    ssize_t ret = 0;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n = libos_write(fd, p, r);

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

int libos_copy_file(const char* oldpath, const char* newpath)
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

    if ((oldfd = libos_open(oldpath, O_RDONLY, 0)) < 0)
        ERAISE(oldfd);

    if (libos_fstat(oldfd, &st) != 0)
        ERAISE(-EINVAL);

    mode = (st.st_mode & (mode_t)(~S_IFMT));

    if ((newfd = libos_open(newpath, O_WRONLY | O_CREAT | O_TRUNC, mode)) < 0)
        ERAISE(newfd);

    while ((n = libos_read(oldfd, buf, sizeof(buf))) > 0)
    {
        ECHECK(libos_writen(newfd, buf, (size_t)n));
    }

    if (n < 0)
        ERAISE((int)n);

done:

    if (oldfd >= 0)
        libos_close(oldfd);

    if (newfd >= 0)
        libos_close(newfd);

    return ret;
}

const char* libos_basename(const char* path)
{
    char* p;

    if ((p = libos_strrchr(path, '/')))
        return p + 1;

    return path;
}
