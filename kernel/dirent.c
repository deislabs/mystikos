#include <dirent.h>
#include <stdlib.h>
#include <assert.h>

#include <libos/deprecated.h>
#include <libos/file.h>
#include <libos/syscall.h>
#include <libos/eraise.h>
#include <libos/malloc.h>

#define DIRENT_BUF_SIZE 14

struct __dirstream
{
    int fd;
    uint8_t* ptr;
    uint8_t* end;
    off_t tell;
    uint8_t buf[4096];
};

DIR* libos_opendir(const char *name)
{
    DIR* ret = NULL;
    DIR* dir = NULL;
    int fd = -1;

    if ((fd = libos_open(name, O_RDONLY|O_DIRECTORY|O_CLOEXEC, 0)) < 0)
        goto done;

    if (!(dir = libos_calloc(1, sizeof(DIR))))
    {
        errno = ENOMEM;
        goto done;
    }

    dir->fd = fd;
    fd = -1;

    ret = dir;
    dir = NULL;

done:

    if (fd >= 0)
    {
        /* Avoid libos_close() since it sets errno */
        libos_syscall_close(fd);
    }

    if (dir)
        libos_free(dir);

    return ret;
}

int libos_closedir(DIR* dir)
{
    int ret = -1;

    if (!dir)
    {
        errno = EINVAL;
        goto done;
    }

    if (libos_close(dir->fd) != 0)
        goto done;

    libos_free(dir);
    ret = 0;

done:
    return ret;
}

struct dirent* libos_readdir(DIR *dir)
{
    struct dirent* ret = NULL;
    struct dirent* ent = NULL;

    if (!dir)
    {
        errno = EINVAL;
        goto done;
    }

    /* If the dirent buffer is exhausted, read more entries */
    if (dir->ptr >= dir->end)
    {
        long n = libos_syscall_getdents64(
            dir->fd,
            (struct dirent*)dir->buf,
            sizeof(dir->buf));

        if (n <= 0)
        {
            errno = (int)n;
            goto done;
        }

        if (n == 0)
        {
            /* end of file */
            goto done;
        }

        assert((size_t)n <= sizeof(dir->buf));
        dir->ptr = dir->buf;
        dir->end = dir->buf + n;
    }

    ent = (struct dirent*)(dir->ptr);

    /* Check for 8-byte alignement */
    assert(((uint64_t)ent % 8) == 0);

    dir->ptr += ent->d_reclen;
    dir->tell = ent->d_off;

    ret = ent;

done:
    return ret;
}
