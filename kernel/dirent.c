#include <dirent.h>
#include <stdlib.h>

#include <libos/assert.h>
#include <libos/deprecated.h>
#include <libos/eraise.h>
#include <libos/file.h>
#include <libos/malloc.h>
#include <libos/strings.h>
#include <libos/syscall.h>

#define DIRENT_BUF_SIZE 14

struct __dirstream
{
    int fd;
    uint8_t* ptr;
    uint8_t* end;
    off_t tell;
    uint8_t buf[4096];
};

int libos_opendir(const char* name, DIR** dirp)
{
    int ret = 0;
    DIR* dir = NULL;
    int fd = -1;

    if (dirp)
        *dirp = NULL;

    if (!name || !dirp)
        ERAISE(-EINVAL);

    if ((fd = libos_open(name, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0)) < 0)
        ERAISE(-ENOENT);

    if (!(dir = libos_calloc(1, sizeof(DIR))))
        ERAISE(-ENOMEM);

    dir->fd = fd;
    fd = -1;

    *dirp = dir;
    dir = NULL;

done:

    if (fd >= 0)
        libos_syscall_close(fd);

    if (dir)
        libos_free(dir);

    return ret;
}

int libos_closedir(DIR* dir)
{
    int ret = 0;

    if (!dir)
        ERAISE(EINVAL);

    if (libos_close(dir->fd) != 0)
        ERAISE(EINVAL);

    libos_free(dir);

done:
    return ret;
}

int libos_readdir(DIR* dir, struct dirent** entp)
{
    int ret = 0;
    struct dirent* ent = NULL;

    if (entp)
        *entp = NULL;

    if (!dir || !entp)
        ERAISE(-EINVAL);

    /* If the dirent buffer is exhausted, read more entries */
    if (dir->ptr >= dir->end)
    {
        long n = libos_syscall_getdents64(
            dir->fd, (struct dirent*)dir->buf, sizeof(dir->buf));

        if (n < 0)
            ERAISE((int)n);

        if (n == 0)
        {
            /* end of file */
            goto done;
        }

        libos_assert((size_t)n <= sizeof(dir->buf));
        dir->ptr = dir->buf;
        dir->end = dir->buf + n;
    }

    ent = (struct dirent*)(dir->ptr);

    /* Check for 8-byte alignement */
    libos_assert(((uint64_t)ent % 8) == 0);

    dir->ptr += ent->d_reclen;
    dir->tell = ent->d_off;

    *entp = ent;
    ret = 1;

done:
    return ret;
}
