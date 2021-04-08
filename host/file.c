// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <myst/eraise.h>
#include <myst/file.h>

int myst_write_file(const char* path, const void* data, size_t size)
{
    int ret = 0;
    int fd;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;
    ssize_t n;

    if ((fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666)) < 0)
        ERAISE(-errno);

    while ((n = write(fd, p, r)) > 0)
    {
        p += n;
        r -= n;
    }

    if (r != 0)
        ERAISE(-EIO);

    close(fd);

done:
    return ret;
}

int myst_write_file_fd(int fd, const void* data, size_t size)
{
    int ret = 0;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;
    ssize_t n;

    if (fd < 0 || !data)
        ERAISE(-EINVAL);

    while (r > 0)
    {
        if ((n = write(fd, p, r)) == 0)
            break;

        if (n < 0)
            ERAISE((int)-n);

        p += n;
        r -= (size_t)n;
    }

    if (r != 0)
        ERAISE(-EIO);

done:
    return ret;
}

/* change owner to ${SUDO_UID}.${SUDO_GID} if possible */
int myst_chown_sudo_user(const char* path)
{
    int ret = 0;
    const char* sudo_uid;
    const char* sudo_gid;
    int uid = getuid();
    int gid = getgid();
    size_t found = 0;

    if ((sudo_uid = getenv("SUDO_UID")))
    {
        ECHECK(myst_str2int(sudo_uid, &uid));
        found++;
    }

    if ((sudo_gid = getenv("SUDO_GID")))
    {
        ECHECK(myst_str2int(sudo_gid, &gid));
        found++;
    }

    if (found && chown(path, uid, gid) != 0)
        ERAISE(-errno);

done:
    return ret;
}
