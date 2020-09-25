#include <errno.h>
#include <string.h>

#include <libos/eraise.h>
#include <libos/strings.h>
#include <libos/syscall.h>

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

        if ((cwd_len = strlen(cwd)) == 0)
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
