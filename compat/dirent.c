#include <dirent.h>
#include <errno.h>
#include <libos/file.h>

int libos_opendir(const char *name, DIR** dirp)
{
    if (!name || !dirp)
        return -EINVAL;

    if (!(*dirp = opendir(name)))
        return -errno;

    return 0;
}

int libos_closedir(DIR* dir)
{
    if (!dir)
        return -EINVAL;

    return closedir(dir);
}

int libos_readdir(DIR *dir, struct dirent** entp)
{
    if (!dir || !entp)
        return -EINVAL;

    if (!(*entp = readdir(dir)))
        return -errno;

    return 1;
}
