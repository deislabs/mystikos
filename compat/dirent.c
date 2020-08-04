#include <dirent.h>

DIR* libos_opendir(const char *name)
{
    return opendir(name);
}

int libos_closedir(DIR* dir)
{
    return closedir(dir);
}

struct dirent* libos_readdir(DIR *dir)
{
    return readdir(dir);
}
