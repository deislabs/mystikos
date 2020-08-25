#include <libos/file.h>
#include <libos/lsr.h>
#include <stddef.h>
#include <string.h>
#include "common.h"

int libos_lsr(const char* root, libos_strarr_t* paths)
{
    int ret = -1;
    DIR* dir = NULL;
    struct dirent* ent;
    char path[PATH_MAX];
    libos_strarr_t dirs = LIBOS_STRARR_INITIALIZER;

    /* Check parameters */
    if (!root || !paths)
        goto done;

    /* Open the directory */
    if (!(dir = libos_opendir(root)))
        goto done;

    /* For each entry */
    while ((ent = libos_readdir(dir)))
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        strlcpy(path, root, sizeof(path));

        if (strcmp(root, "/") != 0)
            strlcat(path, "/", sizeof(path));

        strlcat(path, ent->d_name, sizeof(path));

        /* Append to paths[] array */
        if (libos_strarr_append(paths, path) != 0)
            goto done;

        /* Append to dirs[] array */
        if (ent->d_type & DT_DIR)
        {
            if (libos_strarr_append(&dirs, path) != 0)
                goto done;
        }
    }

    /* Recurse into child directories */
    {
        size_t i;

        for (i = 0; i < dirs.size; i++)
        {
            if (libos_lsr(dirs.data[i], paths) != 0)
                goto done;
        }
    }

    ret = 0;

done:

    if (dir)
        libos_closedir(dir);

    libos_strarr_release(&dirs);

    if (ret != 0 && paths != NULL)
    {
        libos_strarr_release(paths);
        memset(paths, 0, sizeof(libos_strarr_t));
    }

    return ret;
}
