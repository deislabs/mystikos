#include <libos/file.h>
#include <libos/lsr.h>
#include <libos/strings.h>
#include <stddef.h>
#include <string.h>

int libos_lsr(const char* root, libos_strarr_t* paths, bool include_dirs)
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
    if (!(dir = opendir(root)))
        goto done;

    /* For each entry */
    while ((ent = readdir(dir)))
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
        {
            continue;
        }

        libos_strlcpy(path, root, sizeof(path));

        if (strcmp(root, "/") != 0)
            libos_strlcat(path, "/", sizeof(path));

        libos_strlcat(path, ent->d_name, sizeof(path));

        /* Append to dirs[] array */
        if (ent->d_type & DT_DIR)
        {
            if (libos_strarr_append(&dirs, path) != 0)
                goto done;

            if (include_dirs)
            {
                /* Append to paths[] array */
                if (libos_strarr_append(paths, path) != 0)
                    goto done;
            }
        }
        else
        {
            /* Append to paths[] array */
            if (libos_strarr_append(paths, path) != 0)
                goto done;
        }
    }

    /* Recurse into child directories */
    {
        size_t i;

        for (i = 0; i < dirs.size; i++)
        {
            if (libos_lsr(dirs.data[i], paths, include_dirs) != 0)
                goto done;
        }
    }

    ret = 0;

done:

    if (dir)
        closedir(dir);

    libos_strarr_release(&dirs);

    if (ret != 0 && paths != NULL)
    {
        libos_strarr_release(paths);
        memset(paths, 0, sizeof(libos_strarr_t));
    }

    return ret;
}
