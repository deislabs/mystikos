// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <myst/file.h>
#include <myst/lsr.h>
#include <myst/strings.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int myst_lsr(const char* root, myst_strarr_t* paths, bool include_dirs)
{
    int ret = -1;
    DIR* dir = NULL;
    struct dirent* ent;
    myst_strarr_t dirs = MYST_STRARR_INITIALIZER;
    struct vars
    {
        char path[PATH_MAX];
    };
    struct vars* v = NULL;

    /* Check parameters */
    if (!root || !paths)
        goto done;

    if (!(v = malloc(sizeof(struct vars))))
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

        myst_strlcpy(v->path, root, sizeof(v->path));

        if (strcmp(root, "/") != 0)
            myst_strlcat(v->path, "/", sizeof(v->path));

        myst_strlcat(v->path, ent->d_name, sizeof(v->path));

        /* Append to dirs[] array */
        if (ent->d_type & DT_DIR)
        {
            if (myst_strarr_append(&dirs, v->path) != 0)
                goto done;

            if (include_dirs)
            {
                /* Append to paths[] array */
                if (myst_strarr_append(paths, v->path) != 0)
                    goto done;
            }
        }
        else
        {
            /* Append to paths[] array */
            if (myst_strarr_append(paths, v->path) != 0)
                goto done;
        }
    }

    /* Recurse into child directories */
    {
        size_t i;

        for (i = 0; i < dirs.size; i++)
        {
            if (myst_lsr(dirs.data[i], paths, include_dirs) != 0)
                goto done;
        }
    }

    ret = 0;

done:

    if (v)
        free(v);

    if (dir)
        closedir(dir);

    myst_strarr_release(&dirs);

    if (ret != 0 && paths != NULL)
    {
        myst_strarr_release(paths);
        memset(paths, 0, sizeof(myst_strarr_t));
    }

    return ret;
}
