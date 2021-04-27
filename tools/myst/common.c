// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shared.h"

int myst_expand_size_string_to_ulong(const char* size_string, size_t* size)
{
    char* endptr = NULL;
    *size = strtoul(size_string, &endptr, 10);
    if (endptr[0] == '\0')
    {
        // nothing to do... in bytes
    }
    else if (strcasecmp(endptr, "k") == 0)
    {
        *size *= 1024;
    }
    else if (strcasecmp(endptr, "m") == 0)
    {
        *size *= 1024;
        *size *= 1024;
    }
    else if (strcasecmp(endptr, "g") == 0)
    {
        *size *= 1024;
        *size *= 1024;
        *size *= 1024;
    }
    else
    {
        return -1;
    }

    return 0;
}

bool myst_merge_mount_mapping_and_config(
    myst_mounts_config_t* mounts,
    myst_mount_mapping_t* mount_mapping)
{
    bool ret = false;

    for (size_t i = 0; i < mount_mapping->mounts_count; i++)
    {
        char* source;
        char* target;
        bool found = false;
        source = strtok(mount_mapping->mounts[i], "=");
        target = strtok(NULL, "");
        if (target)
        {
            for (size_t j = 0; j < mounts->mounts_count; j++)
            {
                if (strcmp(target, mounts->mounts[j].target) == 0)
                {
                    mounts->mounts[j].source = strdup(source);
                    if (mounts->mounts[j].source == NULL)
                    {
                        fprintf(
                            stderr,
                            "Failed to set up mounting configuration, out of "
                            "memory\n");
                        goto done;
                    }
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                fprintf(
                    stderr,
                    "Target mount point not found in configuration. source=%s, "
                    "target=%s\n",
                    source,
                    target);
                goto done;
            }
        }
        else
        {
            fprintf(
                stderr,
                "Failed to set up mounting configuration, cannot parse mount "
                "mapping %s\nFormat is source=target\n",
                source);
            goto done;
        }
    }
    ret = true;

done:

    return ret;
}

bool myst_validate_mount_config(myst_mounts_config_t* mounts)
{
    size_t i;

    for (i = 0; i < mounts->mounts_count; i++)
    {
        if (mounts->mounts[i].target && mounts->mounts[i].source &&
            mounts->mounts[i].fs_type)
        {
            if (mounts->mounts[i].flags_count)
            {
                fprintf(
                    stderr,
                    "Configuration: cannot add extra mount. source=%s, "
                    "target=%s, "
                    "type: %s. No flags are supported on this mount type\n",
                    mounts->mounts[i].source,
                    mounts->mounts[i].target,
                    mounts->mounts[i].fs_type);
                return false;
            }
            if (strcmp(mounts->mounts[i].fs_type, "ext2") == 0)
            {
                if (mounts->mounts[i].roothash || mounts->mounts[i].public_key)
                {
                    fprintf(
                        stderr,
                        "Configuration: cannot add extra mount. source=%s, "
                        "target=%s, "
                        "type: %s. The roothash and public key configuration "
                        "for this mount is not yet supported. Only unsigned "
                        "ext2 mounts are supported.\n",
                        mounts->mounts[i].source,
                        mounts->mounts[i].target,
                        mounts->mounts[i].fs_type);
                    return false;
                }
            }
            else if (mounts->mounts[i].roothash || mounts->mounts[i].public_key)
            {
                fprintf(
                    stderr,
                    "Configuration: cannot add extra mount. source=%s, "
                    "target=%s, "
                    "type: %s. The roothash and public key configuration is "
                    "only used for ext2 mounts.\n",
                    mounts->mounts[i].source,
                    mounts->mounts[i].target,
                    mounts->mounts[i].fs_type);
                return false;
            }
        }
        else if (!mounts->mounts[i].target)
        {
            fprintf(
                stderr,
                "Configuration: One of the mount configurations is missing "
                "the target path\n");
            return false;
        }
        else if (!mounts->mounts[i].source)
        {
            fprintf(
                stderr,
                "Configuration: Mount configurations is missing the source "
                "path for "
                "target %s. The source mapping needs to be given on the "
                "command line.\n",
                mounts->mounts[i].target);
            return false;
        }
        else if (!mounts->mounts[i].fs_type)
        {
            fprintf(
                stderr,
                "Configuration: Mount configurations is missing the filesystem "
                "type "
                "for target %s. \n",
                mounts->mounts[i].target);
            return false;
        }
    }

    return true;
}
