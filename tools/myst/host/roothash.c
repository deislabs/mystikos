// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <myst/file.h>
#include <myst/hex.h>
#include <myst/strings.h>
#include "roothash.h"
#include "utils.h"

/* load a file containing an ASCII SHA-256 hash into a binary hash */
static int _load_hash_file(const char* path, myst_sha256_t* hash)
{
    int ret = 0;
    int r;
    void* data = NULL;
    size_t size = 0;

    if (!path || !hash)
    {
        ret = -EINVAL;
        goto done;
    }

    /* load the file into memory */
    if ((r = myst_load_file(path, &data, &size)) < 0)
    {
        ret = r;
        goto done;
    }

    /* covert ASCII data to binary SHA-256 */
    {
        char* p = (char*)data;
        char* end = (char*)data + size;
        const size_t n = MYST_SHA256_SIZE;

        /* remove leading space */
        while (*p && isspace(*p))
            p++;

        /* remove trailing space */
        while (end != p && isspace(end[-1]))
            *--end = '\0';

        /* check the length of the ASCII string */
        if (strlen(p) != MYST_SHA256_ASCII_LENGTH)
        {
            ret = -EINVAL;
            goto done;
        }

        if (myst_ascii_to_bin(p, hash->data, n) != n)
        {
            ret = -EINVAL;
            goto done;
        }
    }

done:

    if (data)
        free(data);

    return ret;
}

void get_roothash_options(int* argc, const char* argv[], myst_buf_t* buf)
{
    /* process all --roothash=<filename> options */
    {
        const char* arg = NULL;

        while (cli_getopt(argc, argv, "--roothash", &arg) == 0)
        {
            myst_sha256_t hash;

            if (_load_hash_file(arg, &hash) != 0)
                _err("failed to load hash file: --roothash=%s", arg);

            if (myst_buf_append(buf, &hash, sizeof(hash)) != 0)
                _err("out of memory");
        }
    }
}

int extract_roothashes_from_ext2_images(
    const char* rootfs,
    const myst_args_t* mount_mappings,
    myst_buf_t* buf)
{
    ssize_t ret = 0;
    size_t num_roothashes = 0;
    myst_fssig_t fssig;

    if (!rootfs || !buf)
    {
        ret = -EINVAL;
        goto done;
    }

    /* if an ext2 rootfs, then extract the roothash */
    if (myst_load_fssig(rootfs, &fssig) == 0)
    {
        if (myst_buf_append(buf, fssig.root_hash, sizeof(myst_sha256_t)) != 0)
        {
            ret = -ENOMEM;
            goto done;
        }
    }

    /* extract roothashes for any ext2 mount mappings */
    {
        const size_t count = mount_mappings->size;
        const char** mounts = mount_mappings->data;

        for (size_t i = 0; i < count; i++)
        {
            char path[2 * PATH_MAX + 1];
            char* eq;

            myst_strlcpy(path, mounts[i], sizeof(path));

            if (!(eq = strchr(path, '=')))
            {
                ret = -EINVAL;
                goto done;
            }

            *eq = '\0';

            if (myst_load_fssig(path, &fssig) == 0)
            {
                if (myst_buf_append(
                        buf, fssig.root_hash, sizeof(myst_sha256_t)) != 0)
                {
                    ret = -ENOMEM;
                    goto done;
                }
            }
        }
    }

    ret = num_roothashes;

done:
    return ret;
}

int create_roothashes_file(myst_buf_t* buf, char filename[PATH_MAX])
{
    int ret = 0;
    char template[] = "/tmp/mystXXXXXX";
    int fd = -1;

    if (!buf || !filename)
    {
        ret = -EINVAL;
        goto done;
    }

    if ((fd = mkstemp(template)) < 0)
    {
        ret = -EIO;
        goto done;
    }

    if (myst_write_file_fd(fd, buf->data, buf->size) != 0)
    {
        ret = -EIO;
        goto done;
    }

    myst_strlcpy(filename, template, PATH_MAX);

done:

    if (fd >= 0)
        close(fd);

    return ret;
}
