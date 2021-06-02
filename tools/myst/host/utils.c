// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _XOPEN_SOURCE 500
#include <errno.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <malloc.h>
#include <myst/getopt.h>
#include <myst/strings.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "utils.h"

static int _which(const char* program, char buf[PATH_MAX])
{
    int ret = -1;
    char path[PATH_MAX];

    if (buf)
        *buf = '\0';

    if (!program || !buf)
        goto done;

    /* If the program has slashes the use realpath */
    if (strchr(program, '/'))
    {
        char current[PATH_MAX];

        if (!realpath(program, current))
            goto done;

        if (access(current, X_OK) == 0)
        {
            myst_strlcpy(buf, current, PATH_MAX);
            ret = 0;
            goto done;
        }

        goto done;
    }

    /* Get the PATH environment variable */
    {
        const char* p;

        if (!(p = getenv("PATH")) || strlen(p) >= PATH_MAX)
            goto done;

        myst_strlcpy(path, p, sizeof(path));
    }

    /* Search the PATH for the program */
    {
        char* p;
        char* save;

        for (p = strtok_r(path, ":", &save); p; p = strtok_r(NULL, ":", &save))
        {
            char current[PATH_MAX];
            int n;

            n = snprintf(current, sizeof(current), "%s/%s", p, program);
            if (n >= sizeof(current))
                goto done;

            if (access(current, X_OK) == 0)
            {
                myst_strlcpy(buf, current, PATH_MAX);
                ret = 0;
                goto done;
            }
        }
    }

    /* not found */

done:
    return ret;
}

char _program[PATH_MAX];

const char* set_program_file(const char* program)
{
    if (_which(program, _program) != 0)
    {
        return NULL;
    }
    else
    {
        return _program;
    }
}

const char* get_program_file()
{
    return _program;
}

static const int _format_lib(char* path, size_t size, const char* suffix)
{
    int ret = 0;
    char buf[PATH_MAX];
    char* dir1;
    char* dir2;
    int n;

    if (!path || !size || !suffix)
    {
        ret = -EINVAL;
        goto done;
    }

    if (myst_strlcpy(buf, _program, sizeof(buf)) >= sizeof(buf))
    {
        ret = -ENAMETOOLONG;
        goto done;
    }

    if (!(dir1 = dirname(buf)) || !(dir2 = dirname(dir1)))
    {
        ret = -EINVAL;
        goto done;
    }

    if ((n = snprintf(path, size, "%s/%s", dir2, suffix)) >= size)
    {
        ret = -ENAMETOOLONG;
        goto done;
    }

done:
    return ret;
}

const int format_mystenc(char* path, size_t size)
{
    return _format_lib(path, size, "lib/openenclave/mystenc.so");
}

const int format_libmystcrt(char* path, size_t size)
{
    return _format_lib(path, size, "lib/libmystcrt.so");
}

const int format_libmystkernel(char* path, size_t size)
{
    return _format_lib(path, size, "lib/libmystkernel.so");
}

__attribute__((format(printf, 1, 2))) void _err(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", get_program_file());
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    exit(1);
}

int unlink_cb(
    const char* fpath,
    const struct stat* sb,
    int typeflag,
    struct FTW* ftwbuf)
{
    int rv = remove(fpath);

    if (rv)
        perror(fpath);

    return rv;
}

// delete a directory and anything in it
// NOTE: this is not thread safe!
int remove_recursive(const char* path)
{
    return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

int cli_getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    char err[128];
    int ret;

    ret = myst_getopt(argc, argv, opt, optarg, err, sizeof(err));

    if (ret < 0)
        _err("%s", err);

    return ret;
}

#define MAX_MAPPINGS 8
int cli_get_mapping_opts(
    int* argc,
    const char* argv[],
    myst_host_enc_uid_gid_mappings* uid_gid_mappings)
{
    {
        const char* arg = NULL;
        if (cli_getopt(argc, argv, "--host-to-enc-uid-map", &arg) == 0)
        {
            int i = 0;
            const char comma[2] = ",";
            uid_t enc_uid, host_uid;
            char* token;
            char* arg_copy = strdup(arg);

            token = strtok((char*)arg_copy, comma);
            while (token != NULL)
            {
                if (i >= MAX_ID_MAPPINGS)
                {
                    free(arg_copy);
                    _err(
                        "Uid mappings exceed %d max mappings", MAX_ID_MAPPINGS);
                }
                int ret = sscanf(token, "%d:%d", &host_uid, &enc_uid);
                if (ret != 2)
                {
                    _err("Failed to parse --host-to-enc-uid-map "
                         "<host_uid>:<enc_uid>");
                }
                uid_gid_mappings->uid_mappings[i].enc_uid = enc_uid;
                uid_gid_mappings->uid_mappings[i].host_uid = host_uid;
                i++;

                token = strtok(NULL, comma);
            }
            uid_gid_mappings->num_uid_mappings = i;
            free(arg_copy);
        }
        else
        {
            uid_gid_mappings->uid_mappings[0].enc_uid = 0;
            uid_gid_mappings->uid_mappings[0].host_uid = geteuid();
            uid_gid_mappings->num_uid_mappings = 1;
        }
    }
    {
        const char* arg = NULL;
        if (cli_getopt(argc, argv, "--host-to-enc-gid-map", &arg) == 0)
        {
            int i = 0;
            const char comma[2] = ",";
            gid_t enc_gid, host_gid;
            char* token;
            char* arg_copy = strdup(arg);

            token = strtok((char*)arg, comma);
            while (token != NULL)
            {
                if (i >= MAX_MAPPINGS)
                {
                    free(arg_copy);
                    _err("Gid mappings exceed %d max mappings", MAX_MAPPINGS);
                }

                int ret = sscanf(token, "%d:%d", &host_gid, &enc_gid);
                if (ret != 2)
                {
                    _err("Failed to parse --host-to-enc-gid-map "
                         "<host_gid>:<enc_gid>");
                }
                uid_gid_mappings->gid_mappings[i].enc_gid = enc_gid;
                uid_gid_mappings->gid_mappings[i].host_gid = host_gid;
                i++;

                token = strtok(NULL, comma);
            }
            uid_gid_mappings->num_gid_mappings = i;
            free(arg_copy);
        }
        else
        {
            uid_gid_mappings->gid_mappings[0].enc_gid = 0;
            uid_gid_mappings->gid_mappings[0].host_gid = getegid();
            uid_gid_mappings->num_gid_mappings = 1;
        }
    }
    return 0;
}

int cli_get_mount_mapping_opts(
    int* argc,
    const char* argv[],
    myst_mount_mapping_t* mappings)
{
    bool found;

    do
    {
        const char* arg = NULL;

        found = false;
        if (cli_getopt(argc, argv, "--mount", &arg) == 0)
        {
            if (mappings->mounts_count == 0)
            {
                mappings->mounts = calloc(1, sizeof(char*));
                if (mappings->mounts == NULL)
                    _err("Out of memory\n");
            }
            else
            {
                char** tmp = reallocarray(
                    mappings->mounts,
                    mappings->mounts_count + 1,
                    sizeof(char*));
                if (tmp == NULL)
                    _err("Out of memory\n");
                mappings->mounts = tmp;
            }
            mappings->mounts[mappings->mounts_count] = strdup(arg);
            mappings->mounts_count++;
            found = 1;
        }
    } while (found);

    return 0;
}

void free_mount_mapping_opts(myst_mount_mapping_t* mappings)
{
    if (mappings->mounts)
    {
        int i;
        for (i = 0; i < mappings->mounts_count; i++)
        {
            free(mappings->mounts[i]);
        }
        free(mappings->mounts);
    }
}
