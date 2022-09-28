// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _XOPEN_SOURCE 500
#include <ctype.h>
#include <errno.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include <myst/args.h>
#include <myst/getopt.h>
#include <myst/strings.h>
#include <myst/which.h>

#include "../shared.h"
#include "utils.h"

char _program[PATH_MAX];

const char* set_program_file(const char* program)
{
    if (myst_which(program, _program) != 0)
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

__attribute__((format(printf, 1, 2))) void _err_noexit(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", get_program_file());
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
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
    myst_args_t* mounts_buff)
{
    bool found;

    do
    {
        const char* arg = NULL;

        found = false;
        if (cli_getopt(argc, argv, "--mount", &arg) == 0)
        {
            myst_args_append1(mounts_buff, arg);
            found = 1;
        }
    } while (found);

    return 0;
}

int get_fork_mode_opts(
    int* argc,
    const char* argv[],
    myst_fork_mode_t* fork_mode)
{
    const char* arg = NULL;

    if (fork_mode == 0)
        return -1;

    *fork_mode = myst_fork_none;

    if (cli_getopt(argc, argv, "--fork-mode", &arg) == 0)
    {
        if (arg == NULL)
            return -1;

        if (strcmp(arg, "none") == 0)
        {
            *fork_mode = myst_fork_none;
        }
        else if (strcmp(arg, "pseudo") == 0)
        {
            *fork_mode = myst_fork_pseudo;
        }
        else if (strcmp(arg, "pseudo_wait_for_exit_exec") == 0)
        {
            *fork_mode = myst_fork_pseudo_wait_for_exit_exec;
        }
        else
            return -1;
    }

    return 0;
}

/* if --syslog-level=<arg> option present and arg is one of the valid values - 0
 * through 7, returns 0 and sets the syslog_level pointer. For other values of
 * arg, returns -1. If --syslog-level option not present, sets syslog_level to
 * -1.
 */
int get_syslog_level_opts(int* argc, const char* argv[], int* syslog_level)
{
    const char* arg = NULL;

    if (syslog_level == 0)
        return -1;

    *syslog_level = -1;

    if (cli_getopt(argc, argv, "--syslog-level", &arg) == 0)
    {
        if (arg == NULL)
            return -1;

        *syslog_level = myst_syslog_level_str_to_int(arg);
        if (*syslog_level == -1)
            // unknown syslog level
            return -1;
    }

    return 0;
}
