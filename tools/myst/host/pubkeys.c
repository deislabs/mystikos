// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <myst/buf.h>
#include <myst/cpio.h>
#include <myst/file.h>
#include <myst/getopt.h>
#include <myst/paths.h>
#include <myst/pubkey.h>
#include <myst/round.h>
#include <myst/strings.h>

#include "pubkeys.h"
#include "utils.h"

static int _getopt(
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

void get_pubkeys_options(
    int* argc,
    const char* argv[],
    const char* pubkeys[],
    size_t max_pubkeys,
    size_t* num_pubkeys_out)
{
    const char* pubkey;
    size_t num_pubkeys = 0;

    while (_getopt(argc, argv, "--pubkey", &pubkey) == 0)
    {
        struct stat statbuf;

        if (num_pubkeys == max_pubkeys)
            _err("too many --pubkey options (> %zu)", max_pubkeys);

        if (stat(pubkey, &statbuf) != 0)
            _err("no such file for --pubkey options: %s", pubkey);

        pubkeys[num_pubkeys++] = pubkey;
    }

    *num_pubkeys_out = num_pubkeys;
}

void create_pubkeys_file(
    const char* pubkeys[],
    size_t num_pubkeys,
    char pubkeys_path[PATH_MAX])
{
    int fd = -1;
    char template[] = "/tmp/mystXXXXXX";
    myst_buf_t buf = MYST_BUF_INITIALIZER;
    void* data = NULL;
    size_t size;

    /* open the pubkeys file */
    if ((fd = mkstemp(template)) < 0)
        _err("failed to create temporary file");

    /* build the pubkeys region: ([header][pubkey])+ */
    for (size_t i = 0; i < num_pubkeys; i++)
    {
        /* this function allocates space for a zero-terminator */
        assert(myst_validate_file_path(pubkeys[i]));
        if (myst_load_file(pubkeys[i], &data, &size) != 0)
            _err("failed to read file given by --pubkey=%s", pubkeys[i]);

        /* append the pubkey itself (including the zero-terminator) */
        if (myst_buf_append(&buf, data, size + 1) != 0)
            _err("out of memory");
    }

    /* write the file */
    if (myst_write_file_fd(fd, buf.data, buf.size) != 0)
        _err("failed to write pubkeys temporary file: %s", template);

    myst_strlcpy(pubkeys_path, template, PATH_MAX);

    close(fd);
    free(buf.data);
}
