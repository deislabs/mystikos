// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <libos/cpio.h>
#include "cpio.h"
#include "utils.h"

int _mkcpio(int argc, const char* argv[])
{
    assert(strcmp(argv[1], "mkcpio") == 0);

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s %s <directory> <cpioarchive>\n",
            argv[0], argv[1]);
        return 1;
    }

    const char* directory = argv[2];
    const char* cpioarchive = argv[3];

    if (libos_cpio_pack(directory, cpioarchive) != 0)
    {
        _err("failed to create CPIO archive from %s: %s", directory, cpioarchive);
        return 1;
    }

    return 0;
}

int _excpio(int argc, const char* argv[])
{
    assert(strcmp(argv[1], "excpio") == 0);

    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s %s <cpioarchive> <directory>\n",
            argv[0], argv[1]);
        return 1;
    }

    const char* cpioarchive = argv[2];
    const char* directory = argv[3];

    if (libos_cpio_unpack(cpioarchive, directory) != 0)
    {
        _err("failed to extract CPIO archive to %s: %s", directory, cpioarchive);
        return 1;
    }

    return 0;
}