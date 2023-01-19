// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "cpio.h"
#include <assert.h>
#include <myst/cpio.h>
#include <myst/file.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

#define USAGE_EXCPIO \
    "\
\n\
Usage: %s excpio <cpioarchive> <directory> [options]\n\
\n\
Where:\n\
    excpio        -- extract the CPIO archive into an application directory\n\
    <cpioarchive> -- the CPIO archive file to extract\n\
    <directory>   -- the directory to extract the CPIO archive into\n\
\n\
and <options> are one of:\n\
    --help        -- this message\n\
\n\
"

#define USAGE_MKCPIO \
    "\
\n\
Usage: %s mkcpio <directory> <cpioarchive> [options]\n\
\n\
Where:\n\
    mkcpio        -- create a CPIO archive from an application directory\n\
    <directory>   -- the directory to be recursively added to the CPIO archive\n\
    <cpioarchive> -- the output CPIO archive file name\n\
\n\
and <options> are one of:\n\
    --help        -- this message\n\
\n\
"

int _mkcpio(int argc, const char* argv[])
{
    assert(strcmp(argv[1], "mkcpio") == 0);

    if (argc != 4)
    {
        fprintf(stderr, USAGE_MKCPIO, argv[0]);
        return 1;
    }

    const char* directory = argv[2];
    const char* cpioarchive = argv[3];

    if (myst_cpio_pack(directory, cpioarchive) != 0)
    {
        _err(
            "failed to create CPIO archive from %s: %s",
            directory,
            cpioarchive);
        return 1;
    }

    return 0;
}

int _excpio(int argc, const char* argv[])
{
    assert(strcmp(argv[1], "excpio") == 0);

    if (argc != 4)
    {
        fprintf(stderr, USAGE_EXCPIO, argv[0]);
        return 1;
    }

    const char* cpioarchive = argv[2];
    const char* directory = argv[3];

    assert(myst_validate_file_path(cpioarchive));
    if (myst_cpio_unpack(cpioarchive, directory) != 0)
    {
        _err(
            "failed to extract CPIO archive to %s: %s", directory, cpioarchive);
        return 1;
    }

    return 0;
}
