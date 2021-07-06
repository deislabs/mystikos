// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "cpio.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

#include <myst/cpio.h>
#include <myst/file.h>

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
    bool deflate = false;

    assert(strcmp(argv[1], "mkcpio") == 0);

    /* Get --shell option */
    if (cli_getopt(&argc, argv, "--deflate", NULL) == 0)
        deflate = true;

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

    // if the --deflate option is present, then append a deflated archive to
    // the existing CPI archive file. The resulting layout will be:
    //
    //     [CPIO archive][deflated CPIO archive][deflated trailer]
    //
    if (deflate)
    {
        myst_buf_t buf = MYST_BUF_INITIALIZER;
        int fd;

        /* deflate the CPIO archive into a buffer */
        if (myst_cpio_deflate(cpioarchive, &buf) != 0)
            _err("failed to deflate %s", cpioarchive);

        /* open the CPIO archive for append */
        if ((fd = open(cpioarchive, O_WRONLY | O_APPEND)) < 0)
            _err("failed to open file for write: %s\n", cpioarchive);

        /* append the deflated cpio archive */
        if (myst_write_file_fd(fd, buf.data, buf.size) != 0)
            _err("failed to append deflated CPIO archive: %s", cpioarchive);

        /* append the deflated trailer to the CPIO archive (unaligned) */
        {
            myst_cpio_deflate_trailer_t trailer = {
                .magic = MYST_CPIO_DEFLATE_TRAILER_MAGIC,
                .size = buf.size,
            };

            if (myst_write_file_fd(fd, &trailer, sizeof(trailer)) != 0)
                _err("failed to append deflated CPIO archive: %s", cpioarchive);
        }

        myst_buf_release(&buf);
        close(fd);
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

    if (myst_cpio_unpack(cpioarchive, directory) != 0)
    {
        _err(
            "failed to extract CPIO archive to %s: %s", directory, cpioarchive);
        return 1;
    }

    return 0;
}
