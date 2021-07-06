// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <myst/cpio.h>
#include <myst/file.h>

int main(int argc, const char* argv[])
{
    myst_buf_t buf = MYST_BUF_INITIALIZER;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <cpio-infile> <cpio-outfile>\n", argv[0]);
        return 1;
    }

    if (myst_cpio_deflate(argv[1], &buf) != 0)
    {
        fprintf(stderr, "deflate failed\n");
        exit(1);
    }

    if (myst_write_file(argv[2], buf.data, buf.size) != 0)
    {
        fprintf(stderr, "write file failed\n");
        exit(1);
    }

    return 0;
}
