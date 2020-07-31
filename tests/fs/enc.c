// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <libos/ramfs.h>
#include <stdlib.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "run_t.h"

int run_ecall(void)
{
    libos_fs_t* fs;
    libos_file_t* file = NULL;
    const char alpha[] = "abcdefghijklmnopqrstuvwxyz";
    const char ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    if (libos_init_ramfs(&fs) != 0)
    {
        fprintf(stderr, "libos_init_ramfs() failed\n");
        abort();
    }

    assert(fs != NULL);

    /* Open the root directory */
    {
        if ((*fs->fs_open)(fs, "/", O_RDONLY, 0, &file) != 0)
        {
            fprintf(stderr, "fs_open() failed\n");
            abort();
        }

        assert(file != NULL);
    }

    /* Read the directory entries in the root directory */
    {
        size_t i = 0;
        ssize_t n;
        struct dirent buf;

        while ((n = (*fs->fs_read)(fs, file, &buf, sizeof(buf))) > 0)
        {
            assert(n == sizeof(buf));

            if (i == 0)
            {
                assert(strcmp(buf.d_name, ".") == 0);
            }
            else if (i == 1)
            {
                assert(strcmp(buf.d_name, "..") == 0);
            }

            i++;
        }
    }

    /* Close the root directory */
    {
        if ((*fs->fs_close)(fs, file) != 0)
        {
            fprintf(stderr, "fs_close() failed\n");
            abort();
        }

        file = NULL;
    }

    /* Open a new file */
    {
        int flags = O_WRONLY | O_CREAT;

        if ((*fs->fs_open)(fs, "/file", flags, 0, &file) != 0)
        {
            fprintf(stderr, "fs_open() failed\n");
            abort();
        }
    }

    /* Write to the new file */
    {
        if ((*fs->fs_write)(fs, file, alpha, sizeof(alpha)) != sizeof(alpha))
        {
            fprintf(stderr, "fs_write() failed\n");
            abort();
        }

        if ((*fs->fs_write)(fs, file, ALPHA, sizeof(ALPHA)) != sizeof(ALPHA))
        {
            fprintf(stderr, "fs_write() failed\n");
            abort();
        }
    }

    /* Close the file */
    if ((*fs->fs_close)(fs, file) != 0)
    {
        fprintf(stderr, "fs_close() failed\n");
        abort();
    }

    /* Reopen the file */
    if ((*fs->fs_open)(fs, "/file", O_RDONLY, 0, &file) != 0)
    {
        fprintf(stderr, "fs_open() failed\n");
        abort();
    }

    /* Read the file */
    {
        char buf[sizeof(alpha)];

        if ((*fs->fs_read)(fs, file, buf, sizeof(buf)) != sizeof(buf))
        {
            fprintf(stderr, "fs_read() failed\n");
            abort();
        }

        assert(strcmp(buf, alpha) == 0);

        if ((*fs->fs_read)(fs, file, buf, sizeof(buf)) != sizeof(buf))
        {
            fprintf(stderr, "fs_read() failed\n");
            abort();
        }

        assert(strcmp(buf, ALPHA) == 0);
    }

    /* test stat() */
    {
        struct stat buf;

        if ((*fs->fs_fstat)(fs, file, &buf) != 0)
        {
            fprintf(stderr, "fs_stat() failed\n");
            abort();
        }

        assert(buf.st_size = sizeof(alpha) + sizeof(ALPHA));
        assert(buf.st_blksize == 512);
        assert(buf.st_blocks == 1);
    }

    if ((*fs->fs_close)(fs, file) != 0)
    {
        fprintf(stderr, "fs_close() failed\n");
        abort();
    }

    /* Release the file system */
    if ((*fs->fs_release)(fs) != 0)
    {
        fprintf(stderr, "fs_close() failed\n");
        abort();
    }

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    2);   /* NumTCS */
