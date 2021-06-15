// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <myst/blkdev.h>
#include <myst/ext2.h>
#include <myst/fs.h>
#include <myst/fssig.h>

uid_t myst_syscall_geteuid(void)
{
    return geteuid();
}

gid_t myst_syscall_getegid(void)
{
    return getegid();
}

int check_thread_group_membership(gid_t group)
{
    return 1;
}

typedef struct
{
} myst_thread_t;

myst_thread_t* myst_thread_self()
{
    return NULL;
}

int main(int argc, const char* argv[])
{
    uint8_t buf[4096];
    myst_blkdev_t* dev;
    myst_fs_t* fs;
    myst_fssig_t fssig;
    bool have_root_hash = false;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <ext2fs>\n", argv[0]);
        exit(1);
    }

    if (myst_load_fssig(argv[1], &fssig) == 0)
    {
        have_root_hash = true;
        assert(
            myst_verityblkdev_open(
                argv[1],
                fssig.hash_offset,
                fssig.root_hash,
                MYST_SHA256_SIZE,
                &dev) == 0);
    }
    else
    {
        assert(myst_rawblkdev_open(argv[1], true, 0, &dev) == 0);
    }

    if (ext2_create(dev, &fs, NULL) != 0)
    {
        fprintf(stderr, "%s: ext2_create() failed\n", argv[0]);
        exit(1);
    }

    /* read the file */
    {
        myst_file_t* file;
        char buf[4096];
        ssize_t n;
        ssize_t m = 0;

        assert(ext2_open(fs, "/bigfile", O_RDONLY, 0000, NULL, &file) == 0);

        while ((n = ext2_read(fs, file, buf, sizeof(buf))) > 0)
        {
            m += n;
        }

        printf("total size=%zd\n", m);

        ext2_close(fs, file);
    }

    ext2_release(fs);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
