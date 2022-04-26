// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

// This checks if file contains text "myfile"
int validate_file(const char filename[])
{
    const size_t filesize = 7;

    if (access(filename, R_OK) != 0)
        assert(false);

    /* read a file on the mounted file system */
    {
        int fd;
        struct stat st;
        char buf[128];

        assert((fd = open(filename, O_RDONLY)) >= 0);
        assert(stat(filename, &st) == 0);
        assert(st.st_size == filesize);
        assert(read(fd, buf, sizeof(buf)) == filesize);
        assert(memcmp(buf, "myfile", 6) == 0);
        assert(close(fd) == 0);
    }

    return 0;
}

int test_mount_and_access()
{
    const char filename[] = "/mnt/datafs/myfile";

    if (mount("/ramfs", "/mnt/datafs", "ramfs", 0, NULL) != 0)
    {
        printf("errno: %d\n", errno);
        assert(false);
    }

    validate_file(filename);

    if (umount("/mnt/datafs") != 0)
        assert(false);

    return 0;
}

int test_access_hostfs()
{
    return validate_file("/mnt/hostfs/myfile");
}

int test_access_ramfs()
{
    return validate_file("/mnt/ramfs/myfile");
}

int test_access_ext2fs()
{
    return validate_file("/mnt/ext2fs/myfile");
}

int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        printf("Usage: ./program [hostfs|ramfs|ext2fs]\n");
        return 1;
    }

    test_mount_and_access();

    if (0 == strcmp(argv[1], "hostfs"))
    {
        test_access_hostfs();
    }
    else if (0 == strcmp(argv[1], "ramfs"))
    {
        test_access_ramfs();
    }
    else if (0 == strcmp(argv[1], "ext2fs"))
    {
        test_access_ext2fs();
    }

    printf("=== passed test (%s)\n", argv[0]);
}