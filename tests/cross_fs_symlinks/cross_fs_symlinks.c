// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#define EXT2_S_MAGIC 0xEF53
#define RAMFS_MAGIC 0x858458f6

#define MNT_CPIO_SRC "/cpio_image"
#define MNT_TARGET "/mnt"

void setup_mount()
{
    assert(mkdir(MNT_TARGET, 0777) == 0);
    assert(mount(MNT_CPIO_SRC, MNT_TARGET, "ramfs", 0, NULL) == 0);

    {
        struct statfs buf;
        assert(statfs("/mnt/", &buf) == 0);
        assert(buf.f_type == RAMFS_MAGIC);
    }

    assert(mkdir("/datadir", 0777) == 0);
}

void test_dir_target(const char* rootfs_type)
{
    assert(symlink("/datadir", "/mnt/datadir-slink") == 0);
    assert(mkdir("/mnt/datadir-slink/subdir", 0777) == 0);

    // create regular file - "file1", under /datadir/subdir via the symlink
    {
        int fd;
        const char alpha[] = "abcdefghijklmnopqrstuvwxyz";
        char buf[BUFSIZ];
        mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        assert(
            (fd = open(
                 "/mnt/datadir-slink/subdir/file1",
                 O_CREAT | O_RDWR | O_TRUNC,
                 mode)) > 0);
        assert(write(fd, alpha, sizeof(alpha)) > 0);
        assert(lseek(fd, 0L, 0) == 0);
        assert(read(fd, buf, BUFSIZ) > 0);
        assert(close(fd) == 0);
    }

    {
        assert(truncate("/mnt/datadir-slink/subdir/file1", 0) == 0);
        struct stat statbuf;
        assert(stat("/mnt/datadir-slink/subdir/file1", &statbuf) == 0);
        assert(statbuf.st_size == 0);
    }

    {
        struct statfs buf;
        assert(statfs("/mnt/datadir-slink/subdir/file1", &buf) == 0);
        if (strcmp(rootfs_type, "ramfs") == 0)
            assert(buf.f_type == RAMFS_MAGIC);
        else if (strcmp(rootfs_type, "ext2") == 0)
            assert(buf.f_type == EXT2_S_MAGIC);
    }

    // create symlink to file1 via the directory symlink
    {
        assert(
            symlink(
                "/mnt/datadir-slink/subdir/file1",
                "/mnt/datadir-slink/subdir/file1-slink") == 0);
        int ret;
        char buf[128];
        assert(
            (ret = readlink(
                 "/mnt/datadir-slink/subdir/file1-slink", buf, sizeof(buf))) >
            0);
        printf("buf{%.*s}\n", ret, buf);

        FILE* f = fopen("/mnt/datadir-slink/subdir/file1-slink", "r");
        assert(f);
        fgets(buf, sizeof(buf), f);
        printf("%s\n", buf);
    }

    // cleanup
    {
        assert(unlink("/mnt/datadir-slink/subdir/file1") == 0);
        assert(unlink("/mnt/datadir-slink/subdir/file1-slink") == 0);
        struct stat statbuf;
        assert(stat("/mnt/datadir-slink/subdir/file1", &statbuf) == -1);
        assert(errno == ENOENT);
        assert(rmdir("/mnt/datadir-slink/subdir") == 0);
    }
}

void test_file_target()
{
    {
        int fd;
        const char alpha[] = "abcdefghijklmnopqrstuvwxyz";
        mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        assert(
            (fd = open("/datadir/file2", O_CREAT | O_RDWR | O_TRUNC, mode)) >
            0);
        assert(write(fd, alpha, sizeof(alpha)) > 0);
        assert(close(fd) == 0);
    }

    struct stat statbuf;

    assert(symlink("/datadir/file2", "/mnt/file2-slink") == 0);
    assert(lstat("/datadir/file2", &statbuf) == 0);

    {
        int ret;
        char buf[128];
        assert((ret = readlink("/mnt/file2-slink", buf, sizeof(buf))) > 0);
        assert(ret == strlen("/datadir/file2"));
        assert(strncmp(buf, "/datadir/file2", ret) == 0);

        FILE* f = fopen("/mnt/file2-slink", "r");
        assert(f);
        fgets(buf, sizeof(buf), f);
        printf("%s\n", buf);
    }
}

int main(int argc, const char* argv[])
{
    if (argc != 2 && (!strcmp(argv[1], "ramfs") || !strcmp(argv[1], "ext2")))
    {
        exit(1);
    }

    setup_mount();
    test_dir_target(argv[1]);
    test_file_target();
    umount(MNT_TARGET);

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
