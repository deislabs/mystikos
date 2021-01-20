// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

const char alpha[] = "abcdefghijklmnopqrstuvwxyz";
const char ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

int main(int argc, const char* argv[])
{
    int fd;
    const char filename[] = "/mnt/host/file1";
    const char dirname[] = "/mnt/host/dir1";
    const char slinkname[] = "/mnt/host/link";

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s host-directory\n", argv[0]);
        exit(1);
    }

    /* mount the host directory */
    assert(mkdir("/mnt", 0777) == 0);
    assert(mkdir("/mnt/host", 0777) == 0);
    assert(mount(argv[1], "/mnt/host", "hostfs", 0, NULL) == 0);

    /* test creat() and write() */
    {
        assert((fd = creat(filename, 0666)) >= 0);
        assert(write(fd, alpha, sizeof(alpha)) == sizeof(alpha));
        assert(close(fd) == 0);
    }

    /* test read() */
    {
        char buf[sizeof(alpha)];

        memset(buf, 0, sizeof(buf));
        assert((fd = open(filename, O_RDONLY, 0)) >= 0);
        assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
        assert(close(fd) == 0);
        assert(strcmp(buf, alpha) == 0);
    }

    /* test access() */
    assert(access(filename, R_OK) == 0);

    /* test stat() */
    {
        struct stat buf;
        assert(stat(filename, &buf) == 0);
        assert(buf.st_size == sizeof(alpha));
    }

    /* test fstat() */
    {
        struct stat buf;
        assert((fd = open(filename, O_RDONLY, 0)) >= 0);
        assert(fstat(fd, &buf) == 0);
        assert(buf.st_size == sizeof(alpha));
        assert(close(fd) == 0);
    }

    /* test writev() */
    {
        struct iovec iov[2];
        const int iovcnt = sizeof(iov) / sizeof(iov[0]);
        const size_t n = 13;

        iov[0].iov_base = (void*)alpha;
        iov[0].iov_len = n;
        iov[1].iov_base = (void*)(alpha + n);
        iov[1].iov_len = sizeof(alpha) - n;

        assert((fd = creat(filename, 0666)) >= 0);
        assert(writev(fd, iov, iovcnt) == sizeof(alpha));

        assert(close(fd) == 0);
    }

    /* test readv() */
    {
        struct iovec iov[2];
        const int iovcnt = sizeof(iov) / sizeof(iov[0]);
        const size_t n = 13;
        char buf[sizeof(alpha)];

        iov[0].iov_base = (void*)buf;
        iov[0].iov_len = n;
        iov[1].iov_base = (void*)(buf + n);
        iov[1].iov_len = sizeof(buf) - n;

        assert((fd = open(filename, O_RDONLY, 0)) >= 0);
        assert(fcntl(fd, F_GETFL) >= 0);
        assert(readv(fd, iov, iovcnt) == sizeof(alpha));
        assert(memcmp(buf, alpha, n) == 0);
        assert(memcmp(buf + n, alpha + n, sizeof(alpha) - n) == 0);
        assert(close(fd) == 0);
    }

    /* test unsupported ioctl(FIONBIO) */
    {
        assert((fd = open(filename, O_RDONLY, 0)) >= 0);
        int val = 1;
        assert(ioctl(fd, FIONBIO, &val) == -1 && errno == ENOTSUP);
        assert(close(fd) == 0);
    }

    /* test dup() */
    {
        assert((fd = open(filename, O_RDONLY, 0)) >= 0);
        int dfd;
        assert((dfd = dup(fd)) >= 0);
        assert(close(fd) == 0);

        struct stat buf;
        assert(fstat(dfd, &buf) == 0);
        assert(buf.st_size == sizeof(alpha));

        assert(close(dfd) == 0);
    }

    /* test pwrite() */
    {
        char buf[sizeof(ALPHA)];
        size_t n = 13;
        size_t r = sizeof(ALPHA) - n;

        memset(buf, 0, sizeof(buf));
        assert((fd = open(filename, O_RDWR, 0)) >= 0);
        assert(pwrite(fd, ALPHA + n, r, n) == r);
        assert(close(fd) == 0);
    }

    /* test pread() */
    {
        char buf[sizeof(alpha)];
        size_t n = 13;
        size_t r = sizeof(alpha) - n;

        memset(buf, 0, sizeof(buf));
        assert((fd = open(filename, O_RDONLY, 0)) >= 0);
        assert(pread(fd, buf, r, n) == r);
        assert(memcmp(buf, ALPHA + n, r) == 0);
        assert(close(fd) == 0);
    }

    /* test unlink() */
    {
        assert(access(filename, R_OK) == 0);
        assert(unlink(filename) == 0);
        assert(access(filename, R_OK) != 0);
    }

    /* test mkdir() */
    {
        assert(mkdir(dirname, 0777) == 0);
        struct stat buf;
        assert(stat(dirname, &buf) == 0);
        assert(S_ISDIR(buf.st_mode));
    }

    /* test directory iteration */
    {
        const char filename1[] = "/mnt/host/dir1/file1";
        const char filename2[] = "/mnt/host/dir1/file2";
        DIR* dir;
        struct dirent* ent;

        assert((fd = creat(filename1, 0666)) >= 0);
        close(fd);

        assert((fd = creat(filename2, 0666)) >= 0);
        close(fd);

        assert((dir = opendir(dirname)));
        static const size_t NNAMES = 4;
        size_t nnames = 0;

        while (ent = readdir(dir))
        {
            const char* s = ent->d_name;

            assert(nnames != NNAMES);
            nnames++;

            if (strcmp(s, ".") == 0)
                continue;
            if (strcmp(s, "..") == 0)
                continue;
            if (strcmp(s, "file1") == 0)
                continue;
            if (strcmp(s, "file2") == 0)
                continue;
            assert(0);
        }

        /* should be four entries including "." and ".." */
        assert(nnames == 4);

        assert(closedir(dir) == 0);

        assert(unlink(filename1) == 0);
        assert(unlink(filename2) == 0);
    }

    /* test rmdir() */
    {
        assert(rmdir(dirname) == 0);
        struct stat buf;
        assert(stat(dirname, &buf) != 0 && errno == ENOENT);
        assert(access(dirname, R_OK) != 0 && errno == ENOENT);
    }

    /* test link() */
    {
        const char filename1[] = "/mnt/host/file1";
        const char filename2[] = "/mnt/host/file2";

        assert((fd = creat(filename1, 0666)) >= 0);
        close(fd);
        assert(link(filename1, filename2) == 0);
        assert(access(filename2, R_OK) == 0);
        assert(unlink(filename1) == 0);
        assert(unlink(filename2) == 0);
        assert(access(filename1, R_OK) != 0);
        assert(access(filename2, R_OK) != 0);
    }

    /* test rename() */
    {
        const char filename1[] = "/mnt/host/file1";
        const char filename2[] = "/mnt/host/file2";

        assert((fd = creat(filename1, 0666)) >= 0);
        close(fd);
        assert(rename(filename1, filename2) == 0);
        assert(access(filename1, R_OK) != 0);
        assert(access(filename2, R_OK) == 0);
        assert(unlink(filename2) == 0);
    }

    /* test truncate() */
    {
        assert((fd = creat(filename, 0666)) >= 0);
        assert(write(fd, alpha, sizeof(alpha)) == sizeof(alpha));
        close(fd);

        struct stat buf;
        assert(stat(filename, &buf) == 0);
        assert(buf.st_size == sizeof(alpha));

        const off_t length = 23;
        assert(truncate(filename, length) == 0);

        assert(stat(filename, &buf) == 0);
        assert(buf.st_size == length);

        assert(unlink(filename) == 0);
    }

    /* test ftruncate() */
    {
        assert((fd = creat(filename, 0666)) >= 0);
        assert(write(fd, alpha, sizeof(alpha)) == sizeof(alpha));

        struct stat buf;
        assert(fstat(fd, &buf) == 0);
        assert(buf.st_size == sizeof(alpha));

        const off_t length = 23;
        assert(ftruncate(fd, length) == 0);

        assert(fstat(fd, &buf) == 0);
        assert(buf.st_size == length);

        close(fd);
        assert(unlink(filename) == 0);
    }

    /* test symlink() */
    {
        assert((fd = creat(filename, 0666)) >= 0);
        assert(write(fd, alpha, sizeof(alpha)) == sizeof(alpha));
        close(fd);

        assert(symlink(filename, slinkname) == 0);

        char slinkbuf[PATH_MAX];
        ssize_t n;
        n = readlink(slinkname, slinkbuf, sizeof(slinkbuf));
        assert(n == strlen(filename));

#if 0
        // ATTN: this fails because the target is relative to the kernel
        // file system.
        assert(stat(slinkname, &buf) == 0);
        assert(S_ISREG(buf.st_mode));
        assert(!S_ISLNK(buf.st_mode));
        assert(buf.st_size == sizeof(alpha));
#endif

        struct stat buf;
        assert(lstat(slinkname, &buf) == 0);
        assert(!S_ISREG(buf.st_mode));
        assert(S_ISLNK(buf.st_mode));

        assert(unlink(filename) == 0);
    }

    assert(umount("/mnt/host") == 0);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
