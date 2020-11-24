// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

const char alpha[] = "abcdefghijklmnopqrstuvwxyz";
const char ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static void _passed(const char* name)
{
    printf("=== passed test (fs: %s)\n", name);
}

static size_t _fsize(const char* path)
{
    struct stat buf;

    if (stat(path, &buf) != 0)
        return (size_t)-1;

    return (size_t)buf.st_size;
}

static size_t _fdsize(int fd)
{
    struct stat buf;

    if (fstat(fd, &buf) != 0)
        return (size_t)-1;

    return (size_t)buf.st_size;
}

void test_readv(void)
{
    int fd;
    char buf[sizeof(ALPHA)];

    assert((fd = open("/test_readv", O_CREAT | O_WRONLY, 0)) >= 0);
    assert(write(fd, alpha, sizeof(alpha)) == sizeof(alpha));
    assert(lseek(fd, 0, SEEK_CUR) == sizeof(alpha));
    assert(write(fd, ALPHA, sizeof(ALPHA)) == sizeof(ALPHA));
    assert(lseek(fd, 0, SEEK_CUR) == sizeof(alpha) + sizeof(ALPHA));

    {
        char fdlink[PATH_MAX];
        char target[PATH_MAX];

        snprintf(fdlink, sizeof(fdlink), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(fdlink, target, sizeof(target));
        assert(n > 0);
        assert(strcmp(target, "/test_readv") == 0);
    }

    assert(close(fd) == 0);

    assert((fd = open("/test_readv", O_RDONLY, 0)) >= 0);
    assert(lseek(fd, 0, SEEK_CUR) == 0);
    assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    assert(lseek(fd, 0, SEEK_CUR) == sizeof(alpha));
    assert(strcmp(buf, alpha) == 0);

    /* Test readv() */
    {
        struct iovec iov[2];
        uint8_t buf1[20];
        uint8_t buf2[7];
        iov[0].iov_base = buf1;
        iov[0].iov_len = sizeof(buf1);
        iov[1].iov_base = buf2;
        iov[1].iov_len = sizeof(buf2);
        assert(readv(fd, iov, 2) == sizeof(ALPHA));
        assert(memcmp(buf1, ALPHA, sizeof(buf1)) == 0);
        assert(memcmp(buf2, ALPHA + sizeof(buf1), sizeof(buf2)) == 0);
    }

    /* Test readv() */
    {
        struct iovec iov[2];
        uint8_t buf1[20];
        uint8_t buf2[7];
        iov[0].iov_base = buf1;
        iov[0].iov_len = sizeof(buf1);
        iov[1].iov_base = buf2;
        iov[1].iov_len = sizeof(buf2);
        assert(lseek(fd, 0, SEEK_SET) == 0);
        assert(readv(fd, iov, 2) == sizeof(alpha));
        assert(memcmp(buf1, alpha, sizeof(buf1)) == 0);
        assert(memcmp(buf2, alpha + sizeof(buf1), sizeof(buf2)) == 0);
    }

    assert(lseek(fd, sizeof(alpha), SEEK_SET) == sizeof(alpha));
    assert(lseek(fd, 0, SEEK_CUR) == sizeof(alpha));

    assert(close(fd) == 0);

    _passed(__FUNCTION__);
}

void test_writev(void)
{
    int fd;
    char buf[sizeof(ALPHA)];

    assert((fd = open("/test_writev", O_CREAT | O_WRONLY, 0)) >= 0);

    struct iovec iov[2];
    iov[0].iov_base = (void*)alpha;
    iov[0].iov_len = sizeof(alpha);
    iov[1].iov_base = (void*)ALPHA;
    iov[1].iov_len = sizeof(ALPHA);

    assert(writev(fd, iov, 2) == sizeof(alpha) + sizeof(ALPHA));
    assert(close(fd) == 0);

    assert((fd = open("/test_writev", O_RDONLY, 0)) >= 0);
    assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    assert(strcmp(buf, alpha) == 0);
    assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
    assert(strcmp(buf, ALPHA) == 0);

    assert(close(fd) == 0);

    _passed(__FUNCTION__);
}

void test_stat()
{
    struct stat buf;

    assert(stat("/test_readv", &buf) == 0);
    assert(buf.st_size == sizeof(alpha) + sizeof(ALPHA));

    _passed(__FUNCTION__);
}

static uint64_t _nlink(const char* path)
{
    struct stat buf;
    assert(stat(path, &buf) == 0);
    return buf.st_nlink;
}

void test_mkdir()
{
    struct stat buf;
    int fd;

    assert(mkdir("/a", 0777) == 0);
    assert(stat("/a", &buf) == 0);
    assert(S_ISDIR(buf.st_mode));

    assert(mkdir("/a/bb", 0777) == 0);
    assert(mkdir("/a/bb/ccc", 0777) == 0);

    assert(stat("/a", &buf) == 0);
    assert(S_ISDIR(buf.st_mode));

    assert(stat("/a/bb", &buf) == 0);
    assert(S_ISDIR(buf.st_mode));

    assert(stat("/a/bb/ccc", &buf) == 0);
    assert(S_ISDIR(buf.st_mode));

    for (size_t i = 0; i < 2; i++)
    {
        assert((fd = creat("/a/bb/ccc/file", 0666)) >= 0);
        assert(stat("/a/bb/ccc/file", &buf) == 0);
        assert(S_ISREG(buf.st_mode));
        assert(close(fd) == 0);
    }

    assert(_nlink("/a") == 2);
    assert(_nlink("/a/bb") == 2);
    assert(_nlink("/a/bb/ccc") == 2);
    assert(_nlink("/a/bb/ccc/file") == 1);

    _passed(__FUNCTION__);
}

void test_rmdir()
{
    struct stat buf;

    assert(mkdir("/rmdir", 0777) == 0);
    assert(mkdir("/rmdir/rmdir", 0777) == 0);
    assert(mkdir("/rmdir/rmdir/rmdir", 0777) == 0);

    assert(rmdir("/rmdir/rmdir/rmdir") == 0);
    assert(rmdir("/rmdir/rmdir") == 0);
    assert(rmdir("/rmdir") == 0);
    assert(stat("/", &buf) == 0);

    _passed(__FUNCTION__);
}

void test_readdir()
{
    int fd;
    DIR* dir;
    struct dirent* ent;
    const struct
    {
        const char* name;
        unsigned char type;
    } entries[] = {
        {".", DT_DIR},
        {"..", DT_DIR},
        {"dir1", DT_DIR},
        {"dir2", DT_DIR},
        {"file1", DT_REG},
        {"file2", DT_REG},
    };
    const size_t nentries = sizeof(entries) / sizeof(entries[0]);
    size_t i = 0;
    off_t off = 0;

    assert(mkdir("/readdir", 0777) == 0);
    assert(mkdir("/readdir/dir1", 0777) == 0);
    assert(mkdir("/readdir/dir2", 0777) == 0);
    assert((fd = creat("/readdir/file1", 0666)) >= 0);
    assert(close(fd) == 0);
    assert((fd = creat("/readdir/file2", 0666)) >= 0);
    assert(close(fd) == 0);

    assert((dir = opendir("/readdir")));

    while ((ent = readdir(dir)))
    {
        assert(ent->d_ino != 0);
        assert(strcmp(ent->d_name, entries[i].name) == 0);
        assert(ent->d_type == entries[i].type);
        assert(ent->d_off == off);
        assert(ent->d_reclen == sizeof(struct dirent));
        i++;
        off += (off_t)sizeof(struct dirent);
    }

    assert(i == nentries);
    assert(closedir(dir) == 0);

    _passed(__FUNCTION__);
}

void dump_dirents(const char* path)
{
    DIR* dir;
    struct dirent* ent;

    assert((dir = opendir(path)) == 0);

    printf("=== dump_dirents(%s)\n", path);

    while ((ent = readdir(dir)))
    {
        printf(
            "name=\"%s\": ino=%lx type=%u off=%ld reclen=%ld\n",
            ent->d_name,
            ent->d_ino,
            ent->d_type,
            ent->d_off,
            ent->d_off);
    }

    closedir(dir);
}

void test_link()
{
    int fd;

    assert(mkdir("/link", 0777) == 0);
    assert(mkdir("/link/dir", 0777) == 0);

    assert((fd = creat("/link/file1", 0666)) >= 0);
    assert(close(fd) == 0);

    assert(_nlink("/link/file1") == 1);
    assert(link("/link/file1", "/link/file2") == 0);
    assert(_nlink("/link/file1") == 2);
    assert(_nlink("/link/file2") == 2);
    assert(link("/link/file2", "/link/dir/file3") == 0);
    assert(_nlink("/link/file1") == 3);
    assert(_nlink("/link/file2") == 3);
    assert(_nlink("/link/dir/file3") == 3);

    assert(unlink("/link/file1") == 0);
    assert(_nlink("/link/dir/file3") == 2);
    assert(unlink("/link/file2") == 0);
    assert(_nlink("/link/dir/file3") == 1);
    assert(unlink("/link/dir/file3") == 0);

    _passed(__FUNCTION__);
}

static int _touch(const char* pathname, mode_t mode)
{
    int fd;

    if ((fd = creat(pathname, mode)) < 0)
        return -1;

    if (close(fd) != 0)
        return -1;

    return 0;
}

void test_access()
{
    assert(mkdir("/access", 777) == 0);
    assert(_touch("/access/r", S_IRUSR) == 0);
    assert(_touch("/access/w", S_IWUSR) == 0);
    assert(_touch("/access/x", S_IXUSR) == 0);

    assert(access("/access/r", F_OK) == 0);
    assert(access("/access/w", F_OK) == 0);
    assert(access("/access/x", F_OK) == 0);

    assert(access("/access/r", R_OK) == 0);
    assert(access("/access/w", W_OK) == 0);
    assert(access("/access/x", X_OK) == 0);

    assert(access("/access/r", X_OK) != 0);
    assert(access("/access/w", R_OK) != 0);
    assert(access("/access/x", W_OK) != 0);

    _passed(__FUNCTION__);
}

void test_rename(void)
{
    assert(mkdir("/rename", 0777) == 0);

    assert(_touch("/rename/file1", 0400) == 0);
    assert(rename("/rename/file1", "/rename/file2") == 0);
    assert(access("/rename/file1", R_OK) != 0);
    assert(access("/rename/file2", R_OK) == 0);

    // if newpath - /rename/file2, already exists
    assert(_touch("/rename/file1", 0400) == 0);
    assert(_touch("/rename/file2", 0400) == 0);
    assert(rename("/rename/file1", "/rename/file2") == 0);
    assert(access("/rename/file1", R_OK) != 0);
    assert(access("/rename/file2", R_OK) == 0);

    _passed(__FUNCTION__);
}

void test_truncate(void)
{
    int fd;

    assert(mkdir("/truncate", 777) == 0);

    assert((fd = open("/truncate/alpha", O_CREAT | O_WRONLY, 0)) >= 0);
    assert(write(fd, alpha, sizeof(alpha)) == sizeof(alpha));
    assert(close(fd) == 0);

    {
        const off_t new_size = sizeof(alpha) * 2;
        assert(_fsize("/truncate/alpha") == sizeof(alpha));
        assert(truncate("/truncate/alpha", new_size) == 0);
        assert(_fsize("/truncate/alpha") == (size_t)new_size);
        assert(truncate("/truncate/alpha", sizeof(alpha)) == 0);
        assert(_fsize("/truncate/alpha") == sizeof(alpha));
        assert(truncate("/truncate/alpha", 0) == 0);
        assert(_fsize("/truncate/alpha") == 0);
    }

    {
        assert((fd = open("/truncate/alpha", O_RDWR, 0)) >= 0);
        assert(_fdsize(fd) == 0);
        assert(ftruncate(fd, sizeof(alpha)) == 0);
        assert(_fdsize(fd) == sizeof(alpha));
        assert(ftruncate(fd, 2 * sizeof(alpha)) == 0);
        assert(_fdsize(fd) == 2 * sizeof(alpha));
        assert(ftruncate(fd, 0) == 0);
        assert(_fdsize(fd) == 0);
        assert(close(fd) == 0);
    }

    _passed(__FUNCTION__);
}

void test_symlink(void)
{
    char target[PATH_MAX];
    struct stat st1;
    struct stat st2;
    DIR* dir;

    assert(mkdir("/symlink", 777) == 0);
    assert(_touch("/symlink/file", 0400) == 0);
    assert(access("/symlink/file", R_OK) == 0);
    assert(symlink("/symlink/file", "/symlink/link") == 0);
    assert(access("/symlink/link", R_OK) == 0);
    assert(readlink("/symlink/link", target, sizeof(target)) == 13);
    assert(strcmp(target, "/symlink/file") == 0);

    assert(mkdir("/symlink/aaa", 777) == 0);
    assert(symlink("/symlink/ccc", "/symlink/aaa/bbb") == 0);
    assert(mkdir("/symlink/ccc", 777) == 0);
    assert(mkdir("/symlink/ccc/ddd", 777) == 0);
    assert(stat("/symlink/aaa/bbb/ddd", &st1) == 0);
    assert(stat("/symlink/ccc/ddd", &st2) == 0);
    assert(st1.st_ino == st2.st_ino);
    assert(lstat("/symlink/aaa/bbb/ddd", &st1) == 0);

    assert(mkdir("/symlink/www", 777) == 0);
    assert(symlink("../yyy", "/symlink/www/xxx") == 0);
    assert(mkdir("/symlink/yyy", 777) == 0);
    assert(mkdir("/symlink/yyy/ddd", 777) == 0);
    assert(stat("/symlink/www/xxx/ddd", &st1) == 0);
    assert(stat("/symlink/yyy/ddd", &st2) == 0);
    assert(st1.st_ino == st2.st_ino);
    assert(lstat("/symlink/www/xxx/ddd", &st1) == 0);

    assert((dir = opendir("/symlink/www/xxx/ddd")));
    assert(closedir(dir) == 0);

    _passed(__FUNCTION__);
}

void test_tmpfile(void)
{
    FILE* fp = tmpfile();
    assert(fp != NULL);
    fprintf(fp, "hhheeello\n");
    fclose(fp);
    _passed(__FUNCTION__);
}

void test_pread_pwrite(void)
{
    const ssize_t N = 64;
    uint8_t blk1[N];
    uint8_t blk2[N];
    uint8_t blk3[N];
    uint8_t buf1[N];
    uint8_t buf2[N];
    uint8_t buf3[N];
    int fd;

    getrandom(blk1, sizeof(blk1), 0);
    getrandom(blk2, sizeof(blk2), 0);
    getrandom(blk3, sizeof(blk3), 0);

    assert(mkdir("/pread_pwrite", 777) == 0);
    assert(_touch("/pread_pwrite/file", 0400) == 0);

    assert((fd = open("/pread_pwrite/file", O_RDWR, 0)) >= 0);

    assert(pwrite(fd, blk1, sizeof(blk1), 0) == N);
    assert(pwrite(fd, blk2, sizeof(blk2), N) == N);
    assert(pwrite(fd, blk3, sizeof(blk3), 2 * N) == N);

    assert(pread(fd, buf1, sizeof(buf1), 0) == N);
    assert(pread(fd, buf2, sizeof(buf2), N) == N);
    assert(pread(fd, buf3, sizeof(buf3), 2 * N) == N);

    assert(memcmp(blk1, buf1, sizeof(blk1)) == 0);
    assert(memcmp(blk2, buf2, sizeof(blk2)) == 0);
    assert(memcmp(blk3, buf3, sizeof(blk3)) == 0);

    assert((fd = close(fd)) >= 0);

    _passed(__FUNCTION__);
}

static void test_fstatat(void)
{
    int dirfd;
    const char path[] = "/fstatat/dir1/file1";

    assert(chdir("/") == 0);

    /* Create directories and files */
    {
        assert(mkdir("/fstatat", 0777) == 0);
        assert(mkdir("/fstatat/dir1", 0777) == 0);

        dirfd = open("/fstatat/dir1", O_RDONLY);
        assert(dirfd >= 0);

        int fd;
        assert((fd = open(path, O_CREAT | O_WRONLY, 0666)) >= 0);
        assert(write(fd, alpha, sizeof(alpha)) == sizeof(alpha));
        assert(close(fd) == 0);
    }

    /* Test fstatat() with a relative path */
    {
        struct stat buf;
        int r = fstatat(dirfd, "./file1", &buf, 0);
        assert(r == 0);
        assert(buf.st_size == sizeof(alpha));
    }

    /* Test fstatat() with an absoute path */
    {
        struct stat buf;
        int r = fstatat(dirfd, "/fstatat/dir1/file1", &buf, 0);
        assert(r == 0);
        assert(buf.st_size == sizeof(alpha));
    }

    /* Test fstatat() with AT_FDCWD */
    {
        struct stat buf;
        int r = fstatat(AT_FDCWD, "fstatat/dir1/file1", &buf, 0);
        assert(r == 0);
        assert(buf.st_size == sizeof(alpha));
    }

    /* Test fsstat() with an empty path */
    {
        /* reopen the file */
        int filefd = open(path, O_RDONLY);
        assert(filefd > 0);

        struct stat buf;
        int r = fstatat(filefd, "", &buf, AT_EMPTY_PATH);
        assert(r == 0);
        assert(buf.st_size == sizeof(alpha));
        close(filefd);
    }

    close(dirfd);

    _passed(__FUNCTION__);
}

int main(void)
{
    test_fstatat();
    test_readv();
    test_writev();
    test_stat();
    test_mkdir();
    test_rmdir();
    test_readdir();
    test_link();
    test_access();
    test_rename();
    test_truncate();
    test_symlink();
    test_tmpfile();
    test_pread_pwrite();

    return 0;
}
