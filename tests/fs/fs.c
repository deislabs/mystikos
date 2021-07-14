// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <unistd.h>
#include "../utils/utils.h"

const char* fstype;

const char alpha[] = "abcdefghijklmnopqrstuvwxyz";
const char ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static void _passed(const char* name)
{
    printf("=== passed test (%s)\n", name);
}

__attribute__((__unused__)) static size_t _fsize(const char* path)
{
    struct stat buf;

    if (stat(path, &buf) != 0)
        return (size_t)-1;

    return (size_t)buf.st_size;
}

__attribute__((__unused__)) static size_t _fdsize(int fd)
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

    assert((fd = open("/test_readv", O_CREAT | O_WRONLY, 0666)) >= 0);
    assert(write(fd, alpha, sizeof(alpha)) == sizeof(alpha));
    assert(lseek(fd, 0, SEEK_CUR) == sizeof(alpha));
    assert(write(fd, ALPHA, sizeof(ALPHA)) == sizeof(ALPHA));
    assert(lseek(fd, 0, SEEK_CUR) == sizeof(alpha) + sizeof(ALPHA));

    /* not applicable to hostfs */
    if (strcmp(fstype, "ext2fs") == 0 || strcmp(fstype, "ramfs") == 0)
    {
        char fdlink[PATH_MAX];
        char target[PATH_MAX];
        struct stat st;

        snprintf(fdlink, sizeof(fdlink), "/proc/self/fd/%d", fd);
        assert(stat("/proc/self/fd", &st) == 0);
        assert(lstat(fdlink, &st) == 0);
        assert(stat(fdlink, &st) == 0);
        ssize_t n = readlink(fdlink, target, sizeof(target));
        assert(n > 0);
        assert(memcmp(target, "/test_readv", 11) == 0);
    }

    assert(close(fd) == 0);

    assert((fd = open("/test_readv", O_RDONLY, 0666)) >= 0);
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

    assert((fd = open("/test_writev", O_CREAT | O_WRONLY, 0777)) >= 0);

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

    assert(_nlink("/a") == 3);
    assert(_nlink("/a/bb") == 3);
    assert(_nlink("/a/bb/ccc") == 2);
    assert(_nlink("/a/bb/ccc/file") == 1);

    assert(chdir("/a/bb/ccc") == 0);
    assert(mkdir("/a/bb/ccc/ddd", 0700) == 0);

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

typedef const struct entry
{
    const char* name;
    unsigned char type;
} entry_t;

int _check_entry(
    entry_t* entries,
    size_t nentries,
    const char* name,
    unsigned char type)
{
    for (size_t i = 0; i < nentries; i++)
    {
        if (strcmp(entries[i].name, name) == 0)
        {
            if (type == entries[i].type)
                return 0;

            return -1;
        }
    }

    return -1;
}

void test_readdir()
{
    int fd;
    DIR* dir;
    struct dirent* ent;
    entry_t entries[] = {
        {".", DT_DIR},
        {"..", DT_DIR},
        {"dir1", DT_DIR},
        {"dir2", DT_DIR},
        {"file1", DT_REG},
        {"file2", DT_REG},
    };
    const size_t nentries = sizeof(entries) / sizeof(entries[0]);
    size_t i = 0;

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
        assert(_check_entry(entries, nentries, ent->d_name, ent->d_type) == 0);
        i++;
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
    assert(mkdir("/access", 0777) == 0);
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

    /* ATTN: inconsistency between hostfs and ext2fs/ramfs2 */
    if (0 && strcmp(fstype, "hostfs") == 0)
    {
        assert(access("/access/w", R_OK) == 0);
        assert(access("/access/x", W_OK) == 0);
    }
    else
    {
        assert(access("/access/w", R_OK) != 0);
        assert(access("/access/x", W_OK) != 0);
    }

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
    assert(unlink("/rename/file2") == 0);
    assert(_touch("/rename/file2", 0400) == 0);
    assert(rename("/rename/file1", "/rename/file2") == 0);
    assert(access("/rename/file1", R_OK) != 0);
    assert(access("/rename/file2", R_OK) == 0);

    _passed(__FUNCTION__);
}

void test_renameat(void)
{
    int olddirfd, newdirfd;
    // Create directories and files
    {
        assert(mkdir("/renameat", 0777) == 0);
        assert(mkdir("/renameat/dir1", 0777) == 0);
        assert(_touch("/renameat/dir1/file1", 0600) == 0);
        assert(access("/renameat/dir1/file1", R_OK) == 0);
        assert(mkdir("/renameat/dir2", 0777) == 0);
        assert((olddirfd = open("/renameat/dir1", O_DIRECTORY)) >= 0);
        assert((newdirfd = open("/renameat/dir2", O_DIRECTORY)) >= 0);
        assert((renameat(olddirfd, "file1", newdirfd, "file3")) == 0);
        assert(access("/renameat/dir2/file3", R_OK) == 0);
    }

    _passed(__FUNCTION__);
}

void test_truncate(void)
{
    int fd;

    assert(mkdir("/truncate", 0777) == 0);

    assert((fd = open("/truncate/alpha", O_CREAT | O_WRONLY, 0777)) >= 0);
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

    assert(mkdir("/symlink", 0777) == 0);
    assert(_touch("/symlink/file", 0400) == 0);
    assert(access("/symlink/file", R_OK) == 0);
    assert(symlink("/symlink/file", "/symlink/link") == 0);

    assert(access("/symlink/link", R_OK) == 0);
    assert(readlink("/symlink/link", target, sizeof(target)) == 13);
    assert(memcmp(target, "/symlink/file", 13) == 0);

    assert(mkdir("/symlink/aaa", 0777) == 0);
    assert(symlink("/symlink/ccc", "/symlink/aaa/bbb") == 0);
    assert(mkdir("/symlink/ccc", 0777) == 0);
    assert(mkdir("/symlink/ccc/ddd", 0777) == 0);

    assert(stat("/symlink/aaa/bbb/ddd", &st1) == 0);
    assert(stat("/symlink/ccc/ddd", &st2) == 0);
    assert(st1.st_ino == st2.st_ino);
    assert(lstat("/symlink/aaa/bbb/ddd", &st1) == 0);

    assert(mkdir("/symlink/www", 0777) == 0);
    assert(symlink("../yyy", "/symlink/www/xxx") == 0);
    assert(mkdir("/symlink/yyy", 0777) == 0);
    assert(mkdir("/symlink/yyy/ddd", 0777) == 0);
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

    assert(mkdir("/pread_pwrite", 0777) == 0);
    assert(_touch("/pread_pwrite/file", 0600) == 0);

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

void test_fstatat(void)
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

void test_sendfile(bool test_offset)
{
    const char in_path[] = "/sendfile_in";
    const char out_path[] = "/sendfile_out";
    int out_fd;
    int in_fd;
    const size_t N = 4096;
    size_t n = 0;
    int ret;
    off_t nn = (sizeof(alpha) * N) / 2;
    off_t offset;
    off_t* offset_ptr;
    struct stat st;

    assert(N % 2 == 0);

    if (test_offset)
    {
        offset = nn;
        offset_ptr = &offset;
    }
    else
    {
        offset = 0;
        offset_ptr = NULL;
    }

    /* create the input file */
    {
        assert((in_fd = open(in_path, O_CREAT | O_WRONLY, 0666)) >= 0);

        for (size_t i = 0; i < N; i++)
        {
            assert(write(in_fd, alpha, sizeof(alpha)) == sizeof(alpha));
            n += sizeof(alpha);
        }

        assert(close(in_fd) == 0);
    }

    /* use sendfile() to create the output file */
    {
        assert((in_fd = open(in_path, O_RDONLY, 0)) >= 0);
        assert((out_fd = open(out_path, O_CREAT | O_WRONLY, 00666)) >= 0);

        ret = sendfile(out_fd, in_fd, offset_ptr, n);

        if (test_offset)
            assert(ret == nn);
        else
            assert(ret == n);

        if (test_offset)
            assert(offset == n);

        assert(close(in_fd) == 0);
        assert(close(out_fd) == 0);

        if (test_offset)
            assert(stat(out_path, &st) == 0 && st.st_size == nn);
        else
            assert(stat(out_path, &st) == 0 && st.st_size == n);
    }

    /* check the size of the output file */
    if (test_offset)
        assert(stat(out_path, &st) == 0 && st.st_size == nn);
    else
        assert(stat(out_path, &st) == 0 && st.st_size == n);

    /* check the content of the output file */
    {
        assert((out_fd = open(out_path, O_RDONLY, 0)) >= 0);
        size_t m = 0;
        size_t size;

        if (test_offset)
            size = N / 2;
        else
            size = N;

        for (size_t i = 0; i < size; i++)
        {
            char buf[sizeof(alpha)];
            assert(read(out_fd, buf, sizeof(buf)) == sizeof(buf));
            assert(memcmp(buf, alpha, sizeof(buf)) == 0);
            m += sizeof(alpha);
        }

        assert(close(out_fd) == 0);

        if (test_offset)
            assert(nn == m);
        else
            assert(n == m);
    }

    assert(unlink(in_path) == 0);
    assert(unlink(out_path) == 0);

    _passed(__FUNCTION__);
}

void test_statfs(const char* program_name)
{
    int result;
    struct statfs stats;

    // test statfs fails for non-existent file path
    result = statfs("/unknown/file", &stats);
    assert(result != 0);

    result = statfs(program_name, &stats);
    assert(result == 0);

    _passed(__FUNCTION__);
}

void test_fstatfs(const char* program_name)
{
    int result;
    struct statfs stats;
    int fd = open(program_name, O_RDONLY);
    result = fstatfs(fd, &stats);
    assert(result == 0);

    _passed(__FUNCTION__);
}

void test_openat(void)
{
    assert(mkdir("/openat", 0777) == 0);
    assert(mkdir("/openat/dir", 0777) == 0);

    /* open the directory */
    int dirfd = open("/openat/dir", O_RDONLY);
    assert(dirfd >= 0);

    /* create a file relative the the directory */
    {
        int fd = openat(dirfd, "file", O_WRONLY | O_CREAT | O_TRUNC, 0666);
        assert(fd >= 0);
        assert(write(fd, alpha, sizeof(alpha)) == sizeof(alpha));
        assert(close(fd) == 0);
    }

    struct stat statbuf;
    assert(stat("/openat/dir/file", &statbuf) == 0);

    /* check that the file contains the alphabet */
    {
        char buf[sizeof(alpha)];

        int fd = openat(dirfd, "../dir/file", O_RDONLY, 0666);
        assert(read(fd, buf, sizeof(buf)) == sizeof(buf));
        assert(memcmp(buf, alpha, sizeof(buf)) == 0);
    }

    assert(close(dirfd) == 0);

    _passed(__FUNCTION__);
}

void test_fcntl(void)
{
    assert(mkdir("/fcntl", 0777) == 0);
    int fd;
    assert((fd = open("/fcntl/file", O_CREAT | O_WRONLY, 0666)) >= 0);

    assert(fcntl(fd, F_GETFD) == 0);

    assert(fcntl(fd, F_SETFD, FD_CLOEXEC) == 0);
    assert(fcntl(fd, F_GETFD) == FD_CLOEXEC);

    assert(fcntl(fd, F_SETFD, 0) == 0);
    assert(fcntl(fd, F_GETFD) == 0);

    assert(close(fd) == 0);

    _passed(__FUNCTION__);
}

void diff_timestamps(
    struct stat* st1,
    struct stat* st2,
    long* atim,
    long* ctim,
    long* mtim)
{
    long atim1 = st1->st_atim.tv_sec * 1000000 + st1->st_atim.tv_nsec / 1000;
    long ctim1 = st1->st_ctim.tv_sec * 1000000 + st1->st_ctim.tv_nsec / 1000;
    long mtim1 = st1->st_mtim.tv_sec * 1000000 + st1->st_mtim.tv_nsec / 1000;
    long atim2 = st2->st_atim.tv_sec * 1000000 + st2->st_atim.tv_nsec / 1000;
    long ctim2 = st2->st_ctim.tv_sec * 1000000 + st2->st_ctim.tv_nsec / 1000;
    long mtim2 = st2->st_mtim.tv_sec * 1000000 + st2->st_mtim.tv_nsec / 1000;

    *atim = atim2 - atim1;
    *ctim = ctim2 - ctim1;
    *mtim = mtim2 - mtim1;
}

static uint64_t _timestamp_sleep_msec = 250;

void test_timestamps(void)
{
    int fd;
    struct stat st1;
    struct stat st2;
    long atim;
    long ctim;
    long mtim;

    assert(mkdir("/timestamps", 0777) == 0);

    /* test write() */
    {
        const int flags = O_WRONLY | O_CREAT | O_TRUNC;
        const mode_t mode = 0666;
        assert((fd = open("/timestamps/write", flags, mode)) >= 0);

        assert(fstat(fd, &st1) == 0);
        sleep_msec(_timestamp_sleep_msec);
        assert(write(fd, "0123456789", 10) == 10);
        assert(fstat(fd, &st2) == 0);

        diff_timestamps(&st1, &st2, &atim, &ctim, &mtim);
        printf("atim=%ld ctim=%ld mtim=%ld\n", atim, ctim, mtim);
        assert(atim == 0);
        assert(ctim != 0);
        assert(mtim != 0);

        assert(close(fd) == 0);
    }
}

static void test_pwritev_preadv(const char* version)
{
    int fd;
    int flags = O_CREAT | O_TRUNC | O_RDWR;
    const off_t off = 7;
    const off_t len = 9;
    ssize_t nread;

    assert((fd = open("/pwritev_preadv", flags, 0666)) >= 0);
    assert(write(fd, alpha, sizeof(alpha)) == sizeof(alpha));

    struct iovec iov1[2];
    iov1[0].iov_base = "HIJK";
    iov1[0].iov_len = 4;
    iov1[1].iov_base = "LMNOP";
    iov1[1].iov_len = 5;

    if (strcmp(version, "pwritev") == 0)
        assert(pwritev(fd, iov1, 2, off) == len);
    else if (strcmp(version, "pwritev2") == 0)
        assert(pwritev2(fd, iov1, 2, off, 0) == len);
    else if (strcmp(version, "pwritev64v2") == 0)
        assert(pwritev64v2(fd, iov1, 2, off, 0) == len);
    else
        assert(0);

    struct iovec iov2[3];
    char buf0[3];
    char buf1[5];
    char buf2[1];
    iov2[0].iov_base = buf0;
    iov2[0].iov_len = sizeof(buf0);
    iov2[1].iov_base = buf1;
    iov2[1].iov_len = sizeof(buf1);
    iov2[2].iov_base = buf2;
    iov2[2].iov_len = sizeof(buf2);

    if (strcmp(version, "pwritev") == 0)
        nread = preadv(fd, iov2, 3, off);
    else if (strcmp(version, "pwritev2") == 0)
        nread = preadv2(fd, iov2, 3, off, 0);
    else if (strcmp(version, "pwritev64v2") == 0)
        nread = preadv64v2(fd, iov2, 3, off, 0);
    else
        assert(0);

    assert(nread == len);

#if 0
    printf("nread=%zd errno=%d\n", nread, errno);
    printf("buf0{%.*s}\n", (int)sizeof(buf0), buf0);
    printf("buf1{%.*s}\n", (int)sizeof(buf1), buf1);
    printf("buf2{%.*s}\n", (int)sizeof(buf2), buf2);
#endif

    assert(memcmp(buf0, "HIJ", 3) == 0);
    assert(memcmp(buf1, "KLMNO", 5) == 0);
    assert(memcmp(buf2, "P", 1) == 0);

    close(fd);

    printf("=== passed test (%s: version=%s)\n", __FUNCTION__, version);
}

static void test_ioctl()
{
    assert(mkdir("/ioctl", 0777) == 0);
    int fd;
    assert((fd = open("/ioctl/file", O_CREAT | O_WRONLY, 0666)) >= 0);

    assert(fcntl(fd, F_GETFD) == 0);

    assert(ioctl(fd, FIOCLEX, NULL) == 0);
    assert(fcntl(fd, F_GETFD) == FD_CLOEXEC);

    assert(ioctl(fd, FIONCLEX, NULL) == 0);
    assert(fcntl(fd, F_GETFD) == 0);

    assert(close(fd) == 0);

    _passed(__FUNCTION__);
}

static void test_enotdir()
{
    int fd = creat("/test_enotdir", 0666);
    assert(fd >= 0);
    assert(close(fd) == 0);

    // path has a regular file as an intermediate component
    int ret = lchown("/test_enotdir/symlink", 0, 0);
    assert(ret < 0);
    assert(errno == ENOTDIR);

    _passed(__FUNCTION__);
}

static void test_fdatasync()
{
    int fd = creat("/test_fdatasync", 0666);
    assert(fd >= 0);
    struct stat statbuf;
    int ret = fstat(fd, &statbuf);
    assert(ret == 0);
    int init_size = statbuf.st_size;
    ret = write(fd, alpha, sizeof(alpha));
    assert(ret == sizeof(alpha));
    ret = fdatasync(fd);
    assert(ret == 0);

    ret = stat("/test_fdatasync", &statbuf);
    assert(ret == 0);
    assert(init_size + sizeof(alpha) == statbuf.st_size);

    close(fd);
    _passed(__FUNCTION__);
}

static void test_fsync()
{
    int fd = creat("/test_fsync", 0666);
    assert(fd >= 0);

    struct stat statbuf;
    int ret = fstat(fd, &statbuf);
    assert(ret == 0);
    struct timespec mtime_0 = statbuf.st_mtim;

    // write should change mtime of the file
    ret = write(fd, alpha, sizeof(alpha));
    assert(ret == sizeof(alpha));

    // call fsync to flush file and its metadata to device
    ret = fsync(fd);
    assert(ret == 0);

    ret = stat("/test_fsync", &statbuf);
    assert(ret == 0);
    struct timespec mtime_1 = statbuf.st_mtim;
    assert(mtime_1.tv_sec >= mtime_0.tv_sec);

    close(fd);
    _passed(__FUNCTION__);
}

static void test_o_excl()
{
    int fd = open("/test_o_excl", O_CREAT | O_RDWR | O_EXCL, 0666);
    assert(fd >= 0);
    int fd2 = open("/test_o_excl", O_CREAT | O_RDWR | O_EXCL, 0666);
    assert(fd2 == -1 && errno == EEXIST);
    close(fd);
    _passed(__FUNCTION__);
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <file-system-type>\n", argv[0]);
        exit(1);
    }

    fstype = argv[1];

    if (strcmp(fstype, "ramfs") != 0 && strcmp(fstype, "ext2fs") != 0 &&
        strcmp(fstype, "hostfs") != 0)
    {
        fprintf(stderr, "unknown file system type: %s\n", fstype);
        exit(1);
    }

    /* ext2fs only has 1 second timestamp granularity */
    if (strcmp(fstype, "ext2fs") == 0)
        _timestamp_sleep_msec = 1200; /* 1.2 seconds */

    test_timestamps();
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
    test_renameat();
    test_truncate();
    test_symlink();
    test_tmpfile();
    test_pread_pwrite();
    test_sendfile(true);
    test_sendfile(false);
    test_statfs(argv[0]);
    test_fstatfs(argv[0]);
    test_openat();
    test_fcntl();
    test_pwritev_preadv("pwritev");
    test_pwritev_preadv("pwritev2");
    test_pwritev_preadv("pwritev64v2");
    test_ioctl();
    test_enotdir();
    test_fdatasync();
    test_fsync();
    test_o_excl();

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
