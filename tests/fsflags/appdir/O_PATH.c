// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#define O_PATH 010000000

struct linux_dirent
{
    unsigned long d_ino;     /* Inode number */
    unsigned long d_off;     /* Offset to next linux_dirent */
    unsigned short d_reclen; /* Length of this linux_dirent */
    char d_name[];           /* Filename (null-terminated) */
                             /* length is actually (d_reclen - 2 -
                                offsetof(struct linux_dirent, d_name) */
    /*
    char           pad;       // Zero padding byte
    char           d_type;    // File type (only since Linux 2.6.4;
                              // offset is (d_reclen - 1))
    */
};

const char* test_file = "test.txt";
const char* test_sym = "test_sym";

int opath_open_setup()
{
    remove(test_file);
    int fd = open(test_file, O_CREAT);
    assert(fd > 0);
    fd = open(test_file, O_PATH);
    printf("fd is %i\n", fd);
    assert(fd > 0);
    return fd;
}

void test_expect_error(int ret)
{
    printf("ret is %i, errno is %i\n", ret, errno);
    assert(ret < 0);
    assert(errno == EBADF);
}

void test_read_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    char buffer[5];
    test_expect_error(read(fd, buffer, 3));
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_write_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    char buffer[5];
    test_expect_error(write(fd, buffer, 3));
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_fchmod_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    // Using syscall: fchmod/fchown wrapper does not
    // error in Mystikos due musl behavior difference
    test_expect_error(syscall(SYS_fchmod, fd, S_IRUSR));
    remove(test_file);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_fchown_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    // Using syscall: see fchmod
    test_expect_error(syscall(SYS_fchown, fd, -1, -1));
    remove(test_file);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_ioctl_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    test_expect_error(ioctl(fd, 1));
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_ftruncate_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    test_expect_error(ftruncate(fd, 1));
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_getdents_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    struct linux_dirent dirp;
    test_expect_error(syscall(SYS_getdents64, fd, &dirp, 0));
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_fdatasync_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    test_expect_error(fdatasync(fd));
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_fsync_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    test_expect_error(fsync(fd));
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_lseek_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    test_expect_error(lseek(fd, 1, SEEK_SET));
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_mmap_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    test_expect_error(
        (int)(uintptr_t)mmap(NULL, 1, PROT_NONE, MAP_SHARED, fd, 0));
    printf("=== passed test (%s)\n", __FUNCTION__);
}

// If O_PATH is specified other access flags ignored
void test_fcntl_get_access_flag()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = opath_open_setup();
    int ret = fcntl(fd, F_GETFL);
    assert(ret == O_PATH);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

// Return ELOOP on open if pathname was a symbolic link,
// and flags specified O_NOFOLLOW but not O_PATH
void test_fstatat_eloop()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    opath_open_setup();
    remove(test_sym);
    int ret_sym = symlink(test_file, test_sym);
    assert(ret_sym == 0);
    int ret = open(test_sym, O_NOFOLLOW);
    assert(ret < 0);
    assert(errno == ELOOP);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    printf("== starting testsuite (%s)\n", argv[0]);

    test_read_expect_error();
    test_write_expect_error();
    test_fchmod_expect_error();
    test_fchown_expect_error();
    test_ioctl_expect_error();
    test_ftruncate_expect_error();
    test_getdents_expect_error();
    test_fdatasync_expect_error();
    test_fsync_expect_error();
    test_lseek_expect_error();
    test_mmap_expect_error();

    test_fcntl_get_access_flag();
    test_fstatat_eloop();

    printf("== passed testsuite (%s)\n", argv[0]);

    remove(test_sym);
    remove(test_file);

    return 0;
}
