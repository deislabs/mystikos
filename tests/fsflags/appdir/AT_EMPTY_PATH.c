// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <syscall.h>

#define AT_EMPTY_PATH 0x1000
const char* test_dir = "testdir";

int open_setup(int flags)
{
    remove(test_dir);
    int ret = mkdir(test_dir, 0700);
    assert(ret == 0);
    int fd = open(test_dir, flags);
    printf("fd is %i\n", fd);
    assert(fd > 0);
    return fd;
}

void test_expect_error(int ret, int expected)
{
    printf("ret is %i, errno is %i\n", ret, errno);
    assert(ret < 0);
    assert(errno == expected);
}

void test_fstatat_nullpath_expect_error()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = open_setup(O_RDONLY);
    struct stat buf;
    test_expect_error(fstatat(fd, "", &buf, 0), ENOENT);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

void test_fstatat_atemptypath()
{
    printf("=== starting test (%s)\n", __FUNCTION__);
    int fd = open_setup(O_RDONLY);
    struct stat buf;
    int ret = fstatat(fd, "", &buf, AT_EMPTY_PATH);
    assert(ret == 0);
    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    printf("== starting testsuite (%s)\n", argv[0]);

    test_fstatat_nullpath_expect_error();
    test_fstatat_atemptypath();

    printf("== passed testsuite (%s)\n", argv[0]);

    remove(test_dir);

    return 0;
}
