// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void test_urandom()
{
    int ret;
    char buf[1024];

    int fd = open("/dev/urandom", O_RDONLY);
    assert(fd > 0);

    ret = read(fd, buf, 1024);
    assert(ret == 1024);

    struct stat statbuf;
    ret = fstat(fd, &statbuf);
    assert(ret == 0);

    ret = close(fd);
    assert(ret == 0);
}

void test_zero()
{
    int ret;
    char buf[1024];

    int fd = open("/dev/zero", O_RDWR);
    assert(fd > 0);

    ret = read(fd, buf, 1024);
    assert(ret == 1024);
    for (int i = 0; i < 1024; i++)
        assert(buf[i] == '\0');

    ret = write(fd, buf, 1024);
    assert(ret == 1024);

    ret = close(fd);
    assert(ret == 0);
}

void test_null()
{
    int ret;
    char buf[1024];

    int fd = open("/dev/null", O_RDWR);
    assert(fd > 0);

    ret = read(fd, buf, 1024);
    assert(ret == 0); // Check for EOF

    ret = write(fd, buf, 1024);
    assert(ret == 1024);

    ret = close(fd);
    assert(ret == 0);
}

void test_fd_link()
{
    {
        char buf[1024];
        int expected_len = strlen("/proc/self/fd");
        int ret = readlink("/dev/fd", buf, 1024);
        assert(ret == expected_len);
        assert(strncmp(buf, "/proc/self/fd", expected_len) == 0);
    }

    {
        struct dirent* fd_ent;
        DIR* fd_dir = opendir("/dev/fd");
        assert(fd_dir);

        while ((fd_ent = readdir(fd_dir)) != NULL)
        {
            printf("%s\n", fd_ent->d_name);
        }
        closedir(fd_dir);
    }
}

int main(int argc, const char* argv[])
{
    test_urandom();
    test_zero();
    test_null();
    test_fd_link();
    printf("\n=== passed test (%s)\n", argv[0]);
    return 0;
}
