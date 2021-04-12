// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
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
    ret = read(fd, buf, 1024);
    assert(ret == 1024);
    struct stat statbuf;
    ret = fstat(fd, &statbuf);
    assert(ret == 0);
    ret = close(fd);
    assert(ret == 0);
}

int main(int argc, const char* argv[])
{
    test_urandom();
    printf("\n=== passed test (%s)\n", argv[0]);
    return 0;
}
