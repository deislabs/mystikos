// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <sys/inotify.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    int fd;
    int wd1;
    int wd2;
    int wd3;

    assert((fd = inotify_init1(0)) >= 0);
    assert((wd1 = inotify_add_watch(fd, "/", IN_ACCESS)) >= 0);

    assert((wd2 = inotify_add_watch(fd, "/", IN_ACCESS)) >= 0);
    assert(wd1 == wd2);

    assert((wd3 = inotify_add_watch(fd, "/tmp", IN_ACCESS)) >= 0);
    assert(wd1 != wd3);

    assert(inotify_rm_watch(fd, wd1) == 0);
    assert(inotify_rm_watch(fd, wd3) == 0);

    assert(close(fd) == 0);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
