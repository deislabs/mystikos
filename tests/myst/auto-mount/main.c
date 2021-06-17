// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
    argv[1] = test name
    argv[2] = expected hostname
*/
int test_auto_mount(int argc, const char* argv[])
{
    struct stat details = {0};
    assert(stat("/ramfs-target/ramfs-file", &details) == 0);
    assert(S_ISREG(details.st_mode));
    assert(stat("/ext2-target/ext2-file", &details) == 0);
    assert(S_ISREG(details.st_mode));
    assert(stat("/hostfs-target/hostfs-file", &details) == 0);
    assert(S_ISREG(details.st_mode));
    printf("=== passed test (%s-auto-mount)\n", argv[0]);

    return 0;
}

int test_auto_mount_single_file(int argc, const char* argv[])
{
    struct stat details = {0};
    assert(stat("/etc/resolv.conf", &details) == 0);
    assert(S_ISREG(details.st_mode));
    assert(stat("/targetfile1", &details) == 0);
    assert(S_ISREG(details.st_mode));
    assert(stat("/run/mystikos/automounts/1/testfile1", &details) == 0);
    assert(S_ISREG(details.st_mode));
    assert(stat("/targetfile2", &details) == 0);
    assert(S_ISREG(details.st_mode));
    assert(stat("/run/mystikos/automounts/1/testfile2", &details) == 0);
    assert(S_ISREG(details.st_mode));

    printf("=== passed test (%s-auto-mount-single-file)\n", argv[0]);

    return 0;
}

int main(int argc, const char* argv[])
{
    assert(test_auto_mount(argc, argv) == 0);

    assert(test_auto_mount_single_file(argc, argv) == 0);

    return 0;
}
