// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    assert(getuid() == 0);
    assert(getgid() == 0);
    assert(geteuid() == 0);
    assert(getegid() == 0);
    assert(setuid(0) == 0);
    assert(setgid(0) == 0);

    errno = 0;
    assert(setuid(0xFFFFFFFF) != 0);
    assert(errno = EPERM);
    errno = 0;

    errno = 0;
    assert(setgid(0xFFFFFFFF) != 0);
    assert(errno = EPERM);
    errno = 0;

    pid_t pid = getpid();
    assert(pid > 0);

    pid_t ppid = getppid();
    assert(ppid > 0);
    assert(pid != ppid);

    pid_t sid = getsid(pid);
    assert(ppid = sid);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
