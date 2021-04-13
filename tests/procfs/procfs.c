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

int test_meminfo()
{
    int fd;
    char buf[1024];

    fd = open("/proc/meminfo", O_RDONLY);
    assert(fd > 0);
    assert(read(fd, buf, sizeof(buf)));

    printf("%s\n", buf);
}

int test_self_symlink()
{
    char pid_path[PATH_MAX];
    const size_t n = sizeof(pid_path);
    snprintf(pid_path, n, "/proc/%d", getpid());

    char proc_self_target[PATH_MAX];
    readlink("/proc/self", proc_self_target, sizeof(proc_self_target));

    printf("%s\n", proc_self_target);
    assert(!strcmp(proc_self_target, pid_path));
}

int test_self_exe(const char* pn)
{
    int ret;
    char target[PATH_MAX];
    ret = readlink("/proc/self/exe", target, sizeof(target));
    assert(ret > 0);
    assert(!strcmp(pn, target));
}

int test_self_fd()
{
    const char filename[] = "/file1";
    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR);
    assert(fd > 0);

    char fd_link_path[PATH_MAX];
    char target[PATH_MAX];
    const size_t n = sizeof(fd_link_path);
    snprintf(fd_link_path, n, "/proc/self/fd/%d", fd);
    readlink(fd_link_path, target, sizeof(target));
    assert(!strcmp(target, filename));
}

int test_self_links(const char* pn)
{
    test_self_symlink();
    test_self_exe(pn);
    test_self_fd();
}

int test_readonly()
{
    int fd;
    fd = open("/proc/meminfo", O_RDWR);
    assert(fd == -1);
    assert(errno == EPERM);
}

int main(int argc, const char* argv[])
{
    test_meminfo();
    test_self_links(argv[0]);
    test_readonly();

    printf("\n=== passed test (%s)\n", argv[0]);
    return 0;
}
