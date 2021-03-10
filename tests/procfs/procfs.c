// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
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

int test_self_exe(const char* pn)
{
    int ret;
    char target[PATH_MAX];
    ret = readlink("/proc/self/exe", target, sizeof(target));
    assert(ret > 0);
    assert(!strcmp(pn,target));
}

int test_self_fd()
{

}

int test_self_links(const char* pn)
{
    char target[PATH_MAX];
    readlink("/proc/self", target, sizeof(target));
    printf("%s\n", target);

    test_self_exe(pn);
    test_self_fd();
}

int main(int argc, const char* argv[])
{
    test_meminfo();
    test_self_links(argv[0]);

    printf("\n=== passed test (%s)\n", argv[0]);
    return 0;
}
