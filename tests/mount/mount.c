// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    const char filename[] = "/mnt/datafs/myfile";
    const size_t filesize = 7;

    if (mount("/datafs", "/mnt/datafs", "ramfs", 0, NULL) != 0)
        assert(false);

    if (access(filename, R_OK) != 0)
        assert(false);

    /* read a file on the mounted file system */
    {
        int fd;
        struct stat st;
        char buf[128];

        assert((fd = open(filename, O_RDONLY)) >= 0);
        assert(stat(filename, &st) == 0);
        assert(st.st_size == filesize);
        assert(read(fd, buf, sizeof(buf)) == filesize);
        assert(memcmp(buf, "myfile", 6) == 0);
        assert(close(fd) == 0);
    }

    if (umount("/mnt/datafs") != 0)
        assert(false);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
