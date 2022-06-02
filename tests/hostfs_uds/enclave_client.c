// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define PATH_MAX 4096

const char* hostdir = NULL;

void check_server_readiness_or_failure()
{
    int ret;
    struct stat stbuf;

    while (1)
    {
        if (stat("/mnt/host/SRVR_FAILED", &stbuf) == 0)
        {
            printf("host server failure detected. aborting client!\n");
            _exit(1);
        }

        ret = stat("/mnt/host/SRVR_READY", &stbuf);

        if (ret == 0)
            return;
        else if (errno == ENOENT)
            sleep(1);
        else
        {
            printf("Unexpected error: %s", strerror(errno));
            _exit(1);
        }
    }
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s host-directory\n", argv[0]);
        _exit(1);
    }

    /* mount the host directory */
    assert(mkdir("/mnt", 0777) == 0);
    assert(mkdir("/mnt/host", 0777) == 0);
    assert(mount(argv[1], "/mnt/host", "hostfs", 0, NULL) == 0);

    check_server_readiness_or_failure();

    char sock_path[PATH_MAX];
    snprintf(sock_path, PATH_MAX, "/mnt/host/hostsockfoo");

    int fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    assert(fd >= 0);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    assert(
        connect(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == 0);

    {
        int nsend, nread;
        char sockbuf[1024];
        strcpy(sockbuf, "foO BaR Baz");
        nsend = send(fd, sockbuf, 1024, 0);
        assert(nsend > 0);

        nread = recv(fd, sockbuf, 1024, 0);
        printf("message received from server: %s\n", sockbuf);
        assert(strcmp(sockbuf, "FOO BAR BAZ") == 0);
    }

    close(fd);
    assert(umount("/mnt/host") == 0);

    return 0;
}
