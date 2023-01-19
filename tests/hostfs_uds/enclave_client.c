// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define PATH_MAX 4096
#define SNDTIMEO_SECS 5

const char* hostdir = NULL;
int epfd;

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

void* event_thread_func(void* args)
{
    struct epoll_event evlist[5];
    while (1)
    {
        int nready = epoll_wait(epfd, evlist, 5, -1);
        // printf("nready=%d\n", nready);

        if (nready == -1)
        {
            printf("errno= %d\n", errno);
            break;
        }
    }
    return NULL;
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

    {
        epfd = epoll_create1(EPOLL_CLOEXEC);
        assert(epfd >= 0);

        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLOUT;
        ev.data.fd = fd;
        int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
        assert(ret != -1);

        pthread_t sock_event_thread;
        pthread_create(&sock_event_thread, NULL, event_thread_func, NULL);
    }

    {
        struct timeval timeout;
        socklen_t optlen = sizeof(struct timeval);
        int ret = getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, &optlen);
        assert(ret == 0);
        printf(
            "getsockopt() before set: tv_sec=%ld tv_usec=%ld\n",
            timeout.tv_sec,
            timeout.tv_usec);
    }

    {
        struct timeval timeout;
        timeout.tv_sec = SNDTIMEO_SECS;
        timeout.tv_usec = 0;

        int ret = setsockopt(
            fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval));
        assert(ret == 0);
    }

    {
        struct timeval timeout;
        socklen_t optlen = sizeof(struct timeval);
        int ret = getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, &optlen);
        assert(ret == 0);
        printf(
            "getsockopt() after set: tv_sec=%ld tv_usec=%ld\n",
            timeout.tv_sec,
            timeout.tv_usec);
        assert(timeout.tv_sec == SNDTIMEO_SECS);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    assert(
        connect(fd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == 0);

    /* connect() causes the socket device to be changed to host socket device,
    verify the send timeout settings were transferred */
    {
        struct timeval timeout;
        socklen_t optlen = sizeof(struct timeval);
        int ret = getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, &optlen);
        assert(ret == 0);
        printf(
            "getsockopt() after connect: tv_sec=%ld tv_usec=%ld\n",
            timeout.tv_sec,
            timeout.tv_usec);
        assert(timeout.tv_sec == SNDTIMEO_SECS);
    }

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
