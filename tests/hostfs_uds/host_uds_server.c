
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define PATH_MAX 4096

const char* hostdir = NULL;
char ready_path[PATH_MAX];
bool ready = false;

void failed()
{
    if (ready)
        unlink(ready_path);
    char failed[PATH_MAX];
    snprintf(failed, PATH_MAX, "%s/SRVR_FAILED", hostdir);
    creat(failed, S_IRWXU | S_IROTH);
    _exit(1);
}

void publish_readiness()
{
    ready = true;
    snprintf(ready_path, PATH_MAX, "%s/SRVR_READY", hostdir);
    creat(ready_path, S_IRWXU | S_IROTH);
}

void string_to_upper(char* s)
{
    for (int i = 0; s[i] != '\0'; i++)
    {
        if (s[i] >= 'a' && s[i] <= 'z')
        {
            s[i] = s[i] - 32;
        }
    }
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
        failed();

    hostdir = argv[1];
    if (hostdir[0] != '/')
        failed();

    char sock_path[PATH_MAX];
    snprintf(sock_path, PATH_MAX, "%s/hostsockfoo", hostdir);

    int srvrfd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (srvrfd < 0)
        failed();

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
    if (bind(srvrfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) != 0)
        failed();

    publish_readiness();

    if (listen(srvrfd, 1) != 0)
        failed();

    {
        int connfd = accept(srvrfd, NULL, 0);
        if (connfd < 0)
            failed();

        char sockbuf[1024];
        int nread, nwrite;

        nread = recv(connfd, sockbuf, 1024, 0);
        string_to_upper(sockbuf);
        send(connfd, sockbuf, strlen(sockbuf), 0);
        close(connfd);
    }

    close(srvrfd);
    unlink(sock_path);
    if (ready)
        unlink(ready_path);

    return 0;
}