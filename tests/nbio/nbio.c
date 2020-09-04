#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <assert.h>

int main(int argc, const char* argv[])
{
    int sock;
    int flags;
    int r;
    int val;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    assert(sock >= 0);
    // printf("sock=%d\n", sock);

    flags = fcntl(sock, F_GETFL);
    // printf("flags=0%o (%d)\n", flags, flags);
    assert((flags & O_NONBLOCK) == 0);

    r = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    assert(r == 0);

    flags = fcntl(sock, F_GETFL);
    // printf("flags=0%o (%d)\n", flags, flags);
    assert((flags & O_NONBLOCK) != 0);

    r = fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
    assert(r == 0);

    flags = fcntl(sock, F_GETFL);
    // printf("flags=0%o (%d)\n", flags, flags);
    assert((flags & O_NONBLOCK) == 0);

    val = 1;
    r = ioctl(sock, FIONBIO, &val);
    assert(r == 0);

    flags = fcntl(sock, F_GETFL);
    // printf("flags=0%o (%d)\n", flags, flags);
    assert((flags & O_NONBLOCK) != 0);

    val = 0;
    r = ioctl(sock, FIONBIO, &val);
    assert(r == 0);

    flags = fcntl(sock, F_GETFL);
    // printf("flags=0%o (%d)\n", flags, flags);
    assert((flags & O_NONBLOCK) == 0);

    close(sock);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
