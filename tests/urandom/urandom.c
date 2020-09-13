#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

void _dump(const void* s, size_t n)
{
    const uint8_t* p = (const uint8_t*)s;

    while (n--)
        printf("%02x", *p++);

    printf("\n");
}

static void _test_read(void)
{
    int fd;
    ssize_t n;
    const size_t N = 32;
    char zero_buf[N];
    char buf[N];

    fd = open("/dev/urandom", O_RDONLY);
    assert(fd >= 0);

    memset(zero_buf, 0, sizeof(zero_buf));
    memset(buf, 0, sizeof(buf));
    n = read(fd, buf, sizeof(buf));
    assert(n == sizeof(buf));
    assert(memcmp(zero_buf, buf, sizeof(buf)) != 0);

#if 0
    _dump(buf, n);
#endif

    n = read(fd, NULL, sizeof(buf));
    assert(n == -1);
    assert(errno = EFAULT);

    n = read(fd, buf, 0);
    assert(n == 0);

    n = read(fd, NULL, 0);
    assert(n == 0);

    assert(close(fd) == 0);
}

static void _test_readv(void)
{
    int fd;
    ssize_t n;
    const size_t N = 32;
    char zero_buf[N];
    char buf1[N];
    char buf2[N];
    struct iovec iov[2];

    fd = open("/dev/urandom", O_RDONLY);
    assert(fd >= 0);

    memset(zero_buf, 0, sizeof(zero_buf));
    memset(buf1, 0, sizeof(buf1));
    memset(buf2, 0, sizeof(buf2));

    iov[0].iov_base = buf1;
    iov[0].iov_len = sizeof buf1;

    iov[1].iov_base = buf2;
    iov[1].iov_len = sizeof buf2;

    n = readv(fd, iov, 2);
    assert(n == sizeof(buf1) + sizeof(buf2));
    assert(memcmp(zero_buf, buf1, sizeof(buf1)) != 0);
    assert(memcmp(zero_buf, buf2, sizeof(buf2)) != 0);

    assert(close(fd) == 0);
}

int main(int argc, const char* argv[])
{
    _test_read();
    _test_readv();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
