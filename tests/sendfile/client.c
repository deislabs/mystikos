// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "../utils/utils.h"
#include "common.h"

static ssize_t _readn(int fd, void* data_in, size_t size)
{
    ssize_t ret = 0;
    uint8_t* p = (uint8_t*)data_in;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n = read(fd, p, r);

        if (n <= 0)
        {
            ret = -1;
            goto done;
        }

        p += n;
        r -= (size_t)n;
    }

done:

    return ret;
}

void run_client(uint16_t port)
{
    int sd;
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    char buf[16 * 1024];
    const size_t N = 10;
    ssize_t total = 0;
    char* data_in;
    char* data_out;
    char* ptr;
    int fd;

    if (!(data_in = malloc(BIG_FILE_SIZE)))
        assert("malloc failed" == NULL);

    if (!(data_out = malloc(BIG_FILE_SIZE)))
        assert("malloc failed" == NULL);

    /* read the big file into memory */
    assert((fd = open("/bigfile", O_RDONLY)) > 0);
    assert(_readn(fd, data_out, BIG_FILE_SIZE) == 0);
    close(fd);

    ptr = data_in;

    /* Create the client socket. */
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        assert("socket() failed" == NULL);
    }

    /* Connect to the server. */
    {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port);

        if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        {
            assert("connect() failed" == NULL);
        }
    }

    /* receive the big file that server writes back */
    for (;;)
    {
        sleep_msec(10);
        ssize_t n = read(sd, buf, sizeof(buf));

        if (n == 0)
            break;

        assert(n > 0);

        printf("=== client read %zd\n", n);

        memcpy(ptr, buf, n);
        ptr += n;
        total += n;
    }

    printf("=== client received %zu bytes\n", total);

    /* check that all the bytes were transferred */
    assert(total == BIG_FILE_SIZE);
    assert(ptr == data_in + total);

    /* verify that the file content is correct */
    assert(memcmp(data_in, data_out, BIG_FILE_SIZE) == 0);

    close(sd);
    free(data_in);
    free(data_out);
}
