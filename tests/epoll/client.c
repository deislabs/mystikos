// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

void run_client(uint16_t port)
{
    int sd;
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    char buf[1024];
    const size_t N = 3;

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

    /* write/read "alphabet" to/from  the server. */
    for (size_t i = 0; i < N; i++)
    {
        if (send(sd, alphabet, sizeof(alphabet), 0) != sizeof(alphabet))
        {
            assert("write() failed" == NULL);
        }

        /* Read "alphabet" from the server. */

        if (recv(sd, buf, sizeof(buf), 0) != sizeof(alphabet))
            assert("read() failed" == NULL);

        if (memcmp(alphabet, buf, sizeof(alphabet)) != 0)
        {
            assert("memcmp() failed" == NULL);
        }
    }

    close(sd);
}
