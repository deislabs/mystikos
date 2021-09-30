// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    int fds[2];
    struct pollfd pollfds[1];

    // Create a pipe.
    assert(pipe(fds) == 0);

    // Close both pipe ends, making fds[0] and fds[1] invalid file descriptors.
    close(fds[1]);
    close(fds[0]);

    // Solicit an input event (POLLIN) on the already close file descriptors.
    pollfds[0].fd = fds[1];
    pollfds[0].events = POLLIN;
    pollfds[0].revents = 0;
    assert(poll(pollfds, 1, -1) == 1);

    // expect an invalid event (POLLNVAL)
    assert(pollfds[0].revents == POLLNVAL);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
