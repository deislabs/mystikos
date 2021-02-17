// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <syscall.h>
#include <unistd.h>

void* thread_func(void* args)
{
    int readFd = *(int*)args;
    while (1)
    {
        int ret, data;
        // read is blocking until writer writes to pipe
        while ((ret = read(readFd, &data, 1)) < 0 && errno == EINTR)
            ;

        if (ret < 0)
        {
            close(readFd);
            return;
        }
    }
    printf("unreachable (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    int pipeFds[2];
    int flags = O_CLOEXEC;
    int ret = pipe2(pipeFds, flags);
    assert(ret == 0);
    pthread_t child;
    pthread_create(&child, NULL, thread_func, &pipeFds[0]);
    printf("main thread exiting w/o writing to pipe...\n");
    // CRT will call sys_exit_group as part of exit sequence
    // this should kill the child thread
    return 0;
}
