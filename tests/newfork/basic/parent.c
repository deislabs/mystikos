// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t _time_usec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

int main(int argc, const char* argv[])
{
    uint64_t t1 = _time_usec();
    int fd = open("/tmp/shared", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    assert(fd >= 0);

    pid_t pid = fork();

    if (pid < 0) /* error */
    {
        fprintf(stderr, "%s: fork failed\n", argv[0]);
        exit(1);
    }
    else if (pid > 0) /* parent */
    {
        double elapsed = (double)(_time_usec() - t1) / 1000000.0;
        printf("%s: parent: pid=%d %3.5lfsec\n", argv[0], pid, elapsed);

        /* wait for child to exit */
        int wstatus;
        printf("%s: parent: pid=%d before waitpid\n", argv[0], pid);
        assert(waitpid(pid, &wstatus, 0) == pid);
        assert(WIFEXITED(wstatus));
        assert(WEXITSTATUS(wstatus) == 123);
        printf("%s: parent: pid=%d after waitpid\n", argv[0], pid);

        printf("%s: parent exit\n", argv[0]);
        exit(0);
    }
    else /* child */
    {
        double elapsed = (double)(_time_usec() - t1) / 1000000.0;
        printf("%s: child: %3.5lfsec\n", argv[0], elapsed);

#if 0
        for (size_t i = 0; i < 3; i++)
        {
            printf("%s: child: %zu\n", argv[0], i);
            sleep(1);
        }
#endif

#if 1
        char* args[] = {"/bin/child", NULL};
        char* env[] = {NULL};
        execve("/bin/child", args, env);
        abort();
#else
        _exit(123);
#endif
    }

    return 0;
}
