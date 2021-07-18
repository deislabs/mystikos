// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t _time_usec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
}

void* start(void* arg)
{
    printf("=== child thread\n");
    return arg;
}

int main(int argc, const char* argv[])
{
    uint64_t t1 = _time_usec();
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
        assert(waitpid(pid, &wstatus, 0) == pid);
        assert(WIFEXITED(wstatus));
        assert(WEXITSTATUS(wstatus) == 123);

        printf("%s: parent exit\n", argv[0]);
        exit(0);
    }
    else /* child */
    {
        double elapsed = (double)(_time_usec() - t1) / 1000000.0;
        printf("%s: child: %3.5lfsec\n", argv[0], elapsed);

        for (size_t i = 0; i < 3; i++)
        {
            printf("%s: child: %zu\n", argv[0], i);
            sleep(1);
        }

        pthread_t th;
        assert(pthread_create(&th, NULL, start, NULL) == 0);
        int r = pthread_join(th, NULL);
        printf("pthread_join: %d\n", r);

#if 1
        char* args[] = {"/bin/hello", NULL};
        char* env[] = {NULL};
        execve("/bin/hello", args, env);
        abort();
#endif
        exit(123);
    }

    return 0;
}
