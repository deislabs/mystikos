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

void* start(void* arg)
{
    printf("child thread\n");
    return arg;
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
        assert(waitpid(pid, &wstatus, 0) == pid);
        assert(WIFEXITED(wstatus));
        assert(WEXITSTATUS(wstatus) == 123);

        /* try to access "/tmp/alpha" (created by child process) */
        {
            int fd;
            char buf[1024];
            assert(access("/tmp/alpha", F_OK) == 0);
            assert((fd = open("/tmp/alpha", O_RDONLY)) >= 0);
            assert(read(fd, buf, sizeof(buf)) == 27);
            assert(close(fd) == 0);
            assert(strcmp(buf, "abcdefghijklmnopqrstuvwxyz") == 0);
            printf("PARENT{%s}\n", buf);
        }

        /* try to access /tmp/shared */
        {
            int fd;
            char buf[1024];
            assert(access("/tmp/shared", F_OK) == 0);
            assert((fd = open("/tmp/shared", O_RDONLY)) >= 0);
            assert(read(fd, buf, sizeof(buf)) == 7);
            assert(close(fd) == 0);
            assert(strcmp(buf, "shared") == 0);
            printf("parent: shared{%s}\n", buf);
        }

        printf("%s: parent exit\n", argv[0]);
        exit(0);
    }
    else /* child */
    {
        double elapsed = (double)(_time_usec() - t1) / 1000000.0;
        printf("%s: child: %3.5lfsec\n", argv[0], elapsed);

        /* write to the inherited file */
        assert(write(fd, "shared", 7) == 7);
        close(fd);

        pthread_t th;
        assert(pthread_create(&th, NULL, start, NULL) == 0);

#if 1
        for (size_t i = 0; i < 3; i++)
        {
            printf("%s: child: %zu\n", argv[0], i);
            sleep(1);
        }
#endif

        assert(pthread_join(th, NULL) == 0);

        char* args[] = {"/bin/hello", NULL};
        char* env[] = {NULL};
        execve("/bin/hello", args, env);
        abort();
    }

    return 0;
}
