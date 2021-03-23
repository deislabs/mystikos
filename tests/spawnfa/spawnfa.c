// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char** environ;

int main(int argc, const char* argv[])
{
    /* create a pipe for reading the child's standard output */
    int pipefd[2];
    assert(pipe(pipefd) == 0);

    /* the child will dup pipefd[1] to stdout and close the pipefs[0] */
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, pipefd[0]);

    /* spawn the child (inheriting the parent's environment) */
    pid_t pid;
    char* const child_argv[] = {"/bin/child", NULL};
    int r = posix_spawn(&pid, "/bin/child", &fa, NULL, child_argv, environ);
    assert(r == 0);

    /* release the file actions */
    assert(posix_spawn_file_actions_destroy(&fa) == 0);

    /* read the stdout of the child */
    char buf[256];
    ssize_t n = read(pipefd[0], buf, sizeof(buf));
    assert(n == 26);
    assert(memcmp(buf, "abcdefghijklmnopqrstuvwxyz\n", 26) == 0);
    printf("buf{%s}\n", buf);

    /* wait for child to exit */
    int wstatus;
    assert(waitpid(pid, &wstatus, 0) == pid);
    assert(WIFEXITED(wstatus));
    assert(WEXITSTATUS(wstatus) == 99);

    /* close the parent's end of the pipe */
    close(pipefd[0]);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
