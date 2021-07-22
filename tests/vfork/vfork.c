// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

const char* arg0;

static bool _reached_parent;
static bool _reached_child;

#define STRING1 "\001\001\001\001\001\001\001\001"
#define STRING2 "\002\002\002\002\002\002\002\002"
#define STRING3 "Hello world!"
#define STRING4 "Goodbye world!"

#define VALUE ((uint64_t)0xcca906a5e5e7485a)

void test(bool exec, uint64_t* ptr)
{
    _reached_parent = false;
    _reached_child = false;
    char buf[9];
    char buf2[1024];

    strcpy(buf, STRING1);
    strcpy(buf2, STRING3);

    pid_t pid = vfork();

    if (pid < 0)
    {
        fprintf(
            stderr, "%s: fork() failed: %d: %s\n", arg0, pid, strerror(errno));
        assert(0);
    }
    else if (pid == 0) /* child */
    {
        printf("=== inside child\n");
        _reached_child = true;
        sleep(1);

        strcpy(buf, STRING2);
        strcpy(buf2, STRING4);

        /* verify that vfork() suspended execution of the parent process */
        assert(_reached_parent == false);

        assert(pid == 0);

        *ptr = VALUE;

        if (exec)
        {
            char* args[] = {"/bin/child", NULL};
            char* env[] = {NULL};
            execve("/bin/child", args, env);
            assert(false);
        }

        _exit(123);
    }
    else /* parent */
    {
        printf("=== inside parent\n");
        int wstatus;
        _reached_parent = true;

        /* check that the child changed the parent's stack */
        assert(strcmp(buf, STRING1) == 0);
        assert(strcmp(buf2, STRING3) == 0);

        assert(waitpid(pid, &wstatus, 0) == pid);
        assert(WIFEXITED(wstatus));
        assert(WEXITSTATUS(wstatus) == 123);
        assert(pid != 0);
    }

    assert(_reached_child == true);
    assert(_reached_parent == true);

    printf("=== passed test (%s): %s\n", arg0, (exec ? "exec" : "exit"));
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    uint64_t value;

    test(true, &value);
    test(false, &value);
    assert(value == VALUE);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
