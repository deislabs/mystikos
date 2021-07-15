// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void _run_tests(const char* test_file)
{
    FILE* file = fopen(test_file, "r");

    if (!file)
    {
        fprintf(stderr, "File %s not found \n", test_file);
    }
    char line[256];
    int i = 1;
    while (fgets(line, sizeof(line), file))
    {
        line[strlen(line) - 1] = '\0';
        int r;
        pid_t pid;
        int wstatus;

        printf("=== start test %d: %s\n", i++, line);

        char* const args[] = {(char*)line, NULL};
        char* const envp[] = {"VALUE=1", NULL};

        r = posix_spawn(&pid, line, NULL, NULL, args, envp);

        assert(r == 0);
        assert(pid >= 0);

        assert(waitpid(pid, &wstatus, 0) == pid);
        assert(WIFEXITED(wstatus));
        if ((r = WEXITSTATUS(wstatus)) != 0)
        {
            printf("!!! WEXITSTATUS(wstatus) = %d\n", r);
            assert(0);
        }
        printf("=== passed test (%s)\n", line);
    }

    fclose(file);
}

int main(int argc, const char* argv[])
{
    if (argc < 1)
    {
        fprintf(stderr, "Must pass in the file containing test names\n");
    }
    else
    {
        _run_tests(argv[1]);
    }

    printf("=== passed all tests: %s\n", argv[0]);
    return 0;
}
