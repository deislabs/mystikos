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

    while (fgets(line, sizeof(line), file))
    {
        line[strlen(line) - 1] = '\0';
        int r;
        pid_t pid;
        int wstatus;

        printf("=== start test: %s\n", line);

        /* skip lines that begin with '#' */
        if (line[0] == '#')
            continue;

        char* const args[] = {(char*)line, NULL};
        char* const envp[] = {"VALUE=1", NULL};

        r = posix_spawn(&pid, line, NULL, NULL, args, envp);

        assert(r == 0);
        assert(pid >= 0);

        assert(waitpid(pid, &wstatus, WNOHANG) == 0);
        assert(waitpid(pid, &wstatus, 0) == pid);
        assert(WIFEXITED(wstatus));

        if (WEXITSTATUS(wstatus) != 0)
        {
            fprintf(stderr, "****** libc test failed: %s\n", line);
            fflush(stdout);
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
        fprintf(stderr, "Must pass the file containing test names\n");
    }
    else
    {
        _run_tests(argv[1]);
    }

    printf("=== passed all tests: %s\n", argv[0]);
    return 0;
}
