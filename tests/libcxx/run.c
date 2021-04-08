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

static void _run_tests(const char* test_file, bool passed)
{
    FILE* file = fopen(test_file, "r");

    if (!file)
    {
        fprintf(stderr, "File %s not found \n", test_file);
    }
    char line[256];

    while (fgets(line, sizeof(line), file))
    {
        int r;
        pid_t pid;
        size_t len = strlen(line);

        /* ignore blank lines and comment lines */
        if (line[0] == '\0' || line[0] == '#')
            continue;

        /* remove the trailing newline if any (the final line may have none) */
        if (line[len - 1] == '\n')
            line[len - 1] = '\0';

        printf("=== start test: %s\n", line);

        char* const args[] = {(char*)line, NULL};
        char* const envp[] = {"VALUE=1", NULL};

        r = posix_spawn(&pid, line, NULL, NULL, args, envp);

        if (passed)
        {
            int wstatus = 0;
            assert(r == 0);
            assert(pid >= 0);

            assert(waitpid(pid, &wstatus, WNOHANG) == 0);
            assert(waitpid(pid, &wstatus, 0) == pid);
            assert(WIFEXITED(wstatus));
            assert(WEXITSTATUS(wstatus) == 0);
        }
        printf("=== passed test (%s)\n", line);
    }

    fclose(file);
}

int main(int argc, const char* argv[])
{
    if (argc < 2)
    {
        fprintf(
            stderr,
            "Must pass in \"PASSED\" or \"FAILED\" and the file containing "
            "test names\n");
    }
    else
    {
        if (strcmp(argv[1], "PASSED") == 0)
        {
            _run_tests(argv[2], true);
        }
        else if (strcmp(argv[1], "FAILED") == 0)
        {
            _run_tests(argv[2], false);
        }
        else
        {
            fprintf(
                stderr,
                "Invalid argument %s. Should be \"PASSED\" or \"FAILED\"\n",
                argv[1]);
        }
    }

    printf("=== passed all tests: %s\n", argv[0]);
    return 0;
}
