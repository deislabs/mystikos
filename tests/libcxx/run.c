// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void _run_tests(
    const char* test_file,
    bool passed,
    size_t index,
    size_t increment)
{
    FILE* file = fopen(test_file, "r");

    if (!file)
    {
        fprintf(stderr, "File %s not found \n", test_file);
    }
    char line[256];

    for (size_t i = 0; fgets(line, sizeof(line), file); i++)
    {
        line[strlen(line) - 1] = '\0';
        int r;
        pid_t pid;
        int wstatus;

        /* skip tests below the index */
        if (i < index)
            continue;

        /* skip lines that begin with '#' */
        if (line[0] == '#')
            continue;

        printf("=== start test: %s\n", line);

        char* const args[] = {(char*)line, NULL};
        char* const envp[] = {"VALUE=1", NULL};

        r = posix_spawn(&pid, line, NULL, NULL, args, envp);

        if (passed)
        {
            assert(r == 0);
            assert(pid >= 0);

            assert(waitpid(pid, &wstatus, WNOHANG) == 0);
            assert(waitpid(pid, &wstatus, 0) == pid);
            assert(WIFEXITED(wstatus));
            assert(WEXITSTATUS(wstatus) == 0);
        }
        printf("=== passed test (%s)\n", line);

        if ((i + 1) >= index + increment)
            break;
    }

    fclose(file);
}

int main(int argc, const char* argv[])
{
    size_t index = 0;
    size_t increment = SIZE_MAX;
    bool passed = true;

    if (argc < 2)
    {
        fprintf(
            stderr,
            "Usage: %s [PASSED|FAILED] <testfile> [<index> <increment>]\n",
            argv[0]);
        exit(1);
    }

    if (argc >= 4)
    {
        char* end = NULL;
        index = strtoul(argv[3], &end, 0);

        if (!end || *end)
        {
            fprintf(stderr, "%s: bad <index> argument: %s", argv[0], argv[1]);
            exit(1);
        }
    }

    if (argc >= 5)
    {
        char* end = NULL;
        increment = strtoul(argv[4], &end, 0);

        if (!end || *end || increment == 0)
        {
            fprintf(
                stderr, "%s: bad <increment> argument: %s", argv[0], argv[1]);
            exit(1);
        }
    }

    if (strcmp(argv[1], "PASSED") == 0)
        passed = true;
    else if (strcmp(argv[1], "FAILED") == 0)
        passed = false;
    else
    {
        printf("%s: first argument must be PASSED or FAILED\n", argv[0]);
        exit(1);
    }

    _run_tests(argv[2], passed, index, increment);

    printf("=== passed all tests: %s\n", argv[0]);
    return 0;
}
