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

static void _run_tests(const char* test_file, size_t index, size_t increment)
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

        printf("=== start test: %s index=%zu\n", line, i);

        char* const args[] = {(char*)line, NULL};
        char* const envp[] = {"VALUE=1", NULL};

        r = posix_spawn(&pid, line, NULL, NULL, args, envp);

        assert(r == 0);
        assert(pid >= 0);

        assert(waitpid(pid, &wstatus, WNOHANG) == 0);
        assert(waitpid(pid, &wstatus, 0) == pid);
        assert(WIFEXITED(wstatus));
        assert(WEXITSTATUS(wstatus) == 0);
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

    if (argc < 2)
    {
        fprintf(
            stderr, "Usage: %s <testfile> [<index> <increment>]\n", argv[0]);
        exit(1);
    }

    if (argc >= 3)
    {
        char* end = NULL;
        index = strtoul(argv[2], &end, 0);

        if (!end || *end)
        {
            fprintf(stderr, "%s: bad <index> argument: %s", argv[0], argv[1]);
            exit(1);
        }
    }

    if (argc >= 4)
    {
        char* end = NULL;
        increment = strtoul(argv[3], &end, 0);

        if (!end || *end || increment == 0)
        {
            fprintf(
                stderr, "%s: bad <increment> argument: %s", argv[0], argv[1]);
            exit(1);
        }
    }

    _run_tests(argv[1], index, increment);

    printf("=== passed all tests: %s\n", argv[0]);
    return 0;
}
