// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    pid_t pid = fork();

    if (pid < 0) /* error */
    {
        fprintf(stderr, "%s: fork failed\n", argv[0]);
        exit(1);
    }
    else if (pid > 0) /* parent */
    {
        printf("%s: parent: pid=%d\n", argv[0], pid);

        for (size_t i = 0; i < 10; i++)
        {
            printf("%s: parent: %zu\n", argv[0], i);
            sleep(1);
        }

        sleep(2);
        printf("%s: parent exit\n", argv[0]);
        exit(0);
    }
    else /* child */
    {
        printf("%s: child\n", argv[0]);

        for (size_t i = 0; i < 10; i++)
        {
            printf("%s: child: %zu\n", argv[0], i);
            sleep(1);
        }

        printf("%s: child exit\n", argv[0]);
        exit(0);
    }

    return 0;
}
