// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <stdio.h>
extern char** environ;

int main(int argc, const char* argv[])
{
    char** s = environ;
    int var_found = 0;
    int TOTAL_VARS = 3;
    for (; *s; s++)
    {
        printf("%s\n", *s);

        if (strncmp(*s, "VAR1=var1", 9) == 0)
            var_found++;
        if (strncmp(*s, "VAR2=var1", 9) == 0)
            var_found++;
        if (strncmp(*s, "PATH=", 5) == 0)
            var_found++;
    }

    if (var_found != TOTAL_VARS)
    {
        fprintf(
            stderr,
            "%d variables found, %d variables needed.\n",
            var_found,
            TOTAL_VARS);
        fprintf(stderr, "=== failed test %s\n", argv[0]);
    }
    else
    {
        printf("%d variables found\n", var_found);
        printf("=== passed test (%s)\n", argv[0]);
    }

    return 0;
}
