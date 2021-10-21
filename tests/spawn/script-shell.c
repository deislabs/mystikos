// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <string.h>

int main(int argc, const char** argv)
{
    int ret = 0;

    if (argc == 2)
    {
        if (strcmp(argv[0], "/bin/shell") != 0)
        {
            fprintf(stderr, "shell path wrong: %s\n", argv[0]);
            ret = -1;
        }
        if ((strcmp(argv[1], "/bin/script1.sh") != 0) &&
            (strcmp(argv[1], "/bin/script2.sh") != 0) &&
            (strcmp(argv[1], "/bin/script4.sh") != 0))
        {
            fprintf(stderr, "script name is wrong: %s\n", argv[1]);
            ret = -1;
        }
    }
    else if (argc == 3)
    {
        if (strcmp(argv[0], "/bin/shell") != 0)
        {
            fprintf(stderr, "shell path is wrong: %s\n", argv[0]);
            ret = -1;
        }
        if (strcmp(argv[1], "parameter") != 0)
        {
            fprintf(stderr, "shell parameter is wrong: %s\n", argv[1]);
            ret = -1;
        }
        if ((strcmp(argv[2], "/bin/script3.sh") != 0) &&
            (strcmp(argv[2], "/bin/script5.sh") != 0))
        {
            fprintf(stderr, "script name is wrong: %s\n", argv[2]);
            ret = -1;
        }
    }
    else if (argc == 5)
    {
        if (strcmp(argv[0], "/bin/shell") != 0)
        {
            fprintf(stderr, "shell path wrong: %s\n", argv[0]);
            ret = -1;
        }
        if (strcmp(argv[1], "parameter") != 0)
        {
            fprintf(stderr, "shell parameter is wrong: %s\n", argv[1]);
            ret = -1;
        }
        if (strcmp(argv[2], "/bin/script6.sh") != 0)
        {
            fprintf(stderr, "script name is wrong: %s\n", argv[2]);
            ret = -1;
        }
        if (strcmp(argv[3], "extra") != 0)
        {
            fprintf(stderr, "first script parameter wrong: %s\n", argv[3]);
            ret = -1;
        }
        if (strcmp(argv[4], "options") != 0)
        {
            fprintf(stderr, "second script parameter wrong: %s\n", argv[4]);
            ret = -1;
        }
    }
    else
    {
        fprintf(stderr, "we did not get the correct number of parameters");
        ret = -1;
    }
    return ret;
}