// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char* argv[])
{
    char line[1024];
    FILE* fp = fopen("tmp/myst.key", "r");
    assert(fp != NULL);

    while (fgets(line, 1024, fp) != NULL)
    {
        puts(line);
    }
    fclose(fp);

    fp = fopen("tmp/myst.pem", "r");
    assert(fp != NULL);
    fclose(fp);

    return 0;
}
