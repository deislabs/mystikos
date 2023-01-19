// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void foofoo()
{
}

int main(int argc, const char* argv[])
{
    char buf[PATH_MAX];

    foofoo();

    getcwd(buf, sizeof(buf));
    assert(strcmp(buf, "/") == 0);

    return 0;
}
