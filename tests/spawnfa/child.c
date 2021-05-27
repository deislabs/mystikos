// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdio.h>

int main(int argc, const char* argv[], const char* envp[])
{
    if (printf("abcdefghijklmnopqrstuvwxyz") != 26)
        assert("failed to print alphabet to stdout");
    return 99;
}
