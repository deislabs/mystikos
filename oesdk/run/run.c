// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char* argv[])
{
    void* handle;
    typedef int (*main_t)(int argc, const char* argv[]);
    main_t main_func;
    int ret;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <shlib>\n", argv[0]);
        exit(1);
    }

    if (!(handle = dlopen(argv[1], RTLD_NOW)))
    {
        fprintf(stderr, "%s: dlopen() failed: %s\n", argv[0], argv[1]);
        exit(1);
    }

    if (!(main_func = dlsym(handle, "main")))
    {
        fprintf(stderr, "%s: dlsym() failed: %s\n", argv[0], "main");
        exit(1);
    }

    ret = (*main_func)(argc, argv);

    dlclose(handle);

    return ret;
}
