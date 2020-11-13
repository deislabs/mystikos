// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

int call_foo(const char* argv0)
{
    void* handle;
    typedef int (*func_t)();
    func_t func;
    const char path[] = "/libfoo.so";

    if (!(handle = dlopen(path, RTLD_NOW)))
    {
        fprintf(stderr, "%s: dlopen() failed\n", argv0);
        return -1;
    }

    if (!(func = dlsym(handle, "foo")))
    {
        fprintf(stderr, "%s: dlsym() failed\n", argv0);
        return -1;
    }

    return (*func)();
}

int main(int argc, const char* argv[])
{
    int ret = call_foo(argv[0]);
    assert(ret == 12345);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
