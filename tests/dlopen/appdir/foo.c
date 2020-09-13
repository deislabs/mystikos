#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int call_bar(void)
{
    void* handle;
    typedef int (*func_t)();
    func_t func;
    const char path[] = "/libbar.so";

    if (!(handle = dlopen(path, RTLD_NOW)))
    {
        fprintf(stderr, "libfoo: dlopen() failed\n");
        return -1;
    }

    if (!(func = dlsym(handle, "bar")))
    {
        fprintf(stderr, "libfoo: dlsym() failed\n");
        return -1;
    }

    return (*func)();
}

int foo()
{
    // printf("foo()\n");
    return call_bar();
}
