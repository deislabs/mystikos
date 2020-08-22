#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>

void call_bar(void)
{
    void* handle;
    typedef void (*func_t)();
    func_t func;
    const char path[] = "/libbar.so";

    if (!(handle = dlopen(path, RTLD_NOW)))
    {
        fprintf(stderr, "libfoo: dlopen() failed\n");
        exit(1);
    }

    if (!(func = dlsym(handle, "bar")))
    {
        fprintf(stderr, "libfoo: dlsym() failed\n");
        exit(1);
    }

    (*func)();

    dlclose(handle);
}

void foo()
{
    printf("foo()\n");
    call_bar();
}
