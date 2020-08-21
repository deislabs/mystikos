#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(int argc, const char* argv[])
{
    void* handle;
    typedef void (*func_t)();
    func_t func;
    const char path[] = "/root/oe-libos/samples/dlopen/appdir/lib/libfoo.so";

    if (!(handle = dlopen(path, RTLD_NOW)))
    {
        fprintf(stderr, "%s: dlopen() failed\n", argv[0]);
        exit(1);
    }

    if (!(func = dlsym(handle, "foo")))
    {
        fprintf(stderr, "%s: dlsym() failed\n", argv[0]);
        exit(1);
    }

    (*func)();

    dlclose(handle);

    return 0;
}
