#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

void call_foo(const char* argv0)
{
    void* handle;
    typedef void (*func_t)();
    func_t func;
    const char path[] = "/libfoo.so";

    if (!(handle = dlopen(path, RTLD_NOW)))
    {
        fprintf(stderr, "%s: dlopen() failed\n", argv0);
        exit(1);
    }

    if (!(func = dlsym(handle, "foo")))
    {
        fprintf(stderr, "%s: dlsym() failed\n", argv0);
        exit(1);
    }

    (*func)();

    dlclose(handle);

}

int main(int argc, const char* argv[])
{
    call_foo(argv[0]);
    return 0;
}
