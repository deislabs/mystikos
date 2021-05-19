#include <dlfcn.h>
#include <stdio.h>

int main()
{
    void* handle;

    handle = dlopen("libgomp.so.1.0.0", RTLD_GLOBAL);
    if (!handle)
    {
        printf("%s\n", dlerror());
        return (-1);
    }

    printf("dlopen libgomp.so succeed\n");

    dlclose(handle);
    return (0);
}
