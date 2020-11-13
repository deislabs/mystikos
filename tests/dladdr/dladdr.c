// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

void foo()
{
}

int main(int argc, const char* argv[])
{
    Dl_info info;

    int ret = dladdr(foo, &info);
    assert(ret != 0);

    printf("addr=%p\n", foo);
    printf("dli_fname=%s\n", info.dli_fname);
    printf("dli_sname=%s\n", info.dli_sname);
    printf("dli_saddr=%p\n", info.dli_saddr);
    printf("dli_fbase=%p\n", info.dli_fbase);

    assert(strcmp(info.dli_fname, "/bin/dladdr") == 0);
    assert(strcmp(info.dli_sname, "foo") == 0);
    assert(info.dli_saddr == foo);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
