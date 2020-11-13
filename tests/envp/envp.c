// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, const char* argv[], const char* envp[])
{
    const char* target;
    const char* uuid;

    if (argc != 2)
    {
        fprintf(stderr, "%s: wrong number of arguments\n", argv[0]);
        return 1;
    }

    assert(target = getenv("LIBOS_TARGET"));
    assert(strcmp(target, argv[1]) == 0);

    printf("target=%s\n", target);

    assert(uuid = getenv("UUID_051005DCD0B0448AAD4746E8538F4D81"));
    assert(strcmp(uuid, "12345") == 0);

#if 0
    printf("target=%s\n", target);
    printf("uuid=%s\n", uuid);

    for (size_t i = 0; envp[i]; i++)
        printf("envp[%zu]={%s}\n", i, envp[i]);
#endif

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
