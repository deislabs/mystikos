// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <libos/args.h>
#include <libos/defs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void dump(const char* args[], size_t size)
{
    for (size_t i = 0; i < size; i++)
        printf("args[%zu]={%s}\n", i, args[i]);

    printf("\n");
}

void test(void)
{
    libos_args_t args;

    assert(libos_args_init(&args) == 0);
    assert(args.size == 0);
    assert(args.data[0] == NULL);

    assert(libos_args_append1(&args, "red") == 0);
    assert(args.size == 1);
    assert(strcmp(args.data[0], "red") == 0);
    assert(args.data[1] == NULL);

    assert(libos_args_append1(&args, "green") == 0);
    assert(args.size == 2);
    assert(strcmp(args.data[0], "red") == 0);
    assert(strcmp(args.data[1], "green") == 0);
    assert(args.data[2] == NULL);

    assert(libos_args_append1(&args, "blue") == 0);
    assert(args.size == 3);
    assert(strcmp(args.data[0], "red") == 0);
    assert(strcmp(args.data[1], "green") == 0);
    assert(strcmp(args.data[2], "blue") == 0);
    assert(args.data[3] == NULL);

    assert(libos_args_prepend1(&args, "yellow") == 0);
    assert(args.size == 4);
    assert(strcmp(args.data[0], "yellow") == 0);
    assert(strcmp(args.data[1], "red") == 0);
    assert(strcmp(args.data[2], "green") == 0);
    assert(strcmp(args.data[3], "blue") == 0);
    assert(args.data[4] == NULL);

    assert(libos_args_prepend(&args, args.data, args.size) == 0);
    assert(args.size == 8);
    assert(strcmp(args.data[0], "yellow") == 0);
    assert(strcmp(args.data[1], "red") == 0);
    assert(strcmp(args.data[2], "green") == 0);
    assert(strcmp(args.data[3], "blue") == 0);
    assert(strcmp(args.data[4], "yellow") == 0);
    assert(strcmp(args.data[5], "red") == 0);
    assert(strcmp(args.data[6], "green") == 0);
    assert(strcmp(args.data[7], "blue") == 0);
    assert(args.data[8] == NULL);

    assert(libos_args_remove(&args, 1, 6) == 0);
    assert(args.size == 2);
    assert(strcmp(args.data[0], "yellow") == 0);
    assert(strcmp(args.data[1], "blue") == 0);
    assert(args.data[2] == NULL);

    assert(libos_args_remove(&args, 1, 1) == 0);
    assert(args.size == 1);
    assert(strcmp(args.data[0], "yellow") == 0);
    assert(args.data[1] == NULL);

    assert(libos_args_remove(&args, 0, 1) == 0);
    assert(args.size == 0);
    assert(args.data[0] == NULL);
}

int main(int argc, const char* argv[])
{
    test();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
