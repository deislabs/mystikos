// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

static void test1(size_t stacksize_opt)
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    size_t stacksize;
    pthread_attr_getstacksize(&attr, &stacksize);
    // printf("stacksize=%zu\n", stacksize);
    assert(stacksize == stacksize_opt);

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    /* check the number of command line arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <stacksize>\n", argv[0]);
        exit(1);
    }

    /* get the stacksize option */
    size_t stacksize_opt;
    {
        char* end = NULL;
        stacksize_opt = strtoul(argv[1], &end, 0);
        assert(end && *end == '\0');
        assert(stacksize_opt > 0);
    }

    /* run tests */
    test1(stacksize_opt);

    printf("=== passed all tests (%s)\n", argv[0]);
    return 0;
}
