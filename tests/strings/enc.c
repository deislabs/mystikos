// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <libos/malloc.h>
#include <libos/strings.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "run_t.h"

int test_strsplit(
    const char* str,
    const char* delim,
    const char* toks[],
    size_t ntoks)
{
    int ret = -1;
    char** p = NULL;
    size_t n = 0;

    assert(libos_strsplit(str, delim, &p, &n) == 0);

    if (n != ntoks)
        goto done;

    for (size_t i = 0; i < n; i++)
    {
        if (strcmp(p[i], toks[i]) != 0)
            goto done;
    }

    ret = 0;

done:

    if (p)
        libos_free(p);

    return ret;
}

int run_ecall(void)
{
    {
        const char str[] = "red:green:blue";
        const char* toks[] = {"red", "green", "blue"};
        size_t ntoks = sizeof(toks) / sizeof(toks[0]);
        assert(test_strsplit(str, ":", toks, ntoks) == 0);
        printf("=== passed test (strsplit 1)\n");
    }

    {
        const char str[] = "red,green:blue;";
        const char* toks[] = {"red", "green", "blue"};
        size_t ntoks = sizeof(toks) / sizeof(toks[0]);
        assert(test_strsplit(str, ",;:", toks, ntoks) == 0);
        printf("=== passed test (strsplit 2)\n");
    }

    {
        const char str[] = "t";
        const char* toks[] = {"t"};
        size_t ntoks = sizeof(toks) / sizeof(toks[0]);
        test_strsplit(str, "?", toks, ntoks);
        assert(test_strsplit(str, "?", toks, ntoks) == 0);
        printf("=== passed test (strsplit 3)\n");
    }

    {
        const char str[] = "";
        assert(test_strsplit(str, ":", NULL, 0) == 0);
        printf("=== passed test (strsplit 4)\n");
    }

    {
        const char str[] = "";
        assert(test_strsplit(str, ":", NULL, 0) == 0);
        printf("=== passed test (strsplit 5)\n");
    }

    {
        const char* toks[] = {"red", "green", "blue"};
        size_t ntoks = sizeof(toks) / sizeof(toks[0]);
        char* str = NULL;
        assert(libos_strjoin(toks, ntoks, NULL, ":", NULL, &str) == 0);
        assert(strcmp(str, "red:green:blue") == 0);
        libos_free(str);
    }

    {
        const char* toks[] = {"red", "green", "blue"};
        size_t ntoks = sizeof(toks) / sizeof(toks[0]);
        char* str = NULL;
        assert(libos_strjoin(toks, ntoks, "(", ":", ")", &str) == 0);
        assert(strcmp(str, "(red:green:blue)") == 0);
        libos_free(str);
    }

    {
        const char* toks[] = {"x"};
        size_t ntoks = sizeof(toks) / sizeof(toks[0]);
        char* str = NULL;
        assert(libos_strjoin(toks, ntoks, "(", ":", ")", &str) == 0);
        assert(strcmp(str, "(x)") == 0);
        libos_free(str);
    }

    {
        char* str = NULL;
        assert(libos_strjoin(NULL, 0, "(", ":", ")", &str) == 0);
        assert(strcmp(str, "()") == 0);
        libos_free(str);
    }

    extern int libos_find_leaks(void);
    assert(libos_find_leaks() == 0);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,         /* ProductID */
    1,         /* SecurityVersion */
    true,      /* Debug */
    16 * 4096, /* NumHeapPages */
    4096,      /* NumStackPages */
    2);        /* NumTCS */
