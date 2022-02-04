// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <syscall.h>
#include <unistd.h>
#include <cassert>
#include <cstdbool>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stack>
#include <vector>

static void test_perf(void)
{
    static const size_t N = 2200;
    std::stack<void*> st;

    for (size_t k = 0; k < N; k++)
    {
        for (size_t i = 0; i < N; i++)
        {
            int n = rand() % 4096;

            if (n < 0)
                n = -n;
            else if (n == 0)
                n = 1;

            void* ptr = malloc(n);
            assert(ptr != NULL);
            st.push(ptr);
        }

        for (size_t i = 0; i < N; i++)
        {
            void* ptr = st.top();
            st.pop();
            assert(ptr != NULL);
            free(ptr);
        }
    }
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s [brk|nobrk]\n", argv[0]);
        exit(1);
    }

    bool enable_brk;

    if (strcmp(argv[1], "brk") == 0)
    {
        enable_brk = true;
    }
    else if (strcmp(argv[1], "nobrk") == 0)
    {
        enable_brk = false;
    }
    else
    {
        fprintf(stderr, "%s: bad argument: %s\n", argv[0], argv[1]);
        exit(1);
    }

    errno = 0;
    void* addr = (void*)syscall(SYS_brk, 0);

    if (enable_brk)
    {
        assert(addr != (void*)-1);
    }
    else
    {
        assert(addr == (void*)-1);
        assert(errno == EOPNOTSUPP);
    }

    test_perf();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
