// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

void test_reader(void)
{
    FILE* stream;
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    char buf[sizeof(alphabet)];

    if (!(stream = popen("/bin/reader", "r")))
    {
        fprintf(stderr, "popen() failed\n");
        exit(1);
    }

    memset(buf, 0, sizeof(buf));

    size_t n = fread(buf, 1, sizeof(buf) - 1, stream);
    assert(n == sizeof(alphabet) - 1);
    assert(memcmp(buf, alphabet, sizeof(alphabet) - 1) == 0);
    pclose(stream);

    printf("=== passed test (/bin/reader)\n");
}

void test_writer(void)
{
    FILE* stream;
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    char buf[sizeof(alphabet)];

    if (!(stream = popen("/bin/writer", "w")))
    {
        fprintf(stderr, "popen() failed\n");
        exit(1);
    }

    size_t n = fwrite(alphabet, 1, sizeof(alphabet) - 1, stream);
    assert(n == sizeof(alphabet) - 1);
    assert(pclose(stream) == 0);

    printf("=== passed test (/bin/writer)\n");
}

int main(int argc, const char* argv[])
{
    test_reader();
    test_writer();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
