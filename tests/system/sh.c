#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(int argc, const char* argv[], const char* envp[])
{
#if 0
    for (size_t i = 0; i < argc; i++)
        printf("%s\n", argv[i]);
#endif

    if (argc != 3)
        return 1;

    if (strcmp(argv[0], "/bin/sh") != 0)
        return 2;

    if (strcmp(argv[1], "-c") != 0)
        return 3;

    if (strcmp(argv[2], "cmd 10") == 0)
        return 10;

    if (strcmp(argv[2], "cmd 20") == 0)
        return 20;

    return 99;
}
