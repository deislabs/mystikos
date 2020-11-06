#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(int argc, const char* argv[], const char* envp[])
{
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";

    assert(argc == 3);
    assert(strcmp(argv[0], "/bin/sh") == 0);
    assert(strcmp(argv[1], "-c") == 0);

    if (strcmp(argv[2], "/bin/reader") == 0)
    {
        fprintf(stderr, "child: reader start\n");
        printf("%s", alphabet);
        fprintf(stderr, "child: reader done\n");
        return 0;
    }
    else if (strcmp(argv[2], "/bin/writer") == 0)
    {
        char buf[1024];

        fprintf(stderr, "child: writer start\n");
        size_t n = fread(buf, 1, sizeof(alphabet) - 1, stdin);
        assert(n == sizeof(alphabet) - 1);
        assert(memcmp(buf, alphabet, sizeof(alphabet) - 1) == 0);
        fprintf(stderr, "child: writer done\n");
        return 0;
    }
    else
    {
        fprintf(stderr, "child: failed!\n");
        assert(0);
    }
}
