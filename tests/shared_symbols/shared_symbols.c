#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
    /* Test whether optarg in libc is shared */
    const struct option longopts[] = {
        {"option", required_argument, 0, 'o'},
    };

    int optindex;
    int c;
    while ((c = getopt_long(argc, argv, "o:", longopts, &optindex)) != -1)
    {
        printf("optarg={%s}\n", optarg);
        assert(strcmp(optarg, "testarg") == 0);
    }

    /* Test whether stdin in libc is shared */
    {
        char buf[1];
        size_t n;
        int fd;

        // make sure fread fails
        fd = dup(0);
        close(0);

        n = fread(buf, 1, sizeof buf, stdin);
        assert(n == 0 && ferror(stdin));
    }

    printf("\n=== passed test (%s)\n", argv[0]);
    return 0;
}
