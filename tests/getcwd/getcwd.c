#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    char buf[PATH_MAX];

    getcwd(buf, sizeof(buf));
    assert(strcmp(buf, "/") == 0);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
