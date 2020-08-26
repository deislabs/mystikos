#include <stdio.h>
#include <assert.h>
#include <string.h>

int main(int argc, const char* argv[])
{
    assert(argc == 4);
    assert(strcmp(argv[0], "/bin/argv") == 0);
    assert(strcmp(argv[1], "red") == 0);
    assert(strcmp(argv[2], "green") == 0);
    assert(strcmp(argv[3], "blue") == 0);
    assert(argv[4] == NULL);

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
