#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, const char* argv[])
{
    printf("%s\n", argv[0]);

    for (size_t i = 0; i < 3; i++)
    {
        printf("%s: %zu\n", argv[0], i);
        sleep(1);
    }

    return 123;
}
