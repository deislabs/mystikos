#include <stddef.h>

size_t my_strlen(const char* s)
{
    const char* start = s;

    while (*s)
        s++;

    return s - start;
}

int foo()
{
    return 0;
}

int main()
{
    for (size_t i = 0; i < 1000; i++)
        foo();

    return 0;
}
