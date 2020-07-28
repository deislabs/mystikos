#include <stdio.h>

void foo()
{
    extern void goo();
    printf("foo()\n");
    goo();
}
