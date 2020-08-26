#include <stdio.h>
#include <stdint.h>

uint64_t foo()
{
    extern uint64_t goo();
    return goo();
}
