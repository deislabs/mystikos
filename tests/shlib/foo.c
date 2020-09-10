#include <stdint.h>
#include <stdio.h>

uint64_t foo()
{
    extern uint64_t goo();
    return goo();
}
