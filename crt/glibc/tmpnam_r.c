#include <stdio.h>

char* tmpnam_r(char* buf)
{
    if (!buf)
        return NULL;

    return tmpnam(buf);
}
