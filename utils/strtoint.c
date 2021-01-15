#include <string.h>

#include <myst/strtoint.h>
#include <myst/eraise.h>

int myst_strtou64(const char* s, uint64_t* x_out)
{
    int ret = 0;
    uint64_t x = 0;
    uint64_t r = 1;
    const char* p = s;

    if (x_out)
        *x_out = 0;

    if (!s || !*s || !x_out)
        ERAISE(-EINVAL);

    p += strlen(s);

    while (p != s)
    {
        char c = *--p;
        x += r * (c - '0');
        r *= 10;
    }

    *x_out = x;

done:
    return ret;
}
