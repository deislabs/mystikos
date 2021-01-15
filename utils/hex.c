#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <myst/hex.h>
#include <myst/eraise.h>

void myst_hexdump(
    const char* label,
    const void* data,
    size_t size)
{
    const uint8_t* p = data;

    if (label)
        printf("%s: ", label);

    while (size--)
    {
        uint8_t c = *p++;
        printf("%02x", c);
    }

    printf("\n");
}

static int _char_to_nibble(char c)
{
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');

    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');

    if (c >= '0' && c <= '9')
        return c - '0';

    return -EINVAL;
}

ssize_t myst_ascii_to_bin(const char* s, uint8_t* buf, size_t buf_size)
{
    ssize_t ret = 0;
    size_t len;
    size_t size = 0;

    if ((len = strlen(s)) == 0 || (len % 2) != 0)
        ERAISE(-EINVAL);

    if (len / 2 > buf_size)
        ERAISE(-ENAMETOOLONG);

    for (size_t i = 0; i < len - 1; i += 2)
    {
        int hi;
        int lo;

        ECHECK(hi = _char_to_nibble(s[i]));
        ECHECK(lo = _char_to_nibble(s[i + 1]));
        buf[size++] = (uint8_t)((hi << 4) | lo);
    }

    ret = size;

done:

    return ret;
}
