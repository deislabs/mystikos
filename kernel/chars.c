#include <myst/chars.h>

bool myst_isspace(char c)
{
    switch (c)
    {
        case ' ':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
        case '\v':
            return true;
        default:
            return false;
    }
}
