#include <wchar.h>
#include <stdlib.h>
#include <stddef.h>

wchar_t * __wcscat_chk(wchar_t *dest, const wchar_t *src, size_t len)
{
    wchar_t *tmp1 = dest;
    const wchar_t *tmp2 = src;
    wchar_t c;

    /* Move to the end of the dest. Abort if it's too short  */
    do
    {
        if (len-- == 0)
            abort();
        c = *tmp1++;
    }
    while (c != L'\0');

    /* Append characters in src to the dest. Abort if it's too short  */
    do
    {
        if (len-- == 0)
            abort();
        c = *tmp2++;
        *tmp1++ = c;
    }
    while (c != L'\0');

    return dest;
}

wchar_t * __wcsncpy(wchar_t *dest, const wchar_t *src, size_t len)
{
    wchar_t *tmp1 = dest;
    const wchar_t *tmp2 = src;
    wchar_t c = *src;

    for (size_t i = 0; i < len; i++)
    {
        /* If src has reached the null terminator, don't advance! */
        c = (c == L'\0') ? c : *tmp2++;
        *tmp1++ = c;
    }

    return dest;
}

wchar_t* __wcsncpy_chk(wchar_t *dest, const wchar_t *src, size_t n1, size_t n2)
{
    if (n2 < n1)
        abort();

    return __wcsncpy(dest, src, n1);
}

wchar_t * __wcscpy_chk(wchar_t *dest, const wchar_t *src, size_t len)
{
    wchar_t *tmp = dest;
    wchar_t c;

    do
    {
        if (len-- == 0)
            abort();
        c = *src++;
        *tmp++ = c;
    }
    while (c != L'\0');

    return dest;
}