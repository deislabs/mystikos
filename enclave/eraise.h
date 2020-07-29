#ifndef _OEL_ERAISE_H
#define _OEL_ERAISE_H

#include <stdint.h>
#include <errno.h>
#include <stdio.h>

#define ERAISE(ERRNUM)                                     \
    do                                                     \
    {                                                      \
        ret = ERRNUM;                                      \
        oel_eraise(__FILE__, __LINE__, __FUNCTION__, ret); \
        fflush(stdout);                                    \
        goto done;                                         \
    }                                                      \
    while (0)

#define ECHECK(ERRNUM)                                         \
    do                                                         \
    {                                                          \
        int _r_ = ERRNUM;                                      \
        if (_r_ != 0)                                          \
        {                                                      \
            ret = _r_;                                         \
            oel_eraise(__FILE__, __LINE__, __FUNCTION__, ret); \
            goto done;                                         \
        }                                                      \
    }                                                          \
    while (0)

void oel_eraise(
    const char* file,
    uint32_t line,
    const char* func,
    int errnum);

#endif /* _OEL_ERAISE_H */
