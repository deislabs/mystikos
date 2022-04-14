// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_ERAISE_H
#define _MYST_ERAISE_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#define ERAISE(ERRNUM)                                               \
    do                                                               \
    {                                                                \
        ret = ERRNUM;                                                \
        if (ret < 0)                                                 \
        {                                                            \
            myst_eraise(__FILE__, __LINE__, __FUNCTION__, (int)ret); \
            goto done;                                               \
        }                                                            \
    } while (0)

#define ECHECK(ERRNUM)                                               \
    do                                                               \
    {                                                                \
        typeof(ERRNUM) _r_ = ERRNUM;                                 \
        if (_r_ < 0)                                                 \
        {                                                            \
            ret = (typeof(ret))_r_;                                  \
            myst_eraise(__FILE__, __LINE__, __FUNCTION__, (int)ret); \
            goto done;                                               \
        }                                                            \
    } while (0)

#define ECHECK_LABEL(ERRNUM, LABEL)                                  \
    do                                                               \
    {                                                                \
        typeof(ERRNUM) _r_ = ERRNUM;                                 \
        if (_r_ < 0)                                                 \
        {                                                            \
            ret = (typeof(ret))_r_;                                  \
            myst_eraise(__FILE__, __LINE__, __FUNCTION__, (int)ret); \
            goto LABEL;                                              \
        }                                                            \
    } while (0)

#define ECHECK_QUIET(ERRNUM) \
    do                       \
    {                        \
        int _r_ = ERRNUM;    \
        if (_r_ != 0)        \
        {                    \
            goto done;       \
        }                    \
    } while (0)

#define ERAISE_QUIET(ERRNUM) \
    do                       \
    {                        \
        ret = ERRNUM;        \
        goto done;           \
    } while (0)

#define ECHECK_ERRNO(EXPR)                                           \
    do                                                               \
    {                                                                \
        typeof(EXPR) _r_ = EXPR;                                     \
        if (_r_ < 0)                                                 \
        {                                                            \
            ret = -errno;                                            \
            myst_eraise(__FILE__, __LINE__, __FUNCTION__, (int)ret); \
            goto done;                                               \
        }                                                            \
    } while (0)

void myst_eraise(const char* file, uint32_t line, const char* func, int errnum);

#endif /* _MYST_ERAISE_H */
