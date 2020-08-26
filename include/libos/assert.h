#ifndef _LIBOS_ASSERT_H
#define _LIBOS_ASSERT_H

#include <libos/types.h>

void __libos_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func);

#ifndef NDEBUG
#define libos_assert(EXPR)                                                \
    do                                                                    \
    {                                                                     \
        if (!(EXPR))                                                      \
            __libos_assert_fail(#EXPR, __FILE__, __LINE__, __FUNCTION__); \
    } while (0)
#else
#define libos_assert(EXPR)
#endif

#endif /* _LIBOS_ASSERT_H */
