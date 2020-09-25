#ifndef _LIBOS_PANIC_H
#define _LIBOS_PANIC_H

#include <libos/defs.h>
#include <libos/types.h>

LIBOS_PRINTF_FORMAT(4, 5)
LIBOS_NORETURN void __libos_panic(
    const char* file,
    size_t line,
    const char* func,
    const char* format,
    ...);

#define libos_panic(format, ...) \
    __libos_panic(__FILE__, __LINE__, __FUNCTION__, format, ##__VA_ARGS__)

#endif /* _LIBOS_PANIC_H */
