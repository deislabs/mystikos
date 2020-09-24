#ifndef _LIBOS_DEFS_H
#define _LIBOS_DEFS_H

#define LIBOS_PAGE_SIZE 4096

#define LIBOS_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))

#define LIBOS_STATIC_ASSERT(COND) _Static_assert(COND, __FILE__)

#define LIBOS_INLINE static __inline__

#define LIBOS_WEAK __attribute__((weak))

#define LIBOS_NORETURN __attribute__((__noreturn__))

#define LIBOS_COUNTOF(ARR) (sizeof(ARR) / sizeof((ARR)[0]))

#define LIBOS_WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((__weak__, alias(#OLD)))

#endif /* _LIBOS_DEFS_H */
