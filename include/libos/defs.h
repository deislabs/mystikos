#ifndef _LIBOS_DEFS_H
#define _LIBOS_DEFS_H

#define LIBOS_PAGE_SIZE 4096

#define LIBOS_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))

#define LIBOS_STATIC_ASSERT(COND) _Static_assert(COND, __FILE__)

#define LIBOS_INLINE static __inline__

#define LIBOS_WEAK __attribute__((weak))

#endif /* _LIBOS_DEFS_H */
