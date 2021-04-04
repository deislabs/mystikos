// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_DEFS_H
#define _MYST_DEFS_H

#define MYST_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))

#define MYST_STATIC_ASSERT(COND) _Static_assert(COND, __FILE__)

#define MYST_INLINE static __inline__

#define MYST_WEAK __attribute__((weak))

#define MYST_NORETURN __attribute__((__noreturn__))

#define MYST_COUNTOF(ARR) (sizeof(ARR) / sizeof((ARR)[0]))

#define MYST_WEAK_ALIAS(OLD, NEW) \
    extern __typeof(OLD) NEW __attribute__((__weak__, alias(#OLD)))

#define MYST_NOINLINE __attribute__((noinline))

#define MYST_PACK_BEGIN _Pragma("pack(push, 1)")
#define MYST_PACK_END _Pragma("pack(pop)")

#define MYST_OFFSETOF(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER)

#define MYST_UNUSED __attribute__((__unused__))

#define MYST_ALIGN(ALIGNMENT) __attribute__((__aligned__(ALIGNMENT)))

#endif /* _MYST_DEFS_H */
