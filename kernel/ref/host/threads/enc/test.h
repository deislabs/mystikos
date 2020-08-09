#ifndef _TEST_H
#define _TEST_H

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdarg.h>

extern volatile int t_status;

#define t_error(...) __t_error(__FILE__, __LINE__, __VA_ARGS__)

#define t_setrlim(...)

static __inline__ int __t_error(
    const char* file,
    unsigned line,
    const char* fmt,
    ...)
{
    va_list ap;

    fprintf(stderr, "%s(%u): ", file, line);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    t_status = 1;
    return 1;
}

static __inline__ void t_printf(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

int posix_printf(const char* fmt, ...);

void t_randseed(uint64_t s);

uint64_t t_randn(uint64_t n);

void t_shuffle(uint64_t *p, size_t n);

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wshorten-64-to-32"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wbitwise-op-parentheses"
#pragma GCC diagnostic ignored "-Wshift-op-parentheses"
#pragma GCC diagnostic ignored "-Wliteral-range"
#pragma GCC diagnostic ignored "-Wmissing-braces"
#pragma GCC diagnostic ignored "-Wunused-function"

#endif /* _TEST_H */
