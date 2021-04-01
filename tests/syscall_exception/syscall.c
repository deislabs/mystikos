// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static __inline__ long syscall0(long n)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

static __inline__ long syscall1(long n, long x1)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

static __inline__ long syscall2(long n, long x1, long x2)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

static __inline__ long syscall3(long n, long x1, long x2, long x3)
{
    unsigned long ret;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2), "d"(x3)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

static __inline__ long syscall4(long n, long x1, long x2, long x3, long x4)
{
    unsigned long ret;
    register long r10 __asm__("r10") = x4;

    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2), "d"(x3), "r"(r10)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

static __inline__ long
syscall5(long n, long x1, long x2, long x3, long x4, long x5)
{
    unsigned long ret;
    register long r10 __asm__("r10") = x4;
    register long r8 __asm__("r8") = x5;
    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(n), "D"(x1), "S"(x2), "d"(x3), "r"(r10), "r"(r8)
                         : "rcx", "r11", "memory");

    return (long)ret;
}

static __inline__ long
syscall6(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    unsigned long ret;
    register long r10 __asm__("r10") = x4;
    register long r8 __asm__("r8") = x5;
    register long r9 __asm__("r9") = x6;

    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(n), "D"(x1), "S"(x2), "d"(x3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");

    return (long)ret;
}

static __inline__ long print_string(const char* str)
{
    return syscall3(SYS_write, 1, (long)str, strlen(str));
}

int main(int argc, const char* argv[])
{
    const char msg[] = "Hello world!\n";
    long ret = print_string(msg);
    assert(ret == sizeof(msg) - 1);

    return 0;
}
