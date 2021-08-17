// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <unistd.h>

#define MPOL_DEFAULT 0
#define MPOL_PREFERRED 1
#define MPOL_BIND 2
#define MPOL_INTERLEAVE 3
#define MPOL_LOCAL 4
#define MPOL_MAX 5

#define MPOL_F_NODE (1 << 0)
#define MPOL_F_ADDR (1 << 1)
#define MPOL_F_MEMS_ALLOWED (1 << 2)

#define MPOL_MF_STRICT (1 << 0)
#define MPOL_MF_MOVE (1 << 1)
#define MPOL_MF_MOVE_ALL (1 << 2)

long get_mempolicy(
    int* mode,
    unsigned long* nodemask,
    unsigned long maxnode,
    void* addr,
    unsigned long flags)
{
    return syscall(SYS_get_mempolicy, mode, nodemask, maxnode, addr, flags);
}

void print(
    int* mode,
    unsigned long* nodemask,
    unsigned long maxnode,
    void* addr,
    unsigned long flags)
{
    printf(
        "\nmode = %d\tnodemask = %ld\tmaxnode = %ld\taddr = %p\tflags = %lu",
        *mode,
        *nodemask,
        maxnode,
        addr,
        flags);
}

int test1()
{
    int mode = 0xffffffff;
    unsigned long nodemask = 0xffffffffffffffff;
    unsigned long maxnode = 64;
    void* addr = NULL;
    unsigned long flags = MPOL_DEFAULT;

    printf("1. MPOL_DEFAULT, null addr");
    print(&mode, &nodemask, maxnode, addr, flags);
    long ret = get_mempolicy(&mode, &nodemask, maxnode, addr, flags);
    print(&mode, &nodemask, maxnode, addr, flags);
    printf("\nRet = %ld", ret);
    printf("\nerrno = %d", errno);

    assert(ret == 0);
    assert(mode == 0);
    assert(nodemask == 0);
    assert(maxnode == 64);
    assert(addr == 0);
    assert(flags == MPOL_DEFAULT);
}

int test2()
{
    int mode = 0xffffffff;
    unsigned long nodemask = 0xffffffffffffffff;
    unsigned long maxnode = 64;
    void* addr = NULL;
    unsigned long flags = MPOL_F_MEMS_ALLOWED;

    printf("\n\n2. MPOL_F_MEMS_ALLOWED, null addr");
    print(&mode, &nodemask, maxnode, addr, flags);
    long ret = get_mempolicy(&mode, &nodemask, maxnode, addr, flags);
    print(&mode, &nodemask, maxnode, addr, flags);
    printf("\nRet = %ld", ret);
    printf("\nerrno = %d", errno);

    assert(ret == 0);
    assert(mode == 0);
    assert(nodemask == 0); // mystikos=0 native=1 since mystikos does not
    // support mbind and set_mempolicy
    assert(maxnode == 64);
    assert(addr == 0);
    assert(flags == MPOL_F_MEMS_ALLOWED);
}

int test3()
{
    int mode = 0xffffffff;
    unsigned long nodemask[5];
    unsigned long maxnode = 41;
    void* addr = NULL;
    unsigned long flags = MPOL_DEFAULT;

    printf("\n\n3. MPOL_DEFAULT, maxnode > sizeof(nodemask)*BIT_TO_BYTE");
    print(&mode, (unsigned long*)nodemask, maxnode, addr, flags);
    long ret =
        get_mempolicy(&mode, (unsigned long*)nodemask, maxnode, addr, flags);
    print(&mode, (unsigned long*)nodemask, maxnode, addr, flags);
    printf("\nRet = %ld", ret);
    printf("\nerrno = %d", errno);
    assert(ret == 0);
    assert(errno == 0);
    assert(mode == 0);
    assert(nodemask[0] == 0);
    assert(maxnode == 41);
    assert(addr == 0);
    assert(flags == MPOL_DEFAULT);
}

int test4()
{
    int mode = 5;
    unsigned long nodemask = 0xffffffffffffffff;
    unsigned long maxnode = 64;
    void* addr = NULL;
    unsigned long flags = MPOL_F_ADDR;

    printf("\n\n4. MPOL_F_ADDR, NULL addr, expecting EFAULT");
    print(&mode, &nodemask, maxnode, addr, flags);
    long ret = get_mempolicy(&mode, &nodemask, maxnode, addr, flags);
    print(&mode, &nodemask, maxnode, addr, flags);
    printf("\nRet = %ld", ret);
    printf("\nerrno = %d", errno);
    assert(ret == -1);
    assert(errno == 14);
    // assert(mode == 0); // mode and nodemask here will differ in sgx and
    // native/linux since they do not manipulate the values at all, but sgx
    // sends the ocall an out buffer to populate sgx mode = 0, native/linux mode
    // = unchanged assert(nodemask == 0); // sgx nodemask = 0, native nodemask =
    // unchanged
    assert(maxnode == 64);
    assert(addr == 0);
    assert(flags == MPOL_F_ADDR);
}

int test5()
{
    int mode = 0xffffffff;
    unsigned long nodemask = 0xffffffffffffffff;
    unsigned long maxnode = 64;
    void* addr = malloc(8);
    unsigned long flags = MPOL_DEFAULT;

    printf("\n\n5. MPOL_DEFAULT, non-NULL addr, expecting EINVAL");
    print(&mode, &nodemask, maxnode, addr, flags);
    long ret = get_mempolicy(&mode, &nodemask, maxnode, addr, flags);
    print(&mode, &nodemask, maxnode, addr, flags);
    printf("\nRet = %ld", ret);
    printf("\nerrno = %d", errno);
    assert(ret == -1);
    assert(errno == 22);
    // mode and nodemask here will differ in sgx and linux/native
    // since they do not manipulate the values at all, but sgx sends
    // the ocall an out buffer to populate sgx mode = 0, linux/native mode =
    // unchanged assert(nodemask == 0); // sgx nodemask = 0, linux/native
    // nodemask = unchanged
    assert(maxnode == 64);
    assert(flags == MPOL_DEFAULT);
}

int main(int argc, const char* argv[])
{
    test1();

    test2();

    test3();

    test4();

    test5();

    printf("\n=== passed test (%s)\n", argv[0]);
    return 0;
}
