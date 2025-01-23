#define __SYSCALL_LL_E(x) (x)
#define __SYSCALL_LL_O(x) (x)

long myst_syscall(long n, long params[6]);

static __inline long __syscall0(long n)
{
    long params[6] = { 0, 0, 0, 0, 0, 0 };
    return myst_syscall(n, params);
}

static __inline long __syscall1(long n, long a1)
{
    long params[6] = { 0, 0, 0, 0, 0, 0 };
    params[0] = a1;
    return myst_syscall(n, params);
}

static __inline long __syscall2(long n, long a1, long a2)
{
    long params[6] = { 0, 0, 0, 0, 0, 0 };
    params[0] = a1;
    params[1] = a2;
    return myst_syscall(n, params);
}

static __inline long __syscall3(long n, long a1, long a2, long a3)
{
    long params[6] = { 0, 0, 0, 0, 0, 0 };
    params[0] = a1;
    params[1] = a2;
    params[2] = a3;
    return myst_syscall(n, params);
}

static __inline long __syscall4(long n, long a1, long a2, long a3, long a4)
{
    long params[6] = { 0, 0, 0, 0, 0, 0 };
    params[0] = a1;
    params[1] = a2;
    params[2] = a3;
    params[3] = a4;
    return myst_syscall(n, params);
}

static __inline long __syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
    long params[6] = { 0, 0, 0, 0, 0, 0 };
    params[0] = a1;
    params[1] = a2;
    params[2] = a3;
    params[3] = a4;
    params[4] = a5;
    return myst_syscall(n, params);
}

static __inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    long params[6] = { 0, 0, 0, 0, 0, 0 };
    params[0] = a1;
    params[1] = a2;
    params[2] = a3;
    params[3] = a4;
    params[4] = a5;
    params[5] = a6;
    return myst_syscall(n, params);
}

#define VDSO_USEFUL
#define VDSO_CGT_SYM "__vdso_clock_gettime"
#define VDSO_CGT_VER "LINUX_2.6"
#define VDSO_GETCPU_SYM "__vdso_getcpu"
#define VDSO_GETCPU_VER "LINUX_2.6"

#define IPC_64 0
