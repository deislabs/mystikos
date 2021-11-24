#include <sys/mman.h>

#include <myst/invoke.h>
#include <myst/thread.h>
#include <myst/eraise.h>
#include <myst/mmanutils.h>

typedef struct invoke_arg
{
    myst_invoke_func_t func;
    long args[6];
} invoke_arg_t;

static long _invoke_wrapper(void* arg_)
{
    invoke_arg_t* arg = (invoke_arg_t*)arg_;
    return arg->func(
        arg->args[0],
        arg->args[1],
        arg->args[2],
        arg->args[3],
        arg->args[4],
        arg->args[5]);
}

long myst_invoke(
    size_t stack_size, /* the stack size in bytes */
    myst_invoke_func_t func,
    ...)
{
    long ret = 0;
    uint8_t* stack = NULL;
    size_t length = stack_size + PAGE_SIZE;

    /* stack size must be a non-zero multiple of the page size */
    if (stack_size == 0 || (stack_size % PAGE_SIZE) || !func)
        ERAISE(-EINVAL);

    /* allocate the stack */
    {
        const int prot = PROT_READ | PROT_WRITE;
        const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
        long addr;

        ECHECK(addr = myst_mmap(NULL, length, prot, flags, -1, 0));
        stack = (void*)addr;

        /* protect the guard page */
        if (myst_mprotect(stack, PAGE_SIZE, PROT_NONE) != 0)
            ERAISE(-ENOSYS);
    }

    /* invoke the function */
    {
        va_list ap;
        va_start(ap, func);
        invoke_arg_t arg;
        arg.func = func;
        arg.args[0] = va_arg(ap, long);
        arg.args[1] = va_arg(ap, long);
        arg.args[2] = va_arg(ap, long);
        arg.args[3] = va_arg(ap, long);
        arg.args[4] = va_arg(ap, long);
        arg.args[5] = va_arg(ap, long);
        va_end(ap);

        ret = myst_call_on_stack(stack + length, _invoke_wrapper, &arg);
    }

done:

    /* deallocate the stack */
    if (stack)
        myst_munmap(stack, length);

    return ret;
}
