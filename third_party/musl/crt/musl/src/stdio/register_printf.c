#include "stdio_impl.h"
#include "lock.h"
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <wchar.h>

#define MAX_VA_ARG_TABLE_SIZE 32
#define MAX_ARGINFO_TABLE_SIZE 52
#define MAX_MODIFIER_BIT 32
#define FIRST_PRINTF_USER_TYPE 8

struct printf_info
{
};

struct printf_modifier_record
{
    struct printf_modifier_record *next;
    int bit;
    wchar_t str[0];
};

typedef void printf_va_arg_fn(void *mem, va_list *va);
typedef int printf_arginfo_fn(const struct printf_info *info, size_t n, int *argtypes, int *size);
typedef int printf_convert_fn(FILE *stream, const struct printf_info *info, const void *const *args);

/* Array of printf_modifier_record lists indexed by the
   first char of the modifier. */
static struct printf_modifier_record **_printf_modifier_table = NULL;

/* Array of functions indexed by id.  */
static printf_va_arg_fn **_printf_va_arg_fn_table = NULL;

/* Array of functions indexed by format character.  */
static printf_arginfo_fn **_printf_arginfo_fn_table = NULL;

/* Array of functions indexed by format character.  */
static printf_convert_fn **_printf_convert_fn_table = NULL;

static volatile int lock[1];
static int _atexit_initialized = 0;

static void _free_printf_tables()
{
    free(_printf_va_arg_fn_table);
    free(_printf_arginfo_fn_table);
    if (_printf_modifier_table)
    {
        for (size_t i=0; i<UCHAR_MAX; i++)
        {
            struct printf_modifier_record *tmp = _printf_modifier_table[i];
            for (; tmp != NULL;)
            {
                struct printf_modifier_record *next = tmp->next;
                free(tmp);
                tmp = next;
            }
        }
        free(_printf_modifier_table);
    }
}

/* Register a printf type with its va_args function */
int __register_printf_type (printf_va_arg_fn fn)
{
    static _Atomic int _next_type = FIRST_PRINTF_USER_TYPE;
    int result = -1;

    LOCK(lock);
    if (!_atexit_initialized)
    {
        atexit(_free_printf_tables);
        _atexit_initialized = 1;
    }

    if (_printf_va_arg_fn_table == NULL)
    {
        _printf_va_arg_fn_table = calloc(MAX_VA_ARG_TABLE_SIZE, sizeof(*_printf_va_arg_fn_table));
        if (_printf_va_arg_fn_table == NULL)
        {
            errno = ENOMEM;
            UNLOCK(lock);
            return -1;
        }
    }
    UNLOCK(lock);

    if (_next_type == MAX_VA_ARG_TABLE_SIZE + FIRST_PRINTF_USER_TYPE)
    {
        errno = ENOSPC;
        return -1;
    }

    result = _next_type++;
    _printf_va_arg_fn_table[result - FIRST_PRINTF_USER_TYPE] = fn;

    return result;
}
weak_alias(__register_printf_type, register_printf_type);

/* Register functions to be called to format SPEC specifiers.  */
int __register_printf_specifier (int spec, printf_convert_fn convert_fn, printf_arginfo_fn arginfo_fn)
{
    int index = -1;
    if (spec >= 'a' && spec <= 'z')
        index = spec - 'a' + 26;
    else if (spec >= 'A' && spec <= 'Z')
        index = spec - 'A';
    else
    {
        errno = EINVAL;
        return -1;
    }

    LOCK(lock);
    if (_printf_arginfo_fn_table == NULL)
    {
        _printf_arginfo_fn_table = calloc(MAX_ARGINFO_TABLE_SIZE, sizeof(void*)*2);
        if (_printf_arginfo_fn_table == NULL)
        {
            errno = ENOMEM;
            goto done;
        }
        _printf_convert_fn_table = (printf_convert_fn **)_printf_arginfo_fn_table + MAX_ARGINFO_TABLE_SIZE;
    }
    _printf_arginfo_fn_table[index] = arginfo_fn;
    _printf_convert_fn_table[index] = convert_fn;

done:
    UNLOCK(lock);
    return 0;
}
weak_alias (__register_printf_specifier, register_printf_specifier);

int __register_printf_modifier (const wchar_t *str)
{
    /* Bits to hand out for modifiers.  */
    static int next_bit = 0;

    if (str[0] == L'\0')
    {
        errno = EINVAL;
        return -1;
    }

    const wchar_t *wc = str;
    for (; *wc != L'\0'; ++wc)
    {
        if (*wc < 0 || *wc > (wchar_t) UCHAR_MAX)
        {
            errno = EINVAL;
            return -1;
        }
    }

    if (next_bit == MAX_MODIFIER_BIT)
    {
        errno = ENOSPC;
        return -1;
    }

    int result = -1;
    unsigned char firstchar = (unsigned char)*str;
    LOCK(lock);

    if (_printf_modifier_table == NULL)
    {
        _printf_modifier_table = calloc (UCHAR_MAX, sizeof (*_printf_modifier_table));
        if (_printf_modifier_table == NULL)
        {
            errno = ENOMEM;
            goto done;
        }
    }

    struct printf_modifier_record *newp = malloc (sizeof (*newp) + ((wc - str) * sizeof (wchar_t)));
    if (newp == NULL)
    {
        errno = ENOMEM;
        goto done;
    }

    newp->next = _printf_modifier_table[firstchar];
    newp->bit = 1 << next_bit++;
    wmemcpy (newp->str, str + 1, wc - str);

    _printf_modifier_table[firstchar] = newp;

    result = newp->bit;

done:
    UNLOCK(lock);
    return result;
}
weak_alias (__register_printf_modifier, register_printf_modifier);
