#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <libos/spinlock.h>
#include "cwd.h"
#include "eraise.h"
#include "strings.h"

static libos_path_t _cwd = { .buf = "/" };
static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;

int libos_setcwd(const libos_path_t* cwd)
{
    int ret = 0;
    bool locked = false;

    if (!cwd)
        ERAISE(EINVAL);

    libos_spin_lock(&_lock);
    locked = true;

    if (STRLCPY(_cwd.buf, cwd->buf) >= sizeof(_cwd.buf))
        ERAISE(ERANGE);

done:

    if (locked)
        libos_spin_unlock(&_lock);

    return ret;
}

int libos_getcwd(libos_path_t* cwd)
{
    int ret = 0;
    bool locked = false;

    if (cwd)
        *cwd->buf = '\0';

    if (!cwd)
        ERAISE(EINVAL);

    libos_spin_lock(&_lock);
    locked = true;

    if (STRLCPY(cwd->buf, _cwd.buf) >= sizeof(cwd->buf))
        ERAISE(ERANGE);

done:

    if (locked)
        libos_spin_unlock(&_lock);

    return ret;
}
