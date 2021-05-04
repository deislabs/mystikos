#include <errno.h>
#include <limits.h>
#include <stdint.h>

#include <myst/eraise.h>
#include <myst/mman2.h>

#define MIN_SIZE (1024 * 1024)

static uint8_t* _data;
static size_t _size;

int myst_mman2_init(void* data, size_t size)
{
    int ret = 0;

    if (!data || size < MIN_SIZE || (size % PAGE_SIZE))
        ERAISE(-EINVAL);

    _data = data;
    _size = size;

done:
    return ret;
}
