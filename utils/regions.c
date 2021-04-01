#include <errno.h>
#include <limits.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/regions.h>

int myst_region_find(
    const void* regions_end,
    const char* name,
    myst_region_t* region)
{
    long ret = 0;
    myst_region_trailer_t* p;

    if (region)
        memset(region, 0, sizeof(myst_region_t));

    if (!regions_end || !name || !region)
        ERAISE(-EINVAL);

    /* set pointer to trailer of the final region */
    p = (myst_region_trailer_t*)((uint8_t*)regions_end - PAGE_SIZE);

    /* iterate backwards */
    for (;;)
    {
        if (p->magic != MYST_REGION_MAGIC)
            ERAISE(-EINVAL);

        uint8_t* data = (uint8_t*)p - p->size;

        if (strcmp(p->name, name) == 0)
        {
            region->data = data;
            region->size = p->size;
            return 0;
        }

        if (p->index == 0)
            break;

        /* advance to previous trailer */
        p = (myst_region_trailer_t*)(data - PAGE_SIZE);
    }

    /* not found */
    ret = -ENOENT;

done:
    return ret;
}
