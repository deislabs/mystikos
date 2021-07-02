#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <myst/eraise.h>
#include <myst/regions.h>
#include <myst/strings.h>

#define MAGIC 0xdd131acc5dc846e8

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

struct myst_region_context
{
    uint64_t magic;
    myst_add_page_t add_page;
    void* add_page_arg;

    /* the current virtual address relative to the start of first region */
    uint64_t vaddr;

    /* whether a region is open or not */
    bool opened;

    /* start of the current region */
    uint64_t region_start;

    /* current region index */
    size_t region_index;
};

int myst_region_init(
    myst_add_page_t add_page,
    void* add_page_arg,
    myst_region_context_t** context_out)
{
    int ret = 0;
    myst_region_context_t* context = NULL;

    if (!add_page || !context_out)
        ERAISE(-EINVAL);

    if (!(context = calloc(1, sizeof(myst_region_context_t))))
        ERAISE(-ENOMEM);

    context->magic = MAGIC;
    context->add_page = add_page;
    context->add_page_arg = add_page_arg;

    *context_out = context;
    context = NULL;

done:

    if (context)
        free(context);

    return ret;
}

int myst_region_release(myst_region_context_t* context)
{
    int ret = 0;

    if (!context || context->magic != MAGIC)
        ERAISE(-EINVAL);

    memset(context, 0xdd, sizeof(myst_region_context_t));
    free(context);

done:
    return ret;
}

int myst_region_open(myst_region_context_t* context)
{
    int ret = 0;

    if (!context || context->magic != MAGIC)
        ERAISE(-EINVAL);

    /* fail if a region is already open */
    if (context->opened)
        ERAISE(-EBUSY);

    context->region_start = context->vaddr;
    context->opened = true;

done:
    return ret;
}

int myst_region_close(
    myst_region_context_t* context,
    const char* name,
    uint64_t vaddr,
    size_t file_size)
{
    int ret = 0;
    size_t region_size;

    if (!context || context->magic != MAGIC || !name)
        ERAISE(-EINVAL);

    /* the name must be non-empty and not too long */
    if (*name == '\0' || strlen(name) >= MYST_REGION_NAME_SIZE)
        ERAISE(-ENAMETOOLONG);

    /* fail if no region is open */
    if (!context->opened)
        ERAISE(-EINVAL);

    /* calculate the size of the region */
    region_size = vaddr - context->region_start;

    /* the default file_size is the same as the region size */
    if (file_size == SIZE_MAX)
        file_size = region_size;

    /* fail if file_size is larger than region size */
    if (file_size > region_size)
        ERAISE(-EINVAL);

    /* update the virtual address */
    context->vaddr = vaddr;

    /* append a region trailer */
    {
        __attribute__((__aligned__(PAGE_SIZE))) myst_region_trailer_t trailer;
        memset(&trailer, 0, sizeof(trailer));
        trailer.magic = MYST_REGION_MAGIC;
        trailer.index = context->region_index++;
        myst_strlcpy(trailer.name, name, sizeof(trailer.name));
        trailer.size = region_size;
        trailer.file_size = file_size;

        ECHECK((*context->add_page)(
            context->add_page_arg,
            context->vaddr,
            &trailer,
            PROT_READ | MYST_REGION_EXTEND));

        context->vaddr += PAGE_SIZE;
    }

    /* clear the region field */
    context->region_start = 0;

    /* clear the opened flag */
    context->opened = false;

done:
    return ret;
}

int myst_region_add_page(
    myst_region_context_t* context,
    uint64_t vaddr,
    const void* page,
    int flags)
{
    int ret = 0;

    if (!context || context->magic != MAGIC)
        ERAISE(-EINVAL);

    /* fail if no region is open */
    if (!context->opened)
        ERAISE(-EINVAL);

    /* add the page */
    ECHECK((*context->add_page)(context->add_page_arg, vaddr, page, flags));

done:
    return ret;
}
