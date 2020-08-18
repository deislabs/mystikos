#ifndef _DEBUG_IMAGE_H
#define _DEBUG_IMAGE_H

/* ATTN: these internal OE definitions are replicated */

#include <stdint.h>

#define OE_DEBUG_IMAGE_MAGIC 0xecd538d85d491d0b

typedef struct _debug_image_t
{
    uint64_t magic;
    uint64_t version;
    char* path;
    uint64_t path_length;
    uint64_t base_address;
    uint64_t size;
} oe_debug_image_t;

_Static_assert(OE_OFFSETOF(oe_debug_image_t, magic) == 0, "");
_Static_assert(OE_OFFSETOF(oe_debug_image_t, version) == 8, "");
_Static_assert(OE_OFFSETOF(oe_debug_image_t, path) == 16, "");
_Static_assert(OE_OFFSETOF(oe_debug_image_t, path_length) == 24, "");
_Static_assert(OE_OFFSETOF(oe_debug_image_t, base_address) == 32, "");
_Static_assert(OE_OFFSETOF(oe_debug_image_t, size) == 40, "");

#endif /* _DEBUG_IMAGE_H */
