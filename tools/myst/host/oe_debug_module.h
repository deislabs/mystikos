// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _OE_DEBUG_MODULE_H
#define _OE_DEBUG_MODULE_H

/* ATTN: these internal OE definitions are replicated */

#include <stdint.h>

#define OE_DEBUG_MODULE_VERSION 1
#define OE_DEBUG_MODULE_MAGIC 0xf67ae6230a18a2ce

typedef struct _debug_module_t
{
    uint64_t magic;
    uint64_t version;
    struct _debug_module_t* next;
    const char* path;
    uint64_t path_length;
    const void* base_address;
    uint64_t size;
    struct _debug_enclave_t* enclave;
} oe_debug_module_t;

OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, magic) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, version) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, next) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, path) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, path_length) == 32);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, base_address) == 40);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, size) == 48);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_debug_module_t, enclave) == 56);

#endif /* _OE_DEBUG_MODULE_H */
