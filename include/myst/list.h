// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_LIST_H
#define _MYST_LIST_H

#include <stdlib.h>

#include <myst/defs.h>
#include <myst/types.h>

typedef struct myst_list myst_list_t;
typedef struct myst_list_node myst_list_node_t;

struct myst_list
{
    myst_list_node_t* head;
    myst_list_node_t* tail;
    size_t size;
};

struct myst_list_node
{
    myst_list_node_t* prev;
    myst_list_node_t* next;
};

// If offsets change, update references in debugger/gdb-sgx-plugin/mman.py
MYST_STATIC_ASSERT(sizeof(myst_list_t) == 24);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_list_t, head) == 0);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_list_t, tail) == 8);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_list_t, size) == 16);
MYST_STATIC_ASSERT(sizeof(myst_list_node_t) == 16);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_list_node_t, prev) == 0);
MYST_STATIC_ASSERT(MYST_OFFSETOF(myst_list_node_t, next) == 8);

MYST_INLINE void myst_list_remove(myst_list_t* list, myst_list_node_t* node)
{
    if (node->prev)
        node->prev->next = node->next;
    else
        list->head = node->next;

    if (node->next)
        node->next->prev = node->prev;
    else
        list->tail = node->prev;

    list->size--;
}

MYST_INLINE void myst_list_prepend(myst_list_t* list, myst_list_node_t* node)
{
    if (list->head)
    {
        node->prev = NULL;
        node->next = list->head;
        list->head->prev = node;
        list->head = node;
    }
    else
    {
        node->next = NULL;
        node->prev = NULL;
        list->head = node;
        list->tail = node;
    }

    list->size++;
}

MYST_INLINE void myst_list_append(myst_list_t* list, myst_list_node_t* node)
{
    if (list->tail)
    {
        node->next = NULL;
        node->prev = list->tail;
        list->tail->next = node;
        list->tail = node;
    }
    else
    {
        node->next = NULL;
        node->prev = NULL;
        list->head = node;
        list->tail = node;
    }

    list->size++;
}

MYST_INLINE void myst_list_free(myst_list_t* list)
{
    for (myst_list_node_t* p = list->head; p;)
    {
        myst_list_node_t* next = p->next;
        free(p);
        p = next;
    }

    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
}

#endif /* _MYST_LIST_H */
