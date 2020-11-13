// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_LIST_H
#define _LIBOS_LIST_H

#include <stdlib.h>

#include <libos/defs.h>
#include <libos/types.h>

typedef struct libos_list libos_list_t;
typedef struct libos_list_node libos_list_node_t;

struct libos_list
{
    libos_list_node_t* head;
    libos_list_node_t* tail;
    size_t size;
};

struct libos_list_node
{
    libos_list_node_t* prev;
    libos_list_node_t* next;
};

LIBOS_INLINE void libos_list_remove(libos_list_t* list, libos_list_node_t* node)
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

LIBOS_INLINE void libos_list_prepend(
    libos_list_t* list,
    libos_list_node_t* node)
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

LIBOS_INLINE void libos_list_append(libos_list_t* list, libos_list_node_t* node)
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

LIBOS_INLINE void libos_list_free(libos_list_t* list)
{
    for (libos_list_node_t* p = list->head; p;)
    {
        libos_list_node_t* next = p->next;
        free(p);
        p = next;
    }

    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
}

#endif /* _LIBOS_LIST_H */
