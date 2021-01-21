/*
**==============================================================================
**
** This file contains a template for generating a list type and functions for
** prepending, appending, removing, and freeing list elements. The following
** illustrates how to use it for a given structure type.
**
**     struct widget
**     {
**         struct widget* prev; // must be first field
**         struct widget* next; // must be second field
**         // user-defined fields
**         ...
**     };
**
**     #define MYST_LIST_NODE widget
**     #include <myst/list_t.h>
**     #undef MYST_LIST_NODE widget
**
** The above example generates the following defintions.
**
**     struct widget_list
**     {
**         struct widget_list* head;
**         struct widget_list* tail;
**         size_t size;
**     };
**
**     void widget_list_remove(struct widget_list* list, struct widget* node);
**     void widget_list_prepend(struct widget_list* list, struct widget* node);
**     void widget_list_append(struct widget_list* list, struct widget* node);
**     void widget_list_free(struct widget_list* list);
**
**==============================================================================
*/

#include <stddef.h>
#include <stdlib.h>

#include <myst/defs.h>

#ifndef MYST_LIST_NODE
#error "please define MYST_LIST_NODE"
#endif

struct MYST_CONCAT(MYST_LIST_NODE, _list)
{
    struct MYST_LIST_NODE* head;
    struct MYST_LIST_NODE* tail;
    size_t size;
};

typedef struct MYST_CONCAT(MYST_LIST_NODE, _list)
    MYST_CONCAT(MYST_LIST_NODE, _list_t);

/* verify that prev field is the first field */
MYST_STATIC_ASSERT(offsetof(struct MYST_LIST_NODE, prev) == 0);

/* verify that next field is the second field */
MYST_STATIC_ASSERT(offsetof(struct MYST_LIST_NODE, next) == sizeof(void*));

MYST_INLINE void MYST_CONCAT(MYST_LIST_NODE, _list_remove)(
    struct MYST_CONCAT(MYST_LIST_NODE, _list) * list,
    struct MYST_LIST_NODE* node)
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

MYST_INLINE void MYST_CONCAT(MYST_LIST_NODE, _list_prepend)(
    struct MYST_CONCAT(MYST_LIST_NODE, _list) * list,
    struct MYST_LIST_NODE* node)
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

MYST_INLINE void MYST_CONCAT(MYST_LIST_NODE, _list_append)(
    struct MYST_CONCAT(MYST_LIST_NODE, _list) * list,
    struct MYST_LIST_NODE* node)
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

MYST_INLINE void MYST_CONCAT(MYST_LIST_NODE, _list_free)(
    struct MYST_CONCAT(MYST_LIST_NODE, _list) * list)
{
    for (struct MYST_LIST_NODE* p = list->head; p;)
    {
        struct MYST_LIST_NODE* next = p->next;
        free(p);
        p = next;
    }

    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
}
