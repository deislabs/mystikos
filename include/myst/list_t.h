/*
**==============================================================================
**
** This file contains a template for generating a list type and functions for
** prepending, appending, removing, and freeing list elements. The following
** illustrates how to use it for a given structure type.
**
**     struct widget
**     {
**         struct widget* prev;
**         struct widget* next;
**         struct widget* group_prev;
**         struct widget* group_next;
**         ...
**     };
**
**     #define MYST_LIST widget_list
**     #define MYST_LIST_NODE widget
**     #define MYST_LIST_PREV prev
**     #define MYST_LIST_NEXT next
**     #include <myst/list_t.h>
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

#ifndef MYST_LIST
#error "please define MYST_LIST"
#endif

#ifndef MYST_LIST_NODE
#error "please define MYST_LIST_NODE"
#endif

#ifndef MYST_LIST_PREV
#error "please define MYST_LIST_PREV"
#endif

#ifndef MYST_LIST_NEXT
#error "please define MYST_LIST_NEXT"
#endif

struct MYST_LIST
{
    struct MYST_LIST_NODE* head;
    struct MYST_LIST_NODE* tail;
    size_t size;
};

typedef struct MYST_LIST MYST_CONCAT(MYST_LIST, _t);

MYST_INLINE void MYST_CONCAT(MYST_LIST, _remove)(
    struct MYST_LIST * list,
    struct MYST_LIST_NODE* node)
{
    if (node->MYST_LIST_PREV)
        node->MYST_LIST_PREV->MYST_LIST_NEXT = node->MYST_LIST_NEXT;
    else
        list->head = node->MYST_LIST_NEXT;

    if (node->MYST_LIST_NEXT)
        node->MYST_LIST_NEXT->MYST_LIST_PREV = node->MYST_LIST_PREV;
    else
        list->tail = node->MYST_LIST_PREV;

    list->size--;
}

MYST_INLINE void MYST_CONCAT(MYST_LIST, _prepend)(
    struct MYST_LIST * list,
    struct MYST_LIST_NODE* node)
{
    if (list->head)
    {
        node->MYST_LIST_PREV = NULL;
        node->MYST_LIST_NEXT = list->head;
        list->head->MYST_LIST_PREV = node;
        list->head = node;
    }
    else
    {
        node->MYST_LIST_NEXT = NULL;
        node->MYST_LIST_PREV = NULL;
        list->head = node;
        list->tail = node;
    }

    list->size++;
}

MYST_INLINE void MYST_CONCAT(MYST_LIST, _append)(
    struct MYST_LIST * list,
    struct MYST_LIST_NODE* node)
{
    if (list->tail)
    {
        node->MYST_LIST_NEXT = NULL;
        node->MYST_LIST_PREV = list->tail;
        list->tail->MYST_LIST_NEXT = node;
        list->tail = node;
    }
    else
    {
        node->MYST_LIST_NEXT = NULL;
        node->MYST_LIST_PREV = NULL;
        list->head = node;
        list->tail = node;
    }

    list->size++;
}

MYST_INLINE void MYST_CONCAT(MYST_LIST, _free)(
    struct MYST_LIST * list)
{
    for (struct MYST_LIST_NODE* p = list->head; p;)
    {
        struct MYST_LIST_NODE* MYST_LIST_NEXT = p->MYST_LIST_NEXT;
        free(p);
        p = MYST_LIST_NEXT;
    }

    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
}

#undef MYST_LIST
#undef MYST_LIST_NODE
#undef MYST_LIST_PREV
#undef MYST_LIST_NEXT
