// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <myst/maps.h>

void myst_maps_dump1(const myst_maps_t* maps)
{
    if (maps)
    {
        const myst_maps_t* p = maps;
        char r = (p->prot & PROT_READ) ? 'r' : '-';
        char w = (p->prot & PROT_WRITE) ? 'w' : '-';
        char x = (p->prot & PROT_EXEC) ? 'x' : '-';
        char f = '-';

        if (p->flags & MAP_SHARED)
            f = 's';
        else if (p->flags & MAP_PRIVATE)
            f = 'p';

        printf("%lx-%lx %c%c%c%c\n", p->start, p->end, r, w, x, f);
    }
}

void myst_maps_dump(const myst_maps_t* maps)
{
    for (const myst_maps_t* p = maps; p; p = p->next)
        myst_maps_dump1(p);
}

void myst_maps_free(myst_maps_t* maps)
{
    for (myst_maps_t* p = maps; p;)
    {
        myst_maps_t* next = p->next;
        free(p);
        p = next;
    }
}

int myst_maps_load(myst_maps_t** maps_out)
{
    int ret = 0;
    char path[PATH_MAX];
    FILE* is = NULL;
    myst_maps_t* head = NULL;
    myst_maps_t* tail = NULL;
    char line[4096];

    if (maps_out)
        *maps_out = NULL;

    if (!maps_out)
    {
        ret = -EINVAL;
        goto done;
    }

    snprintf(path, sizeof(path), "/proc/%d/maps", getpid());

    if (!(is = fopen(path, "r")))
    {
        ret = -ENOENT;
        goto done;
    }

    /* read line-by-line */
    while (fgets(line, sizeof(line), is))
    {
        uint64_t start;
        uint64_t end;
        char r;
        char w;
        char x;
        char f;
        int n;
        myst_maps_t* maps;

        n = sscanf(line, "%lx-%lx %c%c%c%c", &start, &end, &r, &w, &x, &f);

        if (n != 6)
        {
            ret = -ENOSYS;
            goto done;
        }

        if (!(maps = calloc(1, sizeof(myst_maps_t))))
        {
            ret = -ENOMEM;
            goto done;
        }

        maps->start = start;
        maps->end = end;

        if (r == 'r')
            maps->prot |= PROT_READ;

        if (w == 'w')
            maps->prot |= PROT_WRITE;

        if (x == 'x')
            maps->prot |= PROT_EXEC;

        if (f == 's')
            maps->flags |= MAP_SHARED;
        else if (f == 'p')
            maps->flags |= MAP_PRIVATE;
        else
        {
            ret = -EINVAL;
            goto done;
        }

        if (tail)
        {
            tail->next = maps;
            tail = maps;
        }
        else
        {
            head = maps;
            tail = maps;
        }

#if 0
        printf("%lx-%lx %c%c%c%c\n", start, end, r, w, x, f);
        fflush(stdout);
#endif
    }

    *maps_out = head;
    head = NULL;

done:

    if (is)
        fclose(is);

    if (head)
        myst_maps_free(head);

    return ret;
}

void myst_mstat_dump(const struct myst_mstat* buf)
{
    if (buf)
    {
        char r = (buf->prot & PROT_READ) ? 'r' : '-';
        char w = (buf->prot & PROT_WRITE) ? 'w' : '-';
        char x = (buf->prot & PROT_EXEC) ? 'x' : '-';
        char f = '-';

        if (buf->flags & MAP_SHARED)
            f = 's';
        else if (buf->flags & MAP_PRIVATE)
            f = 'p';

        printf("%c%c%c%c\n", r, w, x, f);
    }
}

int myst_mstat(
    const myst_maps_t* maps,
    const void* addr,
    struct myst_mstat* buf)
{
    int ret = 0;

    if (buf)
        memset(buf, 0, sizeof(struct myst_mstat));

    if (!maps || !addr || !buf)
    {
        ret = -EINVAL;
        goto done;
    }

    for (const myst_maps_t* p = maps; p; p = p->next)
    {
        if ((uint64_t)addr >= p->start && (uint64_t)addr < p->end)
        {
            buf->prot = p->prot;
            buf->flags = p->flags;
            goto done;
        }
    }

    ret = -ENOMEM;

done:
    return ret;
}
