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
#include <myst/strings.h>

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

        printf(
            "%lx-%lx %c%c%c%c %08lu %02u:%02u %lu %s\n",
            p->start,
            p->end,
            r,
            w,
            x,
            f,
            p->offset,
            p->major,
            p->minor,
            p->inode,
            p->path);
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
        size_t o;
        int n;
        uint32_t major;
        uint32_t minor;
        uint64_t inode;
        myst_maps_t* maps;
        char path[PATH_MAX] = "";
        int path_offset = 0;

        n = sscanf(
            line,
            "%lx-%lx %c%c%c%c %lu %u:%u %lu %n",
            &start,
            &end,
            &r,
            &w,
            &x,
            &f,
            &o,
            &minor,
            &major,
            &inode,
            &path_offset);

        if (n < 10)
        {
            ret = -ENOSYS;
            goto done;
        }

        // This is to avoid overflow when user's input is bigger than path
        if (myst_strlcpy(path, &line[path_offset], sizeof(path)) >=
            sizeof(path))
        {
            // path is not big enough to store input
            ret = -ENOSYS;
            goto done;
        }

        // Since we are not using scanf("%s")
        // we have to remove newline at the end of string
        {
            int path_length = strlen(path);
            if (path_length > 0 && path[path_length - 1] == '\n')
                path[path_length - 1] = 0;
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

        maps->offset = o;
        maps->major = major;
        maps->minor = minor;
        maps->inode = inode;
        if (myst_strlcpy(maps->path, path, sizeof(maps->path)) >=
            sizeof(maps->path))
        {
            // maps->path not big enough to store path
            ret = -ENOSYS;
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
