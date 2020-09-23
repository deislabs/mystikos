#include <libos/bufu64.h>
#include <libos/args.h>
#include <libos/malloc.h>

#define CAP 16

LIBOS_INLINE libos_bufu64_t _to_buf(const libos_args_t* args)
{
    libos_bufu64_t ret;

    ret.data = (uint64_t*)args->data;
    ret.size = args->size + 1;
    ret.cap = args->cap + 1;

    return ret;
}

LIBOS_INLINE libos_args_t _to_args(const libos_bufu64_t* buf)
{
    libos_args_t ret;

    ret.data = (const char**)buf->data;
    ret.size = buf->size - 1;
    ret.cap = buf->cap - 1;

    return ret;
}

int libos_args_init(libos_args_t* self)
{
    if (!self)
        return -1;

    /* allocate an extra entry for the null terminator */
    if (!(self->data = libos_calloc(CAP + 1, sizeof(char*))))
        return -1;

    self->size = 0;
    self->cap = CAP;

    return 0;
}

int libos_args_adopt(libos_args_t* self, const char** data, size_t size)
{
    if (!self || !data)
        return -1;

    /* none of the strings may be null */
    for (size_t i = 0; i < size; i++)
    {
        if (!data[i])
            return -1;
    }

    /* check for null terminator */
    if (data[size])
        return -1;

    self->data = data;
    self->size = size;
    self->cap = size;

    return 0;
}

void libos_args_release(libos_args_t* self)
{
    if (self && self->data)
        libos_free(self->data);
}

int libos_args_reserve(libos_args_t* self, size_t cap)
{
    libos_bufu64_t buf = _to_buf(self);

    if (!self)
        return -1;

    cap++;

    if (libos_bufu64_reserve(&buf, cap) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int libos_args_append(libos_args_t* self, const char** data, size_t size)
{
    libos_bufu64_t buf = _to_buf(self);

    if (!self || !data)
        return -1;

    if (size == 0)
        return 0;

    /* insert right before the null terminator */
    if (libos_bufu64_insert(&buf, self->size, (const uint64_t*)data, size) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int libos_args_append1(libos_args_t* self, const char* data)
{
    libos_bufu64_t buf = _to_buf(self);

    if (!self || !data)
        return -1;

    /* insert right before the null terminator */
    if (libos_bufu64_insert(&buf, self->size, (const uint64_t*)&data, 1) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int libos_args_prepend(libos_args_t* self, const char** data, size_t size)
{
    libos_bufu64_t buf = _to_buf(self);

    if (!self || !data)
        return -1;

    if (size == 0)
        return 0;

    /* insert right before the null terminator */
    if (libos_bufu64_insert(&buf, 0, (const uint64_t*)data, size) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int libos_args_prepend1(libos_args_t* self, const char* data)
{
    libos_bufu64_t buf = _to_buf(self);

    if (!self || !data)
        return -1;

    /* insert right before the null terminator */
    if (libos_bufu64_insert(&buf, 0, (const uint64_t*)&data, 1) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int libos_args_insert(
    libos_args_t* self,
    size_t pos,
    const char** data,
    size_t size)
{
    libos_bufu64_t buf = _to_buf(self);

    if (!self || !data || pos > size)
        return -1;

    if (size == 0)
        return 0;

    if (libos_bufu64_insert(&buf, pos, (const uint64_t*)data, size) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}

int libos_args_remove(libos_args_t* self, size_t pos, size_t size)
{
    libos_bufu64_t buf = _to_buf(self);

    if (!self || pos + size > self->size)
        return -1;

    if (libos_bufu64_remove(&buf, pos, size) != 0)
        return -1;

    *self = _to_args(&buf);
    return 0;
}
