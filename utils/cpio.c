// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <myst/cpio.h>
#include <myst/eraise.h>
#include <myst/round.h>
#include <myst/strarr.h>
#include <myst/strings.h>

void* calloc(size_t nmemb, size_t size);
void free(void* ptr);

#define CPIO_BLOCK_SIZE 512

#define TRACE
#define PRINTF printf

// clang-format off
#if defined(TRACE)
# define GOTO(LABEL) \
    do \
    { \
        PRINTF("GOTO=%s(%u): %s()\n", __FILE__, __LINE__, __FUNCTION__); \
        goto LABEL; \
    } \
    while (0)
#else
# define GOTO(LABEL) goto LABEL
#endif
// clang-format on

typedef struct _cpio_header
{
    char magic[6];
    char ino[8];
    char mode[8];
    char uid[8];
    char gid[8];
    char nlink[8];
    char mtime[8];
    char filesize[8];
    char devmajor[8];
    char devminor[8];
    char rdevmajor[8];
    char rdevminor[8];
    char namesize[8];
    char check[8];
} cpio_header_t;

struct _myst_cpio
{
    int fd;
    cpio_header_t header;
    size_t entry_size;
    off_t eof_offset;
    off_t offset;
    bool write;
};

typedef struct _entry
{
    cpio_header_t header;
    char name[MYST_CPIO_PATH_MAX];
    size_t size;
} entry_t;

entry_t _dot = {
    .header.magic = "070701",
    .header.ino = "00B66448",
    .header.mode = "000041ED",
    .header.uid = "00000000",
    .header.gid = "00000000",
    .header.nlink = "00000002",
    .header.mtime = "5BE31EB3",
    .header.filesize = "00000000",
    .header.devmajor = "00000008",
    .header.devminor = "00000002",
    .header.rdevmajor = "00000000",
    .header.rdevminor = "00000000",
    .header.namesize = "00000002",
    .header.check = "00000000",
    .name = ".",
    .size = sizeof(cpio_header_t) + 2,
};

entry_t _trailer = {.header.magic = "070701",
                    .header.ino = "00000000",
                    .header.mode = "00000000",
                    .header.uid = "00000000",
                    .header.gid = "00000000",
                    .header.nlink = "00000002",
                    .header.mtime = "00000000",
                    .header.filesize = "00000000",
                    .header.devmajor = "00000000",
                    .header.devminor = "00000000",
                    .header.rdevmajor = "00000000",
                    .header.rdevminor = "00000000",
                    .header.namesize = "0000000B",
                    .header.check = "00000000",
                    .name = "TRAILER!!!",
                    .size = sizeof(cpio_header_t) + 11};

#if 0
static void _dump(const uint8_t* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        uint8_t c = data[i];

        if (c >= ' ' && c <= '~')
            printf("%c", c);
        else
            printf("<%02x>", c);
    }

    printf("\n");
}
#endif

static bool _valid_header(const cpio_header_t* header)
{
    return memcmp(header->magic, "070701", 6) == 0;
}

static ssize_t _hex_to_ssize(const char* str, size_t len)
{
    const char* p;
    ssize_t r = 1;
    ssize_t x = 0;

    for (p = str + len; p != str; p--)
    {
        ssize_t xdigit = p[-1];
        ssize_t d;

        if (xdigit >= '0' && xdigit <= '9')
        {
            d = xdigit - '0';
        }
        else if (xdigit >= 'A' && xdigit <= 'F')
        {
            d = (xdigit - 'A') + 10;
        }
        else
            return -1;

        x += r * d;
        r *= 16;
    }

    return x;
}

static char _hex_digit(unsigned int x)
{
    switch (x)
    {
        case 0x0:
            return '0';
        case 0x1:
            return '1';
        case 0x2:
            return '2';
        case 0x3:
            return '3';
        case 0x4:
            return '4';
        case 0x5:
            return '5';
        case 0x6:
            return '6';
        case 0x7:
            return '7';
        case 0x8:
            return '8';
        case 0x9:
            return '9';
        case 0xA:
            return 'A';
        case 0xB:
            return 'B';
        case 0xC:
            return 'C';
        case 0xD:
            return 'D';
        case 0xE:
            return 'E';
        case 0xF:
            return 'F';
    }

    return '\0';
}

static void _uint_to_hex(char buf[8], unsigned int x)
{
    buf[0] = _hex_digit((x & 0xF0000000) >> 28);
    buf[1] = _hex_digit((x & 0x0F000000) >> 24);
    buf[2] = _hex_digit((x & 0x00F00000) >> 20);
    buf[3] = _hex_digit((x & 0x000F0000) >> 16);
    buf[4] = _hex_digit((x & 0x0000F000) >> 12);
    buf[5] = _hex_digit((x & 0x00000F00) >> 8);
    buf[6] = _hex_digit((x & 0x000000F0) >> 4);
    buf[7] = _hex_digit((x & 0x0000000F) >> 0);
}

static ssize_t _get_mode(const cpio_header_t* header)
{
    return _hex_to_ssize(header->mode, 8);
}

static ssize_t _get_filesize(const cpio_header_t* header)
{
    return _hex_to_ssize(header->filesize, 8);
}

static ssize_t _get_namesize(const cpio_header_t* header)
{
    return _hex_to_ssize(header->namesize, 8);
}

static int _skip_padding(int fd)
{
    int ret = -1;
    int64_t pos;
    int64_t new_pos;

    if ((pos = lseek(fd, 0, SEEK_CUR)) < 0)
        GOTO(done);

    if (myst_round_up_signed(pos, 4, &new_pos) != 0)
        GOTO(done);

    if (new_pos != pos && lseek(fd, new_pos, SEEK_SET) < 0)
        GOTO(done);

    ret = 0;

done:
    return ret;
}

static int _write_padding(int fd, size_t n)
{
    int ret = -1;
    int64_t pos;
    int64_t new_pos;

    if ((pos = lseek(fd, 0, SEEK_CUR)) < 0)
        GOTO(done);

    if (myst_round_up_signed(pos, n, &new_pos) != 0)
        GOTO(done);

    for (int64_t i = pos; i < new_pos; i++)
    {
        char c = '\0';

        if (write(fd, &c, sizeof(c)) != 1)
            GOTO(done);
    }

    ret = 0;

done:
    return ret;
}

myst_cpio_t* myst_cpio_open(const char* path, uint32_t flags)
{
    myst_cpio_t* ret = NULL;
    myst_cpio_t* cpio = NULL;
    int fd = -1;

    if (!path)
        GOTO(done);

    if (!(cpio = calloc(1, sizeof(myst_cpio_t))))
        GOTO(done);

    if ((flags & MYST_CPIO_FLAG_CREATE))
    {
        if ((fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640)) < 0)
            GOTO(done);

        if (write(fd, &_dot, _dot.size) != (ssize_t)_dot.size)
            GOTO(done);

        cpio->fd = fd;
        cpio->write = true;
        fd = -1;
    }
    else
    {
        if ((fd = open(path, O_RDONLY, 0640)) < 0)
            GOTO(done);

        cpio->fd = fd;
        fd = -1;
    }

    ret = cpio;
    cpio = NULL;

done:

    if (fd >= 0)
        close(fd);

    if (cpio)
        free(cpio);

    return ret;
}

int myst_cpio_close(myst_cpio_t* cpio)
{
    int ret = -1;

    if (!cpio || cpio->fd < 0)
        return ret;

    if (cpio->write)
    {
        const size_t size = _trailer.size;

        /* Write the trailer. */
        if (write(cpio->fd, &_trailer, size) != (ssize_t)size)
        {
            GOTO(done);
        }

        /* Pad the trailer out to the block size boundary. */
        if (_write_padding(cpio->fd, CPIO_BLOCK_SIZE) != 0)
        {
            GOTO(done);
        }
    }

    ret = 0;

done:

    close(cpio->fd);
    memset(cpio, 0, sizeof(myst_cpio_t));
    free(cpio);

    return ret;
}

/* Read next entry: HEADER + NAME + FILEDATA + PADDING */
int myst_cpio_read_entry(myst_cpio_t* cpio, myst_cpio_entry_t* entry_out)
{
    int ret = -1;
    cpio_header_t hdr;
    myst_cpio_entry_t entry;
    ssize_t r;
    int64_t file_offset;
    size_t namesize;

    if (entry_out)
        memset(entry_out, 0, sizeof(myst_cpio_entry_t));

    if (!cpio || cpio->fd < 0)
        GOTO(done);

    /* Set the position to the next entry. */
    if (lseek(cpio->fd, cpio->offset, SEEK_SET) < 0)
        GOTO(done);

    if (read(cpio->fd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr))
        GOTO(done);

    if (!_valid_header(&hdr))
        GOTO(done);

    /* Get the file size. */
    {
        if ((r = _get_filesize(&hdr)) < 0)
            GOTO(done);

        entry.size = (size_t)r;
    }

    /* Get the file mode. */
    {
        if ((r = _get_mode(&hdr)) < 0 || r >= UINT32_MAX)
            GOTO(done);

        entry.mode = (uint32_t)r;
    }

    /* Get the name size. */
    {
        if ((r = _get_namesize(&hdr)) < 0 || r >= MYST_CPIO_PATH_MAX)
            GOTO(done);

        namesize = (size_t)r;
    }

    /* Read the name. */
    if (read(cpio->fd, &entry.name, namesize) != (ssize_t)namesize)
        GOTO(done);

    /* Skip any padding after the name. */
    if (_skip_padding(cpio->fd) != 0)
        GOTO(done);

    /* Save the file offset. */
    file_offset = lseek(cpio->fd, 0, SEEK_CUR);

    /* Skip over the file data. */
    if (lseek(cpio->fd, (off_t)entry.size, SEEK_CUR) < 0)
        GOTO(done);

    /* Save the file offset. */
    cpio->eof_offset = lseek(cpio->fd, 0, SEEK_CUR);

    /* Skip any padding after the file data. */
    if (_skip_padding(cpio->fd) != 0)
        GOTO(done);

    /* Save the offset of the next entry. */
    cpio->offset = lseek(cpio->fd, 0, SEEK_CUR);

    /* Rewind to the file offset. */
    if (lseek(cpio->fd, file_offset, SEEK_SET) < 0)
        GOTO(done);

    /* Check for end-of-file. */
    if (strcmp(entry.name, "TRAILER!!!") == 0)
    {
        ret = 0;
        goto done;
    }

    *entry_out = entry;

    ret = 1;

done:
    return ret;
}

ssize_t myst_cpio_read_data(myst_cpio_t* cpio, void* data, size_t size)
{
    ssize_t ret = -1;
    size_t rem;
    ssize_t n;
    int64_t offset;

    if (!cpio || cpio->fd < 0 || !data)
        GOTO(done);

    offset = lseek(cpio->fd, 0, SEEK_CUR);

    if (offset > cpio->eof_offset)
        GOTO(done);

    rem = (size_t)(cpio->eof_offset - offset);

    if (size > rem)
        size = rem;

    if ((n = read(cpio->fd, data, size)) != (ssize_t)size)
        GOTO(done);

    ret = (ssize_t)n;

done:
    return ret;
}

int myst_cpio_write_entry(myst_cpio_t* cpio, const myst_cpio_entry_t* entry)
{
    int ret = -1;
    cpio_header_t h;
    size_t namesize;

    if (!cpio || cpio->fd < 0 || !entry)
        GOTO(done);

    /* ATTN: Skip character files and fifos */
    if (S_ISCHR(entry->mode) || S_ISFIFO(entry->mode))
    {
        ret = 0;
        goto done;
    }

    /* Check file type. */
    if (!S_ISREG(entry->mode) && !S_ISDIR(entry->mode) && !S_ISLNK(entry->mode))
    {
        PRINTF("entry=%s mode=%o\n", entry->name, entry->mode);
        GOTO(done);
    }

    /* Calculate the size of the name */
    if ((namesize = strlen(entry->name) + 1) > MYST_CPIO_PATH_MAX)
        GOTO(done);

    /* Write the CPIO header */
    {
        memset(&h, 0, sizeof(h));
        memcpy(h.magic, "070701", sizeof(h.magic));
        _uint_to_hex(h.ino, 0);
        _uint_to_hex(h.mode, entry->mode);
        _uint_to_hex(h.uid, 0);
        _uint_to_hex(h.gid, 0);
        _uint_to_hex(h.nlink, 1);
        _uint_to_hex(h.mtime, 0x56734BA4); /* hardcode a time */
        _uint_to_hex(h.filesize, (unsigned int)entry->size);
        _uint_to_hex(h.devmajor, 8);
        _uint_to_hex(h.devminor, 2);
        _uint_to_hex(h.rdevmajor, 0);
        _uint_to_hex(h.rdevminor, 0);
        _uint_to_hex(h.namesize, (unsigned int)namesize);
        _uint_to_hex(h.check, 0);

        if (write(cpio->fd, &h, sizeof(h)) != sizeof(h))
            GOTO(done);
    }

    /* Write the file name. */
    {
        if (write(cpio->fd, entry->name, namesize) != (ssize_t)namesize)
            GOTO(done);

        /* Pad to four-byte boundary. */
        if (_write_padding(cpio->fd, 4) != 0)
            GOTO(done);
    }

    ret = 0;

done:
    return ret;
}

ssize_t myst_cpio_write_data(myst_cpio_t* cpio, const void* data, size_t size)
{
    ssize_t ret = -1;

    if (!cpio || cpio->fd < 0 || (size && !data) || !cpio->write)
        GOTO(done);

    if (size)
    {
        if (write(cpio->fd, data, size) != (ssize_t)size)
            GOTO(done);
    }
    else
    {
        if (_write_padding(cpio->fd, 4) != 0)
            GOTO(done);
    }

    ret = 0;

done:
    return ret;
}

int myst_cpio_unpack(const char* source, const char* target)
{
    int ret = -1;
    myst_cpio_t* cpio = NULL;
    int r;
    int fd = -1;
    struct locals
    {
        myst_cpio_entry_t entry;
        char path[MYST_CPIO_PATH_MAX];
        char data[512];
        char target[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!source || !target)
        GOTO(done);

    if (!(locals = malloc(sizeof(struct locals))))
        GOTO(done);

    if (!(cpio = myst_cpio_open(source, 0)))
        GOTO(done);

    if (access(target, R_OK) != 0 && mkdir(target, 0766) != 0)
        GOTO(done);

    while ((r = myst_cpio_read_entry(cpio, &locals->entry)) > 0)
    {
        if (strcmp(locals->entry.name, ".") == 0)
            continue;

        MYST_STRLCPY(locals->path, target);
        MYST_STRLCAT(locals->path, "/");
        MYST_STRLCAT(locals->path, locals->entry.name);

        if (S_ISDIR(locals->entry.mode))
        {
            struct stat st;

            if (stat(locals->path, &st) == 0)
            {
                if (!S_ISDIR(st.st_mode))
                {
                    PRINTF("*** cpio: already exists: %s\n", locals->path);
                    GOTO(done);
                }
            }
            else if (mkdir(locals->path, locals->entry.mode) != 0)
            {
                GOTO(done);
            }
        }
        else if (S_ISREG(locals->entry.mode))
        {
            ssize_t n;

            if ((fd = open(locals->path, O_WRONLY | O_CREAT, 0640)) < 0)
                GOTO(done);

            while ((n = myst_cpio_read_data(
                        cpio, locals->data, sizeof(locals->data))) > 0)
            {
                if (write(fd, locals->data, (size_t)n) != n)
                    GOTO(done);
            }

            if (close(fd) != 0)
                GOTO(done);

            fd = -1;
        }
        else if (S_ISLNK(locals->entry.mode))
        {
            ssize_t n;

            /* read the target from CPIO archive */
            n = myst_cpio_read_data(
                cpio, locals->target, sizeof(locals->target));
            if (n < 1 || n >= (ssize_t)sizeof(locals->target))
                GOTO(done);

            locals->target[n] = '\0';

            /* create the symlink */
            if (symlink(target, locals->path) != 0)
                GOTO(done);
        }
        else
        {
            GOTO(done);
        }
    }

    ret = 0;

done:

    if (locals)
        free(locals);

    if (cpio)
        myst_cpio_close(cpio);

    if (fd >= 0)
        close(fd);

    return ret;
}

static int _append_file(myst_cpio_t* cpio, const char* path, const char* name)
{
    int ret = -1;
    struct stat st;
    int fd = -1;
    ssize_t n;
    struct locals
    {
        char buf[4096];
    };
    struct locals* locals = NULL;

    if (!cpio || !path)
        GOTO(done);

    if (!(locals = malloc(sizeof(struct locals))))
        GOTO(done);

    /* Stat the file to get the size and mode. */
    if (lstat(path, &st) != 0)
        GOTO(done);

    if (S_ISREG(st.st_mode))
    {
        if ((fd = open(path, O_RDONLY, 444)) < 0)
            GOTO(done);

        /* Resolve TOC-TOU by getting the statbuf again */
        if (fstat(fd, &st) != 0)
            GOTO(done);
    }

    /* Write the CPIO header. */
    {
        myst_cpio_entry_t ent;

        memset(&ent, 0, sizeof(ent));

        if (S_ISDIR(st.st_mode))
            st.st_size = 0;
        else
            ent.size = (size_t)st.st_size;

        ent.mode = st.st_mode;

        if (MYST_STRLCPY(ent.name, name) >= sizeof(ent.name))
            GOTO(done);

        if (myst_cpio_write_entry(cpio, &ent) != 0)
        {
            GOTO(done);
        }
    }

    /* Write the CPIO data. */
    if (S_ISREG(st.st_mode))
    {
        while ((n = read(fd, locals->buf, sizeof(locals->buf))) > 0)
        {
            if (myst_cpio_write_data(cpio, locals->buf, (size_t)n) != 0)
                GOTO(done);
        }

        if (n < 0)
            GOTO(done);
    }
    else if (S_ISLNK(st.st_mode))
    {
        ssize_t n;

        n = readlink(path, locals->buf, sizeof(locals->buf));

        if (n <= 0 || n >= (ssize_t)sizeof(locals->buf))
            GOTO(done);

        if (myst_cpio_write_data(cpio, locals->buf, (size_t)n) != 0)
            GOTO(done);
    }

    if (myst_cpio_write_data(cpio, NULL, 0) != 0)
        GOTO(done);

    ret = 0;

done:

    if (locals)
        free(locals);

    if (fd >= 0)
        close(fd);

    return ret;
}

static int _pack(myst_cpio_t* cpio, const char* dirname, const char* root)
{
    int ret = -1;
    DIR* dir = NULL;
    struct dirent* ent;
    char path[MYST_CPIO_PATH_MAX];
    myst_strarr_t dirs = MYST_STRARR_INITIALIZER;

    if (!(dir = opendir(root)))
        GOTO(done);

    /* Append this directory to the CPIO archive. */
    if (strcmp(dirname, root) != 0)
    {
        const char* p = root + strlen(dirname);

        assert(*p == '/');

        if (*p == '/')
            p++;

        if (_append_file(cpio, root, p) != 0)
            GOTO(done);
    }

    /* Find all children of this directory. */
    while ((ent = readdir(dir)))
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
        {
            continue;
        }

        *path = '\0';

        if (strcmp(root, ".") != 0)
        {
            MYST_STRLCAT(path, root);
            MYST_STRLCAT(path, "/");
        }

        MYST_STRLCAT(path, ent->d_name);

        /* Append to dirs[] array */
        if (ent->d_type & DT_DIR)
        {
            if (myst_strarr_append(&dirs, path) != 0)
                GOTO(done);
        }
        else
        {
            /* Append this file to the CPIO archive (remove the dirname). */

            const char* p = path + strlen(dirname);

            assert(*p == '/');

            if (*p == '/')
                p++;

            if (_append_file(cpio, path, p) != 0)
                GOTO(done);
        }
    }

    /* Recurse into child directories */
    {
        size_t i;

        for (i = 0; i < dirs.size; i++)
        {
            if (_pack(cpio, dirname, dirs.data[i]) != 0)
                GOTO(done);
        }
    }

    ret = 0;

done:

    if (dir)
        closedir(dir);

    myst_strarr_release(&dirs);

    return ret;
}

int myst_cpio_pack(const char* source, const char* target)
{
    int ret = -1;
    myst_cpio_t* cpio = NULL;

    if (!source || !target)
        GOTO(done);

    if (!(cpio = myst_cpio_open(target, MYST_CPIO_FLAG_CREATE)))
        GOTO(done);

    if (_pack(cpio, source, source) != 0)
        GOTO(done);

    ret = 0;

done:

    if (cpio)
        myst_cpio_close(cpio);

    return ret;
}

/*
**==============================================================================
**
** memory-based scanner:
**
**==============================================================================
*/

int myst_cpio_next_entry(
    const void* data_,
    size_t size,
    size_t* pos_in_out,
    myst_cpio_entry_t* entry_out,
    const void** file_data_out)
{
    int ret = -1;
    const uint8_t* data = (const uint8_t*)data_;
    size_t pos;
    size_t rem;
    ssize_t r;
    size_t namesize;
    uint64_t file_pos;
    struct locals
    {
        cpio_header_t hdr;
        myst_cpio_entry_t entry;
    };
    struct locals* locals = NULL;

    if (!data || !size || !pos_in_out || !entry_out || !file_data_out)
        GOTO(done);

    if (!(locals = malloc(sizeof(struct locals))))
        GOTO(done);

    pos = *pos_in_out;
    memset(entry_out, 0, sizeof(myst_cpio_entry_t));
    *file_data_out = NULL;

    if (pos > size)
        GOTO(done);

    rem = size - pos;

    /* Read the header */
    {
        if (sizeof(locals->hdr) > rem)
            GOTO(done);

        memcpy(&locals->hdr, &data[pos], sizeof(locals->hdr));
        pos += sizeof(locals->hdr);
        rem -= sizeof(locals->hdr);

        if (!_valid_header(&locals->hdr))
            GOTO(done);
    }

    /* Get the file size. */
    {
        if ((r = _get_filesize(&locals->hdr)) < 0)
            GOTO(done);

        locals->entry.size = (size_t)r;
    }

    /* Get the file mode. */
    {
        if ((r = _get_mode(&locals->hdr)) < 0 || r >= UINT32_MAX)
            GOTO(done);

        locals->entry.mode = (uint32_t)r;
    }

    /* Get the name size. */
    {
        if ((r = _get_namesize(&locals->hdr)) < 0 || r >= MYST_CPIO_PATH_MAX)
            GOTO(done);

        namesize = (size_t)r;
    }

    /* Read the name. */
    {
        if (namesize > rem)
            GOTO(done);

        memcpy(&locals->entry.name, &data[pos], namesize);
        pos += namesize;
        rem -= namesize;
    }

    /* Skip any padding after the name. */
    {
        size_t new_pos;

        if (myst_round_up(pos, 4, &new_pos) != 0)
            GOTO(done);

        size_t padding = new_pos - pos;

        if (padding > rem)
            GOTO(done);

        pos += padding;
        rem -= padding;
    }

    /* Save the file offset. */
    file_pos = pos;

    /* Skip over the file data. */
    {
        if (locals->entry.size > rem)
            GOTO(done);

        pos += locals->entry.size;
        rem -= locals->entry.size;
    }

    /* Skip any padding after the file data. */
    {
        size_t new_pos;

        if (myst_round_up(pos, 4, &new_pos) != 0)
            GOTO(done);

        size_t padding = new_pos - pos;

        if (padding > rem)
            GOTO(done);

        pos += padding;
        rem -= padding;
    }

    /* Save the offset to the start of the next entry. */
    *pos_in_out = pos;

    /* Check for end-of-file. */
    if (strcmp(locals->entry.name, "TRAILER!!!") == 0)
    {
        ret = 0;
        goto done;
    }

    *entry_out = locals->entry;
    *file_data_out = &data[file_pos];

    ret = 1;

done:

    if (locals)
        free(locals);

    return ret;
}

int myst_cpio_mem_unpack(
    const void* cpio_data,
    size_t cpio_size,
    const char* target,
    myst_cpio_create_file_function_t create_file)
{
    int ret = -1;
    size_t pos = 0;
    struct locals
    {
        myst_cpio_entry_t ent;
        char path[MYST_CPIO_PATH_MAX];
        char target[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    for (;;)
    {
        const void* file_data;
        int r;

        if ((r = myst_cpio_next_entry(
                 cpio_data, cpio_size, &pos, &locals->ent, &file_data)) == 0)
        {
            break;
        }

        if (strcmp(locals->ent.name, ".") == 0)
            continue;

        MYST_STRLCPY(locals->path, target);
        MYST_STRLCAT(locals->path, "/");
        MYST_STRLCAT(locals->path, locals->ent.name);

        if (S_ISDIR(locals->ent.mode))
        {
            struct stat st;

            if (stat(locals->path, &st) == 0)
            {
                if (!S_ISDIR(st.st_mode))
                {
                    PRINTF("*** cpio: already exists: %s\n", locals->path);
                    GOTO(done);
                }
            }
            else if (mkdir(locals->path, locals->ent.mode) != 0)
            {
                GOTO(done);
            }
        }
        else if (S_ISREG(locals->ent.mode))
        {
            if (create_file)
            {
                if ((*create_file)(
                        locals->path,
                        file_data,
                        locals->ent.size,
                        locals->ent.mode) != 0)
                    GOTO(done);
            }
            else
            {
                int fd;
                ssize_t n = (ssize_t)locals->ent.size;

                // ATTN: Can we replace 0666 with locals->ent.mode?
                if ((fd = open(locals->path, O_WRONLY | O_CREAT, 0640)) < 0)
                    GOTO(done);

                if (write(fd, file_data, (size_t)n) != n)
                {
                    close(fd);
                    GOTO(done);
                }

                close(fd);
                fd = -1;
            }
        }
        else if (S_ISLNK(locals->ent.mode))
        {
            /* read the target from CPIO archive */
            {
                ssize_t n = (ssize_t)locals->ent.size;

                if (n < 1 || n >= (ssize_t)sizeof(locals->target))
                    GOTO(done);

                memcpy(locals->target, file_data, locals->ent.size);
                locals->target[n] = '\0';
            }

            /* create the symlink */
            if (symlink(locals->target, locals->path) != 0)
                GOTO(done);
        }
        else
        {
            GOTO(done);
        }
    }

    ret = 0;

done:

    if (locals)
        free(locals);

    return ret;
}

int myst_cpio_test(const char* path)
{
    int ret = 0;
    int fd = -1;
    const char magic[] = MYST_CPIO_MAGIC_INITIALIZER;
    char buf[sizeof(magic)];

    if (!path)
        ERAISE(-EINVAL);

    if ((fd = open(path, O_RDONLY)) < 0)
    {
        if (errno == EISDIR)
            ERAISE(-ENOTSUP);
        else
            ERAISE(-ENOENT);
    }

    if (read(fd, buf, sizeof(buf)) != sizeof(magic))
        ERAISE(-ENOTSUP);

    if (memcmp(buf, magic, sizeof(magic)) != 0)
        ERAISE(-ENOTSUP);

done:

    if (fd >= 0)
        close(fd);

    return ret;
}
