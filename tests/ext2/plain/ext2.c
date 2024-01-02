// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <myst/blkdev.h>
#include <myst/ext2.h>

uid_t myst_syscall_geteuid(void)
{
    return geteuid();
}

gid_t myst_syscall_getegid(void)
{
    return getegid();
}

int check_thread_group_membership(gid_t group)
{
    return 1;
}

typedef struct
{
} myst_thread_t;

myst_thread_t* myst_thread_self()
{
    return NULL;
}

static void _dump_stat_buf(struct stat* buf)
{
    printf("=== _dump_stat_buf\n");
    printf("st_dev=%lu\n", buf->st_dev);
    printf("st_ino=%lu\n", buf->st_ino);
    printf("st_mode=%o\n", buf->st_mode);
    printf("st_nlink=%lu\n", buf->st_nlink);
    printf("st_uid=%d\n", buf->st_uid);
    printf("st_gid=%d\n", buf->st_gid);
    printf("st_rdev=%lu\n", buf->st_rdev);
    printf("st_size=%zu\n", buf->st_size);
    printf("st_blksize=%zu\n", buf->st_blksize);
    printf("st_blocks=%zu\n", buf->st_blocks);
}

nlink_t _nlink(myst_fs_t* fs, const char* path)
{
    struct stat buf;
    assert(ext2_stat(fs, path, &buf) == 0);
    return buf.st_nlink;
}

void dump_stat(myst_fs_t* fs, const char* path)
{
    struct stat buf;
    assert(ext2_stat(fs, path, &buf) == 0);
    _dump_stat_buf(&buf);
}

static size_t _filesize(myst_fs_t* fs, const char* path)
{
    struct stat buf;

    if (ext2_stat(fs, path, &buf) != 0)
        return (size_t)-1;

    return buf.st_size;
}

static size_t _ffilesize(myst_fs_t* fs, myst_file_t* file)
{
    struct stat buf;

    if (ext2_fstat(fs, file, &buf) != 0)
        return (size_t)-1;

    return buf.st_size;
}

static bool _contains(const myst_strarr_t* arr, const char* path)
{
    for (size_t i = 0; i < arr->size; i++)
    {
        if (strcmp(arr->data[i], path) == 0)
            return true;
    }

    return false;
}

static int _create_file(
    myst_fs_t* fs,
    const char* path,
    mode_t mode,
    const void* buf,
    size_t count)
{
    myst_file_t* file;
    int flags = O_CREAT | O_TRUNC | O_WRONLY;

    assert(ext2_open(fs, path, flags, mode, NULL, &file) == 0);

    if (buf && count)
        assert(ext2_write(fs, file, buf, count) == (ssize_t)count);

    assert(ext2_close(fs, file) == 0);

    return 0;
}

__attribute__((unused)) void _hexdump(const void* data, size_t size)
{
    const uint8_t* p = data;

    while (size--)
        printf("%02x", *p++);

    printf("\n");
}

static void _touch(myst_fs_t* fs, const char* path)
{
    int flags = O_CREAT | O_TRUNC | O_WRONLY;
    myst_file_t* file;
    assert(ext2_open(fs, path, flags, 0666, NULL, &file) == 0);
    assert(ext2_close(fs, file) == 0);
}

static int _touch_mode(myst_fs_t* fs, const char* path, mode_t mode)
{
    int flags = O_CREAT | O_TRUNC | O_WRONLY;
    myst_file_t* file;

    if (ext2_open(fs, path, flags, mode, NULL, &file) != 0)
        return -1;

    if (ext2_close(fs, file) != 0)
        return -1;

    return 0;
}

//#define DUMP
//#define TRACE
ext2_t* __ext2;

int mock_mount_resolve(
    const char* path,
    char suffix[PATH_MAX],
    myst_fs_t** fs_out)
{
    *suffix = '\0';
    strncat(suffix, path, PATH_MAX - 1);
    *fs_out = (myst_fs_t*)__ext2;
    return 0;
}

static void _rand_name(char buf[PATH_MAX])
{
    size_t len = random() % EXT2_FILENAME_MAX;

    if (len == 0)
        len++;

    const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";

    assert(len <= EXT2_FILENAME_MAX);

    for (size_t i = 0; i < len; i++)
    {
        buf[i] = chars[random() % (sizeof(chars) - 1)];
        buf[i + 1] = '\0';
    }
}

static void _test_dir_entries(myst_fs_t* fs)
{
    const char path[] = "/dirents";
    const size_t N = 1093;
    char* names[N];
    struct stat statbuf;

    /* create the root directory */
    assert(ext2_mkdir(fs, path, 0755) == 0);

    /* generate the random names */
    {
        srandom(12345);

        for (size_t i = 0; i < N; i++)
        {
            char buf[PATH_MAX];

            for (;;)
            {
                bool found = false;

                _rand_name(buf);

                for (size_t j = 0; j < i; j++)
                {
                    if (strcmp(names[j], buf) == 0)
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    break;
            }

            names[i] = strdup(buf);
        }
    }

    /* create the directories */
    for (size_t i = 0; i < N; i++)
    {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s/%s", path, names[i]);
        assert(ext2_mkdir(fs, tmp, 0755) == 0);
        assert(ext2_stat(fs, tmp, &statbuf) == 0);
    }

    /* verify that the newly created directories exist */
    for (size_t i = 0; i < N; i++)
    {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s/%s", path, names[i]);
        assert(ext2_stat(fs, tmp, &statbuf) == 0);
    }

    /* remove every third entry */
    for (size_t i = 0; i < N; i += 3)
    {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s/%s", path, names[i]);
        assert(ext2_rmdir(fs, tmp) == 0);
        assert(ext2_stat(fs, tmp, &statbuf) == -ENOENT);
    }

    /* add back every third entry */
    for (size_t i = 0; i < N; i += 3)
    {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s/%s", path, names[i]);
        assert(ext2_mkdir(fs, tmp, 0755) == 0);
        assert(ext2_stat(fs, tmp, &statbuf) == 0);
    }

    /* remove the even entries */
    for (size_t i = 0; i < N; i += 2)
    {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s/%s", path, names[i]);
        assert(ext2_rmdir(fs, tmp) == 0);
        assert(ext2_stat(fs, tmp, &statbuf) == -ENOENT);
        free(names[i]);
        names[i] = NULL;
    }

    /* remove whatever entries remain in reverse order */
    for (size_t i = N; i > 0; i--)
    {
        size_t index = i - 1;

        if (names[index])
        {
            char tmp[PATH_MAX];
            snprintf(tmp, sizeof(tmp), "%s/%s", path, names[index]);
            assert(ext2_rmdir(fs, tmp) == 0);
            assert(ext2_stat(fs, tmp, &statbuf) == -ENOENT);
            free(names[index]);
            names[index] = NULL;
        }
    }

    /* remove the root directory (will fail if any entries) */
    assert(ext2_rmdir(fs, path) == 0);
}

int main(int argc, const char* argv[])
{
    myst_blkdev_t* dev;
    myst_fs_t* fs;
    const char alpha[] = "abcdefghijklmnopqrstuvwxyz";
    const mode_t mode = S_IFREG | 0640;
    ext2_super_block_t sb;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <EXT2-file-system>\n", argv[0]);
        exit(1);
    }

#ifdef TRACE
    extern void myst_set_trace(bool flag);
    myst_set_trace(true);
#endif

    if (myst_rawblkdev_open(argv[1], true, 0, &dev) != 0)
    {
        fprintf(stderr, "%s: failed to open %s\n", argv[0], argv[1]);
        exit(1);
    }

    if (ext2_create(dev, &fs, mock_mount_resolve) != 0)
    {
        fprintf(stderr, "%s: ext2_create() failed\n", argv[0]);
        exit(1);
    }

    __ext2 = (ext2_t*)fs;

    /* save the original superblock */
    memcpy(&sb, &__ext2->sb, sizeof(sb));

#ifdef DUMP
    printf(">>> dump: create\n");
    ext2_dump(fs);
#endif

    /* perform sanity checks */
    assert(ext2_check(__ext2) == 0);

    assert(_create_file(fs, "/alpha", mode, alpha, sizeof(alpha)) == 0);

    /* test ext2_size_file() on "/alpha" */
    {
        myst_file_t* file;
        assert(ext2_open(fs, "/alpha", O_RDONLY, 0000, NULL, &file) == 0);
        assert(_ffilesize(fs, file) == sizeof(alpha));
        assert(ext2_close(fs, file) == 0);
    }

    /* create an empty file */
    assert(_create_file(fs, "/empty", mode, NULL, 0) == 0);

    /* test ext2_size_file() on "/empty" */
    {
        myst_file_t* file;
        assert(ext2_open(fs, "/empty", O_RDONLY, 0000, NULL, &file) == 0);
        assert(_ffilesize(fs, file) == 0);
        assert(ext2_close(fs, file) == 0);
    }

    /* open and read "/alpha" in a single read */
    {
        myst_file_t* file;
        char buf[128];
        ssize_t n;

        assert(ext2_open(fs, "/alpha", O_RDONLY, 0000, NULL, &file) == 0);
        assert((n = ext2_read(fs, file, buf, sizeof(buf))) > 0);
        assert(n == sizeof(alpha));
        assert(memcmp(buf, alpha, sizeof(alpha)) == 0);
        assert(ext2_close(fs, file) == 0);
    }

    /* open and read "/alpha" in two reads */
    {
        myst_file_t* file;
        char buf1[sizeof(alpha) / 2];
        char buf2[sizeof(alpha) - sizeof(buf1)];
        ssize_t n;

        assert(ext2_open(fs, "/alpha", O_RDONLY, 0000, NULL, &file) == 0);

        assert(ext2_lseek(fs, file, 0, SEEK_CUR) == 0);

        assert((n = ext2_read(fs, file, buf1, sizeof(buf1))) > 0);
        assert(n == sizeof(buf1));
        assert(memcmp(buf1, alpha, sizeof(buf1)) == 0);
        assert(ext2_lseek(fs, file, 0, SEEK_CUR) == sizeof(buf1));

        assert((n = ext2_read(fs, file, buf2, sizeof(buf2))) > 0);
        assert(n == sizeof(buf2));
        assert(memcmp(buf2, alpha + sizeof(buf1), sizeof(buf2)) == 0);
        assert(
            ext2_lseek(fs, file, 0, SEEK_CUR) == sizeof(buf1) + sizeof(buf2));

        assert(ext2_close(fs, file) == 0);
    }

    /* open and read the last half of "/alpha" (test seek) */
    {
        myst_file_t* file;
        char buf1[sizeof(alpha) / 2];
        char buf2[sizeof(alpha) - sizeof(buf1)];
        ssize_t n;

        assert(ext2_open(fs, "/alpha", O_RDONLY, 0000, NULL, &file) == 0);
        assert(ext2_lseek(fs, file, sizeof(buf1), SEEK_SET) == sizeof(buf1));
        assert((n = ext2_read(fs, file, buf2, sizeof(buf2))) > 0);
        assert(n == sizeof(buf2));
        assert(memcmp(buf2, alpha + sizeof(buf1), sizeof(buf2)) == 0);
        assert(ext2_close(fs, file) == 0);
    }

    /* open and read "/empty" */
    {
        myst_file_t* file;
        char buf[128];
        ssize_t n;

        assert(ext2_open(fs, "/empty", O_RDONLY, 0000, NULL, &file) == 0);
        assert((n = ext2_read(fs, file, buf, sizeof(buf))) >= 0);
        assert(n == 0);
        assert(ext2_close(fs, file) == 0);
    }

    /* Test stat() on "/alpha" */
    {
        struct stat buf;
        assert(ext2_stat(fs, "/alpha", &buf) == 0);
        assert(buf.st_size == sizeof(alpha));
        assert(buf.st_mode == mode);
        assert(buf.st_nlink == 1);
        assert(buf.st_uid == geteuid());
        assert(buf.st_gid == getegid());
        assert(buf.st_blksize % 1024 == 0);
        assert(buf.st_ino != 0);
        //_dump_stat_buf(&buf);
    }

    /* Test stat() on "/empty" */
    {
        struct stat buf;
        assert(ext2_stat(fs, "/empty", &buf) == 0);
        assert(buf.st_size == 0);
        assert(buf.st_mode == mode);
        assert(buf.st_nlink == 1);
        assert(buf.st_uid == geteuid());
        assert(buf.st_gid == getegid());
        assert(buf.st_blksize % 1024 == 0);
        assert(buf.st_ino != 0);
        //_dump_stat_buf(&buf);
    }

    /* Test stat() on "/existing" */
    {
        struct stat buf;
        const char path[] = "/existing";
        assert(ext2_stat(fs, path, &buf) == 0);
        assert(buf.st_size == sizeof(alpha));
        assert(_filesize(fs, path) == sizeof(alpha));
#if 0
        assert(buf.st_mode == 0100600);
#endif
        assert(buf.st_nlink == 1);
        assert(buf.st_blksize % 1024 == 0);
        assert(buf.st_ino != 0);
    }

    /* Test stat() on "/" */
    {
        struct stat buf;
        assert(ext2_stat(fs, "/", &buf) == 0);
        assert((buf.st_mode & S_IFDIR));
        assert(!(buf.st_mode & S_IFREG));
        assert(buf.st_blksize % 1024 == 0);
        assert(buf.st_ino != 0);
    }

    /* Test stat() on "/dir" */
    {
        struct stat buf;
        assert(ext2_stat(fs, "/dir", &buf) == 0);
        assert((buf.st_mode & S_IFDIR));
        assert(!(buf.st_mode & S_IFREG));
        assert(buf.st_blksize % 1024 == 0);
        assert(buf.st_ino != 0);
        assert(buf.st_nlink == 2); /* two entries: "." and ".." */
    }

    /* test ext2_size_file() on "/dir/alpha" */
    {
        const char path[] = "/dir/alpha";
        myst_file_t* file;
        assert(_create_file(fs, path, mode, alpha, sizeof(alpha)) == 0);
        assert(ext2_open(fs, path, O_RDONLY, 0000, NULL, &file) == 0);
        assert(_ffilesize(fs, file) == sizeof(alpha));
        assert(ext2_close(fs, file) == 0);
    }

    /* test mkdir */
    {
        const char path[] = "/dir/dir";
        struct stat buf;

        assert(ext2_mkdir(fs, path, 0755) == 0);
        assert(ext2_stat(fs, path, &buf) == 0);
        assert(buf.st_mode == (S_IFDIR | 0755));
        assert(buf.st_nlink == 2); /* two entries: "." and ".." */
        assert(buf.st_blksize % 1024 == 0);
        assert(buf.st_ino != 0);
    }

    /* test ext2_size_file() on "/dir/dir/alpha" */
    {
        const char path[] = "/dir/dir/alpha";
        myst_file_t* file;
        assert(_create_file(fs, path, mode, alpha, sizeof(alpha)) == 0);
        assert(ext2_open(fs, path, O_RDONLY, 0000, NULL, &file) == 0);
        assert(_ffilesize(fs, file) == sizeof(alpha));
        assert(ext2_close(fs, file) == 0);
    }

    /* list all files */
    {
        myst_strarr_t arr = MYST_STRARR_INITIALIZER;
        assert(ext2_lsr(__ext2, "/", &arr) == 0);

#if 0
        for (size_t i = 0; i < arr.size; i++)
            printf("path{%s}\n", arr.data[i]);
#endif

        assert(arr.size == 9);
        assert(arr.data != NULL);
        assert(_contains(&arr, "/lost+found"));
        assert(_contains(&arr, "/existing"));
        assert(_contains(&arr, "/dir"));
        assert(_contains(&arr, "/alpha"));
        assert(_contains(&arr, "/empty"));
        assert(_contains(&arr, "/dir/alpha"));
        assert(_contains(&arr, "/dir/dir"));
        assert(_contains(&arr, "/dir/dir/alpha"));
        assert(_contains(&arr, "/dir/README.md"));

        myst_strarr_release(&arr);
    }

    /* scan the "/" directory */
    {
        ext2_dir_t* dir;
        struct dirent* ent;
        int r;
        size_t n = 0;

        assert(ext2_opendir(fs, "/", &dir) == 0);

        while ((r = ext2_readdir(fs, dir, &ent)) == 1)
        {
            const char* s = ent->d_name;
            n++;

            if (strcmp(s, ".") == 0)
                continue;

            if (strcmp(s, "..") == 0)
                continue;

            if (strcmp(s, "lost+found") == 0)
                continue;

            if (strcmp(s, "existing") == 0)
                continue;

            if (strcmp(s, "dir") == 0)
                continue;

            if (strcmp(s, "alpha") == 0)
                continue;

            if (strcmp(s, "empty") == 0)
                continue;

            assert(false);
        }

        assert(r == 0);
        assert(n == 7);
        assert(ext2_closedir(fs, dir) == 0);
    }

    /* scan the "/dir" directory */
    {
        ext2_dir_t* dir;
        struct dirent* ent;
        int r;
        size_t n = 0;

        assert(ext2_opendir(fs, "/dir", &dir) == 0);

        while ((r = ext2_readdir(fs, dir, &ent)) == 1)
        {
            const char* s = ent->d_name;
            n++;

            if (strcmp(s, ".") == 0)
                continue;

            if (strcmp(s, "..") == 0)
                continue;

            if (strcmp(s, "alpha") == 0)
                continue;

            if (strcmp(s, "dir") == 0)
                continue;

            if (strcmp(s, "README.md") == 0)
                continue;

            assert(false);
        }

        assert(r == 0);
        assert(n == 5);
        assert(ext2_closedir(fs, dir) == 0);
    }

    /* truncate "/dir/alpha" */
    {
        struct stat buf;
        const char path[] = "/dir/alpha";

        assert(ext2_stat(fs, path, &buf) == 0);
        assert(ext2_truncate(fs, path, 0) == 0);
        assert(_filesize(fs, path) == 0);
        assert(ext2_stat(fs, path, &buf) == 0);
    }

    /* remove "/dir/alpha" and test stat */
    {
        struct stat buf;
        const char path[] = "/dir/alpha";

        assert(ext2_stat(fs, path, &buf) == 0);
        assert(ext2_unlink(fs, path) == 0);
        assert(ext2_stat(fs, path, &buf) == -ENOENT);
    }

    /* remove "/dir/dir/alpha" and test stat */
    {
        struct stat buf;
        const char path[] = "/dir/dir/alpha";

        assert(ext2_stat(fs, path, &buf) == 0);
        assert(ext2_unlink(fs, path) == 0);
        assert(ext2_stat(fs, path, &buf) == -ENOENT);
    }

    /* remove "/dir/dir" and test stat */
    {
        struct stat buf;
        const char path[] = "/dir/dir";

        assert(_nlink(fs, "/dir/dir") == 2);
        assert(ext2_stat(fs, path, &buf) == 0);
        assert(_nlink(fs, "/dir") == 3);
        assert(ext2_rmdir(fs, path) == 0);
        assert(_nlink(fs, "/dir") == 2);
        assert(ext2_stat(fs, path, &buf) == -ENOENT);
    }

    /* scan the "/dir" directory (now with one less file) */
    {
        ext2_dir_t* dir;
        struct dirent* ent;
        int r;
        size_t n = 0;

        assert(ext2_opendir(fs, "/dir", &dir) == 0);

        while ((r = ext2_readdir(fs, dir, &ent)) == 1)
        {
            const char* s = ent->d_name;
            n++;

            if (strcmp(s, ".") == 0)
                continue;

            if (strcmp(s, "..") == 0)
                continue;

            if (strcmp(s, "README.md") == 0)
                continue;

            assert(false);
        }

        assert(r == 0);
        assert(n == 3);
        assert(ext2_closedir(fs, dir) == 0);
    }

    /* create a big file with lots of pages */
    {
        const char path[] = "/bigfile";
        myst_file_t* file;
        void* data;
        /* force use of inode tripple indirection */
        size_t num_blocks = 12 + 256 + (256 * 256) + 7;
        size_t block_size = __ext2->block_size;
        size_t size = num_blocks * block_size;

        if (!(data = calloc(num_blocks, block_size)))
            assert(0);

        /* fill each block with a given character */
        for (size_t i = 0; i < num_blocks; i++)
        {
            void* ptr = (uint8_t*)data + (i * block_size);
            memset(ptr, (uint8_t)i, block_size);
        }

        assert(_create_file(fs, path, mode, data, size) == 0);
        assert(ext2_open(fs, path, O_RDONLY, 0000, NULL, &file) == 0);
        assert(_ffilesize(fs, file) == size);
        /* read the blocks back */
        {
            ssize_t n;
            size_t i = 0;
            char buf[block_size];

            while ((n = ext2_read(fs, file, buf, block_size)) > 0)
            {
                assert(n == block_size);
                char tmp[block_size];
                memset(tmp, (uint8_t)i, block_size);
                assert(memcmp(tmp, buf, block_size) == 0);
                i++;
            }

            assert(i == num_blocks);
        }

        free(data);

        assert(ext2_close(fs, file) == 0);
        assert(ext2_unlink(fs, "/bigfile") == 0);
    }

    /* test write */
    {
        const char path[] = "/testwrite";
        mode_t mode = 0666;
        struct stat statbuf;
        myst_file_t* file;
        /* ATTN: 10000 crashes */
        const size_t count = 10000;

        /* create a file */
        {
            size_t i = 0;

            assert(_create_file(fs, path, mode, NULL, 0) == 0);
            assert(ext2_stat(fs, path, &statbuf) == 0);
            assert(ext2_open(fs, path, O_WRONLY, 0000, NULL, &file) == 0);

            /* write the alphabet multiple times */
            for (i = 0; i < count; i++)
            {
                char tmp[sizeof(alpha)];
                const ssize_t n = sizeof(alpha);

                memcpy(tmp, alpha, n);
                tmp[0] = (char)i;

                assert(ext2_write(fs, file, tmp, n) == n);
            }

            assert(i == count);
            assert(ext2_close(fs, file) == 0);
        }

        assert(_filesize(fs, path) == count * sizeof(alpha));

        /* read back the file */
        {
            size_t i;

            assert(ext2_open(fs, path, O_RDONLY, 0000, NULL, &file) == 0);

            /* write the alphabet multiple times */
            for (i = 0; i < count; i++)
            {
                char tmp[sizeof(alpha)];
                char buf[sizeof(alpha)];
                const ssize_t n = sizeof(alpha);

                memcpy(tmp, alpha, n);
                tmp[0] = (char)i;

                assert(ext2_read(fs, file, buf, n) == n);
                assert(memcmp(buf, tmp, n) == 0);
            }

            assert(i == count);
            assert(ext2_close(fs, file) == 0);
        }

        assert(_filesize(fs, path) == count * sizeof(alpha));

        /* test open() with O_TRUNC */
        {
            char buf[1024];
            assert(
                ext2_open(fs, path, O_TRUNC | O_RDWR, 0666, NULL, &file) == 0);
            assert(ext2_write(fs, file, "abcd", 4) == 4);
            assert(ext2_write(fs, file, "efg", 3) == 3);
            assert(ext2_write(fs, file, "hijk", 4) == 4);
            assert(ext2_lseek(fs, file, 0, SEEK_SET) == 0);
            assert(ext2_lseek(fs, file, 4, SEEK_SET) == 4);
            assert(ext2_read(fs, file, buf, sizeof(buf)) == 7);
            assert(memcmp(buf, "efghijk", 7) == 0);
            assert(ext2_close(fs, file) == 0);
            assert(_filesize(fs, path) == 11);
        }

        assert(ext2_unlink(fs, path) == 0);
    }

    /* create a file with a file hole in it */
    {
        myst_file_t* file;
        const char path[] = "/holes";
        char buf1[1024];
        char zeros[1024];

        memset(buf1, 0xff, sizeof(buf1));
        memset(zeros, 0x00, sizeof(zeros));

        assert(ext2_open(fs, path, O_WRONLY | O_CREAT, 0666, NULL, &file) == 0);
        assert(ext2_lseek(fs, file, 1024, SEEK_SET) == 1024);
        assert(ext2_write(fs, file, buf1, sizeof(buf1)) == sizeof(buf1));
        assert(ext2_close(fs, file) == 0);
        assert(_filesize(fs, path) == 2048);

        assert(ext2_open(fs, path, O_RDONLY, 0000, NULL, &file) == 0);

        char buf2[1024];
        assert(ext2_lseek(fs, file, 1024, SEEK_SET) == 1024);
        assert(ext2_read(fs, file, buf2, sizeof(buf2)) == sizeof(buf2));
        assert(memcmp(buf1, buf2, sizeof(buf1)) == 0);

        char buf3[1024];
        memset(buf3, 0xdd, sizeof(buf3));
        assert(ext2_lseek(fs, file, 0, SEEK_SET) == 0);
        assert(ext2_read(fs, file, buf3, sizeof(buf3)) == sizeof(buf3));
        assert(memcmp(buf3, zeros, sizeof(buf3)) == 0);

        assert(ext2_close(fs, file) == 0);
        assert(ext2_unlink(fs, path) == 0);
    }

    /* clean up files */
    assert(ext2_unlink(fs, "/alpha") == 0);
    assert(ext2_unlink(fs, "/empty") == 0);

    /* verify that there are no more files */
    {
        ext2_dir_t* dir;
        struct dirent* ent;
        int r;
        size_t n = 0;

        assert(ext2_opendir(fs, "/", &dir) == 0);

        while ((r = ext2_readdir(fs, dir, &ent)) == 1)
        {
            const char* s = ent->d_name;

            if (strcmp(s, ".") == 0)
                continue;

            if (strcmp(s, "..") == 0)
                continue;

            if (strcmp(s, "lost+found") == 0)
                continue;

            if (strcmp(s, "existing") == 0)
                continue;

            if (strcmp(s, "dir") == 0)
                continue;

            n++;
            printf("%s\n", ent->d_name);
        }

        assert(n == 0);
        assert(ext2_closedir(fs, dir) == 0);
    }

    /* test large directories */
    {
        const char dirname[] = "/largedir";
        const size_t N = 1000;

        assert(ext2_mkdir(fs, dirname, 0755) == 0);

        for (size_t i = 0; i < N; i++)
        {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/filename%zu", dirname, i);
            _touch(fs, path);
        }

        {
            ext2_dir_t* dir;
            struct dirent* ent;
            int r;
            size_t i = 0;

            assert(ext2_opendir(fs, dirname, &dir) == 0);

            while ((r = ext2_readdir(fs, dir, &ent)) == 1)
            {
                if (strcmp(ent->d_name, ".") == 0)
                    continue;

                if (strcmp(ent->d_name, "..") == 0)
                    continue;

                char path[PATH_MAX];
                snprintf(path, sizeof(path), "%s/filename%zu", dirname, i);

                char tmp[PATH_MAX];
                snprintf(tmp, sizeof(tmp), "%s/%s", dirname, ent->d_name);

                assert(strcmp(tmp, path) == 0);

                i++;
            }

            assert(i == N);

            assert(ext2_closedir(fs, dir) == 0);
        }

        for (size_t i = 0; i < N; i++)
        {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/filename%zu", dirname, i);
            assert(ext2_unlink(fs, path) == 0);
        }

        assert(ext2_rmdir(fs, dirname) == 0);
    }

    /* test access() */
    {
        assert(_touch_mode(fs, "/access-444", 0444) == 0); /* r-- */
        assert(_touch_mode(fs, "/access-666", 0666) == 0); /* rw- */
        assert(_touch_mode(fs, "/access-777", 0777) == 0); /* rwx */

        assert(ext2_access(fs, "/access-444", F_OK) == 0);
        assert(ext2_access(fs, "/access-444", R_OK) == 0);
        assert(ext2_access(fs, "/access-444", W_OK) != 0);
        assert(ext2_access(fs, "/access-444", X_OK) != 0);

        assert(ext2_access(fs, "/access-666", F_OK) == 0);
        assert(ext2_access(fs, "/access-666", R_OK | W_OK) == 0);
        assert(ext2_access(fs, "/access-666", X_OK) != 0);

        assert(ext2_access(fs, "/access-777", F_OK) == 0);
        assert(ext2_access(fs, "/access-777", R_OK | W_OK | X_OK) == 0);

        assert(ext2_unlink(fs, "/access-444") == 0);
        assert(ext2_unlink(fs, "/access-666") == 0);
        assert(ext2_unlink(fs, "/access-777") == 0);
    }

    /* test link() */
    {
        _create_file(fs, "/link1", 0666, NULL, 0);
        assert(_nlink(fs, "/link1") == 1);

        assert(ext2_link(fs, "/link1", "/link2", 0) == 0);
        assert(_nlink(fs, "/link1") == 2);

        assert(ext2_unlink(fs, "/link1") == 0);
        assert(_nlink(fs, "/link2") == 1);
        assert(ext2_unlink(fs, "/link2") == 0);
    }

    /* test rename() with non-existent newpath */
    {
        _create_file(fs, "/rename1", 0666, alpha, sizeof(alpha));
        assert(ext2_access(fs, "/rename1", R_OK) == 0);
        assert(_filesize(fs, "/rename1") == sizeof(alpha));

        assert(ext2_rename(fs, "/rename1", "/rename2") == 0);
        assert(ext2_access(fs, "/rename1", R_OK) != 0);
        assert(ext2_access(fs, "/rename2", R_OK) == 0);
        assert(_filesize(fs, "/rename2") == sizeof(alpha));

        assert(ext2_unlink(fs, "/rename2") == 0);
    }

    /* test rename() with existent newpath */
    {
        _create_file(fs, "/rename1", 0666, alpha, sizeof(alpha));
        _create_file(fs, "/rename2", 0666, NULL, 0);
        assert(ext2_access(fs, "/rename1", R_OK) == 0);
        assert(ext2_access(fs, "/rename2", R_OK) == 0);

        assert(ext2_rename(fs, "/rename1", "/rename2") == 0);
        assert(ext2_access(fs, "/rename1", R_OK) != 0);
        assert(ext2_access(fs, "/rename2", R_OK) == 0);
        assert(_filesize(fs, "/rename2") == sizeof(alpha));

        assert(ext2_unlink(fs, "/rename2") == 0);
    }

    /* test rename() of directory: with non-existent newpath */
    {
        assert(ext2_mkdir(fs, "/renamedir1", 0755) == 0);
        assert(_touch_mode(fs, "/renamedir1/newfile", 0666) == 0);
        assert(ext2_rename(fs, "/renamedir1", "/renamedir2") == 0);
        assert(ext2_unlink(fs, "/renamedir2/newfile") == 0);
        assert(ext2_rmdir(fs, "/renamedir2") == 0);
    }

    /* test rename() of directory: with existent newpath */
    {
        assert(ext2_mkdir(fs, "/renamedir1", 0755) == 0);
        assert(ext2_mkdir(fs, "/renamedir2", 0755) == 0);
        assert(ext2_rename(fs, "/renamedir1", "/renamedir2") == 0);
        assert(ext2_rmdir(fs, "/renamedir2") == 0);
    }

    /* test rename() of directory: with non-empty directory newpath */
    {
        assert(ext2_mkdir(fs, "/renamedir1", 0755) == 0);
        assert(ext2_mkdir(fs, "/renamedir2", 0755) == 0);
        assert(ext2_mkdir(fs, "/renamedir2/dir", 0755) == 0);
        assert(ext2_rename(fs, "/renamedir1", "/renamedir2") == -ENOTEMPTY);
        assert(ext2_rmdir(fs, "/renamedir2/dir") == 0);
        assert(ext2_rmdir(fs, "/renamedir1") == 0);
        assert(ext2_rmdir(fs, "/renamedir2") == 0);
    }

    /* test symlink() (1) */
    {
        const char target[] = "/target";
        const char linkpath[] = "/symlink";

        _create_file(fs, target, 0666, alpha, sizeof(alpha));
        assert(ext2_symlink(fs, target, linkpath) == 0);

        struct stat statbuf;
        assert(ext2_stat(fs, linkpath, &statbuf) == 0);
        assert(statbuf.st_size == sizeof(alpha));

        assert(ext2_lstat(fs, linkpath, &statbuf) == 0);
        assert(statbuf.st_size == strlen(target));

        myst_file_t* file;
        assert(ext2_open(fs, linkpath, O_RDONLY, 0000, NULL, &file) == 0);
        char buf[128];
        assert(ext2_read(fs, file, buf, sizeof(buf)) == sizeof(alpha));
        assert(memcmp(buf, alpha, sizeof(alpha)) == 0);
        assert(ext2_close(fs, file) == 0);

        assert(ext2_unlink(fs, target) == 0);
        assert(ext2_unlink(fs, linkpath) == 0);
    }

    /* test symlink() (2) */
    {
        const char target[] = "/target";
        const char linkpath[] = "/symlink";

        _create_file(fs, target, 0666, alpha, sizeof(alpha));
        assert(ext2_symlink(fs, "./target", linkpath) == 0);

        myst_file_t* file;
        assert(ext2_open(fs, linkpath, O_RDONLY, 0000, NULL, &file) == 0);
        char buf[128];
        assert(ext2_read(fs, file, buf, sizeof(buf)) == sizeof(alpha));
        assert(memcmp(buf, alpha, sizeof(alpha)) == 0);
        assert(ext2_close(fs, file) == 0);

        assert(ext2_unlink(fs, target) == 0);
        assert(ext2_unlink(fs, linkpath) == 0);
    }

    /* test symlink() (3) */
    {
        const char target[] = "/target";
        const char linkpath[] = "/symlink";

        _create_file(fs, target, 0666, alpha, sizeof(alpha));
        assert(ext2_symlink(fs, "../target", linkpath) == 0);

        myst_file_t* file;
        assert(ext2_open(fs, linkpath, O_RDONLY, 0000, NULL, &file) == 0);
        char buf[128];
        assert(ext2_read(fs, file, buf, sizeof(buf)) == sizeof(alpha));
        assert(memcmp(buf, alpha, sizeof(alpha)) == 0);
        assert(ext2_close(fs, file) == 0);

        assert(ext2_unlink(fs, target) == 0);
        assert(ext2_unlink(fs, linkpath) == 0);
    }

    /* test symlink() with directories */
    {
        assert(ext2_mkdir(fs, "/lnkdir1", 0755) == 0);
        assert(ext2_mkdir(fs, "/lnkdir1/lnkdir2", 0755) == 0);
        assert(ext2_mkdir(fs, "/lnkdir3", 0755) == 0);
        assert(ext2_mkdir(fs, "/lnkdir3/lnkdir4", 0755) == 0);

        const char filename[] = "/lnkdir3/lnkdir4/file";
        _create_file(fs, filename, 0666, alpha, sizeof(alpha));

        const char target[] = "../../lnkdir3";
        const char linkpath[] = "/lnkdir1/lnkdir2/symlink";
        assert(ext2_symlink(fs, target, linkpath) == 0);

        {
            char buf[128];
            ssize_t n = strlen(target);
            assert(ext2_readlink(fs, linkpath, buf, sizeof(buf)) == n);
        }

        struct stat statbuf;
        const char path[] = "/lnkdir1/lnkdir2/symlink/lnkdir4";
        assert(ext2_stat(fs, path, &statbuf) == 0);

        {
            myst_file_t* file;
            const char path[] = "/lnkdir1/lnkdir2/symlink/lnkdir4/file";
            assert(ext2_open(fs, path, O_RDONLY, 0000, NULL, &file) == 0);
            char buf[128];
            assert(ext2_read(fs, file, buf, sizeof(buf)) == sizeof(alpha));
            assert(memcmp(buf, alpha, sizeof(alpha)) == 0);
            assert(ext2_close(fs, file) == 0);
        }

        assert(ext2_unlink(fs, linkpath) == 0);
        assert(ext2_unlink(fs, filename) == 0);
        assert(ext2_rmdir(fs, "/lnkdir1/lnkdir2") == 0);
        assert(ext2_rmdir(fs, "/lnkdir1") == 0);
        assert(ext2_rmdir(fs, "/lnkdir3/lnkdir4") == 0);
        assert(ext2_rmdir(fs, "/lnkdir3") == 0);
    }

    /* test read/write to file from different handles */
    {
        const char path[] = "test_read_write";
        FILE* os = fopen(path, "w");
        assert(os != NULL);

        FILE* is = fopen(path, "r");
        assert(is != NULL);

        fprintf(os, "abcdefghijklmnopqrstuv");
        fflush(os);

        sleep(1);

        int c = getc(is);
        assert(c == 'a');

        fclose(os);
        fclose(is);
    }

    _test_dir_entries(fs);

    /* test using of file after it has been unlinked */
    {
        const char path[] = "/use_after_unlink";
        myst_file_t* file;

        /* open the file for write */
        const int open_flags = O_CREAT | O_TRUNC | O_RDWR;
        assert(ext2_open(fs, path, open_flags, 0666, NULL, &file) == 0);

        /* unlink the file */
        assert(ext2_unlink(fs, path) == 0);

        /* verify that the pathname no longer exists */
        assert(ext2_access(fs, path, F_OK) == -ENOENT);

        /* write to the file */
        assert(ext2_write(fs, file, alpha, sizeof(alpha)) == sizeof(alpha));

        /* verify that the file is the newly written size */
        struct stat statbuf;
        assert(ext2_fstat(fs, file, &statbuf) == 0);
        assert(statbuf.st_size == sizeof(alpha));

        /* attempt to read the data back */
        uint8_t buf[2 * sizeof(alpha)];
        assert(ext2_lseek(fs, file, 0, SEEK_SET) == 0);
        assert(ext2_read(fs, file, buf, sizeof(buf)) == sizeof(alpha));
        assert(memcmp(buf, alpha, sizeof(alpha)) == 0);

        /* close the file */
        ext2_close(fs, file);
    }

    assert(ext2_check(__ext2) == 0);

    /* -- the file system is back to its original state here -- */

#ifdef DUMP
    printf(">>> dump: final\n");
    ext2_dump(fs);
#endif

    /* check superblock against original superblock */
    assert(memcmp(&sb, &__ext2->sb, sizeof(sb)) == 0);

    ext2_release(fs);
    // dev->close(dev);

    printf("=== passed test (%s)\n", argv[0]);

    (void)_dump_stat_buf;

    return 0;
}
