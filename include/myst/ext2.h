// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef MYST_EXT2_H
#define MYST_EXT2_H

#include <dirent.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <myst/blkdev.h>
#include <myst/buf.h>
#include <myst/fs.h>
#include <myst/strarr.h>

/*
**==============================================================================
**
** defines:
**
**==============================================================================
*/

#define EXT2_FILENAME_MAX 255

#define EXT2_MAX_BLOCK_SIZE (8 * 1024)

/* Offset of super block from start of file system */
#define EXT2_BASE_OFFSET 1024

#define EXT2_GOOD_OLD_REV 0 /* Revision 0 ext2_t */
#define EXT2_DYNAMIC_REV 1  /* Revision 1 ext2_t */

#define EXT2_BAD_INO 1
#define EXT2_ROOT_INO 2
#define EXT2_ACL_IDX_INO 3
#define EXT2_ACL_DATA_INO 4
#define EXT2_BOOT_LOADER_INO 5
#define EXT2_UNDEL_DIR_INO 6
#define EXT2_FIRST_INO 11

#define EXT2_FT_UNKNOWN 0
#define EXT2_FT_REG_FILE 1
#define EXT2_FT_DIR 2
#define EXT2_FT_CHRDEV 3
#define EXT2_FT_BLKDEV 4
#define EXT2_FT_FIFO 5
#define EXT2_FT_SOCK 6
#define EXT2_FT_SYMLINK 7

/*
**==============================================================================
**
** structures:
**
**==============================================================================
*/

typedef unsigned int ext2_ino_t;
typedef unsigned int ext2_off_t;

typedef struct ext2 ext2_t;
typedef struct ext2_block ext2_block_t;
typedef struct ext2_super_block ext2_super_block_t;
typedef struct ext2_group_desc ext2_group_desc_t;
typedef struct ext2_inode ext2_inode_t;
typedef struct ext2_dirent ext2_dirent_t;
typedef struct ext2_dir ext2_dir_t;

struct ext2_block
{
    uint8_t data[EXT2_MAX_BLOCK_SIZE];
    uint32_t size;
};

struct ext2_super_block
{
    /* General */
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;

    /* DYNAMIC_REV Specific */
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t s_uuid[16];
    uint8_t s_volume_name[16];
    uint8_t s_last_mounted[64];
    uint32_t s_algo_bitmap;

    /* Performance Hints */
    uint8_t s_prealloc_blocks;
    uint8_t s_prealloc_dir_blocks;
    uint16_t __alignment;

    /* Journaling Support */
    uint8_t s_journal_uuid[16];
    uint32_t s_journal_inum;
    uint32_t s_journal_dev;
    uint32_t s_last_orphan;

    /* Directory Indexing Support */
    uint32_t s_hash_seed[4];
    uint8_t s_def_hash_version;
    uint8_t padding[3];

    /* Other options */
    uint32_t s_default_mount_options;
    uint32_t s_first_meta_bg;
    uint8_t __unused[760];
};

_Static_assert(sizeof(ext2_super_block_t) == 1024, "");

struct ext2_group_desc
{
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint8_t bg_reserved[12];
};

struct ext2_inode
{
    uint16_t i_mode;
    uint16_t i_uid; /* low 16bit of uid */
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid; /* low 16bit of gid */
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_osd1;
    /*
       0:11 -- direct block numbers
       12 -- indirect block number
       13 -- double-indirect block number
       14 -- triple-indirect block number
    */
    uint32_t i_block[15];
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_dir_acl;
    uint32_t i_faddr;
    union {
        uint8_t buf[12];
        struct
        {
            uint8_t reserve1[4];
            uint16_t i_uid_h; /* high 16bit of uid */
            uint16_t i_gid_h; /* high 16bit of gid */
            uint8_t reserve2[4];
        } linux2;
    } i_osd2;
    uint8_t dummy[128]; /* sometimes the inode is bigger */
};

struct ext2_dirent
{
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    char name[EXT2_FILENAME_MAX];
};

// This structure keeps track of the number of times an inode has been opened
// (nopens) and whether the inode shall be freed on the final close (free).
// When pathnames are unlinked, there are two cases (1) there are no open files
// referring to the inode, or (2) there are one or more open files referring to
// the inode. In the first case, the inode and its data blocks are immediately
// freed by the unlink operation. In the second case, the freeing of the inode
// and its data blocks is deferred until the final file referring to that inode
// is closed.
typedef struct ext2_inode_ref
{
    /* whether to free the inode and its data blocks on close */
    uint32_t free : 1;

    /* the number of times the file has been opened */
    uint32_t nopens : 31;
} ext2_inode_ref_t;

struct ext2
{
    myst_fs_t base;
    myst_blkdev_t* dev;
    ext2_super_block_t sb;
    uint32_t block_size; /* block size in bytes */
    uint32_t group_count;
    ext2_group_desc_t* groups;
    ext2_inode_t root_inode;
    char target[PATH_MAX];
    myst_mount_resolve_callback_t resolve;
    myst_fs_t* wrapper_fs;
    ext2_inode_ref_t* inode_refs;
};

/*
**==============================================================================
**
** ext2 lifetime management
**
**==============================================================================
*/

int ext2_create(
    myst_blkdev_t* dev,
    myst_fs_t** fs,
    myst_mount_resolve_callback_t resolve_cb);

int ext2_set_wrapper_fs(myst_fs_t* fs, myst_fs_t* wrapper_fs);

int ext2_release(myst_fs_t* fs);

/*
**==============================================================================
**
** debugging
**
**==============================================================================
*/

int ext2_lsr(ext2_t* ext2, const char* root, myst_strarr_t* paths);

int ext2_check(const ext2_t* ext2);

int ext2_read_block(const ext2_t* ext2, uint32_t blkno, ext2_block_t* block);

int ext2_read_inode(const ext2_t* ext2, ext2_ino_t ino, ext2_inode_t* inode);

int ext2_read_block_bitmap(
    const ext2_t* ext2,
    uint32_t group_index,
    ext2_block_t* block);

int ext2_read_inode_bitmap(
    const ext2_t* ext2,
    uint32_t group_index,
    ext2_block_t* block);

void ext2_dump_super_block(const ext2_super_block_t* sb);

int ext2_dump(const ext2_t* ext2);

/*
**==============================================================================
**
** standard file and directory operations
**
**==============================================================================
*/

int ext2_open(
    myst_fs_t* fs,
    const char* path,
    int flags,
    mode_t mode,
    myst_fs_t** fs_out,
    myst_file_t** file);

int64_t ext2_read(myst_fs_t* fs, myst_file_t* file, void* data, uint64_t size);

int64_t ext2_write(
    myst_fs_t* fs,
    myst_file_t* file,
    const void* data,
    uint64_t size);

off_t ext2_lseek(myst_fs_t* fs, myst_file_t* file, off_t offset, int whence);

int ext2_close(myst_fs_t* fs, myst_file_t* file);

int ext2_access(myst_fs_t* fs, const char* pathname, int mode);

int ext2_link(myst_fs_t* fs, const char* oldpath, const char* newpath);

int ext2_unlink(myst_fs_t* fs, const char* path);

int ext2_rename(myst_fs_t* fs, const char* oldpath, const char* newpath);

int ext2_symlink(myst_fs_t* fs, const char* target, const char* linkpath);

ssize_t ext2_readlink(
    myst_fs_t* fs,
    const char* pathname,
    char* buf,
    size_t bufsiz);

int ext2_fstat(myst_fs_t* fs, myst_file_t* file, struct stat* statbuf);

int ext2_stat(myst_fs_t* fs, const char* pathname, struct stat* statbuf);

int ext2_lstat(myst_fs_t* fs, const char* pathname, struct stat* statbuf);

int ext2_ftruncate(myst_fs_t* fs, myst_file_t* file, off_t length);

int ext2_truncate(myst_fs_t* fs, const char* path, off_t length);

int ext2_mkdir(myst_fs_t* fs, const char* path, mode_t mode);

int ext2_rmdir(myst_fs_t* fs, const char* path);

int ext2_opendir(myst_fs_t* fs, const char* name, ext2_dir_t** dir);

int ext2_readdir(myst_fs_t* fs, ext2_dir_t* dir, struct dirent** ent);

int ext2_closedir(myst_fs_t* fs, ext2_dir_t* dir);

#endif /* MYST_EXT2_H */
