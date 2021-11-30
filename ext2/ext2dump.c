#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <myst/eraise.h>
#include <myst/ext2.h>
#include <myst/strings.h>
#include "ext2common.h"

static void _hex_dump(const uint8_t* data, uint32_t size, bool printables)
{
    uint32_t i;

    printf("%u bytes\n", size);

    for (i = 0; i < size; i++)
    {
        unsigned char c = data[i];

        if (printables && (c >= ' ' && c < '~'))
            printf("'%c", c);
        else
            printf("%02X", c);

        if ((i + 1) % 16)
        {
            printf(" ");
        }
        else
        {
            printf("\n");
        }
    }

    printf("\n");
}

static void _ascii_dump(const uint8_t* data, uint32_t size)
{
    uint32_t i;

    printf("=== ASCII dump:\n");

    for (i = 0; i < size; i++)
    {
        unsigned char c = data[i];

        if (c >= ' ' && c <= '~')
            printf("%c", c);
        else
            printf(".");

        if (i + 1 != size && !((i + 1) % 80))
            printf("\n");
    }

    printf("\n");
}

#if 0
static void _dump_blknos(const uint32_t* data, uint32_t size)
{
    uint32_t i;

    printf("%u blocks\n", size);

    for (i = 0; i < size; i++)
    {
        printf("%08X", data[i]);

        if ((i + 1) % 8)
        {
            printf(" ");
        }
        else
        {
            printf("\n");
        }
    }

    printf("\n");
}
#endif

static bool _zero_filled(const uint8_t* data, uint32_t size)
{
    uint32_t i;

    for (i = 0; i < size; i++)
    {
        if (data[i])
            return 0;
    }

    return 1;
}

static void _dump_bitmap(const ext2_block_t* block)
{
    if (_zero_filled(block->data, block->size))
    {
        printf("...\n\n");
    }
    else
    {
        _hex_dump(block->data, block->size, 0);
    }
}

void ext2_dump_super_block(const ext2_super_block_t* sb)
{
    printf("=== ext2_super_block_t:\n");
    printf("s_inodes_count=%u\n", sb->s_inodes_count);
    printf("s_blocks_count=%u\n", sb->s_blocks_count);
    printf("s_r_blocks_count=%u\n", sb->s_r_blocks_count);
    printf("s_free_blocks_count=%u\n", sb->s_free_blocks_count);
    printf("s_free_inodes_count=%u\n", sb->s_free_inodes_count);
    printf("s_first_data_block=%u\n", sb->s_first_data_block);
    printf("s_log_block_size=%u\n", sb->s_log_block_size);
    printf("s_log_frag_size=%u\n", sb->s_log_frag_size);
    printf("s_blocks_per_group=%u\n", sb->s_blocks_per_group);
    printf("s_frags_per_group=%u\n", sb->s_frags_per_group);
    printf("s_inodes_per_group=%u\n", sb->s_inodes_per_group);
    printf("s_mtime=%u\n", sb->s_mtime);
    printf("s_wtime=%u\n", sb->s_wtime);
    printf("s_mnt_count=%u\n", sb->s_mnt_count);
    printf("s_max_mnt_count=%u\n", sb->s_max_mnt_count);
    printf("s_magic=%X\n", sb->s_magic);
    printf("s_state=%u\n", sb->s_state);
    printf("s_errors=%u\n", sb->s_errors);
    printf("s_minor_rev_level=%u\n", sb->s_minor_rev_level);
    printf("s_lastcheck=%u\n", sb->s_lastcheck);
    printf("s_checkinterval=%u\n", sb->s_checkinterval);
    printf("s_creator_os=%u\n", sb->s_creator_os);
    printf("s_rev_level=%u\n", sb->s_rev_level);
    printf("s_def_resuid=%u\n", sb->s_def_resuid);
    printf("s_def_resgid=%u\n", sb->s_def_resgid);
    printf("s_first_ino=%u\n", sb->s_first_ino);
    printf("s_inode_size=%u\n", sb->s_inode_size);
    printf("s_block_group_nr=%u\n", sb->s_block_group_nr);
    printf("s_feature_compat=%u\n", sb->s_feature_compat);
    printf("s_feature_incompat=%u\n", sb->s_feature_incompat);
    printf("s_feature_ro_compat=%u\n", sb->s_feature_ro_compat);
    printf(
        "s_uuid="
        "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
        sb->s_uuid[0],
        sb->s_uuid[1],
        sb->s_uuid[2],
        sb->s_uuid[3],
        sb->s_uuid[4],
        sb->s_uuid[5],
        sb->s_uuid[6],
        sb->s_uuid[7],
        sb->s_uuid[8],
        sb->s_uuid[9],
        sb->s_uuid[10],
        sb->s_uuid[11],
        sb->s_uuid[12],
        sb->s_uuid[13],
        sb->s_uuid[14],
        sb->s_uuid[15]);
    printf("s_volume_name=%s\n", sb->s_volume_name);
    printf("s_last_mounted=%s\n", sb->s_last_mounted);
    printf("s_algo_bitmap=%u\n", sb->s_algo_bitmap);
    printf("s_prealloc_blocks=%u\n", sb->s_prealloc_blocks);
    printf("s_prealloc_dir_blocks=%u\n", sb->s_prealloc_dir_blocks);
    printf(
        "s_journal_uuid="
        "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
        sb->s_journal_uuid[0],
        sb->s_journal_uuid[1],
        sb->s_journal_uuid[2],
        sb->s_journal_uuid[3],
        sb->s_journal_uuid[4],
        sb->s_journal_uuid[5],
        sb->s_journal_uuid[6],
        sb->s_journal_uuid[7],
        sb->s_journal_uuid[8],
        sb->s_journal_uuid[9],
        sb->s_journal_uuid[10],
        sb->s_journal_uuid[11],
        sb->s_journal_uuid[12],
        sb->s_journal_uuid[13],
        sb->s_journal_uuid[14],
        sb->s_journal_uuid[15]);
    printf("s_journal_inum=%u\n", sb->s_journal_inum);
    printf("s_journal_dev=%u\n", sb->s_journal_dev);
    printf("s_last_orphan=%u\n", sb->s_last_orphan);
    printf(
        "s_hash_seed={%02X,%02X,%02X,%02X}\n",
        sb->s_hash_seed[0],
        sb->s_hash_seed[1],
        sb->s_hash_seed[2],
        sb->s_hash_seed[3]);
    printf("s_def_hash_version=%u\n", sb->s_def_hash_version);
    printf("s_default_mount_options=%u\n", sb->s_default_mount_options);
    printf("s_first_meta_bg=%u\n", sb->s_first_meta_bg);
    printf("\n");
}

static void _dump_group_desc(const ext2_group_desc_t* gd)
{
    printf("=== ext2_group_desc_t\n");
    printf("bg_block_bitmap=%u\n", gd->bg_block_bitmap);
    printf("bg_inode_bitmap=%u\n", gd->bg_inode_bitmap);
    printf("bg_inode_table=%u\n", gd->bg_inode_table);
    printf("bg_free_blocks_count=%u\n", gd->bg_free_blocks_count);
    printf("bg_free_inodes_count=%u\n", gd->bg_free_inodes_count);
    printf("bg_used_dirs_count=%u\n", gd->bg_used_dirs_count);
    printf("\n");
}

static void _dump_group_descs(
    const ext2_group_desc_t* groups,
    uint32_t group_count)
{
    const ext2_group_desc_t* p = groups;
    const ext2_group_desc_t* end = groups + group_count;

    while (p != end)
    {
        _dump_group_desc(p);
        p++;
    }
}

static void _dump_inode(const ext2_t* ext2, const ext2_inode_t* inode)
{
    uint32_t i;
    uint32_t n;
    (void)_hex_dump;
    (void)_ascii_dump;
    (void)n;
    (void)i;

    printf("=== ext2_inode_t\n");
    printf("i_mode=%u (%X)\n", inode->i_mode, inode->i_mode);
    printf("i_uid=%u\n", inode->i_uid);
    printf("i_size=%u\n", inode->i_size);
    printf("i_atime=%u\n", inode->i_atime);
    printf("i_ctime=%u\n", inode->i_ctime);
    printf("i_mtime=%u\n", inode->i_mtime);
    printf("i_dtime=%u\n", inode->i_dtime);
    printf("i_gid=%u\n", inode->i_gid);
    printf("i_links_count=%u\n", inode->i_links_count);
    printf("i_blocks=%u\n", inode->i_blocks);
    printf("i_flags=%u\n", inode->i_flags);
    printf("i_osd1=%u\n", inode->i_osd1);

    {
        printf("i_block[]={");
        n = sizeof(inode->i_block) / sizeof(inode->i_block[0]);

        for (i = 0; i < n; i++)
        {
            printf("%X", inode->i_block[i]);

            if (i + 1 != n)
                printf(", ");
        }

        printf("}\n");
    }

    printf("i_generation=%u\n", inode->i_generation);
    printf("i_file_acl=%u\n", inode->i_file_acl);
    printf("i_dir_acl=%u\n", inode->i_dir_acl);
    printf("i_faddr=%u\n", inode->i_faddr);

    {
        printf("i_osd2[]={");
        n = sizeof(inode->i_osd2) / sizeof(inode->i_osd2.buf[0]);

        for (i = 0; i < n; i++)
        {
            printf("%u", inode->i_osd2.buf[i]);

            if (i + 1 != n)
                printf(", ");
        }

        printf("}\n");
    }

    printf("\n");

    if (inode->i_block[0])
    {
        ext2_block_t block;

        if (!(ext2_read_block(ext2, inode->i_block[0], &block)))
        {
            _ascii_dump(block.data, block.size);
        }
    }
}

#if 0
static void _dump_dirent(const ext2_dirent_t* dirent)
{
    printf("=== ext2_dirent_t:\n");
    printf("inode=%u\n", dirent->inode);
    printf("rec_len=%u\n", dirent->rec_len);
    printf("name_len=%u\n", dirent->name_len);
    printf("file_type=%u\n", dirent->file_type);
    printf("name={%.*s}\n", dirent->name_len, dirent->name);
}
#endif

int ext2_dump(const ext2_t* ext2)
{
    int ret = 0;
    uint32_t grpno;

    if (!ext2)
        ERAISE(-EINVAL);

    /* Print the superblock */
    ext2_dump_super_block(&ext2->sb);

    printf("block_size=%u\n", ext2->block_size);
    printf("group_count=%u\n", ext2->group_count);

    /* Print the groups */
    _dump_group_descs(ext2->groups, ext2->group_count);

    /* Print out the bitmaps for the data blocks */
    {
        for (grpno = 0; grpno < ext2->group_count; grpno++)
        {
            ext2_block_t bitmap;

            ECHECK(ext2_read_block_bitmap(ext2, grpno, &bitmap));

            printf("=== block bitmap:\n");
            _dump_bitmap(&bitmap);
        }
    }

    /* Print the inode bitmaps */
    for (grpno = 0; grpno < ext2->group_count; grpno++)
    {
        ext2_block_t bitmap;

        ECHECK(ext2_read_inode_bitmap(ext2, grpno, &bitmap));

        printf("=== inode bitmap:\n");
        _dump_bitmap(&bitmap);
    }

    /* dump the inodes */
    {
        uint32_t nbits = 0;
        uint32_t mbits = 0;

        /* Print the inode tables */
        for (grpno = 0; grpno < ext2->group_count; grpno++)
        {
            ext2_block_t bitmap;
            uint32_t lino;

            /* Get inode bitmap for this group */
            ECHECK(ext2_read_inode_bitmap(ext2, grpno, &bitmap));

            nbits += ext2_count_bits_n(bitmap.data, bitmap.size);

            /* For each bit set in the bit map */
            for (lino = 0; lino < ext2->sb.s_inodes_per_group; lino++)
            {
                ext2_inode_t inode;
                ext2_ino_t ino;

                if (!ext2_test_bit(bitmap.data, bitmap.size, lino))
                    continue;

                mbits++;

                if ((lino + 1) < EXT2_FIRST_INO && (lino + 1) != EXT2_ROOT_INO)
                    continue;

                ino = ext2_make_ino(ext2, grpno, lino);

                ECHECK(ext2_read_inode(ext2, ino, &inode));

                printf("INODE{%u}\n", ino);
                _dump_inode(ext2, &inode);
            }
        }

        printf("nbits{%u}\n", nbits);
        printf("mbits{%u}\n", mbits);
    }

    /* dump the root inode */
    _dump_inode(ext2, &ext2->root_inode);

    ret = 0;

done:
    return ret;
}

#if 0
static void _DumpDirectoryEntries(
    const ext2_t* ext2,
    const void* data,
    uint32_t size)
{
    const uint8_t* p = (uint8_t*)data;
    const uint8_t* end = (uint8_t*)data + size;

    while (p + sizeof(ext2_dirent_t) - EXT2_PATH_MAX <= end)
    {
        uint32_t n;
        const ext2_dirent_t* ent = (const ext2_dirent_t*)p;

        /* rec_len should not be 0 */
        if (!ent->rec_len)
        {
            assert(0);
            break;
        }
                
        _dump_dirent(ent);

        n = sizeof(ext2_dirent_t) - EXT2_PATH_MAX + ent->name_len;
        n = _next_mult(n, 4);

        if (n != ent->rec_len)
        {
            uint32_t gap = ent->rec_len - n;
            uint32_t offset = ((char*)p - (char*)data) % ext2->block_size;
            uint32_t rem = ext2->block_size - offset;

            printf("gap: %u\n", gap);
            printf("offset: %u\n", offset);
            printf("remaing: %u\n", rem);
        }

        p += ent->rec_len;
    }
}
#endif
