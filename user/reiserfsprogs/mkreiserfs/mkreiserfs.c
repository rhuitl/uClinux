/*
 * Copyright 1996, 1997, 1998, 1999 Hans Reiser
 */

/* mkreiserfs is very simple. It supports only 4 and 8K blocks. It skips
   first 64k of device, and then writes the super
   block, the needed amount of bitmap blocks (this amount is calculated
   based on file system size), and root block. Bitmap policy is
   primitive: it assumes, that device does not have unreadable blocks,
   and it occupies first blocks for super, bitmap and root blocks.
   bitmap blocks are interleaved across the disk, mainly to make
   resizing faster. */

//
// FIXME: not 'not-i386' safe
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <asm/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/vfs.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <linux/major.h>
#include <sys/stat.h>
#include <linux/kdev_t.h>

#ifdef EMBED
#include <getopt.h>
#endif

#include "io.h"
#include "misc.h"
#include "reiserfs_lib.h"
#include "../version.h"


#define print_usage_and_exit() die ("Usage: %s [ -f ] [ -h tea | rupasov | r5 ]"\
				    " [ -v 1 | 2] [ -q ] device [block-count]\n\n", argv[0])


#define DEFAULT_BLOCKSIZE 4096




struct buffer_head * g_sb_bh;
struct buffer_head * g_bitmap_bh;
struct buffer_head * g_rb_bh;
struct buffer_head * g_journal_bh ;


int g_block_size = DEFAULT_BLOCKSIZE;
unsigned long int g_block_number;
int g_hash = DEFAULT_HASH;
int g_3_6_format = 1; /* new format is default */

int quiet = 0;

/* reiserfs needs at least: enough blocks for journal, 64 k at the beginning,
   one block for super block, bitmap block and root block */
static unsigned long min_block_amount (int block_size, unsigned long journal_size)
{
    unsigned long blocks;

    blocks = REISERFS_DISK_OFFSET_IN_BYTES / block_size + 
	1 + 1 + 1 + journal_size;
    if (blocks > block_size * 8)
	die ("mkreiserfs: journal size specified incorrectly");

    return blocks;
}


/* form super block (old one) */
static void make_super_block (int dev)
{
    struct reiserfs_super_block * rs;
    int sb_size = g_3_6_format ? SB_SIZE : SB_SIZE_V1;
    __u32 * oids;


    if (SB_SIZE > g_block_size)
	die ("mkreiserfs: blocksize (%d) too small", g_block_size);

    /* get buffer for super block */
    g_sb_bh = getblk (dev, REISERFS_DISK_OFFSET_IN_BYTES / g_block_size, g_block_size);

    rs = (struct reiserfs_super_block *)g_sb_bh->b_data;
    set_blocksize (rs, g_block_size);
    set_block_count (rs, g_block_number);
    set_state (rs, REISERFS_VALID_FS);
    set_tree_height (rs, 2);

    set_bmap_nr (rs, (g_block_number + (g_block_size * 8 - 1)) / (g_block_size * 8));
    set_version (rs, g_3_6_format ? REISERFS_VERSION_2 : REISERFS_VERSION_1);

    set_hash (rs, g_hash);

    // journal things
    rs->s_v1.s_journal_dev = cpu_to_le32 (0) ;
    rs->s_v1.s_orig_journal_size = cpu_to_le32 (JOURNAL_BLOCK_COUNT) ;
    rs->s_v1.s_journal_trans_max = cpu_to_le32 (0) ;
    rs->s_v1.s_journal_block_count = cpu_to_le32 (0) ;
    rs->s_v1.s_journal_max_batch = cpu_to_le32 (0) ;
    rs->s_v1.s_journal_max_commit_age = cpu_to_le32 (0) ;
    rs->s_v1.s_journal_max_trans_age = cpu_to_le32 (0) ;

    // the differences between sb V1 and sb V2 are: magic string
    memcpy (rs->s_v1.s_magic, g_3_6_format ? REISER2FS_SUPER_MAGIC_STRING : REISERFS_SUPER_MAGIC_STRING,
	    strlen (g_3_6_format ? REISER2FS_SUPER_MAGIC_STRING : REISERFS_SUPER_MAGIC_STRING));
    // start of objectid map
    oids = (__u32 *)((char *)rs + sb_size);
    
    // max size of objectid map
    rs->s_v1.s_oid_maxsize = cpu_to_le16 ((g_block_size - sb_size) / sizeof(__u32) / 2 * 2);

    oids[0] = cpu_to_le32 (1);
    oids[1] = cpu_to_le32 (REISERFS_ROOT_OBJECTID + 1);
    set_objectid_map_size (rs, 2);

    mark_buffer_dirty (g_sb_bh);
    mark_buffer_uptodate (g_sb_bh, 1);
    return;

}


void zero_journal_blocks(int dev, int start, int len) {
    int i ;
    struct buffer_head *bh ;
    unsigned long done = 0;

    printf ("Initializing journal - "); fflush (stdout);

    for (i = 0 ; i < len ; i++) {
	print_how_far (&done, len, 1, quiet);

	bh = getblk (dev, start + i, g_block_size) ;
	memset(bh->b_data, 0, g_block_size) ;
	mark_buffer_dirty(bh) ;
	mark_buffer_uptodate(bh,0) ;
	bwrite (bh);
	brelse(bh) ;
    }
    printf ("\n"); fflush (stdout);
}


/* this only sets few first bits in bitmap block. Fills not initialized fields
   of super block (root block and bitmap block numbers) */
static void make_bitmap (void)
{
    struct reiserfs_super_block * rs = (struct reiserfs_super_block *)g_sb_bh->b_data;
    int i, j;
    
    /* get buffer for bitmap block */
    g_bitmap_bh = getblk (g_sb_bh->b_dev, g_sb_bh->b_blocknr + 1, g_sb_bh->b_size);
  
    /* mark, that first 8K of device is busy */
    for (i = 0; i < REISERFS_DISK_OFFSET_IN_BYTES / g_block_size; i ++)
	set_bit (i, g_bitmap_bh->b_data);
    
    /* mark that super block is busy */
    set_bit (i++, g_bitmap_bh->b_data);

    /* mark first bitmap block as busy */
    set_bit (i ++, g_bitmap_bh->b_data);
  
    /* sb->s_journal_block = g_block_number - JOURNAL_BLOCK_COUNT ; */ /* journal goes at end of disk */
    set_journal_start (rs, i);

    /* mark journal blocks as busy BUG! we need to check to make sure journal
       will fit in the first bitmap block */
    for (j = 0 ; j < (JOURNAL_BLOCK_COUNT + 1); j++) /* the descriptor block goes after the journal */
	set_bit (i ++, g_bitmap_bh->b_data);

    /* and tree root is busy */
    set_bit (i, g_bitmap_bh->b_data);

    set_root_block (rs, i);
    set_free_blocks (rs, rs_block_count (rs) - i - 1);

    /* count bitmap blocks not resides in first s_blocksize blocks - ?? */
    set_free_blocks (rs, rs_free_blocks (rs) - (rs_bmap_nr (rs) - 1));

    mark_buffer_dirty (g_bitmap_bh);
    mark_buffer_uptodate (g_bitmap_bh, 0);

    mark_buffer_dirty (g_sb_bh);
    return;
}


/* form the root block of the tree (the block head, the item head, the
   root directory) */
static void make_root_block (void)
{
    struct reiserfs_super_block * rs = (struct reiserfs_super_block *)g_sb_bh->b_data;
    char * rb;
    struct item_head * ih;

    /* get memory for root block */
    g_rb_bh = getblk (g_sb_bh->b_dev, rs_root_block (rs), rs_blocksize (rs));
    rb = g_rb_bh->b_data;

    /* block head */
    set_leaf_node_level (g_rb_bh);
    set_node_item_number (g_rb_bh, 0);
    set_node_free_space (g_rb_bh, rs_blocksize (rs) - BLKH_SIZE);
    
    /* first item is stat data item of root directory */
    ih = (struct item_head *)(g_rb_bh->b_data + BLKH_SIZE);

    make_dir_stat_data (g_block_size, g_3_6_format ? KEY_FORMAT_2 : KEY_FORMAT_1,
			REISERFS_ROOT_PARENT_OBJECTID, REISERFS_ROOT_OBJECTID,
			ih, g_rb_bh->b_data + g_block_size - (g_3_6_format ? SD_SIZE : SD_V1_SIZE));
    set_ih_location (ih, g_block_size - ih_item_len (ih));

    // adjust block head
    set_node_item_number (g_rb_bh, node_item_number (g_rb_bh) + 1);
    set_node_free_space (g_rb_bh, node_free_space (g_rb_bh) - (IH_SIZE + ih_item_len (ih)));
  

    /* second item is root directory item, containing "." and ".." */
    ih ++;
    ih->ih_key.k_dir_id = cpu_to_le32 (REISERFS_ROOT_PARENT_OBJECTID);
    ih->ih_key.k_objectid = cpu_to_le32 (REISERFS_ROOT_OBJECTID);
    ih->ih_key.u.k_offset_v1.k_offset = cpu_to_le32 (DOT_OFFSET);
    ih->ih_key.u.k_offset_v1.k_uniqueness = cpu_to_le32 (DIRENTRY_UNIQUENESS);
    set_ih_item_len( ih, (g_3_6_format ? EMPTY_DIR_SIZE : EMPTY_DIR_SIZE_V1 ));
    set_ih_location(ih, (ih_location(ih-1) - ih_item_len(ih) ) );
    set_entry_count(ih,2);
    set_ih_key_format (ih, KEY_FORMAT_1);

    if (g_3_6_format)
	make_empty_dir_item (g_rb_bh->b_data + ih_location (ih),
			     REISERFS_ROOT_PARENT_OBJECTID,
                             REISERFS_ROOT_OBJECTID,
			     0, REISERFS_ROOT_PARENT_OBJECTID);
    else
	make_empty_dir_item_v1 (g_rb_bh->b_data + ih_location (ih),
				REISERFS_ROOT_PARENT_OBJECTID,
                                REISERFS_ROOT_OBJECTID,
				0, REISERFS_ROOT_PARENT_OBJECTID);

    // adjust block head
    set_node_item_number (g_rb_bh, node_item_number (g_rb_bh) + 1);
    set_node_free_space (g_rb_bh, node_free_space (g_rb_bh) - (IH_SIZE + ih_item_len (ih)));


    print_block (stdout, 0, g_rb_bh, 3, -1, -1);
    
    mark_buffer_dirty (g_rb_bh);
    mark_buffer_uptodate (g_rb_bh, 0);
    return;
}


/*
 *  write the super block, the bitmap blocks and the root of the tree
 */
static void write_super_and_root_blocks (void)
{
    struct reiserfs_super_block * rs = (struct reiserfs_super_block *)g_sb_bh->b_data;
    int i;

    zero_journal_blocks(g_sb_bh->b_dev, rs_journal_start (rs), JOURNAL_BLOCK_COUNT + 1) ;

    /* super block */
    bwrite (g_sb_bh);

    /* bitmap blocks */
    for (i = 0; i < rs_bmap_nr (rs); i ++) {
	if (i != 0) {
	    g_bitmap_bh->b_blocknr = i * rs_blocksize (rs) * 8;
	    memset (g_bitmap_bh->b_data, 0, g_bitmap_bh->b_size);
	    set_bit (0, g_bitmap_bh->b_data);
	}
	if (i == rs_bmap_nr (rs) - 1) {
	    int j;

	    /* fill unused part of last bitmap block with 1s */
	    if (rs_block_count (rs) % (rs_blocksize (rs) * 8))
		for (j = rs_block_count (rs) % (rs_blocksize (rs) * 8); j < rs_blocksize (rs) * 8; j ++) {
		    set_bit (j, g_bitmap_bh->b_data);
		}
	}
	/* write bitmap */
	mark_buffer_dirty (g_bitmap_bh);
	bwrite (g_bitmap_bh);
    }

    /* root block */
    bwrite (g_rb_bh);
    brelse (g_rb_bh);
    brelse (g_bitmap_bh);
    brelse (g_sb_bh);
}


static void report (char * devname)
{
    struct reiserfs_super_block * rs = (struct reiserfs_super_block *)g_sb_bh->b_data;
    unsigned int i;

    printf ("Creating reiserfs of %s format\n", g_3_6_format ? "3.6" : "3.5");
    printf ("Block size %d bytes\n", rs_blocksize (rs));
    printf ("Block count %d\n", rs_block_count (rs));
    printf ("Used blocks %d\n", rs_block_count (rs) - rs_free_blocks (rs));
    printf ("Free blocks count %d\n", rs_free_blocks (rs));
    printf ("First %ld blocks skipped\n", g_sb_bh->b_blocknr);
    printf ("Super block is in %ld\n", g_sb_bh->b_blocknr);
    printf ("Bitmap blocks (%d) are : \n\t%ld", rs_bmap_nr (rs), g_bitmap_bh->b_blocknr);
    for (i = 1; i < rs_bmap_nr (rs); i ++) {
	printf (", %d", i * rs_blocksize (rs) * 8);
    }
    printf ("\nJournal size %d (blocks %d-%d of file %s)\n",
	    JOURNAL_BLOCK_COUNT, rs_journal_start (rs), 
	    rs_journal_start (rs) + JOURNAL_BLOCK_COUNT, devname);
    printf ("Root block %u\n", rs_root_block (rs));
    printf ("Hash function \"%s\"\n", g_hash == TEA_HASH ? "tea" :
	    ((g_hash == YURA_HASH) ? "rupasov" : "r5"));
    fflush (stdout);
}


/* wipe out first 2 k of a device and both possible reiserfs super block */
static void invalidate_other_formats (int dev)
{
    struct buffer_head * bh;
    
    bh = getblk (dev, 0, 2048);
    mark_buffer_uptodate (bh, 1);
    mark_buffer_dirty (bh);
    bwrite (bh);
    brelse (bh);

    bh = getblk(dev, REISERFS_OLD_DISK_OFFSET_IN_BYTES / 1024, 1024) ;
    mark_buffer_uptodate (bh, 1);
    mark_buffer_dirty (bh);
    bwrite (bh);
    brelse (bh);

    bh = getblk(dev, REISERFS_DISK_OFFSET_IN_BYTES / 1024, 1024) ;
    mark_buffer_uptodate (bh, 1);
    mark_buffer_dirty (bh);
    bwrite (bh);
    brelse (bh);
}


static void set_hash_function (char * str)
{
    if (!strcmp (str, "tea"))
	g_hash = TEA_HASH;
    else if (!strcmp (str, "rupasov"))
	g_hash = YURA_HASH;
    else if (!strcmp (str, "r5"))
	g_hash = R5_HASH;
    else
	printf ("mkreiserfs: wrong hash type specified. Using default\n");
}


static void set_reiserfs_version (char * str)
{
    if (!strcmp (str, "1"))
	g_3_6_format = 0;
    else if (!strcmp (str, "2"))
	g_3_6_format = 1;
    else
	printf ("mkreiserfs: wrong reiserfs version specified. Using default 3.5 format\n");
}


int main (int argc, char **argv)
{
    char *tmp;
    int dev;
    int force = 0;
    struct stat st;
    char * device_name;
    int c;

    print_banner ("mkreiserfs");

    if (argc < 2)
	print_usage_and_exit ();


    while ( ( c = getopt( argc, argv, "fh:v:q" ) ) != EOF )
	switch( c )
	{
	case 'f' : /* force if file is not a block device or fs is
                      mounted. Confirm still required */
	    force = 1;
	    break;

	case 'h':
	    set_hash_function (optarg);
	    break;

	case 'v':
	    set_reiserfs_version (optarg);
	    break;

	case 'q':
	    quiet = 1;
            break;

	default :
	    print_usage_and_exit ();
	}
    device_name = argv [optind];
  

    /* get block number for file system */
    if (optind == argc - 2) {
	g_block_number = strtol (argv[optind + 1], &tmp, 0);
	if (*tmp == 0) {    /* The string is integer */
	    if (g_block_number > count_blocks (device_name, g_block_size, -1))
		die ("mkreiserfs: specified block number (%d) is too high", g_block_number);
	} else {
	    die ("mkreiserfs: bad block count : %s\n", argv[optind + 1]);
	}	
    } else 
	if (optind == argc - 1) {
	    /* number of blocks is not specified */
	    g_block_number = count_blocks (device_name, g_block_size, -1);
	    tmp = "";
	} else
	    print_usage_and_exit ();


    /*g_block_number = g_block_number / 8 * 8;*/

    if (g_block_number < min_block_amount (g_block_size, JOURNAL_BLOCK_COUNT + 1))
	die ("mkreiserfs: can not create filesystem on that small device (%lu blocks).\n"
	     "It should have at least %lu blocks",
	     g_block_number, min_block_amount (g_block_size, JOURNAL_BLOCK_COUNT + 1));

    if (is_mounted (device_name)) {
	printf ("mkreiserfs: '%s' contains a mounted file system\n", device_name);
	if (!force)
	    exit (1);
	if (!user_confirmed ("Forced to continue, but please confirm (y/n)", "y\n"))
	    exit (1);
    }

    dev = open (device_name, O_RDWR);
    if (dev == -1)
	die ("mkreiserfs: can not open '%s': %s", device_name, strerror (errno));
  
    if (fstat (dev, &st) < 0)
	die ("mkreiserfs: unable to stat %s", device_name);

    if (!S_ISBLK (st.st_mode)) {
	printf ("mkreiserfs: %s is not a block special device.\n", device_name);
	if (!force) {
	    exit (1);
	}
	if (!user_confirmed ("Forced to continue, but please confirm (y/n)", "y\n"))
	    exit (1);
    } else {
	// from e2progs-1.18/misc/mke2fs.c
	if ((MAJOR (st.st_rdev) == HD_MAJOR && MINOR (st.st_rdev)%64 == 0) ||
	    (SCSI_BLK_MAJOR (MAJOR(st.st_rdev)) && MINOR (st.st_rdev) % 16 == 0)) {
	    printf ("mkreiserfs: %s is entire device, not just one partition! Continue? (y/n) ", 
		   device_name); 
	    if (!user_confirmed ("Continue (y/n)", "y\n"))
		exit (1);
	}
    }

    /* these fill buffers (super block, first bitmap, root block) with
       reiserfs structures */
    make_super_block (dev);
    make_bitmap ();
    make_root_block ();
  
    report (device_name);

    printf ("ATTENTION: YOU SHOULD REBOOT AFTER FDISK!\n\t    ALL DATA WILL BE LOST ON '%s'! ", device_name);
    if (!user_confirmed ("(y/n)", "y\n"))
	die ("mkreiserfs: Disk was not formatted");

    invalidate_other_formats (dev);
    write_super_and_root_blocks ();

    check_and_free_buffer_mem ();

    printf ("Syncing.."); fflush (stdout);

    close(dev) ;
    sync ();
 
    printf ("\n\nReiserFS core development sponsored by SuSE Labs (suse.com)\n\n"
	    "Journaling sponsored by MP3.com.\n\n"
	    //"Item handlers sponsored by Ecila.com\n\n
	    "To learn about the programmers and ReiserFS, please go to\n"
	    "http://www.devlinux.com/namesys\n\nHave fun.\n\n"); 
    fflush (stdout);
    return 0;
}
