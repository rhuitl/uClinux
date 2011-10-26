/*
 * Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */
#include <time.h>
#include "resize.h"


static unsigned long int_node_cnt   = 0, int_moved_cnt   = 0;
static unsigned long leaf_node_cnt  = 0, leaf_moved_cnt  = 0;
static unsigned long unfm_node_cnt  = 0, unfm_moved_cnt  = 0;
static unsigned long total_node_cnt = 0;
static unsigned long total_moved_cnt = 0;

static unsigned long unused_block;
static unsigned long blocks_used;
static int block_count_mismatch = 0;

static reiserfs_bitmap_t  bmp;
static reiserfs_filsys_t fs;
static struct reiserfs_super_block * rs;

/* abnornal exit from block reallocation process */
static void quit_resizer()
{
	/* save changes to bitmap blocks */
	reiserfs_flush_bitmap (bmp, fs);
	reiserfs_close (fs);
	/* leave fs in ERROR state */
	die ("resize_reiserfs: fs shrinking was not completed successfully, run reiserfsck.\n");
}

/* block moving */
static unsigned long move_generic_block(unsigned long block, unsigned long bnd, int h)
{
    struct buffer_head * bh, * bh2;

	/* primitive fsck */
	if (block > rs_block_count(rs)) {
		fprintf(stderr, "resize_reiserfs: invalid block number (%lu) found.\n", block);
		quit_resizer();
	}
	/* progress bar, 3D style :) */
	if (opt_verbose)
	    print_how_far(&total_node_cnt, blocks_used, 1, 0);
	else
	    total_node_cnt ++;

	/* infinite loop check */
	if( total_node_cnt > blocks_used && !block_count_mismatch) {
		fputs("resize_reiserfs: warning: block count exeeded\n",stderr);
		block_count_mismatch = 1;
	}

	if (block < bnd) /* block will not be moved */
		return 0;
	
	/* move wrong block */ 
	bh = bread(fs->s_dev, block, fs->s_blocksize);

	reiserfs_bitmap_find_zero_bit(bmp, &unused_block);
	if (unused_block == 0 || unused_block >= bnd) {
		fputs ("resize_reiserfs: can\'t find free block\n", stderr);
		quit_resizer();
	}

	/* blocknr changing */
	bh2 = getblk(fs->s_dev, unused_block, fs->s_blocksize);
	memcpy(bh2->b_data, bh->b_data, bh2->b_size);
	reiserfs_bitmap_clear_bit(bmp, block);
	reiserfs_bitmap_set_bit(bmp, unused_block);

	brelse(bh);
	mark_buffer_uptodate(bh2,1);
	mark_buffer_dirty(bh2);
	bwrite(bh2);
	brelse(bh2);

	total_moved_cnt++;
	return unused_block;
}

static unsigned long move_unformatted_block(unsigned long block, unsigned long bnd, int h)
{
	unsigned long b;
	unfm_node_cnt++;
	b = move_generic_block(block, bnd, h);
	if (b)
		unfm_moved_cnt++;
	return b;		
}


/* recursive function processing all tree nodes */
static unsigned long move_formatted_block(unsigned long block, unsigned long bnd, int h)
{
	struct buffer_head * bh;
	struct item_head *ih;
	unsigned long new_blocknr = 0;
	int node_is_internal = 0;
	int i, j;
	
	bh = bread(fs->s_dev, block, fs->s_blocksize);
	
	if (is_leaf_node (bh)) {
		
		leaf_node_cnt++;
		
		for (i=0; i < B_NR_ITEMS(bh); i++) {
			ih = B_N_PITEM_HEAD(bh, i);
			if (is_indirect_ih(ih)) {
				__u32 * indirect;

				indirect = (__u32 *)B_I_PITEM (bh, ih);
				for (j = 0; j < I_UNFM_NUM(ih); j++) {
					unsigned long  unfm_block;

					if (indirect [j] == 0) /* hole */
						continue;
					unfm_block = move_unformatted_block(le32_to_cpu (indirect [j]), bnd, h + 1);
					if (unfm_block) {
						indirect [j] = cpu_to_le32 (unfm_block);
						mark_buffer_dirty(bh);
					}
				}
			}	
		}
	} else if (is_internal_node (bh)) { /* internal node */
		
		int_node_cnt++;
		node_is_internal = 1;
		
		for (i=0; i <= B_NR_ITEMS(bh); i++) {
			unsigned long moved_block;
			moved_block = move_formatted_block(B_N_CHILD_NUM(bh, i), bnd, h+1);
			if (moved_block) {
				set_child_block_number (bh, i, moved_block);
				mark_buffer_dirty(bh);
			}
		}	
	} else {
		die ("resize_reiserfs: block (%lu) has invalid format\n", block);
	}
	
	if (buffer_dirty(bh)) {
		mark_buffer_uptodate(bh,1);
		bwrite(bh);
	}
	
	brelse(bh);	
	
	new_blocknr = move_generic_block(block, bnd, h);
	if (new_blocknr) {
		if (node_is_internal)
			int_moved_cnt++;
		else
			leaf_moved_cnt++;
	}
	
	return new_blocknr;
}

int shrink_fs(reiserfs_filsys_t reiserfs, unsigned long blocks)
{
	unsigned long n_root_block;
	unsigned int bmap_nr_new;
	unsigned long int i;
	
	fs = reiserfs;
	rs = fs->s_rs;
	
	/* warn about alpha version */
	{
		int c;

		printf(
			"You are running BETA version of reiserfs shrinker.\n"
			"This version is only for testing or VERY CAREFUL use.\n"
			"Backup of you data is recommended.\n\n"
			"Do you want to continue? [y/N]:"
			);
		c = getchar();
		if (c != 'y' && c != 'Y')
			exit(1);
	}

	bmap_nr_new = (blocks - 1) / (8 * fs->s_blocksize) + 1;
	
	/* is shrinking possible ? */
	if (rs_block_count(rs) - blocks > rs_free_blocks(rs) + rs_bmap_nr(rs) - bmap_nr_new) {
	    fprintf(stderr, "resize_reiserfs: can\'t shrink fs; too many blocks already allocated\n");
	    return -1;
	}

	reiserfs_reopen(fs, O_RDWR);
	set_state (fs->s_rs, REISERFS_ERROR_FS);
	mark_buffer_uptodate(SB_BUFFER_WITH_SB(fs), 1);
	mark_buffer_dirty(SB_BUFFER_WITH_SB(fs));
	bwrite(SB_BUFFER_WITH_SB(fs));

	/* calculate number of data blocks */		
	blocks_used = 
	    SB_BLOCK_COUNT(fs)
	    - SB_FREE_BLOCKS(fs)
	    - SB_BMAP_NR(fs)
	    - SB_JOURNAL_SIZE(fs)
	    - REISERFS_DISK_OFFSET_IN_BYTES / fs->s_blocksize
	    - 2; /* superblock itself and 1 descriptor after the journal */

	bmp = reiserfs_create_bitmap(rs_block_count(rs));
	reiserfs_fetch_disk_bitmap(bmp, fs);

	unused_block = 1;

	if (opt_verbose) {
		printf("Processing the tree: ");
		fflush(stdout);
	}

	n_root_block = move_formatted_block(rs_root_block(rs), blocks, 0);
	if (n_root_block) {
		set_root_block (rs, n_root_block);
	}

	if (opt_verbose)
	    printf ("\n\nnodes processed (moved):\n"
		    "int        %lu (%lu),\n"
		    "leaves     %lu (%lu),\n" 
		    "unfm       %lu (%lu),\n"
		    "total      %lu (%lu).\n\n",
		    int_node_cnt, int_moved_cnt,
		    leaf_node_cnt, leaf_moved_cnt, 
		    unfm_node_cnt, unfm_moved_cnt,
		    (unsigned long)total_node_cnt, total_moved_cnt);

	if (block_count_mismatch) {
	    fprintf(stderr, "resize_reiserfs: data block count %lu"
		    " doesn\'t match data block count %lu from super block\n",
		    (unsigned long)total_node_cnt, blocks_used);
	}
#if 0
	printf("check for used blocks in truncated region\n");
	{
		unsigned long l;
		for (l = blocks; l < rs_block_count(rs); l++)
			if (is_block_used(bmp, l))
				printf("<%lu>", l);
		printf("\n");
	}
#endif /* 0 */

	reiserfs_free_bitmap_blocks(fs);
	
	set_free_blocks (rs, rs_free_blocks(rs) - (rs_block_count(rs) - blocks) + (rs_bmap_nr(rs) - bmap_nr_new));
	set_block_count (rs, blocks);
	set_bmap_nr (rs, bmap_nr_new);

	reiserfs_read_bitmap_blocks(fs);
	
	for (i = blocks; i < bmap_nr_new * fs->s_blocksize; i++)
		reiserfs_bitmap_set_bit(bmp, i);
#if 0
	PUT_SB_FREE_BLOCKS(s, SB_FREE_BLOCKS(s) - (SB_BLOCK_COUNT(s) - blocks) + (SB_BMAP_NR(s) - bmap_nr_new));
	PUT_SB_BLOCK_COUNT(s, blocks);
	PUT_SB_BMAP_NR(s, bmap_nr_new);
#endif
	reiserfs_flush_bitmap(bmp, fs);

	return 0;
}
