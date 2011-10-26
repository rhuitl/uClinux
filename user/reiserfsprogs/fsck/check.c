/*
 * Copyright 1996, 1997 Hans Reiser
 */

#include "fsck.h"


/* this goes through buffers checking delimiting keys
 */

struct buffer_head * g_left = 0;
struct buffer_head * g_right = 0;
struct key * g_dkey = 0;


static void check_directory_item (struct item_head * ih, struct buffer_head * bh)
{
    int i;
    struct reiserfs_de_head * deh;
    
    for (i = 0, deh = B_I_DEH (bh, ih); i < ih_entry_count (ih) - 1; i ++)
	if (deh_offset(&deh[i]) > deh_offset(&deh[i + 1]))
	    die ("check_directory_item: entries are not sorted properly");
}


static void check_items (struct buffer_head * bh)
{
    int i;
    struct item_head * ih;

    for (i = 0; i < B_NR_ITEMS (bh); i++)
    {
	ih = B_N_PITEM_HEAD (bh, i);
	
	if (is_direntry_ih (ih))
	    check_directory_item (ih, bh);
	
    }
}


static void compare_neighboring_leaves_in_pass1 (void)
{
    struct key * left = B_N_PKEY (g_left, B_NR_ITEMS (g_left) - 1);

    if (comp_keys (left, B_N_PKEY (g_right, 0)) != -1/*SECOND_GREATER*/)
	die ("compare_neighboring_leaves_in_pass1: left key is greater, that the right one");
    
    if (/*comp_keys (B_PRIGHT_DELIM_KEY (g_left), g_dkey) == FIRST_GREATER ||*/
	comp_keys (g_dkey, B_N_PKEY (g_right, 0))) {
	reiserfs_panic (0, "compare_neighboring_leaves_in_pass1: dkey %k, first key in right %k",
			g_dkey, B_N_PKEY (g_right, 0));
    }
    
    check_items (g_left);
    
    /*&&&&&&&&&&&&&&&&&&&&&&&&&&
      for (i = 0, ih = B_N_PITEM_HEAD (g_left, i); i < B_NR_ITEMS (g_left); i ++, ih ++)
      if (is_item_accessed (ih) == YES)
      die ("compare_neighboring_leaves_in_pass1: item marked as accessed in g_left");
      for (i = 0, ih = B_N_PITEM_HEAD (g_right, i); i < B_NR_ITEMS (g_right); i ++, ih ++)
      if (is_item_accessed (ih) == YES)
      die ("compare_neighboring_leaves_in_pass1: item marked as accessed in g_right");
      &&&&&&&&&&&&&&&&&&&&&&&&&&&*/
    
}


static void is_there_unaccessed_items (struct buffer_head * bh)
{
    int i;
    struct item_head * ih;
    
    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < B_NR_ITEMS (bh); i ++, ih ++) {
	if (is_objectid_used (fs, ih->ih_key.k_objectid) == 0)
	    die ("is_there_unaccessed_items: %lu is not marked as used", ih->ih_key.k_objectid);
	
	if (!is_item_reachable (ih)) {
	    die ("is_there_unaccessed_items: block %lu - unaccessed item found",
		 bh->b_blocknr);
	}
    }
}


static void compare_neighboring_leaves_after_all (void)
{
    struct item_head * left = B_N_PITEM_HEAD(g_left, B_NR_ITEMS (g_left) - 1);
    struct item_head * right = B_N_PITEM_HEAD(g_right, 0);
    /*  struct key * left = B_N_PKEY (g_left, B_NR_ITEMS (g_left) - 1);
	struct key * right = B_N_PKEY (g_right, 0);*/
    
    /*
      if (comp_keys (&left->ih_key, B_PRIGHT_DELIM_KEY (g_left)) != SECOND_GREATER)
      die ("compare_neighboring_leaves_after_all: invalid right delimiting key");
    */
    if (comp_keys (&left->ih_key, B_N_PKEY (g_right, 0)) != -1/*SECOND_GREATER*/)
	die ("compare_neighboring_leaves_after_all: left key is greater than the right one");
    
    if (//comp_le_keys (B_PRIGHT_DELIM_KEY (g_left), g_dkey) != KEYS_IDENTICAL ||
	comp_keys (g_dkey, B_N_PKEY (g_right, 0))) {
	reiserfs_panic (0, "compare_neighboring_leaves_after all: invalid delimiting keys from left to right (%k %k)",
			g_dkey, B_N_PKEY (g_right, 0));
    }
    
    if (!not_of_one_file (&left->ih_key, &right->ih_key)) {
	// items of one file: check offset correctness
	if (is_direct_ih (left) || is_indirect_ih (left))
	    //if (get_offset(&right->ih_key) != get_offset(&left->ih_key) + get_bytes_number (g_left, left /*B_NR_ITEMS (g_left) - 1*/, 0, CHECK_FREE_BYTES))
	    if (get_offset(&right->ih_key) != get_offset(&left->ih_key) + get_bytes_number (left, g_left->b_size))
		die ("compare_neighboring_leaves_after all: hole between items or items are overlapped");
    }
    is_there_unaccessed_items (g_left);
    
}


typedef	void (check_function_t)(void);


/* only directory item can be fatally bad */
static int is_leaf_bad_xx (struct buffer_head * bh)
{
    int i;
    struct item_head * ih;

    if (!is_leaf_node (bh))
	return 0;
    for (i = 0, ih = B_N_PITEM_HEAD (bh,  0); i < B_NR_ITEMS (bh); i ++, ih ++)
	if (is_bad_item (bh, ih, B_I_PITEM (bh, ih))) {
	    return 1;
	}
    return 0;
}


static void reiserfsck_check_tree (int dev, int block, int size, check_function_t comp_func)
{
    struct buffer_head * bh;
    int what_node;
    
    bh = bread (dev, block, size);
    if (bh == 0)
        reiserfs_panic("reiserfsck_check_tree: unable to read %lu block on device 0x%x\n",
                block, dev);

    if (!B_IS_IN_TREE (bh)) {
	reiserfs_panic (0, "reiserfsck_check_tree: buffer (%b %z) not in tree", bh, bh);
    }
    
    what_node = who_is_this (bh->b_data, bh->b_size);
    if (what_node != THE_LEAF && what_node != THE_INTERNAL)
	die ("Not formatted node");

    if (!is_block_used (bh->b_blocknr))
	die ("Not marked as used");

    if (is_leaf_node (bh) && is_leaf_bad_xx (bh))
	die ("Bad leaf");

    if (is_internal_node(bh) && is_internal_bad (bh))
	die ("bad internal");
    
    if (is_internal_node (bh)) {
	int i;
	struct disk_child * dc;
	
	dc = B_N_CHILD (bh, 0);
	for (i = 0; i <= B_NR_ITEMS (bh); i ++, dc ++) {
	    reiserfsck_check_tree (dev, dc_block_number(dc), size, comp_func);
	    g_dkey = B_N_PDELIM_KEY (bh, i);
	}
    } else if (is_leaf_node (bh)) {
	g_right = bh;
	if (g_left != 0 && g_dkey != 0) {
	    comp_func ();
	    brelse (g_left);
	}
	g_left = g_right;
	return;
    } else {
	reiserfs_panic ("reiserfsck_check_tree: block %lu has bad block type (%b)",
			bh->b_blocknr, bh);
    }
    brelse (bh);
}

static void reiserfsck_check_cached_tree (int dev, int block, int size)
{
    struct buffer_head * bh;
    int what_node;

    bh =  find_buffer(dev, block, size);
    if (bh == 0)
	return;
    if (!buffer_uptodate (bh)) {
	die ("reiserfsck_check_cached_tree: found notuptodate buffer");
    }

    bh->b_count ++;
    
    if (!B_IS_IN_TREE (bh)) {
	die ("reiserfsck_check_cached_tree: buffer (%b %z) not in tree", bh, bh);
    }

    what_node = who_is_this (bh->b_data, bh->b_size);
    if ((what_node != THE_LEAF && what_node != THE_INTERNAL) ||
	!is_block_used (bh->b_blocknr) ||
	(is_leaf_node (bh) && is_leaf_bad (bh)) ||
	(is_internal_node(bh) && is_internal_bad (bh)))
	die ("reiserfsck_check_cached_tree: bad node in the tree");
    if (is_internal_node (bh)) {
	int i;
	struct disk_child * dc;
	
	dc = B_N_CHILD (bh, 0);
	for (i = 0; i <= B_NR_ITEMS (bh); i ++, dc ++) {
	    reiserfsck_check_cached_tree (dev, dc_block_number(dc), size);
	    g_dkey = B_N_PDELIM_KEY (bh, i);
	}
    } else if (is_leaf_node (bh)) {
	brelse (bh);
	return;
    } else {
	reiserfs_panic ("reiserfsck_check_cached_tree: block %lu has bad block type (%b)",
			bh->b_blocknr, bh);
    }
    brelse (bh);
}


void reiserfsck_tree_check (check_function_t how_to_compare_neighbors)
{
    g_left = 0;
    g_dkey = 0;
    reiserfsck_check_tree (fs->s_dev, SB_ROOT_BLOCK(fs), fs->s_blocksize, how_to_compare_neighbors);
    brelse (g_right);
}


void reiserfsck_check_pass1 ()
{
    /*  if (opt_check == 1)*/
    reiserfsck_tree_check (compare_neighboring_leaves_in_pass1);
}

void check_cached_tree ()
{
    reiserfsck_check_cached_tree (fs->s_dev, SB_ROOT_BLOCK (fs), fs->s_blocksize);
}

void reiserfsck_check_after_all ()
{
    reiserfsck_tree_check (compare_neighboring_leaves_after_all);
}

#if 0
static int is_bad_sd (struct item_head * ih, char * item)
{
    struct stat_data * sd = (struct stat_data *)item;

    if (!S_ISDIR (sd->sd_mode) && !S_ISREG(sd->sd_mode) &&
	!S_ISCHR (sd->sd_mode) && !S_ISBLK(sd->sd_mode) &&
	!S_ISLNK (sd->sd_mode) && !S_ISFIFO(sd->sd_mode) &&
	!S_ISSOCK(sd->sd_mode)) {
	fsck_log ("file %k unexpected mode encountered 0%o\n", &ih->ih_key, sd->sd_mode);
    }
    return 0;
}
#endif



#include <sys/ioctl.h>
#include <sys/mount.h>


int blocks_on_device (int dev, int blocksize)
{
    int size;

    if (ioctl (dev, BLKGETSIZE, &size) >= 0) {
	return  size / (blocksize / 512);
    }
    if (ioctl (dev, BLKGETSIZE, &size) >= 0) {
	return  size / (blocksize / 512);
    } else {
	struct stat stat_buf;
	memset(&stat_buf, '\0', sizeof(struct stat));
	if(fstat(dev, &stat_buf) >= 0) {
	    return stat_buf.st_size / (blocksize / 512);
	} else {
	    die ("can not calculate device size\n");
	}
    }
    return 0;
}


int is_internal_bad (struct buffer_head * bh)
{
    struct key * key;

    int i;
  
    if (!is_internal_node(bh))
	return 0;
    for (i = 0; i < B_NR_ITEMS (bh); i ++) {
	key = B_N_PDELIM_KEY (bh, i);
	if (//key->k_dir_id >= key->k_objectid ||
	    le32_to_cpu(key->u.k_offset_v1.k_uniqueness) != V1_DIRENTRY_UNIQUENESS &&
            le32_to_cpu(key->u.k_offset_v1.k_uniqueness) != V1_DIRECT_UNIQUENESS &&
	    le32_to_cpu(key->u.k_offset_v1.k_uniqueness) != V1_INDIRECT_UNIQUENESS &&
            le32_to_cpu(key->u.k_offset_v1.k_uniqueness) != V1_SD_UNIQUENESS &&
	    offset_v2_k_type( &(key->u.k_offset_v2) ) != TYPE_DIRENTRY &&
            offset_v2_k_type( &(key->u.k_offset_v2) ) != TYPE_DIRECT &&
	    offset_v2_k_type( &(key->u.k_offset_v2) ) != TYPE_INDIRECT &&
            offset_v2_k_type( &(key->u.k_offset_v2) ) != TYPE_STAT_DATA //&&
	    //	key->u.k_offset_v1.k_uniqueness != V1_ANY_UNIQUENESS && key->u.k_offset_v2.k_type != TYPE_ANY	
	    )
	    return 1;
    }
    return 0;
}







