/*
 * Copyright 1999 Hans Reiser
 */

#include "fsck.h"


//
//
//  check S+ tree of the file system 
//
// check_fs_tree stops and recommends to run fsck --rebuild-tree when:
// 1. read fails
// 2. node of wrong level found in the tree
// 3. something in the tree points to wrong block number
//      out of filesystem boundary is pointed by tree
//      to block marked as free in bitmap
//      the same block is pointed from more than one place
//      not data blocks (journal area, super block, bitmaps)
// 4. bad formatted node found
// 5. delimiting keys are incorrect
//      



/* mark every block we see in the tree in control bitmap, so, when to make
   sure, that no blocks are pointed to from more than one place we use
   additional bitmap (control_bitmap). If we see pointer to a block we set
   corresponding bit to 1. If it is set already - run fsck with --rebuild-tree */
static reiserfs_bitmap_t control_bitmap;

static int tree_scanning_failed = 0;


/* 1 if block is not marked as used in the bitmap */
static int is_block_free (reiserfs_filsys_t fs, unsigned long block)
{
    return !reiserfs_bitmap_test_bit (fsck_disk_bitmap (fs), block);
}


/* we have seen this block in the tree, mark corresponding bit in the
   control bitmap */
static void we_met_it (unsigned long block)
{
    reiserfs_bitmap_set_bit (control_bitmap, block);
}


/* have we seen this block somewhere in the tree before? */
static int did_we_meet_it (unsigned long block)
{
    return reiserfs_bitmap_test_bit (control_bitmap, block);
}


static void init_control_bitmap (reiserfs_filsys_t fs)
{
    int i;

    control_bitmap = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));
    if (!control_bitmap)
	die ("init_control_bitmap: could not create control bitmap");

    /* skipped and super block */
    for (i = 0; i <= SB_BUFFER_WITH_SB (fs)->b_blocknr; i ++)
    	we_met_it (i);

    /* bitmaps */
    for (i = 0; i < SB_BMAP_NR (fs); i ++)
        we_met_it (SB_AP_BITMAP (fs)[i]->b_blocknr);

    for (i = 0; i < rs_journal_size (fs->s_rs) + 1; i ++)
        we_met_it (i + SB_JOURNAL_BLOCK (fs));

}


#if 0
static void show_diff (int n, char * disk, char * control, int bits)
{
    int i;
    int last_diff = 0;
    int from, num;
    
    fsck_log ("bitmap %d does not match to the correct one\n", n);

    from = 0;
    num = 0;
    for (i = 0; i < bits; i ++) {
	if (test_bit (i, disk) && !test_bit (i, control)) {
	    if (last_diff == 1) {
		num ++;
		continue;
	    } else if (last_diff == 2) {
		fsck_log ("Block [%d-%d] free in disk bitmap, used in control\n", from, from + num - 1);
	    }
	    num = 1;
	    from = n * bits + i;
	    last_diff = 1;
	    continue;
	}
	if (!test_bit (i, disk) && test_bit (i, control)) {
	    if (last_diff == 2) {
		num ++;
		continue;
	    } else if (last_diff == 1) {
		fsck_log ("Block [%d-%d] used in disk bitmap, free in control\n", from, from + num - 1);
	    }
	    num = 1;
	    from = n * bits + i;
	    last_diff = 2;
	    continue;
	}
	/* the same bits */
	if (last_diff == 1)
	    fsck_log ("Block [%d-%d] used in disk bitmap, free in control\n", from, from + num - 1);
	if (last_diff == 2)
	    fsck_log ("Block [%d-%d] free in disk bitmap, used in control\n", from, from + num - 1);
	    
	num = 0;
	from = 0;
	last_diff = 0;
	continue;
    }
}
#endif


/* if we managed to complete tree scanning and if control bitmap and/or proper
   amount of free blocks mismatch with bitmap on disk and super block's
   s_free_blocks - we can fix that */
static void compare_bitmaps (reiserfs_filsys_t fs)
{
    int diff;

    if (tree_scanning_failed) {
	fsck_progress ("Could not scan whole tree. "
		       "--rebuild-tree is required\n");
	return;
    }

    fsck_progress ("Comparing bitmaps..");

    /* check free block counter */
    if (SB_FREE_BLOCKS (fs) != reiserfs_bitmap_zeros (control_bitmap)) {
	fsck_log ("free block count %lu mismatches with a correct one %lu. \n",
		  SB_FREE_BLOCKS (fs), reiserfs_bitmap_zeros (control_bitmap));
#if 0
	if (fsck_fix_fixable (fs)) {
	    set_free_blocks (fs->s_rs, reiserfs_bitmap_zeros (control_bitmap));
	    mark_buffer_dirty (fs->s_sbh);
	    mark_filesystem_dirty (fs);
	    fsck_log ("Fixed\n");
	} else {
	    fsck_log ("Can be fixed by --fix-fixable\n");
	}
#endif	
    }

    diff = reiserfs_bitmap_compare (fsck_disk_bitmap (fs), control_bitmap);
    if (diff) {
	fsck_log ("on-disk bitmap does not match to the correct one. %d bytes differ\n", diff);
#if 0
	if (fsck_fix_fixable (fs)) {
	    reiserfs_flush_bitmap (control_bitmap, fs);
	    mark_filesystem_dirty (fs);
	    fsck_log ("Fixed\n");
	} else {
	    fsck_log ("Can be fixed by --fix-fixable\n");
	}
#endif
    }

    fsck_progress ("ok\n");
    return;
}



/* is this block legal to be pointed to by some place of the tree? */
static int bad_block_number (struct super_block * s, unsigned long block)
{
    if (block >= SB_BLOCK_COUNT (s)) {
        reiserfs_warning ( stderr, "bad_block_number: block out of filesystem boundary found (%d), max (%d)\n", block, SB_BLOCK_COUNT(s));
        return 1;
    }

    if (not_data_block (s, block)) {
        reiserfs_warning ( stderr, "not data block (%lu) is used in the tree\n",
	  block);
        return 1;
    }

    if (is_block_free (s, block)) {
        fsck_log ("block %lu is not marked as used in the disk bitmap\n", block);
        return 0;
    }

    return 0;
}


static int got_already (struct super_block * s, unsigned long block)
{
    if (0/*opt_fsck_mode == FSCK_FAST_REBUILD*/){
        if (is_block_used(block)){
	    fsck_log ("block %lu is in tree already\n", block);
	    return 1;
	}
    } else {
        if (did_we_meet_it (block)) {
    	    /*fsck_log ("block %lu is in tree already\n", block);*/
    	    return 1;
    	}
        we_met_it (block);
    }
    return 0;
}


/* 1 if some of fields in the block head of bh look bad */
static int bad_block_head (struct buffer_head * bh)
{
    struct block_head * blkh;

    blkh = B_BLK_HEAD (bh);
    if (blkh_nr_item(blkh) > (bh->b_size - BLKH_SIZE) / IH_SIZE) {
	fsck_log ("block %lu has wrong blk_nr_items (%z)\n", 
		  bh->b_blocknr, bh);
	return 1;
    }
    if (blkh_free_space(blkh) > 
	bh->b_size - BLKH_SIZE - IH_SIZE * blkh_nr_item(blkh)) {
	fsck_log ("block %lu has wrong blk_free_space %z\n", 
		  bh->b_blocknr, bh);
	return 1;
    }
    return 0;
}


/* 1 if it does not look like reasonable stat data */
static int bad_stat_data (struct buffer_head * bh, struct item_head * ih)
{
    unsigned long objectid;
    int pos;

/*
    if (opt_fsck_mode == FSCK_FAST_REBUILD)
	return 0;
*/
    objectid = le32_to_cpu (ih->ih_key.k_objectid);
    if (!is_objectid_used (fs, ih->ih_key.k_objectid)) {
	/* FIXME: this could be cured right here */
	fsck_log ("\nbad_stat_data: %lu is marked free, but used by an object %k\n",
		  objectid, &ih->ih_key);
    }

    if (is_objectid_really_used (proper_id_map (fs), ih->ih_key.k_objectid, &pos)) {
	fsck_log ("\nbad_stat_data: %lu is shared by at least two files\n",
		  objectid);
	return 0;
    }
    mark_objectid_really_used (proper_id_map (fs), ih->ih_key.k_objectid);
    return 0;
}


/* it looks like we can check item length only */
static int bad_direct_item (struct buffer_head * bh, struct item_head * ih)
{
    return 0;
}


/* for each unformatted node pointer: make sure it points to data area and
   that it is not in the tree yet */
static int bad_indirect_item (reiserfs_filsys_t fs, struct buffer_head * bh,
			      struct item_head * ih)
{
    int i;
    __u32 * ind = (__u32 *)B_I_PITEM (bh, ih);

    if (ih_item_len (ih) % 4) {
	fsck_log ("bad_indirect_item: block %lu: item (%H) has bad length\n",
		  bh->b_blocknr, ih);
	return 1;
    }

    for (i = 0; i < I_UNFM_NUM (ih); i ++) {
	__u32 unfm_ptr;

	unfm_ptr = le32_to_cpu (ind [i]);
	if (!unfm_ptr)
	    continue;

	/* check unformatted node pointer and mark it used in the
           control bitmap */
	if (bad_block_number (fs, unfm_ptr)) {
	    fsck_log ("bad_indirect_item: block %lu: item %H has bad pointer %d: %lu",
		      bh->b_blocknr, ih, i, unfm_ptr);
	    if (fsck_fix_fixable (fs)) {
		fsck_log (" - fixed");
		ind [i] = 0;
		mark_buffer_dirty (bh);
	    }
	    fsck_log ("\n");
	    continue;
	}

        if (got_already (fs, unfm_ptr)) {
	    fsck_log ("bad_indirect_item: block %lu: item %H has a pointer %d "
		      "to the block %lu which is in tree already",
		      bh->b_blocknr, ih, i, unfm_ptr);
	    if (fsck_fix_fixable (fs)) {
		fsck_log (" - fixed");
		ind [i] = 0;
		mark_buffer_dirty (bh);
	    }
	    fsck_log ("\n");
            continue;
	}
    }

    /* delete this check for 3.6 */
    if (ih_free_space (ih) > fs->s_blocksize - 1)
	fsck_log ("bad_indirect_item: %H has wrong ih_free_space\n", ih);
    return 0;
}


/* FIXME: this was is_bad_directory from pass0.c */
static int bad_directory_item (struct buffer_head * bh, struct item_head * ih)
{
    int i;
    char * name;
    int namelen;
    struct reiserfs_de_head * deh = B_I_DEH (bh, ih);
    int min_entry_size = 1;/* we have no way to understand whether the
                              filesystem were created in 3.6 format or
                              converted to it. So, we assume that minimal name
                              length is 1 */
    __u16 state;


    /* make sure item looks like a directory */
    if (ih_item_len (ih) / (DEH_SIZE + min_entry_size) < ih_entry_count (ih))
	/* entry count can not be that big */
	return 1;

    if (deh_location(&(deh[ih_entry_count (ih) - 1])) != DEH_SIZE * ih_entry_count (ih))
	/* last entry should start right after array of dir entry headers */
	return 1;

    /* check name hashing */
    for (i = 0; i < ih_entry_count (ih); i ++, deh ++) {
	namelen = name_length (ih, deh, i);
	name = name_in_entry (deh, i);
	if (!is_properly_hashed (fs, name, namelen, deh_offset (deh))) {
	    return 1;
	}
    }

    deh = B_I_DEH (bh, ih);
    state = 0;
    set_bit (DEH_Visible, &state);
    /* ok, items looks like a directory */
    for (i = 0; i < ih_entry_count (ih); i ++, deh ++) {
	if ( deh->deh_state != state) { /* JDM not sure why this works, maybe
        different set_bit? */
	    fsck_log ("bad_directory_item: block %lu: item %H has entry "
		      "\"%.*s\" with wrong deh_state %o - expected %o",
		      bh->b_blocknr, ih, name_length (ih, deh, i), 
		      name_in_entry (deh, i), deh->deh_state,
                      state );
	    if (fsck_fix_fixable (fs)) {
		deh->deh_state = 0;
		mark_de_visible (deh);
		mark_buffer_dirty (bh);
		fsck_log (" - fixed");
	    }
	    fsck_log ("\n");
	}
    }

    return 0;
}


static int bad_item (struct super_block * s, struct buffer_head * bh, int i)
{
    struct item_head * ih;

    ih = B_N_PITEM_HEAD (bh, i);
    if (is_stat_data_ih (ih))
	return bad_stat_data (bh, ih);

    if (is_direct_ih (ih))
	return bad_direct_item (bh, ih);

    if (is_indirect_ih(ih))
	return bad_indirect_item (s, bh, ih);
    
    return bad_directory_item (bh, ih);
}


/* 1 if i-th and (i-1)-th items can not be neighbors in a leaf */
int bad_pair (struct super_block * s, struct buffer_head * bh, int i)
{
    struct item_head * ih;

    ih = B_N_PITEM_HEAD (bh, i);


    if (comp_keys (&((ih - 1)->ih_key), &ih->ih_key) != -1)
	return 1;

    if (is_stat_data_ih (ih))
	/* left item must be of another object */
	if (comp_short_keys (&((ih - 1)->ih_key), &ih->ih_key) != -1)
	    return 1;

    if (is_direct_ih(ih)) {
	/* left item must be indirect or stat data item of the same
	   file */
	if (not_of_one_file (&((ih - 1)->ih_key), &ih->ih_key))
	    return 1;

	if (!((is_stat_data_ih (ih - 1) && get_offset (&ih->ih_key) == 1) ||
	      (is_indirect_ih (ih - 1) &&	
	       get_offset (&(ih - 1)->ih_key) + get_bytes_number (ih-1, bh->b_size) == //get_bytes_number (bh, ih - 1, 0, CHECK_FREE_BYTES)  ==
	       get_offset (&ih->ih_key))))
	    return 1;
	
    }

    if (is_indirect_ih (ih) || is_direntry_ih (ih)) {
	/* left item must be stat data of the same object */
	if (not_of_one_file (&((ih - 1)->ih_key), &ih->ih_key))
	    return 1;
	
	if (!is_stat_data_ih (ih - 1))
	    return 1;
    }

    return 0;
}

int bad_leaf_2 (struct super_block * s, struct buffer_head * bh)
{
    int i;

    if (bad_block_head (bh))
	return 1;
    
    for (i = 0; i < B_NR_ITEMS (bh); i ++) {
	if (i && bad_pair (s, bh, i)) {
	    fsck_log ("bad_leaf_2: block %lu has wrong order of items\n", 
			      bh->b_blocknr);
	    return 1;
	}
    }
    return 0;
}


/* 1 if block head or any of items is bad */
static int bad_leaf (struct super_block * s, struct buffer_head * bh)
{
    int i;

    if (bad_block_head (bh))
	return 1;
    
    for (i = 0; i < B_NR_ITEMS (bh); i ++) {
	if (bad_item (s, bh, i)) {
	    fsck_log ("bad_leaf: block %lu has invalid item %d: %H\n",
		      bh->b_blocknr, i, B_N_PITEM_HEAD (bh, i));
	}

	if (i && bad_pair (s, bh, i)) {
	    fsck_log ("bad_leaf: block %lu has wrong order of items\n", 
		      bh->b_blocknr);
	}
    }
    return 0;
}


/* 1 if bh does not look like internal node */
static int bad_internal (struct super_block * s, struct buffer_head * bh)
{
    int i;

    for (i = 0; i <= B_NR_ITEMS (bh); i ++)
    {
        if (i != B_NR_ITEMS (bh) && i != B_NR_ITEMS (bh) - 1)
            if (comp_keys (B_N_PDELIM_KEY (bh, i), B_N_PDELIM_KEY (bh, i + 1)) != -1)
                return 1;
        if (bad_block_number(s, child_block_number(bh,i))){
            return 1;
        }
    }
    return 0;
}


/* h == 0 for root level. block head's level == 1 for leaf level  */
static inline int h_to_level (struct super_block * s, int h)
{
    return SB_TREE_HEIGHT (s) - h - 1;
}


/* bh must be formatted node. blk_level must be tree_height - h + 1 */
static int bad_node (struct super_block * s, struct buffer_head ** path,
		     int h)
{
    struct buffer_head ** pbh = &path[h];

    if (B_LEVEL (*pbh) != h_to_level (s, h)) {
       	fsck_log ("node (%lu) with wrong level (%d) found in the tree (should be %d)\n",
		  (*pbh)->b_blocknr, B_LEVEL (*pbh), h_to_level (s, h));
        return 1;
    }

    if (bad_block_number (s, (*pbh)->b_blocknr)) {
	return 1;
    }

    if (got_already (s, (*pbh)->b_blocknr))
        return 1;
    
    if (is_leaf_node (*pbh))
	return bad_leaf (s, *pbh);
    
    return bad_internal (s, *pbh);
}


/* internal node bh must point to block */
static int get_pos (struct buffer_head * bh, unsigned long block)
{
    int i;

    for (i = 0; i <= B_NR_ITEMS (bh); i ++) {
	if (child_block_number (bh, i) == block)
	    return i;
    }
    die ("get_pos: position for block %lu not found", block);
    return 0;
}


/* path[h] - leaf node */
static struct key * lkey (struct buffer_head ** path, int h)
{
    int pos;

    while (h > 0) {
       pos = get_pos (path[h - 1], path[h]->b_blocknr);
       if (pos)
           return B_N_PDELIM_KEY(path[h - 1], pos - 1);
       h --;
    }
    return 0;
}


/* path[h] - leaf node */
static struct key * rkey (struct buffer_head ** path, int h)
{
    int pos;

    while (h > 0) {
       pos = get_pos (path[h - 1], path[h]->b_blocknr);
       if (pos != B_NR_ITEMS (path[h - 1]))
           return B_N_PDELIM_KEY (path[h - 1], pos);
       h --;
    }
    return 0;
}


/* are all delimiting keys correct */
static int bad_path (struct super_block * s, struct buffer_head ** path, int h1)
{
    int h = 0;
    struct key * dk;
    
    while (path[h])
	h ++;

    h--;
    
    // path[h] is leaf
    if (h != h1)
	die ("bad_path: wrong path");

    dk = lkey (path, h);
    if (dk && comp_keys (dk, B_N_PKEY (path[h], 0)))
	// left delimiting key must be equal to the key of 0-th item in the
	// node
	return 1;
    
    dk = rkey (path, h);
    if (dk && comp_keys (dk, B_N_PKEY (path[h], node_item_number (path[h]) - 1)) != 1)
	// right delimiting key must be bigger than the key of the last item
	// in the node
	return 1;
    
    return 0;
}


/* pass the S+ tree of filesystem */
void check_fs_tree (struct super_block * s)
{
    init_control_bitmap (s);

    proper_id_map (s) = init_id_map ();

    fsck_progress ("Checking S+tree..");

    pass_through_tree (s, bad_node, bad_path);

    /* S+ tree is correct (including all objects have correct
       sequences of items) */
    fsck_progress ("ok\n");
    
    /* compare created bitmap with the original */
    compare_bitmaps (s);

    free_id_map (&proper_id_map (s));
}

#if 0

void remove_internal_pointer(struct super_block * s, struct buffer_head ** path)
{
    int h = 0;
    int pos, items;
    __u32 block;


    while (path[h])
        h ++;

    h--;
    block = path[h]->b_blocknr;
        printf("\nremove pointer to (%d) block", block);
    brelse(path[h]);
    path[h] = 0;
    h--;
    while (h>=0)
    {
        if (B_NR_ITEMS(path[h]) <= 1)
        {
            block = path[h]->b_blocknr;
            brelse(path[h]);
            path[h] = 0;
            mark_block_free(block);
            /*unmark_block_formatted(block);*/
            used_blocks++;
            h --;
            continue;
        }
        pos = get_pos (path[h], block);
        if (pos)
        {
            memmove (B_N_CHILD(path[h],pos), B_N_CHILD(path[h],pos+1),
                s->s_blocksize - BLKH_SIZE - B_NR_ITEMS(path[h])*KEY_SIZE - DC_SIZE*(pos+1));
            memmove(B_N_PDELIM_KEY(path[h],pos-1), B_N_PDELIM_KEY(path[h],pos),
                s->s_blocksize - BLKH_SIZE - (pos)*KEY_SIZE);
        }else{
            __u32 move_block = path[h]->b_blocknr;
            int move_to_pos;
            int height = h;

            while(--height >= 0)
            {
                move_to_pos = get_pos (path[height], move_block);
                if (move_to_pos == 0){
                    move_block = path[height]->b_blocknr;
                    continue;
                }
                *B_N_PDELIM_KEY(path[height], move_to_pos-1) = *B_N_PDELIM_KEY(path[h], 0);
                break;
            }

            memmove (B_N_CHILD(path[h], 0), B_N_CHILD(path[h], 1),
                s->s_blocksize - BLKH_SIZE - B_NR_ITEMS(path[h])*KEY_SIZE - DC_SIZE);
            memmove(B_N_PDELIM_KEY(path[h], 0), B_N_PDELIM_KEY(path[h], 1),
                s->s_blocksize - BLKH_SIZE - KEY_SIZE);
        }
        set_node_item_number(path[h], node_item_number(path[h]) - 1);
        mark_buffer_dirty(path[h], 1);
        break;
    }
    if (h == -1)
    {
        SB_DISK_SUPER_BLOCK(s)->s_root_block = ~0;
        SB_DISK_SUPER_BLOCK(s)->s_tree_height = ~0;
        mark_buffer_dirty(SB_BUFFER_WITH_SB(s), 1);
    }
}

void handle_buffer(struct super_block * s, struct buffer_head * bh)
{
    int i, j;
    struct item_head * ih;

    if (is_leaf_node (bh))
    {
        for (i = 0, ih = B_N_PITEM_HEAD (bh, 0); i < B_NR_ITEMS (bh); i ++, ih ++)
        {
            if (is_indirect_ih(ih))
                for (j = 0; j < I_UNFM_NUM (ih); j ++)
                    if (B_I_POS_UNFM_POINTER(bh,ih,j)){
                        /*mark_block_unformatted(le32_to_cpu(B_I_POS_UNFM_POINTER(bh,ih,j)));*/
                        mark_block_used(le32_to_cpu(B_I_POS_UNFM_POINTER(bh,ih,j)));
                        used_blocks++;
                    }
        	if (is_stat_data_ih (ih)) {
		  /*add_event (STAT_DATA_ITEMS);*/
		    if (ih_key_format(ih) == KEY_FORMAT_1)
		      ((struct stat_data_v1 *)B_I_PITEM(bh,ih))->sd_nlink = 0;
		    else
		      ((struct stat_data *)B_I_PITEM(bh,ih))->sd_nlink = 0;
		    mark_buffer_dirty(bh, 1);
        	}
        }
    }
    mark_block_used(bh->b_blocknr);
//    we_met_it(s, bh->b_blocknr);
    used_blocks++;
}
	
/* bh must be formatted node. blk_level must be tree_height - h + 1 */
static int handle_node (struct super_block * s, struct buffer_head ** path, int h)
{
    if (bad_node(s, path, h)){
       remove_internal_pointer(s, path);
       return 1;
    }
    handle_buffer(s, path[h]);
    return 0;
}

/* are all delimiting keys correct */
static int handle_path (struct super_block * s, struct buffer_head ** path, int h)
{
    if (bad_path(s, path, h)){
        remove_internal_pointer(s, path);
        return 1;
    }
    return 0;
}

//return 1 to run rebuild tree from scratch
void check_internal_structure(struct super_block * s)
{
    /* control bitmap is used to keep all blocks we should not put into tree again */
    /* used bitmap is used to keep all inserted blocks. The same as control bitmap plus unfm blocks */
//    init_control_bitmap(s);

    printf ("Checking S+tree..");

    pass_through_tree (s, handle_node, handle_path);

//    compare_bitmaps(s);
    printf ("ok\n");
}

#endif

int check_sb (struct super_block * s)
{
    int format_sb = 0;
    int problem = 0;
    struct reiserfs_super_block * rs;
    __u32 block_count;

    rs = s->s_rs;
    // in (REISERFS_DISK_OFFSET_IN_BYTES / 4096) block
    if (is_reiser2fs_magic_string (rs) &&
        SB_JOURNAL_BLOCK(s) == get_journal_start_must (rs_blocksize (rs)))
    {
	// 3.6 or >=3.5.22
	printf("\t  3.6.x format SB found\n");
        format_sb = 1;
        goto good_format;
    }

    if (is_reiserfs_magic_string (rs) &&
        SB_JOURNAL_BLOCK(s) == get_journal_start_must (rs_blocksize (rs)))
    {
	// >3.5.9(10) and <=3.5.21
        printf("\t>=3.5.9 format SB found\n");
        format_sb = 2;
        goto good_format;
    }

    // in 2 block
    if (is_reiser2fs_magic_string (rs) &&
        SB_JOURNAL_BLOCK(s) == get_journal_old_start_must (rs))
    {
	// <3.5.9(10) converted to new format
        printf("\t< 3.5.9(10) SB converted to new format found \n");
        format_sb = 3;
        goto good_format;
    }
	
    if (is_reiserfs_magic_string (rs) &&
        SB_JOURNAL_BLOCK(s) == get_journal_old_start_must (rs))
    {
	// <3.5.9(10)
        printf("\t< 3.5.9(10) format SB found\n");
        format_sb = 4;
        goto good_format;
    }
    else	
	die("check SB: wrong SB format found\n");
	
good_format:	
	
        printf("\n\t%d-%d\n", SB_BLOCK_COUNT (s), SB_FREE_BLOCKS (s));
    if (s->s_blocksize != 4096)	{
	fsck_log("check SB: specified block size (%d) is not correct must be 4096\n", s->s_blocksize);
        problem++;
    }
    
    //for 4096 blocksize only
    if ((rs_tree_height(rs) < DISK_LEAF_NODE_LEVEL) || (rs_tree_height(rs) > MAX_HEIGHT)){
	fsck_log ("check SB: wrong tree height (%d)\n", rs_tree_height(rs));
        problem++;
    }

    block_count = count_blocks ("", s->s_blocksize, s->s_dev);

    if (SB_BLOCK_COUNT(s) > block_count){
	fsck_log ("check SB: specified block number (%d) is too high\n", SB_BLOCK_COUNT(s));
        problem++;
    }

    if ((rs_root_block(rs) >= block_count) || (rs_root_block(rs) < 0)){
	fsck_log ("check SB: specified root block number (%d) is too high\n", rs_root_block(rs));
        problem++;
    }

    if (SB_FREE_BLOCKS(s) > SB_BLOCK_COUNT(s)){
	fsck_log ("check SB: specified free block number (%d) is too high\n", SB_FREE_BLOCKS(s));
        problem++;
    }		
    
    if (SB_REISERFS_STATE(s) != REISERFS_VALID_FS){
	fsck_log ("check SB: wrong (%d) state\n", SB_REISERFS_STATE(s));
        problem++;
    }		
    
    if ( SB_BMAP_NR(s) != SB_BLOCK_COUNT(s) / (s->s_blocksize * 8) +
	 ((SB_BLOCK_COUNT(s) % (s->s_blocksize * 8)) ? 1 : 0)){
	fsck_log("check SB: wrong bitmap number (%d)\n", SB_BMAP_NR(s));
        problem++;
    }		
    
    if (SB_VERSION(s) == REISERFS_VERSION_2 || SB_VERSION(s) == REISERFS_VERSION_1)
    {
        if (!(SB_VERSION(s) == REISERFS_VERSION_2 && (format_sb == 1 || format_sb == 3)) &&
            !(SB_VERSION(s) == REISERFS_VERSION_1 && (format_sb == 2 || format_sb == 4))){
	    fsck_log("check SB: wrong SB version == %d, format == %d\n", SB_VERSION(s), format_sb);
	    problem++;
        }		
    }
    else{
	fsck_log ("check SB: wrong SB version (%d)\n", SB_VERSION(s));
        problem++;
    }		

    if (SB_VERSION(s) == REISERFS_VERSION_2 &&
        (rs_hash (rs) < 1 || rs_hash (rs) > 3)) {
	/* FIXME: */
	fsck_log("check SB: wrong hash (%d)\n", rs_hash (rs));
	problem++;
    }		


    if ((SB_VERSION(s) == REISERFS_VERSION_2) ?
	(rs_objectid_map_max_size (rs) != ((s->s_blocksize - SB_SIZE) / sizeof(__u32) / 2 * 2)) :
	(rs_objectid_map_max_size (rs) != ((s->s_blocksize - SB_SIZE_V1) / sizeof(__u32) / 2 * 2))) {
	fsck_log("check SB: objectid map corrupted max_size == %d\n", rs_objectid_map_max_size (rs));
        problem++;
    }

    if (rs_objectid_map_size (rs) < 2 ||
	rs_objectid_map_size (rs) > rs_objectid_map_max_size (rs)) {
	fsck_log("check SB: objectid map corrupted cur_size == %d\n", rs_objectid_map_size (rs));
	problem++;
    }		

    if (rs_journal_size(rs) != JOURNAL_BLOCK_COUNT){
	fsck_log("check SB: specified journal size (%d) is not correct must be %d\n",
		 rs_journal_size(rs), JOURNAL_BLOCK_COUNT);
        problem++;
    }

    if (!problem) {
        fsck_progress ("\t  No problem found\n");
    } else if (fsck_log_file (fs) != stderr)
	fsck_progress ("Look for super block corruptions in the log file\n");

    return format_sb;
}


