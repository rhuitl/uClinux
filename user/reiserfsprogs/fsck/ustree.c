/*
 * Copyright 1996-2001 Hans Reiser
 */
#include "fsck.h"


/* key1 and key2 are pointer to deh_offset of the struct reiserfs_de_head */
int comp_dir_entries (void * key1, void * key2)
{
    __u32 off1, off2;

    off1 = le32_to_cpu (*(__u32 *)key1);
    off2 = le32_to_cpu (*(__u32 *)key2);

    if (off1 < off2)
	return -1;
    if (off1 > off2)
	return 1;
    return 0;
}


void init_tb_struct (struct tree_balance * tb, struct super_block  * s, struct path * path, int size)
{
    memset (tb, '\0', sizeof(struct tree_balance));
    tb->tb_sb = s;
    tb->tb_path = path;

    PATH_OFFSET_PBUFFER(path, ILLEGAL_PATH_ELEMENT_OFFSET) = NULL;
    PATH_OFFSET_POSITION(path, ILLEGAL_PATH_ELEMENT_OFFSET) = 0;
    tb->insert_size[0] = size;
}


struct tree_balance * cur_tb = 0;

void reiserfsck_paste_into_item (struct path * path, const char * body, int size)
{
    struct tree_balance tb;
  
    init_tb_struct (&tb, fs, path, size);
    if (fix_nodes (/*tb.transaction_handle,*/ M_PASTE, &tb, 0/*ih*/) != CARRY_ON)
	//fix_nodes(options, tree_balance, ih_to_option, body_to_option)
	
	die ("reiserfsck_paste_into_item: fix_nodes failed");
    
    do_balance (/*tb.transaction_handle,*/ &tb, 0, body, M_PASTE, 0/*zero num*/);
}


void reiserfsck_insert_item (struct path * path, struct item_head * ih, const char * body)
{
    struct tree_balance tb;
    
    init_tb_struct (&tb, fs, path, IH_SIZE + ih_item_len(ih));
    if (fix_nodes (/*tb.transaction_handle,*/ M_INSERT, &tb, ih/*, body*/) != CARRY_ON)
	die ("reiserfsck_insert_item: fix_nodes failed");
    do_balance (/*tb.transaction_handle,*/ &tb, ih, body, M_INSERT, 0/*zero num*/);
}


static void free_unformatted_nodes (struct item_head * ih, struct buffer_head * bh)
{
    __u32 * punfm = (__u32 *)B_I_PITEM (bh, ih);
    int i;

    for (i = 0; i < I_UNFM_NUM (ih); i ++, punfm ++)
	if (*punfm) {
	    struct buffer_head * to_be_forgotten;

	    to_be_forgotten = find_buffer (fs->s_dev, *punfm, fs->s_blocksize);
	    if (to_be_forgotten) {
		//atomic_inc(&to_be_forgotten->b_count);
		to_be_forgotten->b_count ++;
		bforget (to_be_forgotten);
	    }

	    reiserfs_free_block (fs, *punfm);
	}
}


void reiserfsck_delete_item (struct path * path, int temporary)
{
    struct tree_balance tb;
    struct item_head * ih = PATH_PITEM_HEAD (path);
    
    if (is_indirect_ih (ih) && !temporary)
	free_unformatted_nodes (ih, PATH_PLAST_BUFFER (path));

    init_tb_struct (&tb, fs, path, -(IH_SIZE + ih_item_len(ih)));

    if (fix_nodes (/*tb.transaction_handle,*/ M_DELETE, &tb, 0/*ih*/) != CARRY_ON)
	die ("reiserfsck_delete_item: fix_nodes failed");
    
    do_balance (/*tb.transaction_handle,*/ &tb, 0, 0, M_DELETE, 0/*zero num*/);
}


void reiserfsck_cut_from_item (struct path * path, int cut_size)
{
    struct tree_balance tb;
    struct item_head * ih;

    if (cut_size >= 0)
	die ("reiserfsck_cut_from_item: cut size == %d", cut_size);

    if (is_indirect_ih (ih = PATH_PITEM_HEAD (path))) {
	__u32 unfm_ptr = B_I_POS_UNFM_POINTER (PATH_PLAST_BUFFER (path), ih, I_UNFM_NUM (ih) - 1);
	if (unfm_ptr) {
	    struct buffer_head * to_be_forgotten;

	    to_be_forgotten = find_buffer (fs->s_dev, le32_to_cpu (unfm_ptr), fs->s_blocksize);
	    if (to_be_forgotten) {
		//atomic_inc(&to_be_forgotten->b_count);
		to_be_forgotten->b_count ++;
		bforget (to_be_forgotten);
	    }
	    reiserfs_free_block (fs, le32_to_cpu (unfm_ptr));
	}
    }


    init_tb_struct (&tb, fs, path, cut_size);

    if (fix_nodes (/*tb.transaction_handle,*/ M_CUT, &tb, 0) != CARRY_ON)
	die ("reiserfsck_cut_from_item: fix_nodes failed");

    do_balance (/*tb.transaction_handle,*/ &tb, 0, 0, M_CUT, 0/*zero num*/);
}


/* uget_lkey is utils clone of stree.c/get_lkey */
struct key * uget_lkey (struct path * path)
{
    int pos, offset = path->path_length;
    struct buffer_head * bh;
    
    if (offset < FIRST_PATH_ELEMENT_OFFSET)
	die ("uget_lkey: illegal offset in the path (%d)", offset);


    /* While not higher in path than first element. */
    while (offset-- > FIRST_PATH_ELEMENT_OFFSET) {
	if (! buffer_uptodate (PATH_OFFSET_PBUFFER (path, offset)) )
	    die ("uget_lkey: parent is not uptodate");
	
	/* Parent at the path is not in the tree now. */
	if (! B_IS_IN_TREE (bh = PATH_OFFSET_PBUFFER (path, offset)))
	    die ("uget_lkey: buffer on the path is not in tree");

	/* Check whether position in the parent is correct. */
	if ((pos = PATH_OFFSET_POSITION (path, offset)) > B_NR_ITEMS (bh))
	    die ("uget_lkey: invalid position (%d) in the path", pos);

	/* Check whether parent at the path really points to the child. */
	if (B_N_CHILD_NUM (bh, pos) != PATH_OFFSET_PBUFFER (path, offset + 1)->b_blocknr)
	    die ("uget_lkey: invalid block number (%d). Must be %d",
		 B_N_CHILD_NUM (bh, pos), PATH_OFFSET_PBUFFER (path, offset + 1)->b_blocknr);
	
	/* Return delimiting key if position in the parent is not equal to zero. */
	if (pos)
	    return B_N_PDELIM_KEY(bh, pos - 1);
    }
    
    /* there is no left delimiting key */
    return 0;
}


/* uget_rkey is utils clone of stree.c/get_rkey */
struct key * uget_rkey (struct path * path)
{
    int pos, offset = path->path_length;
    struct buffer_head * bh;

    if (offset < FIRST_PATH_ELEMENT_OFFSET)
	die ("uget_rkey: illegal offset in the path (%d)", offset);

    while (offset-- > FIRST_PATH_ELEMENT_OFFSET) {
	if (! buffer_uptodate (PATH_OFFSET_PBUFFER (path, offset)))
	    die ("uget_rkey: parent is not uptodate");

	/* Parent at the path is not in the tree now. */
	if (! B_IS_IN_TREE (bh = PATH_OFFSET_PBUFFER (path, offset)))
	    die ("uget_rkey: buffer on the path is not in tree");

	/* Check whether position in the parrent is correct. */
	if ((pos = PATH_OFFSET_POSITION (path, offset)) > B_NR_ITEMS (bh))
	    die ("uget_rkey: invalid position (%d) in the path", pos);

	/* Check whether parent at the path really points to the child. */
	if (B_N_CHILD_NUM (bh, pos) != PATH_OFFSET_PBUFFER (path, offset + 1)->b_blocknr)
	    die ("uget_rkey: invalid block number (%d). Must be %d",
		 B_N_CHILD_NUM (bh, pos), PATH_OFFSET_PBUFFER (path, offset + 1)->b_blocknr);
	
	/* Return delimiting key if position in the parent is not the last one. */
	if (pos != B_NR_ITEMS (bh))
	    return B_N_PDELIM_KEY(bh, pos);
    }
    
    /* there is no right delimiting key */
    return 0;
}


inline int ubin_search (void * key, void * base, int num, int width, __u32 *ppos, comp_function_t comp_func)
{
    __u32 rbound, lbound, j;

    lbound = 0;

    if (num == 0){
        *ppos = 0;
        return ITEM_NOT_FOUND;
    }

    rbound = num - 1;

    for (j = (rbound + lbound) / 2; lbound <= rbound; j = (rbound + lbound) / 2) {
	switch (comp_func ((void *)((char *)base + j * width), key ) ) {
	case -1:/* second is greater */
	    lbound = j + 1;
	    continue;

	case 1: /* first is greater */
	    if (j == 0){
                *ppos = lbound;
                return ITEM_NOT_FOUND;
	    }
	    rbound = j - 1;
	    continue;

	case 0:
	    *ppos = j;
	    return ITEM_FOUND;
	}
    }

    *ppos = lbound;
    return ITEM_NOT_FOUND;
}


/* this searches in tree through items */
int usearch_by_key (struct super_block * s, struct key * key, struct path * path)
{
    struct buffer_head * bh;
    unsigned long block = SB_ROOT_BLOCK (s);
    struct path_element * curr;
    int retval;

    path->path_length = ILLEGAL_PATH_ELEMENT_OFFSET;
    while (1) {
	curr = PATH_OFFSET_PELEMENT (path, ++ path->path_length);
	bh = curr->pe_buffer = bread (s->s_dev, block, s->s_blocksize);
        if (bh == 0)
            reiserfs_panic ("usearch_by_key: unable to read %lu block on device 0x%x\n",block, s->s_dev);
	retval = ubin_search (key, B_N_PKEY (bh, 0), B_NR_ITEMS (bh),
			      is_leaf_node (bh) ? IH_SIZE : KEY_SIZE, &(curr->pe_position), comp_keys);
	if (retval == ITEM_FOUND) {
	    /* key found, return if this is leaf level */
	    if (is_leaf_node (bh)) {
		path->pos_in_item = 0;
		return ITEM_FOUND;
	    }
	    curr->pe_position ++;
	} else {
	    /* key not found in the node */
	    if (is_leaf_node (bh))
		return ITEM_NOT_FOUND;
	}
	block = B_N_CHILD_NUM (bh, curr->pe_position);
    }
    die ("search_by_key: you can not get here");
    return 0;
}


/* key is key of directory entry. This searches in tree through items and in
   the found directory item as well */
int usearch_by_entry_key (struct super_block * s, struct key * key, struct path * path)
{
    struct buffer_head * bh;
    struct item_head * ih;
    struct key tmpkey;

    if (usearch_by_key (s, key, path) == ITEM_FOUND) {
	/* entry found */
        path->pos_in_item = 0;
        return POSITION_FOUND;
    }

    bh = PATH_PLAST_BUFFER (path);

    if (PATH_LAST_POSITION (path) == 0) {
        /* previous item does not exist, that means we are in leftmost leaf of
	   the tree */
        if (uget_lkey (path) != 0)
            die ("search_by_entry_key: invalid position after search_by_key");

        if (not_of_one_file (B_N_PKEY (bh, 0), key)) {
            path->pos_in_item = 0;
            return DIRECTORY_NOT_FOUND;
        }

        if (!is_direntry_ih (get_ih (path))) {
            fsck_progress ("search_by_entry_key: directory expected to have this key %K\n", key);
            return REGULAR_FILE_FOUND;
        }

	/* position for name insertion is found */
        path->pos_in_item = 0;
        return POSITION_NOT_FOUND;
    }

    /* take previous item */
    PATH_LAST_POSITION (path) --;
    ih = PATH_PITEM_HEAD (path);
    if (not_of_one_file (&(ih->ih_key), key) || !is_direntry_ih(ih)) {
        /* previous item belongs to another object or is stat data, check next
           item */

        PATH_LAST_POSITION (path) ++;
        if (PATH_LAST_POSITION (path) < B_NR_ITEMS (bh))
        {
	    /* found item is not last item of the node */
            struct item_head * next_ih = B_N_PITEM_HEAD (bh, PATH_LAST_POSITION (path));
    		
            if (not_of_one_file (&(next_ih->ih_key), key))
            {
                path->pos_in_item = 0;
                return DIRECTORY_NOT_FOUND;
            } 	
            if (!is_direntry_ih(next_ih))
            {
                /* there is an item in the tree, but it is not a directory item */
                reiserfs_warning (stderr, "search_by_entry_key: directory expected to have this key %k\n",
				  key);
                return REGULAR_FILE_FOUND;
            }
        } else {
                /* found item is last item of the node */
            struct key * next_key = uget_rkey (path);

            if (next_key == 0 || not_of_one_file (next_key, key))
            {
                /* there is not any part of such directory in the tree */
                path->pos_in_item = 0;
                return DIRECTORY_NOT_FOUND;
            }

            if (!is_direntry_key (next_key))
            {
                /* there is an item in the tree, but it is not a directory item */
                fsck_progress ("search_by_entry_key: directory expected to have this key %k\n",
			       key);
                return REGULAR_FILE_FOUND;
            }
      
            // we got right delimiting key - search for it - the entry will be
            // pasted in position 0
            copy_key (&tmpkey, next_key);
            pathrelse (path);
            if (usearch_by_key (s, &tmpkey, path) != ITEM_FOUND || PATH_LAST_POSITION (path) != 0)
                die ("search_by_entry_key: item not found by corresponding delimiting key");
        }

        /* next item is the part of this directory */
        path->pos_in_item = 0;

        return POSITION_NOT_FOUND;
    }

    /* previous item is part of desired directory */
    if (ubin_search (&(key->u.k_offset_v1.k_offset), B_I_DEH (bh, ih), ih_entry_count (ih),
		     DEH_SIZE, &(path->pos_in_item), comp_dir_entries) == ITEM_FOUND)
	return POSITION_FOUND;

    return POSITION_NOT_FOUND;
}


/* key is key of byte in the regular file. This searches in tree
   through items and in the found item as well */
int usearch_by_position (struct super_block * s, struct key * key, int version, struct path * path)
{
    struct buffer_head * bh;
    struct item_head * ih;

    if (usearch_by_key (s, key, path) == ITEM_FOUND)
    {
    	ih = PATH_PITEM_HEAD (path);

	if (!is_direct_ih(ih) && !is_indirect_ih(ih))
	    return DIRECTORY_FOUND;
	path->pos_in_item = 0;
	return POSITION_FOUND;
    }

    bh = PATH_PLAST_BUFFER (path);
    ih = PATH_PITEM_HEAD (path);


    if ( (PATH_LAST_POSITION(path) < B_NR_ITEMS (bh)) &&
         !not_of_one_file (&ih->ih_key, key) &&
         (get_offset(&ih->ih_key) == get_offset(key)) )
    {

	if (!is_direct_ih(ih) && !is_indirect_ih(ih))
	    return DIRECTORY_FOUND;
	path->pos_in_item = 0;
	
	
	return POSITION_FOUND;
    }

    if (PATH_LAST_POSITION (path) == 0) {
	/* previous item does not exist, that means we are in leftmost leaf of the tree */
	if (!not_of_one_file (B_N_PKEY (bh, 0), key)) {
	    if (!is_direct_ih(ih) && !is_indirect_ih (ih))
		return DIRECTORY_FOUND;
	    return POSITION_NOT_FOUND;
	}
	return FILE_NOT_FOUND;
    }


    /* take previous item */
    PATH_LAST_POSITION (path) --;
    ih = PATH_PITEM_HEAD (path);

    if (not_of_one_file (&ih->ih_key, key) || is_stat_data_ih(ih)) {
	struct key * next_key;

	/* previous item belongs to another object or is a stat data, check next item */
	PATH_LAST_POSITION (path) ++;
	if (PATH_LAST_POSITION (path) < B_NR_ITEMS (PATH_PLAST_BUFFER (path)))
	    /* next key is in the same node */
	    next_key = B_N_PKEY (PATH_PLAST_BUFFER (path), PATH_LAST_POSITION (path));
	else
	    next_key = uget_rkey (path);
	if (next_key == 0 || not_of_one_file (next_key, key)) {
	    /* there is no any part of such file in the tree */
	    path->pos_in_item = 0;
	    return FILE_NOT_FOUND;
	}

	if (is_direntry_key (next_key)) {
	    fsck_log ("\nusearch_by_position: looking for %k found a directory with the same key\n", next_key);
	    return DIRECTORY_FOUND;
	}
	/* next item is the part of this file */
	path->pos_in_item = 0;
	if ( get_offset(next_key) == get_offset(key) ) {
	    pathrelse(path);
	    if (usearch_by_key (s, next_key, path) != ITEM_FOUND) {
	        reiserfs_panic ("usearch_by_position: keys must be equals %k %k",
				next_key, &PATH_PITEM_HEAD (path)->ih_key);
	    }
	    return POSITION_FOUND;
	}
	
	return POSITION_NOT_FOUND;
    }

    if (is_direntry_ih(ih)) {
	return DIRECTORY_FOUND;
    }
    if (is_stat_data_ih(ih)) {
	PATH_LAST_POSITION (path) ++;
	return FILE_NOT_FOUND;
    }

    /* previous item is part of desired file */


    //if (is_key_in_item (bh,ih,key,bh->b_size)) {
    if (I_K_KEY_IN_ITEM (ih, key, bh->b_size)) {
	path->pos_in_item = get_offset (key) - get_offset (&ih->ih_key);
	if (is_indirect_ih (ih) )
	    path->pos_in_item /= bh->b_size;
	return POSITION_FOUND;
    }
    
    path->pos_in_item = is_indirect_ih (ih) ? I_UNFM_NUM (ih) : ih_item_len (ih);
    return POSITION_NOT_FOUND;
}


static unsigned long first_child (struct buffer_head * bh)
{
    return child_block_number (bh, 0);
}

#if 0
static unsigned long last_child (struct buffer_head * bh)
{
    return child_block_number (bh, node_item_number (bh));
}
#endif

static unsigned long get_child (int pos, struct buffer_head * parent)
{
    if (pos == -1)
        return -1;

    if (pos > B_NR_ITEMS (parent))
        die ("get_child: no child found, should not happen: %d of %d", pos, B_NR_ITEMS (parent));
    return child_block_number (parent, pos);

/*
    for (i = 0; i < B_NR_ITEMS (parent); i ++)
    {
	if (child_block_number (parent, i) == block)
	    return child_block_number (parent, i + 1);
    }
    die ("next_child: no child found: should not happen");
    return 0;
    */
}


static void print (int cur, int total)
{
    printf ("/%3d (of %3d)", cur, total);fflush (stdout);
}


/* erase /XXX(of XXX) */
static void erase (void)
{
    printf ("\b\b\b\b\b\b\b\b\b\b\b\b\b");
    printf ("             ");
    printf ("\b\b\b\b\b\b\b\b\b\b\b\b\b");
    fflush (stdout);
}

#if 0
void pass_through_tree2 (struct super_block * s, do_after_read_t action1,
			do_on_full_path_t action2)
{
    struct buffer_head * path[MAX_HEIGHT] = {0,};
    int total[MAX_HEIGHT] = {0,};
    int cur[MAX_HEIGHT] = {0,};
    int h = 0;
    unsigned long block = SB_ROOT_BLOCK (s);
    int del_p;

    if (block >= SB_BLOCK_COUNT (s) || not_data_block (s, block))
	return;

    while ( 1 ) {
        if (path[h])
            die ("pass_through_tree: empty slot expected");
        if (h)
            print (cur[h - 1], total[h - 1]);

        path[h] = bread (s->s_dev, block, s->s_blocksize);
        get_child (-1, path[h]);

        if (path[h] == 0)
            reiserfs_warning ("pass_through_tree: unable to read %lu block on device 0x%x\n",
			      block, s->s_dev);

        del_p = 0;
        if (path[h] && action1) {
            if (action1 (s, path, h)) {
		;
#if 0
		// something wrong with a buffer we just have read
                if (opt_fsck_mode == FSCK_FAST_REBUILD){
                    //need to change the way we are going on
		    del_p = 1;
		    if (h == 0)
			break;
                } else {
		    ;
                    //reiserfs_panic (s, "Run reiserfsck with --rebuild-tree\n");
		}
#endif
	    }
	}

        if (!path[h] || is_leaf_node (path[h]))
        {
            if (path[h] && action2) {
                if (action2 (s, path, h)) {
		    ;
#if 0
                    if (opt_fsck_mode == FSCK_FAST_REBUILD) {
			//need to change the way we are going on
                        del_p = 1;
                        if (h == 0)
                            break;
		    } else {
			;
			//reiserfs_panic (s, "Run reiserfsck with --rebuild-tree\n");
		    }
#endif
		}
	    }

            if (path[h])
                brelse (path[h]);
            if (h)
              erase ();

            while (h && (!path[h-1] || cur[h-1] == total[h-1] ))
            {
    	    	path[h] = 0;
		        h --;
		        if (path[h])
        	    	brelse (path[h]);
	        	if (h)
    		      erase ();
	        }

    	    if (h == 0) {
    	    	path[h] = 0;
	        	break;
    	    }

	        if (path[h])
	            cur[h - 1] ++;
	        if (del_p){
	            total[h-1]--;
	            del_p = 0;
	        }
            block = get_child (cur[h - 1] - 1, path[h-1]);
            path[h] = 0;
            continue;
	    }
        total[h] = B_NR_ITEMS (path[h]) + 1;
        cur[h] = 1;
        block = first_child (path[h]);
        h ++;
    }
}
#endif

void pass_through_tree (struct super_block * s, do_after_read_t action1,
			do_on_full_path_t action2)
{
    struct buffer_head * path[MAX_HEIGHT] = {0,};
    int total[MAX_HEIGHT] = {0,};
    int cur[MAX_HEIGHT] = {0,};
    int h = 0;
    unsigned long block = SB_ROOT_BLOCK (s);


    if (block >= SB_BLOCK_COUNT (s) || not_data_block (s, block)) {
	fsck_progress ("\nBad root block %lu. (--rebuild-tree did not complete)\n", block);
	return;
    }


    while ( 1 ) {
        if (path[h])
            die ("pass_through_tree: empty slot expected");
        if (h)
            print (cur[h - 1], total[h - 1]);

        path[h] = bread (s->s_dev, block, s->s_blocksize);
        if (path[h] == 0)
	    /* FIXME: handle case when read failed */
            die ("pass_through_tree: unable to read %lu block on device 0x%x\n",
		 block, s->s_dev);

        if (action1)
	    action1 (s, path, h);

        if (is_leaf_node (path[h])) {
            if (action2)
		action2 (s, path, h);

	    brelse (path[h]);
            if (h)
		erase ();

            while (h && (cur[h-1] == total[h-1])) {
    	    	path[h] = 0;
		h --;
		brelse (path[h]);
		if (h)
		    erase ();
	    }

    	    if (h == 0) {
    	    	path[h] = 0;
		break;
    	    }

            block = get_child (cur[h - 1], path[h-1]);
	    cur[h - 1] ++;
            path[h] = 0;
            continue;
	}
        total[h] = B_NR_ITEMS (path[h]) + 1;
        cur[h] = 1;
        block = first_child (path[h]);
        h ++;
    }
}
