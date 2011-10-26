/*
 * Copyright 1996-1999 Hans Reiser
 */
#include "fsck.h"
#include <stdlib.h>


reiserfs_bitmap_t bad_unfm_in_tree_once_bitmap;

//int step = 0; // 0 - find stat_data or any item ; 1 - find item ; 2 - already found


/* allocates buffer head and copy buffer content */
struct buffer_head * make_buffer (int dev, int blocknr, int size, char * data)
{
    struct buffer_head * bh;
    
    bh = getblk (dev, blocknr, size);
    if (buffer_uptodate (bh))
	return bh;
//    die ("make_buffer: uptodate buffer found");
    memcpy (bh->b_data, data, size);
    set_bit (BH_Uptodate, (char *)&bh->b_state);
    return bh;
}


int find_not_of_one_file(struct key * to_find, struct key * key)
{
    if ((to_find->k_objectid != -1) &&
        (to_find->k_objectid != key->k_objectid))
        return 1;
    if ((to_find->k_dir_id != -1) &&
        (to_find->k_dir_id != key->k_dir_id))
        return 1;
    return 0;
}


int is_item_reachable (struct item_head * ih)
{
    return ih_reachable (ih) ? 1 : 0;
}


void mark_item_unreachable (struct item_head * ih)
{
    mark_ih_unreachable (ih);

    if (is_indirect_ih (ih))
	set_free_space (ih, 0);
}


void mark_item_reachable (struct item_head * ih, struct buffer_head * bh)
{
    mark_ih_ok (ih);
    mark_buffer_dirty (bh);
}


static void stat_data_in_tree (struct buffer_head *bh,
			       struct item_head * ih)
{
#if 0
    __u32 objectid;
    
    objectid = le32_to_cpu (ih->ih_key.k_objectid);
    
    if (mark_objectid_really_used (proper_id_map (fs), objectid)) {
	stat_shared_objectid_found (fs);
	mark_objectid_really_used (shared_id_map (fs), objectid);
    }
#endif
    
    zero_nlink (ih, B_I_PITEM (bh, ih));
}


/* this just marks blocks pointed by an indirect item as used in the
   new bitmap */
static void indirect_in_tree (struct buffer_head * bh,
			      struct item_head * ih)
{
    int i;
    __u32 * unp;
    unsigned long unfm_ptr;

    unp = (__u32 *)B_I_PITEM (bh, ih);
    
    for (i = 0; i < I_UNFM_NUM (ih); i ++) {
	unfm_ptr = le32_to_cpu (unp[i]);
	if (unfm_ptr == 0)
	    continue;

	if (still_bad_unfm_ptr_1 (unfm_ptr))
	    reiserfs_panic ("mark_unformatted_used: (%lu: %k) "
			    "still has bad pointer %lu",
			    bh->b_blocknr, &ih->ih_key, unfm_ptr);
	
	mark_block_used (unfm_ptr);
    }
}


static void leaf_is_in_tree_now (struct buffer_head * bh)
{
    item_action_t actions[] = {stat_data_in_tree, indirect_in_tree, 0, 0};

    mark_block_used ((bh)->b_blocknr);

    for_every_item (bh, mark_item_unreachable, actions);

    stats(fs)->inserted_leaves ++;

    mark_buffer_dirty (bh);
}


static void insert_pointer (struct buffer_head * bh, struct path * path)
{
    struct item_head * ih;
    char * body;
    int zeros_number;
    int retval;
    struct tree_balance tb;
    
    init_tb_struct (&tb, fs, path, 0x7fff);

    /* fix_nodes & do_balance must work for internal nodes only */
    ih = 0;

    retval = fix_nodes (/*tb.transaction_handle,*/ M_INTERNAL, &tb, ih);
    if (retval != CARRY_ON)
	die ("insert_pointer: fix_nodes failed with retval == %d", retval);
    
    /* child_pos: we insert after position child_pos: this feature of the insert_child */
    /* there is special case: we insert pointer after
       (-1)-st key (before 0-th key) in the parent */
    if (PATH_LAST_POSITION (path) == 0 && path->pos_in_item == 0)
	PATH_H_B_ITEM_ORDER (path, 0) = -1;
    else {
	if (PATH_H_PPARENT (path, 0) == 0)
	    PATH_H_B_ITEM_ORDER (path, 0) = 0;
/*    PATH_H_B_ITEM_ORDER (path, 0) = PATH_H_PPARENT (path, 0) ? PATH_H_B_ITEM_ORDER (path, 0) : 0;*/
    }
    
    ih = 0;
    body = (char *)bh;
    //memmode = 0;
    zeros_number = 0;
    
    do_balance (&tb, ih, body, M_INTERNAL, zeros_number);

    leaf_is_in_tree_now (bh);
}


/* return 1 if left and right can be joined. 0 otherwise */
int balance_condition_fails (struct buffer_head * left, struct buffer_head * right)
{
    if (B_FREE_SPACE (left) >= B_CHILD_SIZE (right) -
	(are_items_mergeable (B_N_PITEM_HEAD (left, B_NR_ITEMS (left) - 1), B_N_PITEM_HEAD (right, 0), left->b_size) ? IH_SIZE : 0))
	return 1;
    return 0;
}


/* return 1 if new can be joined with last node on the path or with
   its right neighbor, 0 otherwise */
int balance_condition_2_fails (struct buffer_head * new, struct path * path)
{
    struct buffer_head * bh;
    struct key * right_dkey;
    int pos, used_space;
    
    bh = PATH_PLAST_BUFFER (path);
    

    if (balance_condition_fails (bh, new))
	/* new node can be joined with last buffer on the path */
	return 1;
    
    /* new node can not be joined with its left neighbor */
    
    right_dkey = uget_rkey (path);
    if (right_dkey == 0)
	/* there is no right neighbor */
	return 0;
    
    pos = PATH_H_POSITION (path, 1);
    if (pos == B_NR_ITEMS (bh = PATH_H_PBUFFER (path, 1))) {
	/* we have to read parent of right neighbor. For simplicity we
	   call search_by_key, which will read right neighbor as well */
	INITIALIZE_PATH(path_to_right_neighbor);
	
	if (usearch_by_key (fs, right_dkey, &path_to_right_neighbor) != ITEM_FOUND)
	    die ("get_right_neighbor_free_space: invalid right delimiting key");
	used_space =  B_CHILD_SIZE (PATH_PLAST_BUFFER (&path_to_right_neighbor));
	pathrelse (&path_to_right_neighbor);
    }
    else
	used_space = dc_size(B_N_CHILD (bh, pos + 1));
    
    if (B_FREE_SPACE (new) >= used_space -
	(are_items_mergeable (B_N_PITEM_HEAD (new, B_NR_ITEMS (new) - 1), (struct item_head *)right_dkey, new->b_size) ? IH_SIZE : 0))
	return 1;
    
    return 0;
}


static void get_max_buffer_key (struct buffer_head * bh, struct key * key)
{
    struct item_head * ih;

    ih = B_N_PITEM_HEAD (bh, B_NR_ITEMS (bh) - 1);
    copy_key (key, &(ih->ih_key));

    if (is_direntry_key (key)) {
	/* copy 3-rd and 4-th key components of the last entry */
	//set_le_key_k_offset (ih_version(ih), key, B_I_DEH (bh, ih)[I_ENTRY_COUNT (ih) - 1].deh_offset);
	//set_le_key_k_type (ih_version(ih), key, TYPE_DIRENTRY);
	set_offset (KEY_FORMAT_1, key, 
			     deh_offset (&(B_I_DEH (bh, ih)[ih_entry_count (ih) - 1])));

    } else if (!is_stat_data_key (key))
	/* get key of the last byte, which is contained in the item */
	set_offset (key_format (key), key, get_offset (key) + get_bytes_number (ih, bh->b_size) - 1);
    //set_le_key_k_offset(ih_version(ih), key,
    //		    le_key_k_offset(ih_version(ih), key) + get_bytes_number (bh, ih, 0, CHECK_FREE_BYTES) - 1 );
}


static int tree_is_empty (void)
{
  return (SB_ROOT_BLOCK (fs) == ~0) ? 1 : 0;
}


static void make_single_leaf_tree (struct buffer_head * bh)
{
    /* tree is empty, make tree root */
    set_root_block (fs->s_rs, bh->b_blocknr);
    set_tree_height (fs->s_rs, 2);
    mark_buffer_dirty (fs->s_sbh);
    leaf_is_in_tree_now (bh);
}


/* inserts pointer to leaf into tree if possible. If not, marks node as
   uninsertable in special bitmap */
static void try_to_insert_pointer_to_leaf (struct buffer_head * new_bh)
{
    INITIALIZE_PATH (path);
    struct buffer_head * bh;			/* last path buffer */
    struct key * first_bh_key, last_bh_key;	/* first and last keys of new buffer */
    struct key last_path_buffer_last_key, * right_dkey;
    int ret_value;

    if (tree_is_empty () == 1) {
	make_single_leaf_tree (new_bh);
	return;
    }


    first_bh_key = B_N_PKEY (new_bh, 0);
    
    /* try to find place in the tree for the first key of the coming node */
    ret_value = usearch_by_key (fs, first_bh_key, &path);
    if (ret_value == ITEM_FOUND)
	goto cannot_insert;

    /* get max key in the new node */
    get_max_buffer_key (new_bh, &last_bh_key);

    bh = PATH_PLAST_BUFFER (&path);
    if (comp_keys (B_N_PKEY (bh, 0), &last_bh_key) == 1/* first is greater*/) {
	/* new buffer falls before the leftmost leaf */
	if (balance_condition_fails (new_bh, bh))
	    goto cannot_insert;
	
	if (uget_lkey (&path) != 0 || PATH_LAST_POSITION (&path) != 0)
	    die ("try_to_insert_pointer_to_leaf: bad search result");
	
	path.pos_in_item = 0;
	goto insert;
    }
    
    /* get max key of buffer, that is in tree */
    get_max_buffer_key (bh, &last_path_buffer_last_key);
    if (comp_keys (&last_path_buffer_last_key, first_bh_key) != -1/* second is greater */)
	/* first key of new buffer falls in the middle of node that is in tree */
	goto cannot_insert;
    
    right_dkey = uget_rkey (&path);
    if (right_dkey && comp_keys (right_dkey, &last_bh_key) != 1 /* first is greater */)
	goto cannot_insert;
    
    if (balance_condition_2_fails (new_bh, &path))
	goto cannot_insert;
    
 insert:
    insert_pointer (new_bh, &path);
    goto out;
    
 cannot_insert:
    /* statistic */
    stats (fs)->uninsertable_leaves ++;

    mark_block_uninsertable (new_bh->b_blocknr);
    
 out:
    pathrelse (&path);
    return;
}



/* everything should be correct already in the leaf but contents of indirect
   items. So we only
   1. zero slots pointing to a leaf
   2. zero pointers to blocks which are pointed already
   3. what we should do with directory entries hashed by another hash?
   they are deleted for now
*/
static void pass1_correct_leaf (reiserfs_filsys_t s,
				struct buffer_head * bh)
{
    int i, j;
    struct item_head * ih;
    __u32 * ind_item;
    unsigned long unfm_ptr;
    int dirty = 0;


    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < B_NR_ITEMS (bh); i ++, ih ++) {
	if (is_direntry_ih (ih)) {
	    struct reiserfs_de_head * deh;
	    char * name;
	    int name_len;
	    int hash_code;

	    deh = B_I_DEH (bh, ih);
	    for (j = 0; j < ih_entry_count (ih); j ++) {
		name = name_in_entry (deh + j, j);
		name_len = name_length (ih, deh + j, j);

		if ((j == 0 && is_dot (name, name_len)) ||
		    (j == 1 && is_dot_dot (name, name_len))) {
		    continue;
		}

		hash_code = find_hash_in_use (name, name_len,
					      GET_HASH_VALUE (deh_offset (deh + j)),
					      rs_hash (fs->s_rs));
		if (hash_code != rs_hash (fs->s_rs)) {
		    fsck_log ("pass1: block %lu, %H, entry \"%.*s\" "
			      "hashed with %s whereas proper hash is %s\n",
			      bh->b_blocknr, ih, name_len, name, 
			      code2name (hash_code), code2name (rs_hash (fs->s_rs)));
		    if (ih_entry_count (ih) == 1) {
			delete_item (fs, bh, i);
			i --;
			ih --;
			break;
		    } else {
			cut_entry (fs, bh, i, j, 1);
			j --;
			deh = B_I_DEH (bh, ih);
		    }
		}
	    }
	    continue;
	}


	if (!is_indirect_ih (ih))
	    continue;

	/* correct indirect items */
	ind_item = (__u32 *)B_I_PITEM (bh, ih);

	for (j = 0; j < I_UNFM_NUM (ih); j ++, ind_item ++) {
	    unfm_ptr = le32_to_cpu (*ind_item);

	    if (!unfm_ptr)
		continue;

	    /* this corruption of indirect item had to be fixed in pass0 */
	    if (not_data_block (s, unfm_ptr) || unfm_ptr >= SB_BLOCK_COUNT (s))
		/*!was_block_used (unfm_ptr))*/
		reiserfs_panic ("pass1_correct_leaf: (%lu: %k), %d-th slot is not fixed",
				bh->b_blocknr, &ih->ih_key, j);

	    /* 1. zero slots pointing to a leaf */
	    if (is_used_leaf (unfm_ptr)) {
		dirty ++;
		*ind_item = 0;
		stats(fs)->wrong_pointers ++;
		continue;
	    }

	    /* 2. zero pointers to blocks which are pointed already */
	    if (is_bad_unformatted (unfm_ptr)) {
		/* this unformatted pointed more than once. Did we see it already? */
		if (!is_bad_unfm_in_tree_once (unfm_ptr))
		    /* keep first reference to it and mark about that in
                       special bitmap */
		    mark_bad_unfm_in_tree_once (unfm_ptr);
		else {
		    /* Yes, we have seen this pointer already, zero other pointers to it */
		    dirty ++;
		    *ind_item = 0;
		    stats(fs)->wrong_pointers ++;
		    continue;
		}
	    }		
	}
    }

    if (dirty)
	mark_buffer_dirty (bh);
}


/*######### has to die ##########*/
/* append item to end of list. Set head if it is 0. For indirect item
   set wrong unformatted node pointers to 0 */
void save_item (struct si ** head, struct buffer_head * bh, struct item_head * ih, char * item)
{
    struct si * si, * cur;

    if (is_bad_item (bh, ih, item/*, fs->s_blocksize, fs->s_dev*/)) {
	return;
    }

    if (is_indirect_ih (ih)) {
	fsck_progress ("save_item: %H (should not happen)\n", ih);
    }
    
    stats(fs)->saved_on_pass1 ++;

    si = getmem (sizeof (*si));
    si->si_dnm_data = getmem (ih_item_len(ih));
    /*si->si_blocknr = blocknr;*/
    memcpy (&(si->si_ih), ih, IH_SIZE);
    memcpy (si->si_dnm_data, item, ih_item_len(ih));

    // changed by XB
    si->last_known = NULL;

    if (*head == 0)
	*head = si;
    else {
	cur = *head;
	// changed by XB
	//    while (cur->si_next)
	//      cur = cur->si_next;

	{
	  int count = 0;
	  int speedcount = 0;
	  
	  while (cur->si_next) {
	    if (cur->last_known!=NULL) {
	      cur = cur->last_known; // speed up to the end if the chain
	      speedcount++;
	    } else {
	      cur = cur->si_next;
	      count++;
	    }
	  }
	  
	  if ((*head)!=cur) // no self referencing loop please
	    (*head)->last_known = cur;
	}
	
	cur->si_next = si;
    }
    return;
}


static void save_items (struct si ** head, struct buffer_head * bh)
{
    int i;
    struct item_head * ih;

    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < B_NR_ITEMS (bh); i ++, ih ++) {
	save_item (head, bh, ih, B_I_PITEM (bh, ih));
    }
}


struct si * remove_saved_item (struct si * si)
{
    struct si * tmp = si->si_next;
    
    freemem (si->si_dnm_data);
    freemem (si);
    return tmp;
}


/* insert_item_separately */
static void put_saved_items_into_tree_1 (struct si * si)
{
    while (si) {
	insert_item_separately (&(si->si_ih), si->si_dnm_data,
				0/*was not in tree*/);
	si = remove_saved_item (si);
    }
}


/* reads the device by set of 8 blocks, takes leaves and tries to
   insert them into tree */
void pass_1_pass_2_build_the_tree (void)
{
    struct buffer_head * bh;
    int i; 
    int what_node;
    unsigned long done = 0, total;
    struct si * saved_items = 0;

    if (fsck_log_file (fs) != stderr)
	fsck_log ("####### Pass 1 #######\n");

    bad_unfm_in_tree_once_bitmap = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));


    /* on pass0 we have found that amount of leaves */
    total = how_many_leaves_were_there ();

    fsck_progress ("\nPass1:\n");

    /* read all leaves found on the pass 0 */
    for (i = 0; i < SB_BLOCK_COUNT (fs); i ++) {
	if (!is_used_leaf (i))
	    continue;

	print_how_far (&done, total, 1, fsck_quiet (fs));

	/* at least one of nr_to_read blocks is to be checked */
	bh = bread (fs->s_dev, i, fs->s_blocksize);
	if (!bh) {
	    /* we were reading one block at time, and failed, so mark
	       block bad */
	    fsck_progress ("pass1: reading block %lu failed\n", i);
	    continue;
	}

	what_node = who_is_this (bh->b_data, fs->s_blocksize);
	if ( what_node != THE_LEAF ) {
	    fsck_progress ("build_the_tree: nothing but leaves are expected. "
			   "Block %lu - %s\n", i,
			   (what_node == THE_INTERNAL) ? "internal" : "??");
	    brelse (bh);
	    continue;
	}
	
	if (is_block_used (i))
	    /* block is in new tree already */
	    die ("build_the_tree: leaf (%lu) is in tree already\n", i);
		    
	/* fprintf (block_list, "leaf %d\n", i + j);*/
	stats(fs)->analyzed ++;

	/* the leaf may still contain indirect items with wrong
	   slots. Fix that */
	pass1_correct_leaf (fs, bh);

	if (node_item_number (bh) == 0) {
	    /* all items were deleted on pass 0 or pass 1 */
	    mark_buffer_clean (bh);
	    brelse (bh);
	    continue;
	}

	if (is_leaf_bad (bh)) {
	    /* FIXME: will die */
	    fsck_log ("pass1: (is_leaf_bad) bad leaf (%lu)\n", bh->b_blocknr);
	    
	    /* Save good items only to put them into tree at the
	       end of this pass */
	    save_items (&saved_items, bh);

	    brelse (bh);
	    continue;
	}
	
	try_to_insert_pointer_to_leaf (bh);
	brelse (bh);
    }


#if 0
    /* read all leaves found on the pass 0 */
    for (i = 0; i < SB_BLOCK_COUNT (fs); i += nr_to_read) {
	to_scan = how_many_to_scan (fs, i, nr_to_read);
	if (to_scan) {
	    print_how_far (&done, total, to_scan, fsck_quiet (fs));

	    /* at least one of nr_to_read blocks is to be checked */
	    bbh = bread (fs->s_dev, i / nr_to_read, fs->s_blocksize * nr_to_read);
	    if (bbh) {
		for (j = 0; j < nr_to_read; j ++) {
		    if (!is_used_leaf (i + j))
			continue;

		    data = bbh->b_data + j * fs->s_blocksize;

		    what_node = who_is_this (data, fs->s_blocksize);
		    if ( what_node != THE_LEAF ) {
			fsck_progress ("build_the_tree: nothing but leaves are expected. "
				       "Block %lu - %s\n", i + j,
				       (what_node == THE_INTERNAL) ? "internal" : "??");
			continue;
		    }

		    if (is_block_used (i + j))
			/* block is in new tree already */
			die ("build_the_tree: leaf (%lu) is in tree already\n",
			     i + j);
		    
		    /* fprintf (block_list, "leaf %d\n", i + j);*/

		    bh = make_buffer (fs->s_dev, i + j, fs->s_blocksize, data);
		    stats(fs)->analyzed ++;

		    /* the leaf may still contain indirect items with wrong
                       slots. Fix that */
		    pass1_correct_leaf (fs, bh);

		    if (node_item_number (bh) == 0) {
			/* all items were deleted on pass 0 or pass 1 */
			mark_buffer_clean (bh);
			brelse (bh);
			continue;
		    }

		    if (is_leaf_bad (bh)) {
			/* FIXME: will die */
			fsck_log ("pass1: (is_leaf_bad) bad leaf (%lu)\n", bh->b_blocknr);

			/* Save good items only to put them into tree at the
                           end of this pass */
			save_items (&saved_items, bh);

			brelse (bh);
			continue;
		    }
		    
		    try_to_insert_pointer_to_leaf (bh);
		    brelse (bh);
		}

		bforget (bbh);
	    } else {
		done -= to_scan;

		/* bread failed */
		if (nr_to_read != 1) {
		    /* we tryied to read bunch of blocks. Try to read them by one */
		    nr_to_read = 1;
		    i --;
		    continue;
		} else {
		    /* we were reading one block at time, and failed, so mark
                       block bad */
		    fsck_progress ("pass0: block %lu is bad, marked used\n", i);
		}
	    }
	}

	if (nr_to_read == 1 && ((i + 1) % NR_TO_READ) == 0) {
	    /* we have read NR_TO_READ blocks one at time, switch back to
               reading NR_TO_READ blocks at time */
	    i -= (NR_TO_READ - 1);
	    nr_to_read = NR_TO_READ;
	}
    }
#endif
    fsck_progress ("\n");

    /* Pass 1a (this should die) */

    /* put saved items into tree. These items were in leaves, those could not
       be inserted into tree because some indirect items point to those
       leaves. Rather than lookup for corresponding unfm pointers in the tree,
       we save items of those leaves and put them into tree separately */
    if (how_many_items_were_saved ()) {
	fsck_progress ("There were %lu saved items\nPass 1a - ",
		       how_many_items_were_saved ());
	fflush (stdout);
	put_saved_items_into_tree_1 (saved_items);
    }

    stage_report (1, fs);
    /* end of pass 1 */


    if (SB_ROOT_BLOCK(fs) == -1)
        die ("\n\nNo reiserfs metadata found");

    /* pass 2 */
    pass_2_take_bad_blocks_put_into_tree ();

    flush_buffers ();

    stage_report (2, fs);

    fsck_progress ("Tree is built. Checking it - "); fflush (stdout);
    reiserfsck_check_pass1 ();
    fsck_progress ("done\n"); fflush (stdout);

    reiserfs_delete_bitmap (bad_unfm_in_tree_once_bitmap);

}

#if 0

/* pass the S+ tree of filesystem */
void recover_internal_tree (struct super_block * s)
{
    check_internal_structure(s);
    build_the_tree();
}
#endif


void rebuild_sb (reiserfs_filsys_t fs)
{
    int version;
    struct buffer_head * bh;
    struct reiserfs_super_block * rs;
    __u32 blocks;


    if (no_reiserfs_found (fs)) {
	char * answer = 0;
	size_t n = 0;
        printf("\nwhat is version of ReiserFS you use[1-4]\n"
	       "\t(1)   3.6.x\n"
	       "\t(2) >=3.5.9\n"
	       "\t(3) < 3.5.9 converted to new format\n"
	       "\t(4) < 3.5.9\n"
	       "\t(X)   exit\n");
	getline (&answer, &n, stdin);
	version = atoi (answer);
        if (version < 1 || version > 4)
    	    die ("rebuild_sb: wrong version");

	fs->s_blocksize = 4096;
    	
        switch(version){
        case 1:
        case 2:
            bh = getblk (fs->s_dev, (REISERFS_DISK_OFFSET_IN_BYTES / fs->s_blocksize),
			 fs->s_blocksize);
            break;
        case 3:
        case 4:
            bh = getblk (fs->s_dev, (2), fs->s_blocksize);
            break;
        default:
            exit(0);
        }
        if (!bh)
            die ("rebuild_sb: can't bread");
        rs = (struct reiserfs_super_block *)bh->b_data;
        fs->s_rs = rs;
    }
    else
    {
	/* reiserfs super block is found */
        version = check_sb(fs);
        if (!user_confirmed ("\nDo you want to remake your super block\n"
			    "(say no if you use resizer)[Yes/no]: ", "Yes\n"))
	    return;
        rs = fs->s_rs;
	bh = fs->s_sbh;
    }
    
    // set block number on the device and number of bitmap blocks needed to
    // address all blocks
    blocks = (count_blocks ("", fs->s_blocksize, fs->s_dev) / 8) * 8;
    set_block_count (rs, blocks);
    //rs->s_block_count = cpu_to_le32(blocks);

    set_bmap_nr (rs, (blocks + (fs->s_blocksize * 8 - 1)) / (fs->s_blocksize * 8));
    set_journal_size(rs, JOURNAL_BLOCK_COUNT);
    
    //rs->s_bmap_nr = cpu_to_le16( blocks / (g_sb.s_blocksize * 8) +
    //      ((blocks % (g_sb.s_blocksize * 8)) ? 1 : 0) );

    switch (version){
    case 1:
	// super block v2 at 64k offset
	set_blocksize (rs, fs->s_blocksize);
	strncpy (rs->s_v1.s_magic, REISER2FS_SUPER_MAGIC_STRING,
		 strlen(REISER2FS_SUPER_MAGIC_STRING));
	set_journal_start (rs, get_journal_start_must (fs->s_blocksize));
	set_version (rs, REISERFS_VERSION_2);
	set_objectid_map_max_size (rs, (fs->s_blocksize - SB_SIZE) / sizeof(__u32) / 2 * 2);
	break;
	
    case 2:
	// super block v1 at 64k offset
	set_blocksize (rs, fs->s_blocksize);
	strncpy (rs->s_v1.s_magic, REISERFS_SUPER_MAGIC_STRING,
		 strlen(REISERFS_SUPER_MAGIC_STRING));
	set_journal_start (rs, get_journal_start_must (fs->s_blocksize));
	set_version (rs, REISERFS_VERSION_1);
	set_objectid_map_max_size (rs, (fs->s_blocksize - SB_SIZE_V1) / sizeof(__u32) / 2 * 2);
	break;

    case 3:
	// super block v2 at 8k offset
	set_blocksize (rs, fs->s_blocksize);
	strncpy (rs->s_v1.s_magic, REISER2FS_SUPER_MAGIC_STRING,
		 strlen(REISER2FS_SUPER_MAGIC_STRING));
	set_journal_start (rs, get_journal_old_start_must (rs));
	set_version (rs, REISERFS_VERSION_2);
	set_objectid_map_max_size (rs, (fs->s_blocksize - SB_SIZE) / sizeof(__u32) / 2 * 2);
	break;

    case 4:
	// super block v1 at 8k offset
	set_blocksize (rs, fs->s_blocksize);
	strncpy (rs->s_v1.s_magic, REISERFS_SUPER_MAGIC_STRING,
		 strlen(REISERFS_SUPER_MAGIC_STRING));
	set_journal_start (rs, get_journal_old_start_must (rs));
	set_version (rs, REISERFS_VERSION_1);
	set_objectid_map_max_size (rs, (fs->s_blocksize - SB_SIZE_V1) / sizeof(__u32) / 2 * 2);
	break;
    }

    print_block (stderr, fs, bh);
    if (user_confirmed ("Is this ok ? [N/Yes]: ", "Yes\n")) {
	mark_buffer_uptodate (bh, 1);
	mark_buffer_dirty (bh);
	bwrite (bh);
	fsck_progress ("\nDo not forget to run reiserfsck --rebuild-tree\n\n");
    } else
	fsck_progress ("Super block was not written\n");
    brelse (bh);
}

/*
   check_sb and rebuild-sb don't touch these fields:
   __u32 s_journal_dev;
   __u32 s_journal_trans_max ;
   __u32 s_journal_block_count ;
   __u32 s_journal_max_batch ;
   __u32 s_journal_max_commit_age ;
   __u32 s_journal_max_trans_age ;

   others are checked and set in either rebuild_sb or rebuild-tree
*/


















