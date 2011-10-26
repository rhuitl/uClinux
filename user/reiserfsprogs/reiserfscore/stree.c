/*
 *  Copyright 1996, 1997, 1998 Hans Reiser, see reiserfs/README for licensing and copyright details
 */

/*
 *  Written by Anatoly P. Pinchuk pap@namesys.botik.ru
 *  Programm System Institute
 *  Pereslavl-Zalessky Russia
 */

/*
 *  This file contains functions dealing with S+tree
 *
 * comp_keys
 * comp_short_keys
 * bin_search
 * get_lkey
 * get_rkey
 * key_in_buffer
 * decrement_bcount
 * decrement_counters_in_path
 * pathrelse
 * search_by_key
 * search_for_position_by_key
 * comp_items
 * prepare_for_delete_or_cut
 * calc_deleted_bytes_number
 * init_tb_struct
 * reiserfs_delete_item
 * indirect_to_direct
 * maybe_indirect_to_direct
 * reiserfs_cut_from_item
 * reiserfs_cut_dir_entry
 * reiserfs_paste_into_item
 * reiserfs_insert_item
 */
#include "includes.h"


/* Does the buffer contain a disk block which is in the tree. */
inline int B_IS_IN_TREE (struct buffer_head * p_s_bh)
{

#ifdef CONFIG_REISERFS_CHECK
  if ( node_level (p_s_bh) > MAX_HEIGHT ) {
    reiserfs_panic(0, "PAP-1010: B_IS_IN_TREE: block (%b) has too big level (%z)",
		   p_s_bh, p_s_bh);
  }
#endif

  return ( node_level (p_s_bh) != FREE_LEVEL );
}


/*
 Compare keys using REISERFS_SHORT_KEY_LEN fields.
 Returns:  -1 if key1 < key2
            0 if key1 = key2
            1 if key1 > key2
*/
int comp_short_keys (void * k1, void * k2)
{
    __u32 * p_s_key1, * p_s_key2;
    int n_key_length = REISERFS_SHORT_KEY_LEN;

    p_s_key1 = (__u32 *)k1;
    p_s_key2 = (__u32 *)k2;

    for( ; n_key_length--; ++p_s_key1, ++p_s_key2 ) {
	if ( le32_to_cpu(*p_s_key1) < le32_to_cpu(*p_s_key2) )
	    return -1;
	if ( le32_to_cpu(*p_s_key1) > le32_to_cpu(*p_s_key2) )
	    return 1;
    }

    return 0;
}


/*
 Compare keys using all 4 key fields.
 Returns:  -1 if key1 < key2
            0 if key1 = key2
            1 if key1 > key2
*/
int comp_keys (void * p1, void * p2)
{
    int retval;
    struct key * k1, * k2;
    
    k1 = p1;
    k2 = p2;

    retval = comp_short_keys (k1, k2);
    if (retval)
	return retval;

    if (get_offset (k1) < get_offset (k2))
	return -1;

    if (get_offset (k1) > get_offset (k2))
	return 1;

    /* this part is needed only when tail conversion is in progress */
    if (get_type (k1) < get_type (k2))
	return -1;

    if (get_type (k1) > get_type (k2))
	return 1;

    return 0;
}


/**************************************************************************
 *  Binary search toolkit function                                        *
 *  Search for an item in the array by the item key                       *
 *  Returns:    1 if found,  0 if not found;                              *
 *        *p_n_pos = number of the searched element if found, else the    *
 *        number of the first element that is larger than p_v_key.        *
 **************************************************************************/
/* For those not familiar with binary search: n_lbound is the leftmost item that it
 could be, n_rbound the rightmost item that it could be.  We examine the item
 halfway between n_lbound and n_rbound, and that tells us either that we can increase
 n_lbound, or decrease n_rbound, or that we have found it, or if n_lbound <= n_rbound that
 there are no possible items, and we have not found it. With each examination we
 cut the number of possible items it could be by one more than half rounded down,
 or we find it. */
inline	int bin_search (
              void    * p_v_key,    /* Key to search for.                   */
	      void    * p_v_base,   /* First item in the array.             */
	      int       p_n_num,    /* Number of items in the array.        */
	      int       p_n_width,  /* Item size in the array.
				       searched. Lest the reader be
				       confused, note that this is crafted
				       as a general function, and when it
				       is applied specifically to the array
				       of item headers in a node, p_n_width
				       is actually the item header size not
				       the item size.                      */
	      int     * p_n_pos     /* Number of the searched for element. */
            ) {
    int   n_rbound, n_lbound, n_j;

    for ( n_j = ((n_rbound = p_n_num - 1) + (n_lbound = 0))/2; n_lbound <= n_rbound; n_j = (n_rbound + n_lbound)/2 )
	switch( COMP_KEYS((struct key *)((char * )p_v_base + n_j * p_n_width), p_v_key) )  {
	case -1: n_lbound = n_j + 1; continue;
	case  1: n_rbound = n_j - 1; continue;
	case  0: *p_n_pos = n_j;     return ITEM_FOUND; /* Key found in the array.  */
	}

    /* bin_search did not find given key, it returns position of key,
     that is minimal and greater than the given one. */
    *p_n_pos = n_lbound;
    return ITEM_NOT_FOUND;
}

#ifdef CONFIG_REISERFS_CHECK
extern struct tree_balance * cur_tb;
extern struct tree_balance init_tb;
extern int init_item_pos, init_pos_in_item, init_mode;
#endif



/* Minimal possible key. It is never in the tree. */
struct key  MIN_KEY = {0, 0, {{0, 0},}};

/* Maximal possible key. It is never in the tree. */
struct key  MAX_KEY = {0xffffffff, 0xffffffff, {{0xffffffff, 0xffffffff},}};


/* Get delimiting key of the buffer by looking for it in the buffers in the
   path, starting from the bottom of the path, and going upwards.  We must
   check the path's validity at each step.  If the key is not in the path,
   there is no delimiting key in the tree (buffer is first or last buffer in
   tree), and in this case we return a special key, either MIN_KEY or
   MAX_KEY. */
inline	struct  key * get_lkey  (
    struct path         * p_s_chk_path,
    struct super_block  * p_s_sb
    ) {
    int                   n_position, n_path_offset = p_s_chk_path->path_length;
    struct buffer_head  * p_s_parent;
  
#ifdef CONFIG_REISERFS_CHECK
    if ( n_path_offset < FIRST_PATH_ELEMENT_OFFSET )
	reiserfs_panic(p_s_sb,"PAP-5010: get_lkey: illegal offset in the path");
#endif

    /* While not higher in path than first element. */
    while ( n_path_offset-- > FIRST_PATH_ELEMENT_OFFSET ) {

#ifdef CONFIG_REISERFS_CHECK
	if ( ! buffer_uptodate(PATH_OFFSET_PBUFFER(p_s_chk_path, n_path_offset)) )
	    reiserfs_panic(p_s_sb, "PAP-5020: get_lkey: parent is not uptodate");
#endif

	/* Parent at the path is not in the tree now. */
	if ( ! B_IS_IN_TREE(p_s_parent = PATH_OFFSET_PBUFFER(p_s_chk_path, n_path_offset)) )
	    return &MAX_KEY;
	/* Check whether position in the parent is correct. */
	if ( (n_position = PATH_OFFSET_POSITION(p_s_chk_path, n_path_offset)) > B_NR_ITEMS(p_s_parent) )
	    return &MAX_KEY;
	/* Check whether parent at the path really points to the child. */
	if ( B_N_CHILD_NUM(p_s_parent, n_position) !=
	     PATH_OFFSET_PBUFFER(p_s_chk_path, n_path_offset + 1)->b_blocknr )
	    return &MAX_KEY;
	/* Return delimiting key if position in the parent is not equal to zero. */
	if ( n_position )
	    return B_N_PDELIM_KEY(p_s_parent, n_position - 1);
    }
    /* Return MIN_KEY if we are in the root of the buffer tree. */
    if ( PATH_OFFSET_PBUFFER(p_s_chk_path, FIRST_PATH_ELEMENT_OFFSET)->b_blocknr ==
	 SB_ROOT_BLOCK (p_s_sb) )
	return &MIN_KEY;
    return  &MAX_KEY;
}


/* Get delimiting key of the buffer at the path and its right neighbor. */
inline	struct  key * get_rkey  (
    struct path         * p_s_chk_path,
    struct super_block  * p_s_sb
    ) {
    int                   n_position,
	n_path_offset = p_s_chk_path->path_length;
    struct buffer_head  * p_s_parent;

#ifdef CONFIG_REISERFS_CHECK
    if ( n_path_offset < FIRST_PATH_ELEMENT_OFFSET )
	reiserfs_panic(p_s_sb,"PAP-5030: get_rkey: illegal offset in the path");
#endif

    while ( n_path_offset-- > FIRST_PATH_ELEMENT_OFFSET ) {

#ifdef CONFIG_REISERFS_CHECK
	if ( ! buffer_uptodate(PATH_OFFSET_PBUFFER(p_s_chk_path, n_path_offset)) )
	    reiserfs_panic(p_s_sb, "PAP-5040: get_rkey: parent is not uptodate");
#endif

	/* Parent at the path is not in the tree now. */
	if ( ! B_IS_IN_TREE(p_s_parent = PATH_OFFSET_PBUFFER(p_s_chk_path, n_path_offset)) )
	    return &MIN_KEY;
	/* Check whether position in the parrent is correct. */
	if ( (n_position = PATH_OFFSET_POSITION(p_s_chk_path, n_path_offset)) > B_NR_ITEMS(p_s_parent) )
	    return &MIN_KEY;
	/* Check whether parent at the path really points to the child. */
	if ( B_N_CHILD_NUM(p_s_parent, n_position) !=
	     PATH_OFFSET_PBUFFER(p_s_chk_path, n_path_offset + 1)->b_blocknr )
	    return &MIN_KEY;
	/* Return delimiting key if position in the parent is not the last one. */
	if ( n_position != B_NR_ITEMS(p_s_parent) )
	    return B_N_PDELIM_KEY(p_s_parent, n_position);
    }
    /* Return MAX_KEY if we are in the root of the buffer tree. */
    if ( PATH_OFFSET_PBUFFER(p_s_chk_path, FIRST_PATH_ELEMENT_OFFSET)->b_blocknr ==
	 SB_ROOT_BLOCK (p_s_sb) )
	return &MAX_KEY;
    return  &MIN_KEY;
}


/* Check whether a key is contained in the tree rooted from a buffer at a
   path.  This works by looking at the left and right delimiting keys for the
   buffer in the last path_element in the path.  These delimiting keys are
   stored at least one level above that buffer in the tree. If the buffer is
   the first or last node in the tree order then one of the delimiting keys
   may be absent, and in this case get_lkey and get_rkey return a special key
   which is MIN_KEY or MAX_KEY. */
static  inline  int key_in_buffer (
    struct path         * p_s_chk_path, /* Path which should be checked.  */
    struct key          * p_s_key,      /* Key which should be checked.   */
    struct super_block  * p_s_sb        /* Super block pointer.           */
    ) {

#ifdef CONFIG_REISERFS_CHECK
    if ( ! p_s_key || p_s_chk_path->path_length < FIRST_PATH_ELEMENT_OFFSET ||
	 p_s_chk_path->path_length > MAX_HEIGHT )
	reiserfs_panic(p_s_sb, "PAP-5050: key_in_buffer:  pointer to the key(%p) is NULL or illegal path length(%d)",
		       p_s_key, p_s_chk_path->path_length);
  
    if ( PATH_PLAST_BUFFER(p_s_chk_path)->b_dev == NODEV )
	reiserfs_panic(p_s_sb, "PAP-5060: key_in_buffer: device must not be NODEV");
#endif

    if ( COMP_KEYS(get_lkey(p_s_chk_path, p_s_sb), p_s_key) == 1 )
	return 0;
    if ( COMP_KEYS(p_s_key, get_rkey(p_s_chk_path, p_s_sb)) != -1 )
	return 0;
    return 1;
}


/* Release all buffers in the path. */
void  pathrelse (struct path * p_s_search_path) 
{
    int n_path_offset = p_s_search_path->path_length;
    
#ifdef CONFIG_REISERFS_CHECK
    if ( n_path_offset < ILLEGAL_PATH_ELEMENT_OFFSET )
	reiserfs_panic(NULL, "PAP-5090: pathrelse: illegal path offset");
#endif
    
    while ( n_path_offset > ILLEGAL_PATH_ELEMENT_OFFSET ) 
	brelse(PATH_OFFSET_PBUFFER(p_s_search_path, n_path_offset--));

    p_s_search_path->path_length = ILLEGAL_PATH_ELEMENT_OFFSET;
}


/**************************************************************************
 * Algorithm   SearchByKey                                                *
 *             look for item in the Disk S+Tree by its key                *
 * Input:  p_s_sb   -  super block                                        *
 *         p_s_key  - pointer to the key to search                        *
 * Output: true value -  1 - found,  0 - not found                        *
 *         p_s_search_path - path from the root to the needed leaf        *
 **************************************************************************/

/* This function fills up the path from the root to the leaf as it
   descends the tree looking for the key.  It uses reiserfs_bread to
   try to find buffers in the cache given their block number.  If it
   does not find them in the cache it reads them from disk.  For each
   node search_by_key finds using reiserfs_bread it then uses
   bin_search to look through that node.  bin_search will find the
   position of the block_number of the next node if it is looking
   through an internal node.  If it is looking through a leaf node
   bin_search will find the position of the item which has key either
   equal to given key, or which is the maximal key less than the given
   key.  search_by_key returns a path that must be checked for the
   correctness of the top of the path but need not be checked for the
   correctness of the bottom of the path */
int search_by_key(
    struct super_block  * p_s_sb,         /* Super block.                           */
    struct key          * p_s_key,        /* Key to search.                         */
    struct path         * p_s_search_path,/* This structure was allocated and initialized by
					     the calling function. It is filled up by this
					     function.  */
    int                 * p_n_repeat,     /* Whether schedule occured. */
    int                   n_stop_level   /* How far down the tree to search.*/
    ) {
    dev_t                      n_dev           = p_s_sb->s_dev;
    int                         n_repeat,
	n_block_number  = SB_ROOT_BLOCK (p_s_sb),
	expected_level = SB_TREE_HEIGHT (p_s_sb),
	n_block_size    = p_s_sb->s_blocksize;
    struct buffer_head  *       p_s_bh;
    struct path_element *       p_s_last_element;
    int				n_retval;
    int 			right_neighbor_of_leaf_node;

#ifdef CONFIG_REISERFS_CHECK
    int n_repeat_counter = 0;
#endif

    /* As we add each node to a path we increase its count.  This
       means that we must be careful to release all nodes in a path
       before we either discard the path struct or re-use the path
       struct, as we do here. */
    pathrelse (p_s_search_path);

    *p_n_repeat = CARRY_ON;

    /* With each iteration of this loop we search through the items in
       the current node, and calculate the next current node(next path
       element) for the next iteration of this loop.. */
    while ( 1 ) {

#ifdef CONFIG_REISERFS_CHECK
	if ( !(++n_repeat_counter % 50000) )
	    printk ("PAP-5100: search_by_key(pid %u): there were %d searches from the tree_root lokking for key %p\n",
		    current->pid, n_repeat_counter, p_s_key);
#endif

	/* prep path to have another element added to it. */
	p_s_last_element = PATH_OFFSET_PELEMENT(p_s_search_path, ++p_s_search_path->path_length);
	expected_level --;
	n_repeat = CARRY_ON;

	/* Read the next tree node, and set the last element in the
           path to have a pointer to it. */
	if ( ! (p_s_bh = p_s_last_element->pe_buffer =
		reiserfs_bread(n_dev, n_block_number, n_block_size, &n_repeat)) ) {
	    p_s_search_path->path_length --;
	    pathrelse(p_s_search_path);
	    *p_n_repeat |= n_repeat;
	    return IO_ERROR;
	}

	*p_n_repeat |= n_repeat;

	/* It is possible that schedule occured. We must check whether
	   the key to search is still in the tree rooted from the
	   current buffer. If not then repeat search from the root. */
	if ( n_repeat != CARRY_ON && 
	     (!B_IS_IN_TREE (p_s_bh) || (! key_in_buffer(p_s_search_path, p_s_key, p_s_sb))) ) {
	    pathrelse (p_s_search_path);

	    /* Get the root block number so that we can repeat the
               search starting from the root. */
	    n_block_number  = SB_ROOT_BLOCK (p_s_sb);
	    expected_level = SB_TREE_HEIGHT (p_s_sb);
	    right_neighbor_of_leaf_node = 0;

	    /* repeat search from the root */
	    continue;
	}

#ifdef CONFIG_REISERFS_CHECK

	if ( ! key_in_buffer(p_s_search_path, p_s_key, p_s_sb) )
	    reiserfs_panic(p_s_sb, "PAP-5130: search_by_key: key is not in the buffer");
	if ( cur_tb ) {
/*	print_tb (init_mode, init_item_pos, init_pos_in_item, &init_tb, "5140");*/
	    reiserfs_panic(p_s_sb, "PAP-5140: search_by_key: schedule occurred in do_balance!");
	}

#endif

	// make sure, that the node contents look like a nod of
	// certain level
	if (!is_tree_node (p_s_bh, expected_level)) {
	    print_block (stderr, 0, p_s_bh, 3, -1, -1);
	    reiserfs_panic ("vs-5150: search_by_key: expeced level %d", expected_level);
	    pathrelse (p_s_search_path);
	    return IO_ERROR;
	}

	/* ok, we have acquired next formatted node in the tree */
	n_retval = bin_search (p_s_key, B_N_PITEM_HEAD(p_s_bh, 0), B_NR_ITEMS(p_s_bh),
			       is_leaf_node (p_s_bh) ? IH_SIZE : KEY_SIZE, &(p_s_last_element->pe_position));
	if (node_level (p_s_bh) == n_stop_level)
	    return n_retval;

	/* we are not in the stop level */
	if (n_retval == ITEM_FOUND)
	    /* item has been found, so we choose the pointer which is to the right of the found one */
	    p_s_last_element->pe_position++;
	/* if item was not found we choose the position which is to the left of the found item. This
	   requires no code, bin_search did it already.*/


	/* So we have chosen a position in the current node which is an
	   internal node.  Now we calculate child block number by position in the node. */
	n_block_number = B_N_CHILD_NUM(p_s_bh, p_s_last_element->pe_position);
    }
}


int bin_search_in_dir_item (struct item_head * ih, struct reiserfs_de_head * deh, 
			    struct key * key, int * pos_in_item)
{
    int rbound, lbound, j;

    lbound = 0;
    rbound = ih_entry_count (ih) - 1;

    for (j = (rbound + lbound) / 2; lbound <= rbound; j = (rbound + lbound) / 2) {
	if (get_offset (key) < deh_offset (deh + j)) {
	    rbound = j - 1;
	    continue;
	}
	if (get_offset (key) > deh_offset (deh + j)) {
	    lbound = j + 1;
	    continue;
	}
	/* key found */
	*pos_in_item = j;
	return POSITION_FOUND;
    }
    
    *pos_in_item = lbound;
    return POSITION_NOT_FOUND;
}
