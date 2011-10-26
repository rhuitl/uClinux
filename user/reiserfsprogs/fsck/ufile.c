/*
 * Copyright 1996, 1997, 1998 Hans Reiser
 */
#include "fsck.h"




static int do_items_have_the_same_type (struct item_head * ih, struct key * key)
{
    return (get_type (&ih->ih_key) == get_type (key)) ? 1 : 0;
}

static int are_items_in_the_same_node (struct path * path)
{
  return (PATH_LAST_POSITION (path) < B_NR_ITEMS (PATH_PLAST_BUFFER (path)) - 1) ? 1 : 0;
}


/* FIXME: there is get_next_key in pass4.c */
static struct key * get_next_key_2 (struct path * path)
{
    if (PATH_LAST_POSITION (path) < B_NR_ITEMS (get_bh (path)) - 1)
	return B_N_PKEY (get_bh (path), PATH_LAST_POSITION (path) + 1);
    return uget_rkey (path);
}


int do_make_tails ()
{
    return 1;/*SB_MAKE_TAIL_FLAG (&g_sb) == MAKE_TAILS ? YES : NO;*/
}


static void cut_last_unfm_pointer (struct path * path, struct item_head * ih)
{
    set_free_space(ih, 0);
    if (I_UNFM_NUM (ih) == 1)
	reiserfsck_delete_item (path, 0);
    else
	reiserfsck_cut_from_item (path, -UNFM_P_SIZE);
}


// we use this to convert symlinks back to direct items if they were
// direct2indirect converted on tree building
static unsigned long indirect_to_direct (struct path * path, __u64 *symlink_size)
{
    struct buffer_head * bh = PATH_PLAST_BUFFER (path);
    struct item_head * ih = PATH_PITEM_HEAD (path);
    unsigned long unfm_ptr;
    struct buffer_head * unfm_bh = 0;
    struct item_head ins_ih;
    char * buf;
    int len;
    __u32 * indirect;
    char bad_link[] = "broken_link";

/*    add_event (INDIRECT_TO_DIRECT);*/


    /* direct item to insert */
    ins_ih.ih_formats.ih_format.key_format = ih->ih_formats.ih_format.key_format; /* both le */
    ins_ih.ih_key.k_dir_id = ih->ih_key.k_dir_id;
    ins_ih.ih_key.k_objectid = ih->ih_key.k_objectid;
    set_type_and_offset (ih_key_format (ih), &ins_ih.ih_key,
			 get_offset (&ih->ih_key) + (I_UNFM_NUM (ih) - 1) * bh->b_size, TYPE_DIRECT);

    // we do not know what length this item should be
    indirect = get_item (path);
    unfm_ptr = le32_to_cpu (indirect [I_UNFM_NUM (ih) - 1]);
    if (unfm_ptr && (unfm_bh = bread (bh->b_dev, unfm_ptr, bh->b_size))) {
	buf = unfm_bh->b_data;
	// get length of direct item
	for (len = 0; buf[len] && len < bh->b_size; len ++);
    } else {
	fsck_log ("indirect_to_direct: could not read block %lu, "
		  "making (%K) bad link instead\n", unfm_ptr, &ih->ih_key);
	buf = bad_link;
	len = strlen (bad_link);
    }

    if (len > MAX_DIRECT_ITEM_LEN (fs->s_blocksize)) {
	fsck_log ("indirect_to_direct: symlink %K seems too long %d, "
		  "Cutting it down to %d byte\n",
			  &ih->ih_key, len, MAX_DIRECT_ITEM_LEN (fs->s_blocksize) - 8);
	len = MAX_DIRECT_ITEM_LEN (fs->s_blocksize) - 8;
    }

    if (!len) {
	buf = bad_link;
	len = strlen (bad_link);
    }

    *symlink_size = len;
    
    ins_ih.ih_item_len = cpu_to_le16 ((ih_key_format (ih) == KEY_FORMAT_2) ? ROUND_UP(len) : len);
    set_free_space (&ins_ih, MAX_US_INT);


    // last last unformatted node pointer
    path->pos_in_item = I_UNFM_NUM (ih) - 1;
    cut_last_unfm_pointer (path, ih);

    /* insert direct item */
    if (usearch_by_key (fs, &(ins_ih.ih_key), path) == ITEM_FOUND)
	die ("indirect_to_direct: key must be not found");
    reiserfsck_insert_item (path, &ins_ih, (const char *)(buf));

    brelse (unfm_bh);

    /* put to stat data offset of first byte in direct item */
    return get_offset (&ins_ih.ih_key); //offset;
}


extern inline __u64 get_min_bytes_number (struct item_head * ih, int blocksize)
{
    switch (get_type (&ih->ih_key)) {
    case TYPE_DIRECT:
	if (SB_VERSION(fs) == REISERFS_VERSION_2)
	    return ROUND_UP(ih_item_len (ih) - 8);
        else
	    return ih_item_len (ih);
    case TYPE_INDIRECT:
	return (I_UNFM_NUM(ih) - 1) * blocksize;
    }
    fsck_log ("get_min_bytes_number: called for wrong type of item %H\n", ih);
    return 0;
}


/* returns 1 when file looks correct, -1 if directory items appeared
   there, 0 - only holes in the file found */
/* when it returns, key->k_offset is offset of the last item of file */
int are_file_items_correct (struct key * key, int key_version, __u64 * size,
			    /*__u64 * min_size,*/ __u32 * blocks,
			    int mark_passed_items, int symlink, __u64 symlink_size)
{
    struct path path;
    int retval, i;
    struct item_head * ih;
    struct key * next_key;
    int had_direct = 0;

    set_offset (key_version, key, 1);
    set_type (key_version, key, TYPE_DIRECT);

    *size = 0;
    /*    *min_size = 0;*/
    *blocks = 0;

    path.path_length = ILLEGAL_PATH_ELEMENT_OFFSET;

    do {
	retval = usearch_by_position (fs, key, key_version, &path);
	if (retval == POSITION_FOUND && path.pos_in_item != 0)
	    die ("are_file_items_correct: all bytes we look for must be found at position 0");

	switch (retval) {
	case POSITION_FOUND:/**/

	    ih = PATH_PITEM_HEAD (&path);

	    set_type (ih_key_format (ih), key, get_type (&ih->ih_key));

	    if (mark_passed_items == 1) {
		mark_item_reachable (ih, PATH_PLAST_BUFFER (&path));
	    }
	    // does not change path
	    next_key = get_next_key_2 (&path);

    	    if (get_type (&ih->ih_key) == TYPE_INDIRECT)
	    {
                if (symlink)
                    *blocks = 1;
                else
                    for (i = 0; i < I_UNFM_NUM (ih); i ++)
                    {
                        __u32 * ind = (__u32 *)get_item(&path);

                        if (ind[i] != 0)
                             *blocks += (fs->s_blocksize >> 9);
                    }

	    }else if ((get_type (&ih->ih_key) == TYPE_DIRECT) && !(had_direct))
            {
                if (symlink)
                    *blocks = (fs->s_blocksize >> 9);
                else
                    *blocks += (fs->s_blocksize >> 9);
	        had_direct++;
	    }
	
	    if (next_key == 0 || not_of_one_file (key, next_key) ||
  		(!is_indirect_key (next_key) && !is_direct_key(next_key) ) )
            {
		/* next item does not exists or is of another object,
                   therefore all items of file are correct */
	
	      /*		*min_size = get_offset (key) + get_min_bytes_number (ih, fs->s_blocksize);*/
		*size = get_offset (key) + get_bytes_number (ih, fs->s_blocksize) - 1;
		
		
		/* here is a problem: if file system being repaired was full
                   enough, then we should avoid indirect_to_direct
                   conversions. This is because unformatted node we have to
                   free will not get into pool of free blocks, but new direct
                   item is very likely of big size, therefore it may require
                   allocation of new blocks. So, skip it for now */
		if (symlink && is_indirect_ih (ih)) {
//		    struct key sd_key;
		    unsigned long first_direct_byte;

		    if (fsck_mode (fs) == FSCK_CHECK) {
			fsck_log ("are_file_items_correct: symlink found in indirect item %K\n", &ih->ih_key);
		    } else {
			first_direct_byte = indirect_to_direct (&path, &symlink_size);
			
			/* last item of the file is direct item */		
			set_offset (key_version, key, first_direct_byte);
			set_type (key_version, key, TYPE_DIRECT);
			*size = symlink_size;
		    }
		} else
		    pathrelse (&path);
		return 1;
	    }

	    /* next item is item of this file */
	    if ((is_indirect_ih (ih) &&
                 (get_offset (&ih->ih_key) + fs->s_blocksize * I_UNFM_NUM (ih) != get_offset (next_key))) ||
		(is_direct_ih (ih) &&
		 (get_offset (&ih->ih_key) + ih_item_len (ih) != get_offset (next_key))))
	    {
		/* next item has incorrect offset (hole or overlapping) */
		*size = get_offset (&ih->ih_key) + get_bytes_number (ih, fs->s_blocksize) - 1;
		/**min_size = *size;*/
		pathrelse (&path);
		return 0;
	    }
	    if (do_items_have_the_same_type (ih, next_key) == 1 && are_items_in_the_same_node (&path) == 1) 
	    {
		/* two indirect items or two direct items in the same leaf. FIXME: Second will be deleted */
		*size = get_offset (&ih->ih_key) + get_bytes_number (ih, fs->s_blocksize) - 1;
		/**min_size = *size;*/
		pathrelse (&path);
		return 0;
	    }

	    /* items are of different types or are in different nodes */
	    if (get_offset (&ih->ih_key) + get_bytes_number (ih, fs->s_blocksize) != get_offset (next_key))
            {
		/* indirect item free space is not set properly */
		if (!is_indirect_ih (ih) ) //|| get_ih_free_space(ih) == 0)
		    fsck_log ("are_file_items_correct: "
			      "item must be indirect and must have invalid free space (%H)", ih);
	
                if (fsck_mode (fs) != FSCK_CHECK)
                {		
                    set_free_space(ih, 0);
                    mark_buffer_dirty (PATH_PLAST_BUFFER (&path));
        	}
	    }

	    /* next item exists */
	    set_type_and_offset(key_version, key, get_offset (next_key), get_type(next_key));
	
	    if (comp_keys (key, next_key))
		die ("are_file_items_correct: keys do not match %k and %k", key, next_key);
	    pathrelse (&path);
	    break;

	case POSITION_NOT_FOUND:
	    // we always must have next key found. Exception is first
	    // byte. It does not have to exist
	
	    if (get_offset (key) != 1)
		die ("are_file_items_correct: key not found %byte can be not found only when it is first byte of file");
	    pathrelse (&path);
	    return 0;
      
	case FILE_NOT_FOUND:
	    if (get_offset (key) != 1)
		die ("are_file_items_correct: there is no items of this file, byte 0 found though");
	    pathrelse (&path);
	    return 1;

	case DIRECTORY_FOUND:
	    pathrelse (&path);
	    return -1;
	}
    } while (1);

    die ("are_file_items_correct: code can not reach here");
    return 0;
}


/* delete all items and put them back (after that file should have
   correct sequence of items.It is very similar to
   pass2.c:relocate_file () and should_relocate () */
static void rewrite_file (struct item_head * ih)
{
    struct key key;
    struct key * rkey;
    struct path path;
    struct item_head * path_ih;
    struct si * si;

    /* starting with the leftmost one - look for all items of file,
       store and delete and  */
    key = ih->ih_key;
    set_type_and_offset (KEY_FORMAT_1, &key, SD_OFFSET, TYPE_STAT_DATA);

    si = 0;
    while (1) {
	usearch_by_key (fs, &key, &path);
	if (get_item_pos (&path) == B_NR_ITEMS (get_bh (&path))) {
	    rkey = uget_rkey (&path);
	    if (rkey && !not_of_one_file (&key, rkey)) {
		/* file continues in the right neighbor */
		copy_key (&key, rkey);
		pathrelse (&path);
		continue;
	    }
	    /* there is no more items with this key */
	    pathrelse (&path);
	    break;
	}

	path_ih = get_ih (&path);
	if (not_of_one_file (&key, &(path_ih->ih_key))) {
	    /* there are no more item with this key */
	    pathrelse (&path);
	    break;
	}

	/* ok, item found, but make sure that it is not a directory one */
	if ((is_stat_data_ih (path_ih) && !not_a_directory (get_item (&path))) ||
	    (is_direntry_ih (path_ih)))
	    reiserfs_panic ("rewrite_file: no directory items of %K are expected",
			    &key);

	si = save_and_delete_file_item (si, &path);
    }

    /* put all items back into tree */
    while (si) {
	insert_item_separately (&(si->si_ih), si->si_dnm_data, 1/*was in tree*/);
	si = remove_saved_item (si);
    }
}


/* file must have correct sequence of items and tail must be stored in
   unformatted pointer */
static int make_file_writeable (struct item_head * ih)
{
    struct key key;
    __u64 size;/*, min_size;*/
    __u32 blocks;
    int retval;

    copy_key (&key, &(ih->ih_key));

    retval = are_file_items_correct (&key, ih_key_format (ih), &size,/* &min_size, */
				     &blocks, 0/*do not mark accessed*/, 0, 0);
    if (retval == 1)
	/* file looks correct */
	return 1;

    rewrite_file (ih);
    stats(fs)->rewritten ++;

/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/
    copy_key (&key, &(ih->ih_key));
    size = 0;
    if (are_file_items_correct (&key, ih_key_format (ih), &size, &blocks,
				0/*do not mark accessed*/, 0, 0) == 0) {
	fsck_progress ("file still incorrect %K\n", &key);
    }
/*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*/

    return 1;
}


/* this inserts __first__ indirect item (having k_offset == 1 and only
   one unfm pointer) into tree */
static int create_first_item_of_file (struct item_head * ih, char * item, struct path * path,
				      int *pos_in_coming_item, int was_in_tree)
{
    __u32 unfm_ptr;
    struct buffer_head * unbh;
    struct item_head indih;
    int retval;
    __u32 free_sp = 0;

    if (get_offset (&ih->ih_key) > fs->s_blocksize) {
	/* insert indirect item containing 0 unfm pointer */
	unfm_ptr = 0;
	set_free_space (&indih, 0);
	free_sp = 0;
	retval = 0;
    } else {
	if (is_direct_ih (ih)) {
	    /* copy direct item to new unformatted node. Save information about it */
	    //__u64 len = get_bytes_number(0, ih, item, CHECK_FREE_BYTES);
	    __u64 len = get_bytes_number (ih, fs->s_blocksize);

	    unbh = reiserfsck_get_new_buffer (PATH_PLAST_BUFFER (path)->b_blocknr);
	    memset (unbh->b_data, 0, unbh->b_size);
	    unfm_ptr = cpu_to_le32 (unbh->b_blocknr);
/* this is for check only */
	    /*mark_block_unformatted (le32_to_cpu (unfm_ptr));*/
	    memcpy (unbh->b_data + get_offset (&ih->ih_key) - 1, item, len);

	    save_unfm_overwriting (le32_to_cpu (unfm_ptr), ih);

	    set_free_space (&indih, fs->s_blocksize - len - (get_offset (&ih->ih_key) - 1));
	    free_sp = fs->s_blocksize - len - (get_offset (&ih->ih_key) - 1);
	    mark_buffer_dirty (unbh);
//      mark_buffer_uptodate (unbh, 0);
	    mark_buffer_uptodate (unbh, 1);
	    brelse (unbh);

	    retval = len;
	} else {
	    /* take first unformatted pointer from an indirect item */
	    unfm_ptr = cpu_to_le32 (*(__u32 *)item);/*B_I_POS_UNFM_POINTER (bh, ih, 0);*/
	    if (!was_in_tree) {
		if (still_bad_unfm_ptr_2 (unfm_ptr))
		    die ("create_first_item_of_file: bad unfm pointer %d", unfm_ptr);
		mark_block_used (unfm_ptr);
	    }

	    //free_sp = ih_get_free_space(0, ih, item);
	    free_sp = ih_free_space (ih);
	    set_free_space (&indih, ((ih_item_len(ih) == UNFM_P_SIZE) ? free_sp /*get_ih_free_space(ih)*/ : 0));
	    if (ih_item_len (ih) != UNFM_P_SIZE)
		free_sp = 0;
//      free_sp = ((ih->ih_item_len == UNFM_P_SIZE) ? ih->u.ih_free_space : 0);
	    retval = fs->s_blocksize - free_sp;
	    (*pos_in_coming_item) ++;
	}
    }
    indih.ih_formats.ih_format.key_format = ih->ih_formats.ih_format.key_format;
    //ih_version(&indih) = ih_version(ih);
    copy_key (&(indih.ih_key), &(ih->ih_key));
    set_offset (key_format (&(ih->ih_key)), &indih.ih_key, 1);
    set_type (key_format (&(ih->ih_key)), &indih.ih_key, TYPE_INDIRECT);

    indih.ih_item_len = cpu_to_le16 (UNFM_P_SIZE);
    mark_item_unreachable (&indih);
    reiserfsck_insert_item (path, &indih, (const char *)&unfm_ptr);

    return retval;
}


/* path points to first part of tail. Function copies file tail into unformatted node and returns
   its block number. If we are going to overwrite direct item then keep free space (keep_free_space
   == YES). Else (we will append file) set free space to 0 */
/* we convert direct item that is on the path to indirect. we need a number of free block for
   unformatted node. reiserfs_new_blocknrs will start from block number returned by this function */
static unsigned long block_to_start (struct path * path)
{
  struct buffer_head * bh;
  struct item_head * ih;

  bh = PATH_PLAST_BUFFER (path);
  ih = PATH_PITEM_HEAD (path);
  if (get_offset(&ih->ih_key) == 1 || PATH_LAST_POSITION (path) == 0)
    return bh->b_blocknr;

  ih --;
  return (B_I_POS_UNFM_POINTER (bh, ih, I_UNFM_NUM (ih) - 1)) ?: bh->b_blocknr;
}


static void direct2indirect2 (unsigned long unfm, struct path * path, int keep_free_space)
{
    struct item_head * ih;
    struct key key;
    struct buffer_head * unbh;
    struct unfm_nodeinfo ni;
    int copied = 0;

    ih = PATH_PITEM_HEAD (path);
    copy_key (&key, &(ih->ih_key));

    if (get_offset (&key) % fs->s_blocksize != 1) {
	/* look for first part of tail */
	pathrelse (path);
	set_offset (key_format (&key), &key, (get_offset (&key) & ~(fs->s_blocksize - 1)) + 1);	
	if (usearch_by_key (fs, &key, path) != ITEM_FOUND)
	    die ("direct2indirect: can not find first part of tail");
    }

    unbh = reiserfsck_get_new_buffer (unfm ?: block_to_start (path));
    memset (unbh->b_data, 0, unbh->b_size);

    /* delete parts of tail coping their contents to new buffer */
    do {
	//__u64 len = get_bytes_number(PATH_PLAST_BUFFER(path), ih, 0, CHECK_FREE_BYTES);
	__u64 len;

	ih = PATH_PITEM_HEAD (path);
	
	len = get_bytes_number(ih, fs->s_blocksize);
	
	memcpy (unbh->b_data + copied, B_I_PITEM (PATH_PLAST_BUFFER (path), ih), len);

	save_unfm_overwriting (unbh->b_blocknr, ih);
	copied += len;	
	set_offset (key_format (&key), &key, get_offset (&key) +  len);
//	set_offset (ih_key_format (ih), &key, get_offset (&key) +  len);

	reiserfsck_delete_item (path, 0);
	
    } while (usearch_by_key (fs, &key, path) == ITEM_FOUND);
	ih = PATH_PITEM_HEAD (path);

    pathrelse (path);

    /* paste or insert pointer to the unformatted node */
    set_offset (key_format (&key), &key, get_offset (&key) - copied);
//    set_offset (ih_key_format (ih), &key, get_offset (&key) - copied);
//  key.k_offset -= copied;
    ni.unfm_nodenum = cpu_to_le32 (unbh->b_blocknr);
    ni.unfm_freespace = (keep_free_space == 1) ? (fs->s_blocksize - copied) : 0;

/* this is for check only */
    /*mark_block_unformatted (ni.unfm_nodenum);*/

    if (usearch_by_position (fs, &key, key_format (&key), path) == FILE_NOT_FOUND) {
	struct item_head insih;

	copy_key (&(insih.ih_key), &key);
	set_ih_key_format (&insih, key_format (&key));
	set_type (ih_key_format (&insih), &insih.ih_key, TYPE_INDIRECT);
	set_free_space (&insih, ni.unfm_freespace);
//    insih.u.ih_free_space = ni.unfm_freespace;
	mark_item_unreachable (&insih);
	insih.ih_item_len = cpu_to_le16 (UNFM_P_SIZE);
	reiserfsck_insert_item (path, &insih, (const char *)&(ni.unfm_nodenum));
    } else {
	ih = PATH_PITEM_HEAD (path);

	if (!is_indirect_ih (ih) || get_offset (&key) != get_bytes_number (ih, fs->s_blocksize) + 1)
	    die ("direct2indirect: incorrect item found");
	reiserfsck_paste_into_item (path, (const char *)&ni, UNFM_P_SIZE);
    }

    mark_buffer_dirty (unbh);
//  mark_buffer_uptodate (unbh, 0);
    mark_buffer_uptodate (unbh, 1);
    brelse (unbh);

    if (usearch_by_position (fs, &key, ih_key_format (ih), path) != POSITION_FOUND || !is_indirect_ih (PATH_PITEM_HEAD (path)))
	die ("direct2indirect: position not found");
    return;
}




static int append_to_unformatted_node (struct item_head * comingih, struct item_head * ih, char * item,
                                        struct path * path, __u16 * free_sp, __u64 coming_len)
{
    struct buffer_head * bh, * unbh;
    __u64 end_of_data; //ih->u.ih_free_space;
    __u64 offset = get_offset (&comingih->ih_key) % fs->s_blocksize - 1;
    int zero_number;
    __u32 unfm_ptr;
    
    /* append to free space of the last unformatted node of indirect item ih */
    if (*free_sp /*ih->u.ih_free_space*/ < coming_len)
    {

	*free_sp = get_offset (&ih->ih_key) + fs->s_blocksize * I_UNFM_NUM (ih) - get_offset (&comingih->ih_key);
	if (*free_sp < coming_len)
	        die ("reiserfsck_append_file: there is no enough free space in unformatted node");
    }

    end_of_data = fs->s_blocksize - *free_sp;
    zero_number = offset - end_of_data;

    bh = PATH_PLAST_BUFFER (path);
    
    unfm_ptr = B_I_POS_UNFM_POINTER (bh, ih, I_UNFM_NUM (ih) - 1);

    /*if (unfm_ptr != 0 && unfm_ptr < SB_BLOCK_COUNT (fs))*/
    if (unfm_ptr && !not_data_block (fs, unfm_ptr))
    {
	unbh = bread (fs->s_dev, unfm_ptr, fs->s_blocksize);
	if (!is_block_used (unfm_ptr))
	    die ("append_to_unformatted_node:  unused block %d", unfm_ptr);
	if (unbh == 0)
	    unfm_ptr = 0;
    } else {
	/* indirect item points to block which can not be pointed or to 0, in
           any case we have to allocate new node */
	/*if (unfm_ptr == 0 || unfm_ptr >= SB_BLOCK_COUNT (fs)) {*/
	unbh = reiserfsck_get_new_buffer (bh->b_blocknr);
	memset (unbh->b_data, 0, unbh->b_size);
	B_I_POS_UNFM_POINTER (bh, ih, I_UNFM_NUM (ih) - 1) = unbh->b_blocknr;
	/*mark_block_unformatted (unbh->b_blocknr);*/
	mark_buffer_dirty (bh);
    }
    memset (unbh->b_data + end_of_data, 0, zero_number);
    memcpy (unbh->b_data + offset, item, coming_len);

    save_unfm_overwriting (unbh->b_blocknr, comingih);

    *free_sp /*ih->u.ih_free_space*/ -= (zero_number + coming_len);
    set_free_space(ih, ih_free_space(ih) - (zero_number + coming_len));
    memset (unbh->b_data + offset + coming_len, 0, *free_sp);
//  mark_buffer_uptodate (unbh, 0);
    mark_buffer_uptodate (unbh, 1);
    mark_buffer_dirty (unbh);
    brelse (unbh);
    pathrelse (path);
    return coming_len;
}


static void adjust_free_space (struct buffer_head * bh, struct item_head * ih, struct item_head * comingih, __u16 *free_sp)
{
  //    printf ("adjust_free_space does nothing\n");
    return;
    if (is_indirect_ih (comingih)) {
	set_free_space(ih, 0);//??
	*free_sp = (__u16)0;
    } else {
	if (get_offset (&comingih->ih_key) < get_offset (&ih->ih_key) + fs->s_blocksize * I_UNFM_NUM (ih))
	{
	    /* append to the last unformatted node */
	    set_free_space (ih, fs->s_blocksize - get_offset(&ih->ih_key) % fs->s_blocksize + 1);//??
	    *free_sp = (__u16)fs->s_blocksize - get_offset(&ih->ih_key) % fs->s_blocksize + 1;
	}
	else
	{
	    set_free_space(ih,0);//??
	    *free_sp =0;
	}
    }
    mark_buffer_dirty (bh);
}


/* this appends file with one unformatted node pointer (since balancing
   algorithm limitation). This pointer can be 0, or new allocated block or
   pointer from indirect item that is being inserted into tree */
int reiserfsck_append_file (struct item_head * comingih, char * item, int pos, struct path * path,
			    int was_in_tree)
{
    struct unfm_nodeinfo ni;
    struct buffer_head * unbh;
    int retval;
    struct item_head * ih = PATH_PITEM_HEAD (path);
    __u16 keep_free_space;
    __u32 bytes_number;

    if (!is_indirect_ih (ih))
	die ("reiserfsck_append_file: can not append to non-indirect item");

    //keep_free_space = ih_get_free_space(PATH_PLAST_BUFFER (path), PATH_PITEM_HEAD(path), 0);
    keep_free_space = ih_free_space (ih);

    if (get_offset (&ih->ih_key) + get_bytes_number (ih, fs->s_blocksize)
	//get_bytes_number (PATH_PLAST_BUFFER (path), PATH_PITEM_HEAD(path), 0, CHECK_FREE_BYTES)
	!= get_offset (&comingih->ih_key)){
	adjust_free_space (PATH_PLAST_BUFFER (path), ih, comingih, &keep_free_space);
    }

    if (is_direct_ih (comingih)) {
	//__u64 coming_len = get_bytes_number (0,comingih, item, CHECK_FREE_BYTES);
	__u64 coming_len = get_bytes_number (comingih, fs->s_blocksize);

	if (get_offset (&comingih->ih_key) < get_offset (&ih->ih_key) + fs->s_blocksize * I_UNFM_NUM (ih)) {
	    /* direct item fits to free space of indirect item */
	    return append_to_unformatted_node (comingih, ih, item, path, &keep_free_space, coming_len);
	}

	unbh = reiserfsck_get_new_buffer (PATH_PLAST_BUFFER (path)->b_blocknr);
	memset (unbh->b_data, 0, unbh->b_size);
	/* this is for check only */
	/*mark_block_unformatted (unbh->b_blocknr);*/
	memcpy (unbh->b_data + get_offset (&comingih->ih_key) % unbh->b_size - 1, item, coming_len);

	save_unfm_overwriting (unbh->b_blocknr, comingih);

	mark_buffer_dirty (unbh);
//    mark_buffer_uptodate (unbh, 0);
	mark_buffer_uptodate (unbh, 1);

	ni.unfm_nodenum = unbh->b_blocknr;
	ni.unfm_freespace = fs->s_blocksize - coming_len - (get_offset (&comingih->ih_key) % unbh->b_size - 1);
	brelse (unbh);
	retval = coming_len;
    } else {
	/* coming item is indirect item */
	//bytes_number = get_bytes_number (PATH_PLAST_BUFFER (path), PATH_PITEM_HEAD(path), 0, CHECK_FREE_BYTES);
	bytes_number = get_bytes_number (ih, fs->s_blocksize);
	if (get_offset (&comingih->ih_key) + pos * fs->s_blocksize != get_offset (&ih->ih_key) + bytes_number)
	    fsck_progress ("reiserfsck_append_file: can not append indirect item (%H) to the %H",
			   comingih, ih);

	/* take unformatted pointer from an indirect item */
	ni.unfm_nodenum = *(__u32 *)(item + pos * UNFM_P_SIZE);/*B_I_POS_UNFM_POINTER (bh, ih, pos);*/
	    
	if (!was_in_tree) {
	    if (still_bad_unfm_ptr_2 (ni.unfm_nodenum))
		die ("reiserfsck_append_file: bad unfm pointer");
	    mark_block_used (ni.unfm_nodenum);
	}

	ni.unfm_freespace = ((pos == (I_UNFM_NUM (comingih) - 1)) ?
			     //ih_get_free_space(0, comingih, item) /*comingih->u.ih_free_space*/ : 0);
			     ih_free_space (comingih) /*comingih->u.ih_free_space*/ : 0);
	retval = fs->s_blocksize - ni.unfm_freespace;
    }

    reiserfsck_paste_into_item (path, (const char *)&ni, UNFM_P_SIZE);
    return retval;
}


int must_there_be_a_hole (struct item_head * comingih, struct path * path)
{
    struct item_head * ih = PATH_PITEM_HEAD (path);
    int keep_free_space;

    if (is_direct_ih (ih)) {
	direct2indirect2 (0, path, keep_free_space = 1);
	ih = PATH_PITEM_HEAD (path);
    }

    path->pos_in_item = I_UNFM_NUM (ih);
    if (get_offset (&ih->ih_key) + (I_UNFM_NUM (ih) + 1) * fs->s_blocksize <= get_offset (&comingih->ih_key))
	return 1;

    return 0;
}


int reiserfs_append_zero_unfm_ptr (struct path * path)
{
    struct unfm_nodeinfo ni;
    int keep_free_space;

    ni.unfm_nodenum = 0;
    ni.unfm_freespace = 0;

    if (is_direct_ih (PATH_PITEM_HEAD (path)))
	/* convert direct item to indirect */
	direct2indirect2 (0, path, keep_free_space = 0);
	
    reiserfsck_paste_into_item (path, (const char *)&ni, UNFM_P_SIZE);
    return 0;
}


/* write direct item to unformatted node */
/* coming item is direct */
static int overwrite_by_direct_item (struct item_head * comingih, char * item, struct path * path)
{
    __u32 unfm_ptr;
    struct buffer_head * unbh, * bh;
    struct item_head * ih;
    int offset;
    __u64 coming_len = get_bytes_number (comingih, fs->s_blocksize);


    bh = PATH_PLAST_BUFFER (path);
    ih = PATH_PITEM_HEAD (path);

    unfm_ptr = le32_to_cpu (B_I_POS_UNFM_POINTER (bh, ih, path->pos_in_item));
    unbh = 0;

    if (unfm_ptr != 0 && unfm_ptr < SB_BLOCK_COUNT (fs)) {
	/**/
	unbh = bread (fs->s_dev, unfm_ptr, bh->b_size);
	if (!is_block_used (unfm_ptr))
	    die ("overwrite_by_direct_item: unused block %d", unfm_ptr);
	if (unbh == 0)
	    unfm_ptr = 0;
    }
    if (unfm_ptr == 0 || unfm_ptr >= SB_BLOCK_COUNT (fs))
    {
	unbh = reiserfsck_get_new_buffer (bh->b_blocknr);
	memset (unbh->b_data, 0, unbh->b_size);
	B_I_POS_UNFM_POINTER (bh, ih, path->pos_in_item) = cpu_to_le32 (unbh->b_blocknr);
	mark_buffer_dirty (bh);
    }

    if (!unbh) {
	die ("overwrite_by_direct_item: could not put direct item in");
    }
      
    offset = (get_offset (&comingih->ih_key) % bh->b_size) - 1;
    if (offset + coming_len > MAX_DIRECT_ITEM_LEN (bh->b_size))
    	die ("overwrite_by_direct_item: direct item too long (offset=%lu, length=%u)",
	         get_offset (&comingih->ih_key), coming_len);

    memcpy (unbh->b_data + offset, item, coming_len);

    save_unfm_overwriting (unbh->b_blocknr, comingih);

    if ((path->pos_in_item == (I_UNFM_NUM (ih) - 1)) && 
	(bh->b_size - ih_free_space (ih)) < (offset + coming_len)) {
	set_free_space (ih, bh->b_size - (offset + coming_len)) ;
	mark_buffer_dirty (bh);
    }
    mark_buffer_dirty (unbh);
//  mark_buffer_uptodate (unbh, 0);
    mark_buffer_uptodate (unbh, 1);
    brelse (unbh);
    return coming_len;
}



void overwrite_unfm_by_unfm (unsigned long unfm_in_tree, unsigned long coming_unfm, int bytes_in_unfm)
{
  struct overwritten_unfm_segment * unfm_os_list;/* list of overwritten segments of the unformatted node */
  struct overwritten_unfm_segment unoverwritten_segment;
  struct buffer_head * bh_in_tree, * coming_bh;

  if (!test_bit (coming_unfm % (fs->s_blocksize * 8), SB_AP_BITMAP (fs)[coming_unfm / (fs->s_blocksize * 8)]->b_data))
    /* block (pointed by indirect item) is free, we do not have to keep its contents */
    return;

  /* coming block is marked as used in disk bitmap. Put its contents to block in tree preserving
     everything, what has been overwritten there by direct items */
  unfm_os_list = find_overwritten_unfm (unfm_in_tree, bytes_in_unfm, &unoverwritten_segment);
  if (unfm_os_list) {
    /*    add_event (UNFM_OVERWRITING_UNFM);*/
    bh_in_tree = bread (fs->s_dev, unfm_in_tree, fs->s_blocksize);
    coming_bh = bread (fs->s_dev, coming_unfm, fs->s_blocksize);
    if (bh_in_tree == 0 || coming_bh == 0)
        return;

    while (get_unoverwritten_segment (unfm_os_list, &unoverwritten_segment)) {
      if (unoverwritten_segment.ous_begin < 0 || unoverwritten_segment.ous_end > bytes_in_unfm - 1 ||
	  unoverwritten_segment.ous_begin > unoverwritten_segment.ous_end)
	die ("overwrite_unfm_by_unfm: invalid segment found (%d %d)", unoverwritten_segment.ous_begin, unoverwritten_segment.ous_end);

      memcpy (bh_in_tree->b_data + unoverwritten_segment.ous_begin, coming_bh->b_data + unoverwritten_segment.ous_begin,
	      unoverwritten_segment.ous_end - unoverwritten_segment.ous_begin + 1);
      mark_buffer_dirty (bh_in_tree);
    }

    brelse (bh_in_tree);
    brelse (coming_bh);
  }
}


/* put unformatted node pointers from incoming item over the in-tree ones */
static int overwrite_by_indirect_item (struct item_head * comingih, __u32 * coming_item, struct path * path, int * pos_in_coming_item)
{
    struct buffer_head * bh = PATH_PLAST_BUFFER (path);
    struct item_head * ih = PATH_PITEM_HEAD (path);
    int written;
    __u32 * item_in_tree;
    int src_unfm_ptrs, dest_unfm_ptrs, to_copy;
    int i;
    __u16 free_sp;


    item_in_tree = (__u32 *)B_I_PITEM (bh, ih) + path->pos_in_item;
    coming_item += *pos_in_coming_item;

    dest_unfm_ptrs = I_UNFM_NUM (ih) - path->pos_in_item;
    src_unfm_ptrs = I_UNFM_NUM (comingih) - *pos_in_coming_item;
  
    if (dest_unfm_ptrs >= src_unfm_ptrs) {
	/* whole coming item (comingih) fits into item in tree (ih) starting with path->pos_in_item */

	//free_sp = ih_get_free_space(0, comingih, (char *)coming_item);
	free_sp = ih_free_space (comingih);

	written = get_bytes_number (comingih, fs->s_blocksize) -
	    free_sp - *pos_in_coming_item * fs->s_blocksize;
	*pos_in_coming_item = I_UNFM_NUM (comingih);
	to_copy = src_unfm_ptrs;
	if (dest_unfm_ptrs == src_unfm_ptrs)
	    set_free_space(ih, free_sp); //comingih->u.ih_free_space;
    } else {
	/* only part of coming item overlaps item in the tree */
	*pos_in_coming_item += dest_unfm_ptrs;
	written = dest_unfm_ptrs * fs->s_blocksize;
	to_copy = dest_unfm_ptrs;
	set_free_space(ih, 0);
    }
  
    for (i = 0; i < to_copy; i ++) {
	if (!is_block_used (coming_item[i]) && !is_block_uninsertable (coming_item[i])) {
	    if (item_in_tree[i]) {
		/* do not overwrite unformatted pointer. We must save everything what is there already from
		   direct items */
		overwrite_unfm_by_unfm (item_in_tree[i], coming_item[i], fs->s_blocksize);
	    } else {
		item_in_tree[i] = coming_item[i];
		mark_block_used (coming_item[i]);
	    }
	}
    }
    mark_buffer_dirty (bh);
    return written;
}


static int reiserfsck_overwrite_file (struct item_head * comingih, char * item,
				      struct path * path, int * pos_in_coming_item,
				      int was_in_tree)
{
    __u32 unfm_ptr;
    int written = 0;
    int keep_free_space;
    struct item_head * ih = PATH_PITEM_HEAD (path);


    if (not_of_one_file (ih, &(comingih->ih_key)))
	die ("reiserfsck_overwrite_file: found [%lu %lu], new item [%lu %lu]",
	     ih->ih_key.k_dir_id, ih->ih_key.k_objectid,
	     comingih->ih_key.k_dir_id, comingih->ih_key.k_objectid);

    if (is_direct_ih (ih)) {
	unfm_ptr = 0;
	if (is_indirect_ih (comingih)) {
	    if (get_offset (&ih->ih_key) % fs->s_blocksize != 1)
		die ("reiserfsck_overwrite_file: second part of tail can not be overwritten by indirect item");
	    /* use pointer from coming indirect item */
	    unfm_ptr = le32_to_cpu (*(__u32 *)(item + *pos_in_coming_item * UNFM_P_SIZE));
	    if (!was_in_tree) {
		if (still_bad_unfm_ptr_2 (unfm_ptr))
		    die ("reiserfsck_overwrite_file: still bad ");
	    }
	}
	/* */
	direct2indirect2 (le32_to_cpu (unfm_ptr), path, keep_free_space = 1);
    }
    if (is_direct_ih (comingih))
    {
	written = overwrite_by_direct_item (comingih, item, path);
    } else {
	if (was_in_tree)
	    die ("reiserfsck_overwrite_file: item we are going to overwrite with could not be in the tree yet");
	written = overwrite_by_indirect_item (comingih, (__u32 *)item, path, pos_in_coming_item);
    }

    return written;
}


/*
 */
int reiserfsck_file_write (struct item_head * ih, char * item, int was_in_tree)
{
    struct path path;
    struct item_head * path_ih;
    int count, pos_in_coming_item;
    int retval;
    struct key key;
    int written;


    if (make_file_writeable (ih) == -1) {
	/* write was not completed. Skip that item. Maybe it should be
	   saved to lost_found */
	fsck_progress ("reiserfsck_file_write: skip writing %H\n", ih);
	return 0;
    }

    count = get_bytes_number (ih, fs->s_blocksize);
    pos_in_coming_item = 0;

    copy_key (&key, &(ih->ih_key));

    while (count) {

	retval = usearch_by_position (fs, &key, key_format (&key), &path);
	
	if (retval == DIRECTORY_FOUND)
	    reiserfs_panic ("directory found %k", key);


	if (retval == POSITION_FOUND) {
	    written = reiserfsck_overwrite_file (ih, item, &path, &pos_in_coming_item, was_in_tree);
            count -= written;
	    set_offset (key_format (&key), &key, get_offset (&key) + written);
	}
	if (retval == FILE_NOT_FOUND) {
	    written = create_first_item_of_file (ih, item, &path, &pos_in_coming_item, was_in_tree);
	    count -= written;

	    set_offset (key_format (&key), &key, get_offset (&key) + written );
	}
	if (retval == POSITION_NOT_FOUND) {
	
	    path_ih = PATH_PITEM_HEAD (&path);
	
	    if (must_there_be_a_hole (ih, &path) == 1)
	    {
		reiserfs_append_zero_unfm_ptr (&path);
	    }else {
		count -= reiserfsck_append_file (ih, item, pos_in_coming_item, &path, was_in_tree);
		set_offset (key_format (&key), &key, get_offset (&key) + fs->s_blocksize);
		pos_in_coming_item ++;
	    }
	}
	if (count < 0)
	    die ("reiserfsck_file_write: count < 0 (%d)", count);
	pathrelse (&path);
    }

    return get_bytes_number (ih, fs->s_blocksize);
}















































