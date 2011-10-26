/*
 * Copyright 1996, 1997, 1998 Hans Reiser, see reiserfs/README for licensing and copyright details
 */

#include "includes.h"


/* these are used in do_balance.c */

/* leaf_move_items
   leaf_shift_left
   leaf_shift_right
   leaf_delete_items
   leaf_insert_into_buf
   leaf_paste_in_buffer
   leaf_cut_from_buffer
   leaf_paste_entries
   */


extern struct tree_balance init_tb;
extern int init_item_pos;
extern int init_pos_in_item;
extern int init_mode;



/* copy copy_count entries from source directory item to dest buffer (creating new item if needed) */
static void leaf_copy_dir_entries (reiserfs_filsys_t fs,
			           struct buffer_info * dest_bi, struct buffer_head * source, 
				   int last_first, int item_num, int from, int copy_count)
{
    struct buffer_head * dest = dest_bi->bi_bh;
    int item_num_in_dest;		/* either the number of target item,
					   or if we must create a new item,
					   the number of the item we will
					   create it next to */
    struct item_head * ih;
    struct reiserfs_de_head * deh;
    int copy_records_len;			/* length of all records in item to be copied */
    char * records;

    ih = B_N_PITEM_HEAD (source, item_num);

#ifdef CONFIG_REISERFS_CHECK
    if (!I_IS_DIRECTORY_ITEM (ih))
	reiserfs_panic(0, "vs-10000: leaf_copy_dir_entries: item must be directory item");
#endif

    /* length of all record to be copied and first byte of the last of them */
    deh = B_I_DEH (source, ih);
    if (copy_count) {
	copy_records_len = (from ? deh_location(&(deh[from - 1])) : ih_item_len(ih)) - 
	    deh_location(&(deh[from + copy_count - 1]));
	records = source->b_data + ih_location(ih) + deh_location(&(deh[from + copy_count - 1]));
    } else {
	copy_records_len = 0;
	records = 0;
    }

    /* when copy last to first, dest buffer can contain 0 items */
    item_num_in_dest = (last_first == LAST_TO_FIRST) ? (( B_NR_ITEMS(dest) ) ? 0 : -1) : (B_NR_ITEMS(dest) - 1);

    /* if there are no items in dest or the first/last item in dest is not item of the same directory */
    if ( (item_num_in_dest == - 1) ||
#ifndef FU //REISERFS_FSCK
	 (last_first == FIRST_TO_LAST && are_items_mergeable (B_N_PITEM_HEAD (dest, item_num_in_dest), ih, dest->b_size) == 0) ||
	 (last_first == LAST_TO_FIRST && are_items_mergeable (ih, B_N_PITEM_HEAD (dest, item_num_in_dest), dest->b_size) == 0)) {
#else
	(last_first == FIRST_TO_LAST && get_offset (&ih->ih_key) == DOT_OFFSET) ||
	    (last_first == LAST_TO_FIRST && not_of_one_file (&ih->ih_key, B_N_PKEY (dest, item_num_in_dest)))) {
#endif
	/* create new item in dest */
	struct item_head new_ih;

	/* form item header */
	memcpy (&new_ih.ih_key, &ih->ih_key, KEY_SIZE);

	/* calculate item len */
        set_ih_item_len( &new_ih, (DEH_SIZE * copy_count + copy_records_len ));
	set_entry_count (&new_ih, 0);
    
	if (last_first == LAST_TO_FIRST) {
	    /* form key by the following way */
	    if (from < ih_entry_count (ih)) {
		new_ih.ih_key.u.k_offset_v1.k_offset = deh[from].deh_offset; /* ok, both 32-bit LE */
		new_ih.ih_key.u.k_offset_v1.k_uniqueness = cpu_to_le32(DIRENTRY_UNIQUENESS);
		/*memcpy (&new_ih.ih_key.k_offset, &deh[from].deh_offset, SHORT_KEY_SIZE);*/
	    } else {
		/* no entries will be copied to this item in this function */
		new_ih.ih_key.u.k_offset_v1.k_offset = cpu_to_le32(MAX_KEY1_OFFSET);
		/* this item is not yet valid, but we want I_IS_DIRECTORY_ITEM to return 1 for it, so we -1 */
		new_ih.ih_key.u.k_offset_v1.k_uniqueness = cpu_to_le32(DIRENTRY_UNIQUENESS)/*TYPE_DIRECTORY_MAX*/;
	    }
	}
        /* Copy both key_format and fsck_need */
        new_ih.ih_formats.em_ih_format = ih->ih_formats.em_ih_format;
    
	/* insert item into dest buffer */
	leaf_insert_into_buf (fs, dest_bi, (last_first == LAST_TO_FIRST) ? 0 : B_NR_ITEMS(dest), &new_ih, NULL, 0);
    } else {
	/* prepare space for entries */
	leaf_paste_in_buffer (fs, dest_bi, (last_first==FIRST_TO_LAST) ? (B_NR_ITEMS(dest) - 1) : 0, USHRT_MAX,
			      DEH_SIZE * copy_count + copy_records_len, records, 0);
    }
  
    item_num_in_dest = (last_first == FIRST_TO_LAST) ? (B_NR_ITEMS(dest)-1) : 0;
  
    leaf_paste_entries (dest_bi->bi_bh, item_num_in_dest,
			(last_first == FIRST_TO_LAST) ? ih_entry_count (B_N_PITEM_HEAD (dest, item_num_in_dest)) : 0,
			copy_count, deh + from, records,
			DEH_SIZE * copy_count + copy_records_len
	);
}


/* Copy the first (if last_first == FIRST_TO_LAST) or last (last_first == LAST_TO_FIRST) item or 
   part of it or nothing (see the return 0 below) from SOURCE to the end 
   (if last_first) or beginning (!last_first) of the DEST */
/* returns 1 if anything was copied, else 0 */
static int leaf_copy_boundary_item (reiserfs_filsys_t fs,
                                    struct buffer_info * dest_bi, struct buffer_head * src, int last_first,
				    int bytes_or_entries)
{
    struct buffer_head * dest = dest_bi->bi_bh;
    int dest_nr_item, src_nr_item; /* number of items in the source and destination buffers */
    struct item_head * ih;
    struct item_head * dih;
  
    dest_nr_item = B_NR_ITEMS(dest);
  
    if ( last_first == FIRST_TO_LAST ) {
	/* if ( DEST is empty or first item of SOURCE and last item of DEST are the items of different objects
	   or of different types ) then there is no need to treat this item differently from the other items
	   that we copy, so we return */
	ih = B_N_PITEM_HEAD (src, 0);
	dih = B_N_PITEM_HEAD (dest, dest_nr_item - 1);
#ifndef FU //REISERFS_FSCK
	if (!dest_nr_item || (are_items_mergeable (dih, ih, src->b_size) == 0))
#else
	    if (!dest_nr_item || (!is_left_mergeable (ih, src->b_size)))
#endif
		/* there is nothing to merge */
		return 0;
      
#ifdef CONFIG_REISERFS_CHECK
	if ( ! ih_item_len(ih) )
	    reiserfs_panic (0, "vs-10010: leaf_copy_boundary_item: item can not have empty dynamic length");
#endif
      
	if ( I_IS_DIRECTORY_ITEM(ih) ) {
	    if ( bytes_or_entries == -1 )
		/* copy all entries to dest */
		bytes_or_entries = ih_entry_count(ih);
	    leaf_copy_dir_entries (fs, dest_bi, src, FIRST_TO_LAST, 0, 0, bytes_or_entries);
	    return 1;
	}
      
	/* copy part of the body of the first item of SOURCE to the end of the body of the last item of the DEST
	   part defined by 'bytes_or_entries'; if bytes_or_entries == -1 copy whole body; don't create new item header
	*/
	if ( bytes_or_entries == -1 )
	    bytes_or_entries = ih_item_len(ih);

#ifdef CONFIG_REISERFS_CHECK
	else {
	    if (bytes_or_entries == ih_item_len(ih) && I_IS_INDIRECT_ITEM(ih))
		if (ih_free_space (ih))
		    reiserfs_panic (0, "vs-10020: leaf_copy_boundary_item: "
				    "last unformatted node must be filled entirely (free_space=%d)",
				    ih_free_space (ih));
	}
#endif
      
	/* merge first item (or its part) of src buffer with the last
	   item of dest buffer. Both are of the same file */
	leaf_paste_in_buffer (fs, dest_bi,
			      dest_nr_item - 1, ih_item_len(dih), bytes_or_entries, B_I_PITEM(src,ih), 0
	    );
      
	if (I_IS_INDIRECT_ITEM(dih)) {
#ifdef CONFIG_REISERFS_CHECK
	    if (ih_free_space (dih))
		reiserfs_panic (0, "vs-10030: leaf_copy_boundary_item: " 
				"merge to left: last unformatted node of non-last indirect item must be filled entirely (free_space=%d)",
				ih_free_space (dih));
#endif
	    if (bytes_or_entries == ih_item_len(ih))
		//dih->u.ih_free_space = ih->u.ih_free_space;
		set_free_space (dih, ih_free_space (ih));
	}
    
	return 1;
    }
  

    /* copy boundary item to right (last_first == LAST_TO_FIRST) */

    /* ( DEST is empty or last item of SOURCE and first item of DEST
       are the items of different object or of different types )
    */
    src_nr_item = B_NR_ITEMS (src);
    ih = B_N_PITEM_HEAD (src, src_nr_item - 1);
    dih = B_N_PITEM_HEAD (dest, 0);

#ifndef FU //REISERFS_FSCK
    if (!dest_nr_item || are_items_mergeable (ih, dih, src->b_size) == 0)
#else
	if (!dest_nr_item || !is_left_mergeable (dih, src->b_size))
#endif
	    return 0;
  
    if ( I_IS_DIRECTORY_ITEM(ih)) {
	if ( bytes_or_entries == -1 )
	    /* bytes_or_entries = entries number in last item body of SOURCE */
	    bytes_or_entries = ih_entry_count(ih);
    
	leaf_copy_dir_entries (fs, dest_bi, src, LAST_TO_FIRST, src_nr_item - 1, ih_entry_count(ih) - bytes_or_entries, 
			       bytes_or_entries);
	return 1;
    }

    /* copy part of the body of the last item of SOURCE to the begin of the body of the first item of the DEST;
       part defined by 'bytes_or_entries'; if byte_or_entriess == -1 copy whole body; change first item key of the DEST;
       don't create new item header
    */
  
#ifdef CONFIG_REISERFS_CHECK  
    if (I_IS_INDIRECT_ITEM(ih) && ih_free_space (ih))
	reiserfs_panic (0, "vs-10040: leaf_copy_boundary_item: " 
			"merge to right: last unformatted node of non-last indirect item must be filled entirely (free_space=%d)",
			ih_free_space (ih));
#endif

    if ( bytes_or_entries == -1 ) {
	/* bytes_or_entries = length of last item body of SOURCE */
	bytes_or_entries = ih_item_len(ih);

#ifdef CONFIG_REISERFS_CHECK
	if (get_offset (&dih->ih_key) != get_offset (&ih->ih_key) + get_bytes_number (ih, src->b_size))/*I_DNM_DATA_LEN(ih))*/
	    reiserfs_panic (0, "vs-10050: leaf_copy_boundary_item: right item offset (%lu) must not be (%lu),it must be %lu",
			    get_offset (&dih->ih_key), get_offset (&ih->ih_key) + get_bytes_number (ih, src->b_size), get_offset (&dih->ih_key));
#endif

	/* change first item key of the DEST */
	//dih->ih_key.k_offset = ih->ih_key.k_offset;
	set_offset (key_format (&dih->ih_key), &dih->ih_key, get_offset (&ih->ih_key));

	/* item becomes non-mergeable */
	/* or mergeable if left item was */
	//dih->ih_key.k_uniqueness = ih->ih_key.k_uniqueness;
	set_type (key_format (&dih->ih_key), &dih->ih_key, get_type (&ih->ih_key));
    } else {
	/* merge to right only part of item */
#ifdef CONFIG_REISERFS_CHECK
	if ( ih_item_len(ih) <= bytes_or_entries )
	    reiserfs_panic (0, "vs-10060: leaf_copy_boundary_item: no so much bytes %lu (needed %lu)",
			    ih_item_len(ih), bytes_or_entries);
#endif
    
	/* change first item key of the DEST */
	if ( I_IS_DIRECT_ITEM(dih) ) {
#ifdef CONFIG_REISERFS_CHECK
	    if (get_offset (&dih->ih_key) <= (unsigned long)bytes_or_entries)
		reiserfs_panic (0, "vs-10070: leaf_copy_boundary_item: dih->ih_key.k_offset(%d) <= bytes_or_entries(%d)", 
				get_offset (&dih->ih_key), bytes_or_entries);
#endif
	    //dih->ih_key.k_offset -= bytes_or_entries;
	    set_offset (key_format (&dih->ih_key), &dih->ih_key, get_offset (&dih->ih_key) - bytes_or_entries);
	} else {
#ifdef CONFIG_REISERFS_CHECK
	    if (get_offset (&dih->ih_key) <=(bytes_or_entries/UNFM_P_SIZE)*dest->b_size )
		reiserfs_panic (0, "vs-10080: leaf_copy_boundary_item: dih->ih_key.k_offset(%d) <= bytes_or_entries(%d)",
				get_offset (&dih->ih_key), (bytes_or_entries/UNFM_P_SIZE)*dest->b_size);
#endif
	    //dih->ih_key.k_offset -= ((bytes_or_entries/UNFM_P_SIZE)*dest->b_size);
	    set_offset (key_format (&dih->ih_key), &dih->ih_key, 
			get_offset (&dih->ih_key) - ((bytes_or_entries/UNFM_P_SIZE)*dest->b_size));
	}
    }
  
    leaf_paste_in_buffer (fs, dest_bi, 0, 0, bytes_or_entries, B_I_PITEM(src,ih) + ih_item_len(ih) - bytes_or_entries, 0);
    return 1;
}


/* copy cpy_mun items from buffer src to buffer dest
 * last_first == FIRST_TO_LAST means, that we copy cpy_num  items beginning from first-th item in src to tail of dest
 * last_first == LAST_TO_FIRST means, that we copy cpy_num  items beginning from first-th item in src to head of dest
 */
static void leaf_copy_items_entirely (reiserfs_filsys_t fs, struct buffer_info * dest_bi, 
                                      struct buffer_head * src, int last_first,
				      int first, int cpy_num)
{
    struct buffer_head * dest;
    int nr;
    int dest_before;
    int last_loc, last_inserted_loc, location;
    int i, j;
    struct block_head * blkh;
    struct item_head * ih;


#ifdef CONFIG_REISERFS_CHECK
    if (last_first != LAST_TO_FIRST  && last_first != FIRST_TO_LAST) 
	reiserfs_panic (0, "vs-10090: leaf_copy_items_entirely: bad last_first parameter %d", last_first);

    if (B_NR_ITEMS (src) - first < cpy_num)
	reiserfs_panic (0, "vs-10100: leaf_copy_items_entirely: too few items in source %d, required %d from %d",
			B_NR_ITEMS(src), cpy_num, first);

    if (cpy_num < 0)
	reiserfs_panic (0, "vs-10110: leaf_copy_items_entirely: can not copy negative amount of items");

    if ( ! dest_bi )
	reiserfs_panic (0, "vs-10120: leaf_copy_items_entirely: can not copy negative amount of items");
#endif

    dest = dest_bi->bi_bh;

#ifdef CONFIG_REISERFS_CHECK
    if ( ! dest )
	reiserfs_panic (0, "vs-10130: leaf_copy_items_entirely: can not copy negative amount of items");
#endif

    if (cpy_num == 0)
	return;

    blkh = B_BLK_HEAD(dest);
    nr = blkh_nr_item(blkh);
  
    /* we will insert items before 0-th or nr-th item in dest buffer. It depends of last_first parameter */
    dest_before = (last_first == LAST_TO_FIRST) ? 0 : nr;

    /* location of head of first new item */
    ih = B_N_PITEM_HEAD (dest, dest_before);

#ifdef CONFIG_REISERFS_CHECK
    if (blkh_free_space(blkh) < cpy_num * IH_SIZE) {
	reiserfs_panic (0, "vs-10140: leaf_copy_items_entirely: not enough free space for headers %d (needed %d)",
			blkh_free_space(blkh), cpy_num * IH_SIZE);
    }
#endif

    /* prepare space for headers */
    memmove (ih + cpy_num, ih, (nr-dest_before) * IH_SIZE);

    /* copy item headers */
    memcpy (ih, B_N_PITEM_HEAD (src, first), cpy_num * IH_SIZE);

    set_blkh_free_space(blkh, blkh_free_space(blkh) - (IH_SIZE * cpy_num) );

    /* location of unmovable item */
    j = location = (dest_before == 0) ? dest->b_size : ih_location(ih-1);
    for (i = dest_before; i < nr + cpy_num; i ++)
        set_ih_location( &(ih[i-dest_before]),
	    (location -= ih_item_len( &(ih[i-dest_before]))));

    /* prepare space for items */
    last_loc = ih_location( &(ih[nr+cpy_num-1-dest_before]) );
    last_inserted_loc = ih_location( &(ih[cpy_num-1]) );

    /* check free space */
#ifdef CONFIG_REISERFS_CHECK
    if (blkh_free_space(blkh) < j - last_inserted_loc) {
	reiserfs_panic (0, "vs-10150: leaf_copy_items_entirely: not enough free space for items %d (needed %d)",
			blkh_free_space(blkh), j - last_inserted_loc);
    }
#endif

    memmove (dest->b_data + last_loc,
	     dest->b_data + last_loc + j - last_inserted_loc,
	     last_inserted_loc - last_loc);

    /* copy items */
    memcpy (dest->b_data + last_inserted_loc, B_N_PITEM(src,(first + cpy_num - 1)),
	    j - last_inserted_loc);

    /* sizes, item number */
    set_blkh_nr_item(blkh, blkh_nr_item(blkh) + cpy_num);
    set_blkh_free_space(blkh, blkh_free_space(blkh) - (j - last_inserted_loc));
  
    mark_buffer_dirty (dest);

    if (dest_bi->bi_parent) {
        struct disk_child *t_dc;
#ifdef CONFIG_REISERFS_CHECK
	if (dc_block_number(B_N_CHILD (dest_bi->bi_parent, dest_bi->bi_position)) != dest->b_blocknr) {
	    reiserfs_panic (0, "vs-10160: leaf_copy_items_entirely: "
			    "block number in bh does not match to field in disk_child structure %lu and %lu",
			    dest->b_blocknr, dc_block_number(B_N_CHILD(dest_bi->bi_parent, dest_bi->bi_position)));
	}
#endif
        t_dc = B_N_CHILD (dest_bi->bi_parent, dest_bi->bi_position);
        set_dc_size(t_dc, dc_size(t_dc) +
                                (j - last_inserted_loc + IH_SIZE * cpy_num));
    
	mark_buffer_dirty(dest_bi->bi_parent);
    }
}


/* This function splits the (liquid) item into two items (useful when
   shifting part of an item into another node.) */
static void leaf_item_bottle (reiserfs_filsys_t fs,
			      struct buffer_info * dest_bi, struct buffer_head * src, int last_first,
			      int item_num, int cpy_bytes)
{
    struct buffer_head * dest = dest_bi->bi_bh;
    struct item_head * ih;
  
#ifdef CONFIG_REISERFS_CHECK  
    if ( cpy_bytes == -1 ) 
	reiserfs_panic (0, "vs-10170: leaf_item_bottle: bytes == - 1 means: do not split item");
#endif

    if ( last_first == FIRST_TO_LAST ) {
	/* if ( if item in position item_num in buffer SOURCE is directory item ) */
	if (I_IS_DIRECTORY_ITEM(ih = B_N_PITEM_HEAD(src,item_num)))
	    leaf_copy_dir_entries (fs, dest_bi, src, FIRST_TO_LAST, item_num, 0, cpy_bytes);
	else {
	    struct item_head n_ih;
      
	    /* copy part of the body of the item number 'item_num' of SOURCE to the end of the DEST 
	       part defined by 'cpy_bytes'; create new item header; change old item_header (????);
	       n_ih = new item_header;
	    */
	    memcpy (&n_ih, ih, IH_SIZE);
            set_ih_item_len(&n_ih, cpy_bytes);
	    if (I_IS_INDIRECT_ITEM(ih)) {
#ifdef CONFIG_REISERFS_CHECK
		if (cpy_bytes == ih_item_len(ih) && ih_free_space (ih))
		    reiserfs_panic (0, "vs-10180: leaf_item_bottle: " 
				    "when whole indirect item is bottle to left neighbor, it must have free_space==0 (not %lu)",
				    ih_free_space (ih));
#endif
		//n_ih.u.ih_free_space = 0;
		set_free_space (&n_ih, 0);;
	    }

#ifdef CONFIG_REISERFS_CHECK
	    if (is_left_mergeable (ih, src->b_size))
		reiserfs_panic (0, "vs-10190: leaf_item_bottle: item %h should not be mergeable", ih);
#endif
	    //n_ih.ih_version = ih->ih_version;
            /* Copy both key_format and fsck need at the same time */
            n_ih.ih_formats.em_ih_format = ih->ih_formats.em_ih_format;
	    leaf_insert_into_buf (fs, dest_bi, B_NR_ITEMS(dest), &n_ih, B_N_PITEM (src, item_num), 0);
	}
    } else {
	/*  if ( if item in position item_num in buffer SOURCE is directory item ) */
	if (I_IS_DIRECTORY_ITEM(ih = B_N_PITEM_HEAD (src, item_num)))
	    leaf_copy_dir_entries (fs, dest_bi, src, LAST_TO_FIRST, item_num, ih_entry_count(ih) - cpy_bytes, cpy_bytes);
	else {
	    struct item_head n_ih;
      
	    /* copy part of the body of the item number 'item_num' of SOURCE to the begin of the DEST 
	       part defined by 'cpy_bytes'; create new item header;
	       n_ih = new item_header;
	    */
	    memcpy (&n_ih, ih, SHORT_KEY_SIZE);
      
	    if (I_IS_DIRECT_ITEM(ih)) {
		//n_ih.ih_key.k_offset = ih->ih_key.k_offset + ih->ih_item_len - cpy_bytes;
		set_offset (key_format (&ih->ih_key), &n_ih.ih_key, get_offset (&ih->ih_key) + ih_item_len(ih) - cpy_bytes);
		//n_ih.ih_key.k_uniqueness = TYPE_DIRECT;
		set_type (key_format (&ih->ih_key), &n_ih.ih_key, TYPE_DIRECT);
		//n_ih.u.ih_free_space = USHRT_MAX;
		set_free_space (&n_ih, USHRT_MAX);
	    } else {
		/* indirect item */
#ifdef CONFIG_REISERFS_CHECK
		if (!cpy_bytes && ih_free_space (ih))
		    reiserfs_panic (0, "vs-10200: leaf_item_bottle: ih->ih_free_space must be 0 when indirect item will be appended");
#endif
		//n_ih.ih_key.k_offset = ih->ih_key.k_offset + (ih->ih_item_len - cpy_bytes) / UNFM_P_SIZE * dest->b_size;
		set_offset (key_format (&ih->ih_key), &n_ih.ih_key,
			    get_offset (&ih->ih_key) + (ih->ih_item_len - cpy_bytes) / UNFM_P_SIZE * dest->b_size);
		//n_ih.ih_key.k_uniqueness = TYPE_INDIRECT;
		set_type (key_format (&ih->ih_key), &n_ih.ih_key, TYPE_INDIRECT);
		//n_ih.u.ih_free_space = ih->u.ih_free_space;
		set_free_space (&n_ih, ih_free_space (ih));
	    }
      
	    /* set item length */
            set_ih_item_len( &n_ih, cpy_bytes );
	    /* Copy both key_format and fsck need */
            n_ih.ih_formats.em_ih_format = ih->ih_formats.em_ih_format;
	    leaf_insert_into_buf (fs, dest_bi, 0, &n_ih, B_N_PITEM(src,item_num) + ih_item_len(ih) - cpy_bytes, 0);
	}
    }
}


/* If cpy_bytes equals minus one than copy cpy_num whole items from SOURCE to DEST.
   If cpy_bytes not equal to minus one than copy cpy_num-1 whole items from SOURCE to DEST.
   From last item copy cpy_num bytes for regular item and cpy_num directory entries for
   directory item. */
static int leaf_copy_items (reiserfs_filsys_t fs,
                            struct buffer_info * dest_bi, struct buffer_head * src,
			    int last_first, int cpy_num,
			    int cpy_bytes)
{
    struct buffer_head * dest;
    int pos, i, src_nr_item, bytes;

    dest = dest_bi->bi_bh;
#ifdef CONFIG_REISERFS_CHECK
    if (!dest || !src)
	reiserfs_panic (0, "vs-10210: leaf_copy_items: !dest || !src");
  
    if ( last_first != FIRST_TO_LAST && last_first != LAST_TO_FIRST )
	reiserfs_panic (0, "vs-10220: leaf_copy_items: last_first != FIRST_TO_LAST && last_first != LAST_TO_FIRST");

    if ( B_NR_ITEMS(src) < cpy_num )
	reiserfs_panic (0, "vs-10230: leaf_copy_items: No enough items: %d, required %d", B_NR_ITEMS(src), cpy_num);

    if ( cpy_num < 0 )
	reiserfs_panic (0, "vs-10240: leaf_copy_items: cpy_num < 0 (%d)", cpy_num);
#endif

    if ( cpy_num == 0 )
	return 0;
 
    if ( last_first == FIRST_TO_LAST ) {
	/* copy items to left */
	pos = 0;
	if ( cpy_num == 1 )
	    bytes = cpy_bytes;
	else
	    bytes = -1;
   
	/* copy the first item or it part or nothing to the end of the DEST (i = leaf_copy_boundary_item(DEST,SOURCE,0,bytes)) */
	i = leaf_copy_boundary_item (fs, dest_bi, src, FIRST_TO_LAST, bytes);
	cpy_num -= i;
	if ( cpy_num == 0 )
	    return i;
	pos += i;
	if ( cpy_bytes == -1 )
	    /* copy first cpy_num items starting from position 'pos' of SOURCE to end of DEST */
	    leaf_copy_items_entirely(fs, dest_bi, src, FIRST_TO_LAST, pos, cpy_num);
	else {
	    /* copy first cpy_num-1 items starting from position 'pos-1' of the SOURCE to the end of the DEST */
	    leaf_copy_items_entirely(fs, dest_bi, src, FIRST_TO_LAST, pos, cpy_num-1);
	     
	    /* copy part of the item which number is cpy_num+pos-1 to the end of the DEST */
	    leaf_item_bottle (fs, dest_bi, src, FIRST_TO_LAST, cpy_num+pos-1, cpy_bytes);
	} 
    } else {
	/* copy items to right */
	src_nr_item = B_NR_ITEMS (src);
	if ( cpy_num == 1 )
	    bytes = cpy_bytes;
	else
	    bytes = -1;
   
	/* copy the last item or it part or nothing to the begin of the DEST (i = leaf_copy_boundary_item(DEST,SOURCE,1,bytes)); */
	i = leaf_copy_boundary_item (fs, dest_bi, src, LAST_TO_FIRST, bytes);
   
	cpy_num -= i;
	if ( cpy_num == 0 )
	    return i;
   
	pos = src_nr_item - cpy_num - i;
	if ( cpy_bytes == -1 ) {
	    /* starting from position 'pos' copy last cpy_num items of SOURCE to begin of DEST */
	    leaf_copy_items_entirely(fs, dest_bi, src, LAST_TO_FIRST, pos, cpy_num);
	} else {
	    /* copy last cpy_num-1 items starting from position 'pos+1' of the SOURCE to the begin of the DEST; */
	    leaf_copy_items_entirely(fs, dest_bi, src, LAST_TO_FIRST, pos+1, cpy_num-1);

	    /* copy part of the item which number is pos to the begin of the DEST */
	    leaf_item_bottle (fs, dest_bi, src, LAST_TO_FIRST, pos, cpy_bytes);
	}
    }
    return i;
}


/* there are types of coping: from S[0] to L[0], from S[0] to R[0],
   from R[0] to L[0]. for each of these we have to define parent and
   positions of destination and source buffers */
static void leaf_define_dest_src_infos (int shift_mode, struct tree_balance * tb, struct buffer_info * dest_bi,
					struct buffer_info * src_bi, int * first_last,
					struct buffer_head * Snew)
{
#ifdef CONFIG_REISERFS_CHECK
    memset (dest_bi, 0, sizeof (struct buffer_info));
    memset (src_bi, 0, sizeof (struct buffer_info));
#endif

    /* define dest, src, dest parent, dest position */
    switch (shift_mode) {
    case LEAF_FROM_S_TO_L:    /* it is used in leaf_shift_left */
	src_bi->bi_bh = PATH_PLAST_BUFFER (tb->tb_path);
	src_bi->bi_parent = PATH_H_PPARENT (tb->tb_path, 0);
	src_bi->bi_position = PATH_H_B_ITEM_ORDER (tb->tb_path, 0);	/* src->b_item_order */
	dest_bi->bi_bh = tb->L[0];
	dest_bi->bi_parent = tb->FL[0];
	dest_bi->bi_position = get_left_neighbor_position (tb, 0);
	*first_last = FIRST_TO_LAST;
	break;

    case LEAF_FROM_S_TO_R:  /* it is used in leaf_shift_right */
	src_bi->bi_bh = PATH_PLAST_BUFFER (tb->tb_path);
	src_bi->bi_parent = PATH_H_PPARENT (tb->tb_path, 0);
	src_bi->bi_position = PATH_H_B_ITEM_ORDER (tb->tb_path, 0);
	dest_bi->bi_bh = tb->R[0];
	dest_bi->bi_parent = tb->FR[0];
	dest_bi->bi_position = get_right_neighbor_position (tb, 0);
	*first_last = LAST_TO_FIRST;
	break;

    case LEAF_FROM_R_TO_L:  /* it is used in balance_leaf_when_delete */
	src_bi->bi_bh = tb->R[0];
	src_bi->bi_parent = tb->FR[0];
	src_bi->bi_position = get_right_neighbor_position (tb, 0);
	dest_bi->bi_bh = tb->L[0];
	dest_bi->bi_parent = tb->FL[0];
	dest_bi->bi_position = get_left_neighbor_position (tb, 0);
	*first_last = FIRST_TO_LAST;
	break;
    
    case LEAF_FROM_L_TO_R:  /* it is used in balance_leaf_when_delete */
	src_bi->bi_bh = tb->L[0];
	src_bi->bi_parent = tb->FL[0];
	src_bi->bi_position = get_left_neighbor_position (tb, 0);
	dest_bi->bi_bh = tb->R[0];
	dest_bi->bi_parent = tb->FR[0];
	dest_bi->bi_position = get_right_neighbor_position (tb, 0);
	*first_last = LAST_TO_FIRST;
	break;

    case LEAF_FROM_S_TO_SNEW:
	src_bi->bi_bh = PATH_PLAST_BUFFER (tb->tb_path);
	src_bi->bi_parent = PATH_H_PPARENT (tb->tb_path, 0);
	src_bi->bi_position = PATH_H_B_ITEM_ORDER (tb->tb_path, 0);
	dest_bi->bi_bh = Snew;
	dest_bi->bi_parent = 0;
	dest_bi->bi_position = 0;
	*first_last = LAST_TO_FIRST;
	break;
    
    default:
	reiserfs_panic (0, "vs-10250: leaf_define_dest_src_infos: shift type is unknown (%d)", shift_mode);
    }
#ifdef CONFIG_REISERFS_CHECK
    if (src_bi->bi_bh == 0 || dest_bi->bi_bh == 0) {
	reiserfs_panic (0, "vs-10260: leaf_define_dest_src_etc: mode==%d, source (%p) or dest (%p) buffer is initialized incorrectly",
			shift_mode, src_bi->bi_bh, dest_bi->bi_bh);
    }
#endif
}




/* copy mov_num items and mov_bytes of the (mov_num-1)th item to
   neighbor. Delete them from source */
int leaf_move_items (int shift_mode, struct tree_balance * tb, 
		     int mov_num, int mov_bytes, struct buffer_head * Snew)
{
    int ret_value;
    struct buffer_info dest_bi, src_bi;
    int first_last;

    leaf_define_dest_src_infos (shift_mode, tb, &dest_bi, &src_bi, &first_last, Snew);

    ret_value = leaf_copy_items (tb->tb_sb, &dest_bi, src_bi.bi_bh, first_last, mov_num, mov_bytes);

    leaf_delete_items (tb->tb_sb, &src_bi, first_last, (first_last == FIRST_TO_LAST) ? 0 : 
		       (B_NR_ITEMS(src_bi.bi_bh) - mov_num), mov_num, mov_bytes);

  
    return ret_value;
}


/* Shift shift_num items (and shift_bytes of last shifted item if shift_bytes != -1)
   from S[0] to L[0] and replace the delimiting key */
int leaf_shift_left (struct tree_balance * tb, int shift_num, int shift_bytes)
{
    struct buffer_head * S0 = PATH_PLAST_BUFFER (tb->tb_path);
    int i;

    /* move shift_num (and shift_bytes bytes) items from S[0] to left neighbor L[0] */
    i = leaf_move_items (LEAF_FROM_S_TO_L, tb, shift_num, shift_bytes, 0);

    if ( shift_num ) {
	if (B_NR_ITEMS (S0) == 0) { 
	    /* everything is moved from S[0] */

#ifdef CONFIG_REISERFS_CHECK
	    if ( shift_bytes != -1 )
		reiserfs_panic (tb->tb_sb, "vs-10270: leaf_shift_left: S0 is empty now, but shift_bytes != -1 (%d)", shift_bytes);

	    if (init_mode == M_PASTE || init_mode == M_INSERT) {
		print_tb (init_mode, init_item_pos, init_pos_in_item, &init_tb, "vs-10275");
		reiserfs_panic (tb->tb_sb, "vs-10275: leaf_shift_left: balance condition corrupted (%c)", init_mode);
	    }
#endif

	    if (PATH_H_POSITION (tb->tb_path, 1) == 0)
		replace_key(tb->tb_sb, tb->CFL[0], tb->lkey[0], PATH_H_PPARENT (tb->tb_path, 0), 0);

	} else {     
	    /* replace lkey in CFL[0] by 0-th key from S[0]; */
	    replace_key(tb->tb_sb, tb->CFL[0], tb->lkey[0], S0, 0);
      
#ifdef CONFIG_REISERFS_CHECK
	    if (shift_bytes != -1 && !(I_IS_DIRECTORY_ITEM (B_N_PITEM_HEAD (S0, 0))
				       && !ih_entry_count (B_N_PITEM_HEAD (S0, 0)))) {
		if (!is_left_mergeable (B_N_PITEM_HEAD (S0, 0), S0->b_size)) {
		    reiserfs_panic (tb->tb_sb, "vs-10280: leaf_shift_left: item must be mergeable");
		}
	    }
#endif
	}
    }
  
    return i;
}





/* CLEANING STOPPED HERE */




/* Shift shift_num (shift_bytes) items from S[0] to the right neighbor, and replace the delimiting key */
int leaf_shift_right (struct tree_balance * tb, int shift_num, int shift_bytes)
{
    int ret_value;

    /* move shift_num (and shift_bytes) items from S[0] to right neighbor R[0] */
    ret_value = leaf_move_items (LEAF_FROM_S_TO_R, tb, shift_num, shift_bytes, 0);

    /* replace rkey in CFR[0] by the 0-th key from R[0] */
    if (shift_num) {
	replace_key(tb->tb_sb, tb->CFR[0], tb->rkey[0], tb->R[0], 0);
    }

    return ret_value;
}



static void leaf_delete_items_entirely (struct super_block * sb,
					/*struct reiserfs_transaction_handle *th,*/
					struct buffer_info * bi,
					int first,
					int del_num);
/*  If del_bytes == -1, starting from position 'first' delete del_num items in whole in buffer CUR.
    If not. 
    If last_first == 0. Starting from position 'first' delete del_num-1 items in whole. Delete part of body of
    the first item. Part defined by del_bytes. Don't delete first item header
    If last_first == 1. Starting from position 'first+1' delete del_num-1 items in whole. Delete part of body of
    the last item . Part defined by del_bytes. Don't delete last item header.
*/
void leaf_delete_items (reiserfs_filsys_t fs,
			struct buffer_info * cur_bi,
			int last_first, 
			int first, int del_num, int del_bytes)
{
    struct buffer_head * bh;
    int item_amount = B_NR_ITEMS (bh = cur_bi->bi_bh);
    
#ifdef CONFIG_REISERFS_CHECK
    if ( !bh )
	reiserfs_panic (0, "leaf_delete_items: 10155: bh is not defined");
    
    if ( del_num < 0 )
	reiserfs_panic (0, "leaf_delete_items: 10160: del_num can not be < 0. del_num==%d", del_num);
    
    if ( first < 0 || first + del_num > item_amount )
	reiserfs_panic (0, "leaf_delete_items: 10165: invalid number of first item to be deleted (%d) or "
			"no so much items (%d) to delete (only %d)", first, first + del_num, item_amount);
#endif
    
    if ( del_num == 0 )
	return;
    
    if ( first == 0 && del_num == item_amount && del_bytes == -1 ) {
	make_empty_node (cur_bi);
	mark_buffer_dirty (bh);
	return;
    }
    
    if ( del_bytes == -1 )
	/* delete del_num items beginning from item in position first */
	leaf_delete_items_entirely (fs, cur_bi, first, del_num);
    else {
	if ( last_first == FIRST_TO_LAST ) {
	    /* delete del_num-1 items beginning from item in position first  */
	    leaf_delete_items_entirely (fs, cur_bi, first, del_num-1);
	    
	    /* delete the part of the first item of the bh do not
	       delete item header */
	    leaf_cut_from_buffer (fs, cur_bi, 0, 0, del_bytes);
	} else  {
	    struct item_head * ih;
	    int len;
	    
	    /* delete del_num-1 items beginning from item in position first+1  */
	    leaf_delete_items_entirely (fs, cur_bi, first+1, del_num-1);
	    
	    if (I_IS_DIRECTORY_ITEM(ih = B_N_PITEM_HEAD(bh, B_NR_ITEMS(bh)-1))) 	/* the last item is directory  */
	        /* len = numbers of directory entries in this item */
	        len = ih_entry_count(ih);
	    else
		/* len = body len of item */
 	        len = ih_item_len(ih);
	    
	    /* delete the part of the last item of the bh 
	       do not delete item header
	    */
	    leaf_cut_from_buffer (fs, cur_bi, B_NR_ITEMS(bh) - 1, len - del_bytes, del_bytes);
	}
    }
}


/* insert item into the leaf node in position before */
void leaf_insert_into_buf (struct super_block * s,
			   struct buffer_info * bi,
			   int before,
			   struct item_head * inserted_item_ih,
			   const char * inserted_item_body,
			   int zeros_number
			   )
{
    struct buffer_head * bh = bi->bi_bh;
    int nr;
    struct block_head * blkh;
    struct item_head * ih;
    int i;
    int last_loc, unmoved_loc;
    char * to;

    blkh = B_BLK_HEAD (bh);
    nr = blkh_nr_item(blkh);

#ifdef CONFIG_REISERFS_CHECK
    /* check free space */
    if (blkh_free_space(blkh) < ih_item_len(inserted_item_ih) + IH_SIZE)
	reiserfs_panic (0, "leaf_insert_into_buf: 10170: not enough free space: needed %d, available %d",
			ih_item_len(inserted_item_ih) + IH_SIZE,
                        blkh_free_space(blkh));
    if (zeros_number > ih_item_len(inserted_item_ih))
	reiserfs_panic (0, "vs-10172: leaf_insert_into_buf: zero number == %d, item length == %d", zeros_number, ih_item_len(inserted_item_ih));
#endif /* CONFIG_REISERFS_CHECK */


    /* get item new item must be inserted before */
    ih = B_N_PITEM_HEAD (bh, before);

    /* prepare space for the body of new item */
    last_loc = nr ? ih_location( &(ih[nr - before - 1]) ) : bh->b_size;
    unmoved_loc = before ? ih_location(ih-1) : bh->b_size;

    memmove (bh->b_data + last_loc - ih_item_len(inserted_item_ih), 
	     bh->b_data + last_loc, unmoved_loc - last_loc);

    to = bh->b_data + unmoved_loc - ih_item_len(inserted_item_ih);
    memset (to, 0, zeros_number);
    to += zeros_number;

    /* copy body to prepared space */
    if (inserted_item_body)
	//if (mem_mode == REISERFS_USER_MEM)
	//  copy_from_user (to, inserted_item_body, inserted_item_ih->ih_item_len - zeros_number);
	//else {
	memmove (to, inserted_item_body, ih_item_len(inserted_item_ih) - zeros_number);
    //}
    else
	memset(to, '\0', ih_item_len(inserted_item_ih) - zeros_number);
  
    /* insert item header */
    memmove (ih + 1, ih, IH_SIZE * (nr - before));
    memmove (ih, inserted_item_ih, IH_SIZE);
  
    /* change locations */
    for (i = before; i < nr + 1; i ++)
        set_ih_location( &(ih[i-before]), (unmoved_loc -= ih_item_len(&(ih[i-before]))));
  
    /* sizes, free space, item number */
    set_blkh_nr_item(blkh, blkh_nr_item(blkh) + 1 );
    set_blkh_free_space(blkh, blkh_free_space(blkh) -
                                (IH_SIZE + ih_item_len(inserted_item_ih)));

    mark_buffer_dirty(bh) ;

    if (bi->bi_parent) { 
        struct disk_child *t_dc;
        t_dc = B_N_CHILD (bi->bi_parent, bi->bi_position);
        set_dc_size(t_dc, dc_size(t_dc) + (IH_SIZE + ih_item_len(inserted_item_ih)));
	mark_buffer_dirty(bi->bi_parent) ;
    }

    if (who_is_this (bh->b_data, bh->b_size) != THE_LEAF)
	reiserfs_panic ("leaf_insert_into_buf: bad leaf %lu: %b",
			bh->b_blocknr, bh);
}


/* paste paste_size bytes to affected_item_num-th item. 
   When item is a directory, this only prepare space for new entries */
void leaf_paste_in_buffer (reiserfs_filsys_t fs,
			   struct buffer_info * bi,
			   int affected_item_num,
			   int pos_in_item,
			   int paste_size,
			   const char * body,
			   int zeros_number)
{
    struct buffer_head * bh = bi->bi_bh;
    int nr;
    struct block_head * blkh;
    struct item_head * ih;
    int i;
    int last_loc, unmoved_loc;


    blkh = B_BLK_HEAD(bh);
    nr = blkh_nr_item(blkh);

#ifdef CONFIG_REISERFS_CHECK
    /* check free space */
    if (blkh_free_space(blkh) < paste_size)
	reiserfs_panic (th->t_super, "vs-10175: leaf_paste_in_buffer: "
			"not enough free space: needed %d, available %d",
			paste_size, blkh_free_space(blkh));
    if (zeros_number > paste_size) {
	print_tb (init_mode, init_item_pos, init_pos_in_item, &init_tb, "10177");
	reiserfs_panic (th->t_super, "vs-10177: leaf_paste_in_buffer: "
			"zero number == %d, paste_size == %d", zeros_number, paste_size);
    }
#endif /* CONFIG_REISERFS_CHECK */


    /* item to be appended */
    ih = B_N_PITEM_HEAD(bh, affected_item_num);

    last_loc = ih_location( &(ih[nr - affected_item_num - 1]));
    unmoved_loc = affected_item_num ? ih_location(ih-1) : bh->b_size;  

    /* prepare space */
    memmove (bh->b_data + last_loc - paste_size, bh->b_data + last_loc,
	     unmoved_loc - last_loc);


    /* change locations */
    for (i = affected_item_num; i < nr; i ++)
        set_ih_location( &(ih[i-affected_item_num]),
            ih_location( &(ih[i-affected_item_num])) - paste_size );

    if ( body ) {
	if (!I_IS_DIRECTORY_ITEM(ih)) {
	    //if (mem_mode == REISERFS_USER_MEM) {
	    //memset (bh->b_data + unmoved_loc - paste_size, 0, zeros_number);
	    //copy_from_user (bh->b_data + unmoved_loc - paste_size + zeros_number, body, paste_size - zeros_number);
	    //} else 
	    {
		if (!pos_in_item) {
		    /* shift data to right */
		    memmove (bh->b_data + ih_location(ih) + paste_size, 
			     bh->b_data + ih_location(ih), ih_item_len(ih));
		    /* paste data in the head of item */
		    memset (bh->b_data + ih_location(ih), 0, zeros_number);
		    memcpy (bh->b_data + ih_location(ih) + zeros_number, body, paste_size - zeros_number);
		} else {
		    memset (bh->b_data + unmoved_loc - paste_size, 0, zeros_number);
		    memcpy (bh->b_data + unmoved_loc - paste_size + zeros_number, body, paste_size - zeros_number);
		}
	    }
	}
    }
    else
	memset(bh->b_data + unmoved_loc - paste_size,'\0',paste_size);

    set_ih_item_len(ih, ih_item_len(ih) + paste_size );

    /* change free space */
    set_blkh_free_space(blkh, blkh_free_space(blkh) - paste_size );

    mark_buffer_dirty(bh) ;

    if (bi->bi_parent) { 
        struct disk_child *t_dc;
        t_dc = B_N_CHILD (bi->bi_parent, bi->bi_position);
        set_dc_size(t_dc, dc_size(t_dc) + paste_size );
	mark_buffer_dirty(bi->bi_parent);
    }
    if (who_is_this (bh->b_data, bh->b_size) != THE_LEAF)
	reiserfs_panic ("leaf_paste_in_buffer: bad leaf %lu: %b",
			bh->b_blocknr, bh);
}

/* cuts DEL_COUNT entries beginning from FROM-th entry. Directory item
   does not have free space, so it moves DEHs and remaining records as
   necessary. Return value is size of removed part of directory item
   in bytes. */
static int leaf_cut_entries (struct buffer_head * bh,
			     struct item_head * ih, 
			     int from, int del_count)
{
    char * item;
    struct reiserfs_de_head * deh;
    int prev_record_offset;	/* offset of record, that is (from-1)th */
    char * prev_record;		/* */
    int cut_records_len;		/* length of all removed records */
    int i;
    int entry_count;


    /* first byte of item */
    item = bh->b_data + ih_location (ih);

    /* entry head array */
    deh = B_I_DEH (bh, ih);
    entry_count = ih_entry_count (ih);

    if (del_count == 0) {
	int shift;
	int last_location;

	last_location = deh_location (deh + entry_count - 1);
	shift = last_location - DEH_SIZE * entry_count;
	
	memmove (deh + entry_count, item + last_location,
		 ih_item_len (ih) - last_location);
	for (i = 0; i < entry_count; i ++)
	    deh[i].deh_location = cpu_to_le16 (deh_location (deh + i) - shift);
	return shift;
    }

    /* first byte of remaining entries, those are BEFORE cut entries
       (prev_record) and length of all removed records (cut_records_len) */
    prev_record_offset = (from ? deh_location(&(deh[from - 1])) : ih_item_len(ih));
    cut_records_len = prev_record_offset/*from_record*/ - deh_location(&(deh[from + del_count - 1]));
    prev_record = item + prev_record_offset;


    /* adjust locations of remaining entries */
    for (i = ih_entry_count (ih) - 1; i > from + del_count - 1; i --)
        set_deh_location(&(deh[i]), deh_location(&(deh[i])) - (DEH_SIZE * del_count ) );

    for (i = 0; i < from; i ++)
        set_deh_location(&(deh[i]), deh_location(&(deh[i])) - (DEH_SIZE * del_count + cut_records_len ) );

    set_entry_count (ih, ih_entry_count (ih) - del_count);

    /* shift entry head array and entries those are AFTER removed entries */
    memmove ((char *)(deh + from),
	     deh + from + del_count, 
	     prev_record - cut_records_len - (char *)(deh + from + del_count));
  
    /* shift records, those are BEFORE removed entries */
    memmove (prev_record - cut_records_len - DEH_SIZE * del_count,
	     prev_record, item + ih_item_len(ih) - prev_record);

    return DEH_SIZE * del_count + cut_records_len;
}


/*  when cut item is part of regular file
        pos_in_item - first byte that must be cut
        cut_size - number of bytes to be cut beginning from pos_in_item
 
   when cut item is part of directory
        pos_in_item - number of first deleted entry
        cut_size - count of deleted entries
    */
void leaf_cut_from_buffer (reiserfs_filsys_t fs,
			   struct buffer_info * bi, int cut_item_num,
			   int pos_in_item, int cut_size)
{
    int nr;
    struct buffer_head * bh = bi->bi_bh;
    struct block_head * blkh;
    struct item_head * ih;
    int last_loc, unmoved_loc;
    int i;

    blkh = B_BLK_HEAD(bh);
    nr = blkh_nr_item(blkh);

    /* item head of truncated item */
    ih = B_N_PITEM_HEAD (bh, cut_item_num);

    if (I_IS_DIRECTORY_ITEM (ih)) {
        /* first cut entry ()*/
        cut_size = leaf_cut_entries (bh, ih, pos_in_item, cut_size);
        if (pos_in_item == 0) {
	        /* change key */
#ifdef CONFIG_REISERFS_CHECK
            if (cut_item_num)
                reiserfs_panic (th->t_super, "leaf_cut_from_buffer: 10190: " 
                    "when 0-th enrty of item is cut, that item must be first in the node, not %d-th", cut_item_num);
#endif
            /* change item key by key of first entry in the item */
	    ih->ih_key.u.k_offset_v1.k_offset = B_I_DEH (bh, ih)->deh_offset; /* both 32-bit LE */
	    
            /*memcpy (&ih->ih_key.k_offset, &(B_I_DEH (bh, ih)->deh_offset), SHORT_KEY_SIZE);*/
	    }
    } else {
        /* item is direct or indirect */
#ifdef CONFIG_REISERFS_CHECK
        if (I_IS_STAT_DATA_ITEM (ih))
	    reiserfs_panic (th->t_super, "leaf_cut_from_buffer: 10195: item is stat data");
	
        if (pos_in_item && pos_in_item + cut_size != ih_item_len(ih) )
            reiserfs_panic (th->t_super, "cut_from_buf: 10200: invalid offset (%lu) or trunc_size (%lu) or ih_item_len (%lu)",
			    pos_in_item, cut_size, ih_item_len(ih));
#endif

        /* shift item body to left if cut is from the head of item */
        if (pos_in_item == 0) {
            memmove (bh->b_data + ih_location(ih), bh->b_data + ih_location(ih) + cut_size,
                ih_item_len(ih) - cut_size);

            /* change key of item */
            if (I_IS_DIRECT_ITEM(ih)) {
                //ih->ih_key.k_offset += cut_size;
                set_offset (key_format (&ih->ih_key), &ih->ih_key, get_offset (&ih->ih_key) + cut_size);
            } else {
                //ih->ih_key.k_offset += (cut_size / UNFM_P_SIZE) * bh->b_size;
                set_offset (key_format (&ih->ih_key), &ih->ih_key, 
			    get_offset (&ih->ih_key) + (cut_size / UNFM_P_SIZE) * bh->b_size);
#ifdef CONFIG_REISERFS_CHECK
                if ( ih_item_len(ih) == cut_size && ih_free_space (ih) )
                    reiserfs_panic (th->t_super, "leaf_cut_from_buf: 10205: invalid ih_free_space (%lu)", ih_free_space (ih));
#endif
	        }
	    }
    }
  

    /* location of the last item */
    last_loc = ih_location( &(ih[nr - cut_item_num - 1]) );

    /* location of the item, which is remaining at the same place */
    unmoved_loc = cut_item_num ? ih_location(ih-1) : bh->b_size;


    /* shift */
    memmove (bh->b_data + last_loc + cut_size, bh->b_data + last_loc,
	       unmoved_loc - last_loc - cut_size);

    /* change item length */
    set_ih_item_len(ih, ih_item_len(ih) - cut_size);
  
    if (I_IS_INDIRECT_ITEM(ih)) {
        if (pos_in_item)
            //ih->u.ih_free_space = 0;
            set_free_space (ih, 0);
    }

    /* change locations */
    for (i = cut_item_num; i < nr; i ++)
        set_ih_location( &(ih[i-cut_item_num]),
            ih_location( &(ih[i-cut_item_num])) + cut_size );

    /* size, free space */
    set_blkh_free_space(blkh, blkh_free_space(blkh) + cut_size);

    mark_buffer_dirty(bh);
    
    if (bi->bi_parent) { 
        struct disk_child *t_dc;
        t_dc = B_N_CHILD (bi->bi_parent, bi->bi_position);
        set_dc_size(t_dc, dc_size(t_dc) - cut_size);
        mark_buffer_dirty(bi->bi_parent);
    }
    if (who_is_this (bh->b_data, bh->b_size) != THE_LEAF)
	reiserfs_panic ("leaf_cut_from_buffer: bad leaf %lu: %b",
			bh->b_blocknr, bh);
}


/* delete del_num items from buffer starting from the first'th item */
static void leaf_delete_items_entirely (reiserfs_filsys_t fs,
					struct buffer_info * bi,
					int first, int del_num)
{
    struct buffer_head * bh = bi->bi_bh;
    int nr;
    int i, j;
    int last_loc, last_removed_loc;
    struct block_head * blkh;
    struct item_head * ih;


#ifdef CONFIG_REISERFS_CHECK
    if (bh == NULL)
	reiserfs_panic (0, "leaf_delete_items_entirely: 10210: buffer is 0");

    if (del_num < 0)
	reiserfs_panic (0, "leaf_delete_items_entirely: 10215: del_num less than 0 (%d)", del_num);
#endif /* CONFIG_REISERFS_CHECK */
    
    if (del_num == 0)
	return;
    
    blkh = B_BLK_HEAD(bh);
    nr = blkh_nr_item(blkh);

#ifdef CONFIG_REISERFS_CHECK
    if (first < 0 || first + del_num > nr)
	reiserfs_panic (0, "leaf_delete_items_entirely: 10220: first=%d, number=%d, there is %d items", first, del_num, nr);
#endif /* CONFIG_REISERFS_CHECK */

    if (first == 0 && del_num == nr) {
	/* this does not work */
	make_empty_node (bi);
	
	mark_buffer_dirty(bh);
	return;
    }
    
    ih = B_N_PITEM_HEAD (bh, first);
    
    /* location of unmovable item */
    j = (first == 0) ? bh->b_size : ih_location(ih-1);
    
    /* delete items */
    last_loc = ih_location( &(ih[nr-1-first]) );
    last_removed_loc = ih_location( &(ih[del_num-1]));
    
    memmove (bh->b_data + last_loc + j - last_removed_loc,
	     bh->b_data + last_loc, last_removed_loc - last_loc);
    
    /* delete item headers */
    memmove (ih, ih + del_num, (nr - first - del_num) * IH_SIZE);
    
    /* change item location */
    for (i = first; i < nr - del_num; i ++)
        set_ih_location( &(ih[i-first]),
            ih_location( &(ih[i-first]) ) + (j - last_removed_loc));
    
    /* sizes, item number */
    set_blkh_nr_item(blkh, blkh_nr_item(blkh) - del_num);
    set_blkh_free_space(blkh, blkh_free_space(blkh) +
                                (j - last_removed_loc + IH_SIZE * del_num));
    
    mark_buffer_dirty(bh);
    
    if (bi->bi_parent) {
        struct disk_child *t_dc;
        t_dc = B_N_CHILD (bi->bi_parent, bi->bi_position);
        set_dc_size(t_dc, dc_size(t_dc) -
                                (j - last_removed_loc + IH_SIZE * del_num));
	mark_buffer_dirty(bi->bi_parent);
    }
    if (who_is_this (bh->b_data, bh->b_size) != THE_LEAF)
	reiserfs_panic ("leaf_delete_items_entirely: bad leaf %lu: %b",
			bh->b_blocknr, bh);
}





/* paste new_entry_count entries (new_dehs, records) into position before to item_num-th item */
void leaf_paste_entries (struct buffer_head * bh,
			 int item_num, int before, int new_entry_count,
			 struct reiserfs_de_head * new_dehs,
			 const char * records, int paste_size)
{
    struct item_head * ih;
    char * item;
    struct reiserfs_de_head * deh;
    char * insert_point;
    int i, old_entry_num;

    if (new_entry_count == 0)
        return;

    ih = B_N_PITEM_HEAD(bh, item_num);

#ifdef CONFIG_REISERFS_CHECK
    /* make sure, that item is directory, and there are enough records in it */
    if (!I_IS_DIRECTORY_ITEM (ih))
	reiserfs_panic (0, "leaf_paste_entries: 10225: item is not directory item");

    if (ih_entry_count (ih) < before)
	reiserfs_panic (0, "leaf_paste_entries: 10230: there are no entry we paste entries before. entry_count = %d, before = %d",
			ih_entry_count (ih), before);
#endif


    /* first byte of dest item */
    item = bh->b_data + ih_location(ih);

    /* entry head array */
    deh = B_I_DEH (bh, ih);

    /* new records will be pasted at this point */
    insert_point = item + (before ? deh_location(&(deh[before - 1])) : (ih_item_len(ih) - paste_size));

    /* adjust locations of records that will be AFTER new records */
    for (i = ih_entry_count (ih) - 1; i >= before; i --)
        set_deh_location(&(deh[i]), deh_location(&(deh[i])) + (DEH_SIZE * new_entry_count ) );

    /* adjust locations of records that will be BEFORE new records */
    for (i = 0; i < before; i ++)
        set_deh_location(&(deh[i]), deh_location(&(deh[i])) + paste_size );

    old_entry_num = ih_entry_count (ih);
    //I_ENTRY_COUNT(ih) += new_entry_count;
    set_entry_count (ih, old_entry_num + new_entry_count);

    /* prepare space for pasted records */
    memmove (insert_point + paste_size, insert_point, item + (ih_item_len(ih) - paste_size) - insert_point);

    /* copy new records */
    memcpy (insert_point + DEH_SIZE * new_entry_count, records,
	    paste_size - DEH_SIZE * new_entry_count);
  
    /* prepare space for new entry heads */
    deh += before;
    memmove ((char *)(deh + new_entry_count), deh, insert_point - (char *)deh);

    /* copy new entry heads */
    deh = (struct reiserfs_de_head *)((char *)deh);
    memcpy (deh, new_dehs, DEH_SIZE * new_entry_count);

    /* set locations of new records */
    for (i = 0; i < new_entry_count; i ++)
        set_deh_location(&(deh[i]), deh_location(&(deh[i])) + 
	    (- deh_location(&(new_dehs[new_entry_count - 1])) + insert_point +
            DEH_SIZE * new_entry_count - item));


    /* change item key if neccessary (when we paste before 0-th entry */
    if (!before)
	ih->ih_key.u.k_offset_v1.k_offset = new_dehs->deh_offset; /* both 32-bit LE */


#ifdef CONFIG_REISERFS_CHECK
    {
	int prev, next;
	/* check record locations */
	deh = B_I_DEH (bh, ih);
	for (i = 0; i < ih_entry_count(ih); i ++) {
	    next = (i < ih_entry_count(ih) - 1) ? deh_location(&(deh[i + 1])) : 0;
	    prev = (i != 0) ? deh_location(&(deh[i - 1])) : 0;
      
	    if (prev && prev <= deh_location(&(deh[i])))
		reiserfs_warning ("vs-10240: leaf_paste_entries: directory item corrupted (%d %d)\n", prev, deh_location(&(deh[i])));
	    if (next && next >= deh_location(&(deh[i])))
		reiserfs_warning ("vs-10250: leaf_paste_entries: directory item corrupted (%d %d)\n", prev, deh_location(&(deh[i])));
	}
    }
#endif

}



/* wrappers for operations on one separated node */

void delete_item (reiserfs_filsys_t fs,
		  struct buffer_head * bh, int item_num)
{
    struct buffer_info bi;

    bi.bi_bh = bh;
    bi.bi_parent = 0;
    bi.bi_position = 0;
    leaf_delete_items_entirely (fs, &bi, item_num, 1);
}


void cut_entry (reiserfs_filsys_t fs, struct buffer_head * bh,
		int item_num, int entry_num, int del_count)
{
    struct buffer_info bi;

    bi.bi_bh = bh;
    bi.bi_parent = 0;
    bi.bi_position = 0;
    leaf_cut_from_buffer (fs, &bi, item_num, entry_num, del_count);
}

