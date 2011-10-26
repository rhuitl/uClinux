/*
 * Copyright 1996-2001 Hans Reiser
 */

#include "fsck.h"



static unsigned long tmp_zeroed;

/* pass 0 scans the partition (used part). It creates two maps which will be
   used on the pass 1. These are a map of nodes looking like leaves and a map
   of "bad" unformatted nodes. */


/* leaves */
reiserfs_bitmap_t leaves_bitmap;
#define pass0_is_leaf(block) __is_marked (leaves, block)
#define pass0_mark_leaf(block) __mark (leaves, block)

/* nodes which are referred to from only one indirect item */
reiserfs_bitmap_t good_unfm_bitmap;
#define pass0_is_good_unfm(block) __is_marked (good_unfm, block)
#define pass0_mark_good_unfm(block) __mark (good_unfm, block)
#define pass0_unmark_good_unfm(block) __unmark (good_unfm, block)

/* nodes which are referred to from more than one indirect item */
reiserfs_bitmap_t bad_unfm_bitmap;
#define pass0_is_bad_unfm(block) __is_marked (bad_unfm, block)
#define pass0_mark_bad_unfm(block) __mark (bad_unfm, block)
#define pass0_unmark_bad_unfm(block) __unmark (bad_unfm, block)



/* there are three way to say of which blocks the tree should be built off:
 default - */
static void make_aux_bitmaps (reiserfs_filsys_t fs)
{

    /* bitmap of leaves found on the device. It will be saved if -c specified */
    leaves_bitmap = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));

    good_unfm_bitmap = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));

    bad_unfm_bitmap = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));

}


/* register block some indirect item points to */
static void register_unfm (unsigned long block)
{
    if (!pass0_is_good_unfm (block) && !pass0_is_bad_unfm (block)) {
	/* this block was not pointed by other indirect items yet */
	pass0_mark_good_unfm (block);
	return;
    }

    if (pass0_is_good_unfm (block)) {
	/* block was pointed once already, unmark it in bitmap of good
           unformatted nodes and mark in bitmap of bad pointers */
	pass0_unmark_good_unfm (block);
	pass0_mark_bad_unfm (block);
	return;
    }

    assert (pass0_is_bad_unfm (block));
}


/* 'upper' item is correct if 'upper + 2' exists and its key is greater than
   key of 'upper' */
static int upper_correct (struct buffer_head * bh, struct item_head * upper,
			  int upper_item_num)
{
    if (upper_item_num + 2 < B_NR_ITEMS (bh)) {
	if (comp_keys (&upper->ih_key, &(upper + 2)->ih_key) != -1)
	    /* item-num's item is out of order of order */
	    return 0;
	return 1;
    }
    
    /* there is no item above the "bad pair" */
    return 2;
}


/* 'lower' item is correct if 'lower - 2' exists and its key is smaller than
   key of 'lower' */
static int lower_correct (struct buffer_head * bh, struct item_head * lower,
			  int lower_item_num)
{
    if (lower_item_num - 2 >= 0) {
	if (comp_keys (&(lower - 2)->ih_key, &lower->ih_key) != -1)
	    return 0;
	return 1;
    }
    return 2;
}


/* return 1 if something was changed */
static int correct_key_format (struct item_head * ih)
{
    int dirty = 0;

    if (is_stat_data_ih (ih)) {
	/* for stat data we have no way to check whether key format in item
	   head matches to the key format found from the key directly */
	if (ih_item_len (ih) == SD_V1_SIZE) {
	    if (ih_key_format (ih) != KEY_FORMAT_1) {
		fsck_log ("correct_key_format: ih_key_format of (%H) is set to format 1\n",
			  ih);
		set_ih_key_format (ih, KEY_FORMAT_1);
		return 1;
	}
	    return 0;
	}
	if (ih_item_len (ih) == SD_SIZE) {
	    if (ih_key_format (ih) != KEY_FORMAT_2) {
		fsck_log ("correct_key_format: ih_key_format of (%H) is set to format 2\n",
			  ih);
		set_ih_key_format (ih, KEY_FORMAT_2);
		return 1;
	    }
	    return 0;
	}
	
	die ("stat data of wrong length");
    }
    
    if (key_format (&ih->ih_key) != ih_key_format (ih)) {
	fsck_log ("correct_key_format: ih_key_format of (%H) is set to format found in the key\n",
		  ih);
	set_ih_key_format (ih, key_format (&ih->ih_key));
	dirty = 1;
    }
    
    if (type_unknown (&ih->ih_key)) {
	/* FIXME: */
	set_type (key_format (&ih->ih_key), &ih->ih_key, TYPE_DIRECT);
	dirty = 1;	
    }
    
    return dirty;
}

#if 0
/* fixme: we might try all available hashes */
static int prob_name (reiserfs_filsys_t fs,
		      char ** name, int max_len, __u32 deh_offset)
{
    int start; /* */
    int len;

    for (start = 0; start < max_len; start ++) {
	for (len = 0; len < max_len - start; len ++) {
	    if (is_properly_hashed (fs, *name + start, len + 1, deh_offset)) {
		*name = *name + start;
		return len + 1;
	    }
	}
    }
    return 0;
}
#endif


static void hash_hits_init (reiserfs_filsys_t fs)
{
    stats (fs)->hash_amount = known_hashes ();
    stats (fs)->hash_hits = getmem (sizeof (unsigned long) * stats (fs)->hash_amount);
    return;
}


static void add_hash_hit (reiserfs_filsys_t fs, int hash_code)
{
    stats (fs)->hash_hits [hash_code] ++;
}


/* deh_location look reasonable, try to find name length. return 0 if
   we failed */
static int try_to_get_name_length (struct item_head * ih, struct reiserfs_de_head * deh,
				int i)
{
    int len;

    len = name_length (ih, deh, i);
    if (i == 0 || !de_bad_location (deh - 1))
	return (len > 0) ? len : 0;

    /* previous entry had bad location so we had no way to find
       name length */
    return 0;
}



/* define this if you are using -t to debug recovering of corrupted directory
   item */
#define DEBUG_VERIFY_DENTRY
#undef DEBUG_VERIFY_DENTRY


/* check directory item and try to recover something */
static int verify_directory_item (reiserfs_filsys_t fs, struct buffer_head * bh,
				  int item_num)
{
    struct item_head * ih;
    struct item_head tmp;
    char * item;
    struct reiserfs_de_head * deh;
    char * name;
    int name_len;
    int bad;
    int i, j;
#if 0
    int bad_entries; /* how many bad neighboring entries */
    int total_entry_len;
    char * entries, * end;
#endif
    int dirty;
    int entry_count;
    int hash_code;
    int bad_locations;

#ifdef DEBUG_VERIFY_DENTRY
    char * direntries;
#endif


    ih = B_N_PITEM_HEAD (bh, item_num);
    item = B_I_PITEM (bh,ih);
    deh = (struct reiserfs_de_head *)item;

    dirty = 0;
    bad_locations = 0;
    entry_count = ih_entry_count (ih);


    /* check deh_location */
    for (i = 0; i < ih_entry_count (ih); i ++) {
	/* silently fix deh_state */
	if (deh [i].deh_state != (1 << DEH_Visible)) {
	    deh [i].deh_state = cpu_to_le16 (1 << DEH_Visible);
	    mark_buffer_dirty (bh);
	}
	if (dir_entry_bad_location (deh + i, ih, !i))
	    mark_de_bad_location (deh + i);
    }

#ifdef DEBUG_VERIFY_DENTRY
    direntries = getmem (ih_entry_count (ih) * sizeof (int));

    printf ("entries with bad locations: ");
    for (i = 0; i < ih_entry_count (ih); i ++) {
	if (de_bad_location (deh + i))
	    printf ("%d ", i);
    }
    printf ("\n");
#endif /* DEBUG_VERIFY_DENTRY */


    /* find entries names in which have mismatching deh_offset */
    for (i = ih_entry_count (ih) - 1; i >= 0; i --) {
	if (de_bad (deh + i))
	    /* bad location */
	    continue;

	if (i) {
	    if (deh_location (deh + i - 1) < deh_location (deh + i))
		mark_de_bad_location (deh + i - 1);
	}

	name = name_in_entry (deh + i, i);
	/* we found a name, but we not always we can get its length as
           it depends on deh_location of previous entry */
	name_len = try_to_get_name_length (ih, deh + i, i);

#ifdef DEBUG_VERIFY_DENTRY
	if (name_len == 0)
	    printf ("trying to find name length for %d-th entry\n", i);
#endif /* DEBUG_VERIFY_DENTRY */
	if (is_dot (name, name_len)) {
	    if (i != 0)
		fsck_log ("block %lu: item %d: \".\" is %d-th entry\n",
			  bh->b_blocknr, item_num, i);
	    /* check and fix "." */
	    
	    if (deh_offset (deh + i) != DOT_OFFSET) {
		set_deh_offset(&(deh[i]), DOT_OFFSET);
		mark_buffer_dirty (bh);
	    }
	    /* "." must point to the directory it is in */
	    if (not_of_one_file (&(deh[i].deh_dir_id), &(ih->ih_key))) { /* endian safe */
		fsck_log ("verify_direntry: block %lu, item %H has entry \".\" "
			  "pointing to (%K) instead of (%K)\n", 
			  bh->b_blocknr, ih,
			  &(deh[i].deh_dir_id), &(ih->ih_key));
		deh[i].deh_dir_id = ih->ih_key.k_dir_id; /* both LE */
		deh[i].deh_objectid = ih->ih_key.k_objectid; /* both LE */
		mark_buffer_dirty (bh);
	    }
	} else if (is_dot_dot (name, name_len)) {
	    if (i != 1)
		fsck_log ("block %lu: item %d: \"..\" is %d-th entry\n",
			  bh->b_blocknr, item_num, i);
	    
	    /* check and fix ".." */
	    if (deh_offset (deh + i) != DOT_DOT_OFFSET)
		set_deh_offset(&(deh[i]), DOT_DOT_OFFSET);
	} else {
	    int min_length, max_length;

	    /* check other name */

	    if (name_len == 0) {
		/* we do not know the length of name - we will try to find it */
		min_length = 1;
		max_length = item + ih_item_len (ih) - name;
	    } else
		/* we kow name length, so we will try only one name length */
		min_length = max_length = name_len;

	    for (j = min_length; j <= max_length; j ++) {
		hash_code = find_hash_in_use (name, j,
					      GET_HASH_VALUE (deh_offset (deh + i)),
					      rs_hash (fs->s_rs));
		add_hash_hit (fs, hash_code);
		if (code2func (hash_code) != 0) {
		    /* deh_offset matches to some hash of the name */
		    if (!name_len) {
			fsck_log ("pass0: block %lu, item %H: entry %d. found a name \"%.*s\" "
				  "matching to deh_offset %u. FIXME: should set deh_location "
				  "of previous entry (not ready)\n",
				  bh->b_blocknr, ih, i, j, name, deh_offset (deh + i));
			/* FIXME: if next byte is 0 we think that the name is aligned to 8 byte boundary */
			if (i) {
			    set_deh_location( &(deh[i - 1]),
                                deh_location (deh + i) +
                                ((name[j] || SB_VERSION (fs) ==
                                REISERFS_VERSION_1) ? j : ROUND_UP (j)));
			    mark_de_good_location (deh + i - 1);
			    mark_buffer_dirty (bh);
			}
		    }
		    break;
		}
	    }
	    if (j == max_length + 1) {
		/* deh_offset does not match to anything. it will be
		   deleted for now, but maybe we could just fix a
		   deh_offset if it is in ordeer */
		mark_de_bad_offset (deh + i);
	    }
	}
    } /* for */



#if 0
    /* find entries names in which have mismatching deh_offset */
    for (i = 0; i < ih_entry_count (ih); i ++) {
	if (de_bad (deh + i))
	    /* bad location */
	    continue;

	name = name_in_entry (deh + i, i);
	/* we found a name, but we not always we can get its length as
           it depends on deh_location of previous entry */
	name_len = try_to_get_name_length (ih, deh + i, i);

	if (i == 0 && is_dot (name, name_len)) {
	    
	    /* check and fix "." */
	    
	    if (deh_offset (deh + i) != DOT_OFFSET) {
		deh[i].deh_offset = cpu_to_le32 (DOT_OFFSET);
	    }
	    /* "." must point to the directory it is in */
	    if (not_of_one_file (&(deh[i].deh_dir_id), &(ih->ih_key))) {
		fsck_log ("verify_direntry: block %lu, item %H has entry \".\" "
			  "pointing to (%K) instead of (%K)\n", 
			  bh->b_blocknr, ih,
			  &(deh[i].deh_dir_id), &(ih->ih_key));
		deh[i].deh_dir_id = ih->ih_key.k_dir_id; /* both 32 bit LE */
		deh[i].deh_objectid = ih->ih_key.k_objectid; /* both 32 bit LE */
		mark_buffer_dirty (bh);
	    }
	} else if (i == 1 && is_dot_dot (name, name_len)) {
	    
	    /* check and fix ".." */

	    if (deh_offset (deh + i) != DOT_DOT_OFFSET)
		deh[i].deh_offset = cpu_to_le32 (DOT_DOT_OFFSET);
	} else {
	    int min_length, max_length;

	    /* check other name */

	    if (name_len == 0) {
		/* we do not know the length of name - we will try to find it */
		min_length = 1;
		max_length = item + ih_item_len (ih) - name;
	    } else
		/* we kow name length, so we will try only one name length */
		min_length = max_length = name_len;

	    for (j = min_length; j <= max_length; j ++) {
		hash_code = find_hash_in_use (name, j,
					      GET_HASH_VALUE (deh_offset (deh + i)),
					      rs_hash (fs->s_rs));
		add_hash_hit (fs, hash_code);
		if (code2func (hash_code) != 0) {
		    /* deh_offset matches to some hash of the name */
		    if (!name_len) {
			fsck_log ("pass0: block %lu, item %H: entry %d. found a name \"%.*s\" "
				  "matching to deh_offset %u. FIXME: should set deh_location "
				  "of previous entry (not ready)\n",
				  bh->b_blocknr, ih, i, j, name, deh_offset (deh + i));
			/* FIXME: if next byte is 0 we think that the name is aligned to 8 byte boundary */
			deh[i - 1].deh_location = cpu_to_le16 (deh_location (deh + i) +
							       ((name[j] || SB_VERSION (fs) == REISERFS_VERSION_1) ? j : ROUND_UP (j)));
		    }
		    break;
		}
	    }
	    if (j == max_length + 1) {
		/* deh_offset does not match to anything. it will be
		   deleted for now, but maybe we could just fix a
		   deh_offset if it is in ordeer */
		mark_de_bad_offset (deh + i);
	    }
	}
   }
 #endif

 #ifdef DEBUG_VERIFY_DENTRY
     printf ("entries with mismatching deh_offsets: ");
     for (i = 0; i < ih_entry_count (ih); i ++) {
       if (de_bad_offset (deh + i))
           printf ("%d ", i);
     }
     printf ("\n");
 #endif /* DEBUG_VERIFY_DENTRY */


     /* correct deh_locations such that code cutting entries will not get
        screwed up */
     {
       int prev_loc;
       int loc_fixed;


       prev_loc = ih_item_len (ih);
       for (i = 0; i < ih_entry_count (ih); i ++) {
           loc_fixed = 0;
           if (de_bad_location (deh + i)) {
               set_deh_location(&(deh[i]), prev_loc/* - 1*/);
               mark_buffer_dirty (bh);
               loc_fixed = 1;
           } else {
               if (deh_location (deh + i) >= prev_loc) {
                   set_deh_location(&(deh[i]), prev_loc/* - 1*/);
                   mark_buffer_dirty (bh);
                   loc_fixed = 1;
               }
           }

           prev_loc = deh_location (deh + i);

           if (i == ih_entry_count (ih) - 1) {
               /* last entry starts right after an array of dir entry headers */
               if (!de_bad (deh + i) &&
                   deh_location (deh + i) != (DEH_SIZE * ih_entry_count (ih))) {

                   /* free space in the directory item */
                   fsck_log ("verify_direntry: block %lu, item %H has free
pace\n",
                             bh->b_blocknr, ih);
                   cut_entry (fs, bh, item_num, ih_entry_count (ih), 0);
               }
               if (deh_location (deh + i) != (DEH_SIZE * ih_entry_count (ih)))
               {

                   set_deh_location(&(deh[i]), DEH_SIZE * ih_entry_count (ih));
                   loc_fixed = 1;
                   mark_buffer_dirty (bh);
               }
           }

 #ifdef DEBUG_VERIFY_DENTRY
           if (loc_fixed)
               direntries [i] = 1;
 #endif
       } /* for */

 #ifdef DEBUG_VERIFY_DENTRY
       printf ("entries with fixed deh_locations: ");
       for (i = 0; i < ih_entry_count (ih); i ++) {
           if (direntries [i])
               printf ("%d ", i);
       }
       printf ("\n");
 #endif /* DEBUG_VERIFY_DENTRY */

     }

 #ifdef DEBUG_VERIFY_DENTRY
     printf (" N  location name\n");
     for (i = 0; i < ih_entry_count (ih); i ++) {
       if (de_bad (deh + i) ||
           (i && de_bad (deh + i - 1)) || /* previous entry marked bad */
           (i < ih_entry_count (ih) - 1 && de_bad (deh + i + 1))) { /* next
ntry is marked bad */
           /* print only entries to be deleted and their nearest neighbors */
           printf ("%3d: %8d ", i, deh_location (deh + i));
           if (de_bad (deh + i))
               printf ("will be deleted\n");
           else
               printf ("\"%.*s\"\n", name_length (ih, deh + i, i),
                       name_in_entry (deh + i, i));
       }
     }
 #endif

     bad = 0;
     tmp = *ih;

     /* delete entries which are marked bad */
     for (i = 0; i < ih_entry_count (ih); i ++) {
       deh = B_I_DEH (bh, ih) + i;
       if (de_bad (deh)) {
           bad ++;
           if (ih_entry_count (ih) == 1) {
               delete_item (fs, bh, item_num);
               break;
           } else {
               cut_entry (fs, bh, item_num, i, 1);
           }
	   i --;
	}
    }
    
    if (bad == ih_entry_count (&tmp)) {
	fsck_log ("pass0: block %lu, item %H - all entries were deleted\n", bh->b_blocknr, &tmp);
	return 0;
    }

    deh = B_I_DEH (bh, ih);
    if (get_offset (&ih->ih_key) != deh_offset (deh)) {
	fsck_log ("verify_direntry: block %lu, item %H:  k_offset and deh_offset %u mismatched\n",
		  bh->b_blocknr, ih, deh_offset (deh));
	set_offset (KEY_FORMAT_1, &ih->ih_key, deh_offset (deh));
	mark_buffer_dirty (bh);
    }
    
    if (bad)
	fsck_log ("pass0: block %lu, item %H: %d entries were deleted of \n",
		  bh->b_blocknr, &tmp, bad);
	
    return 0;

#if 0

    /* FIXME: temporary */
    if (bad_locations > ih_entry_count (ih) / 2) {
	fsck_log ("pass0: block %u: item %d (%H) had too bad directory - deleted\n",
		  bh->b_blocknr, item_num, ih);
	delete_item (fs, bh, item_num);
	return 0;
    }

    if (!dirty)
	return 0;
    
    /* something is broken */

    fsck_log ("pass0: block %lu: %d-th item (%H) has %d bad entries..",
	      bh->b_blocknr, item_num, ih, dirty);

    if (get_offset (&ih->ih_key) == DOT_OFFSET) {
	/* first item of directory - make sure that "." and ".." are in place */
	if (deh_offset (deh) != DOT_OFFSET || name_in_entry (deh, 0)[0] != '.') {
	    set_deh_offset(deh, DOT_OFFSET);
	    name_in_entry (deh, 0)[0] = '.';
	}
	if (deh_offset (deh + 1) != DOT_DOT_OFFSET ||
	    name_in_entry (deh + 1, 1)[0] != '.' || name_in_entry (deh + 1, 1)[1] != '.') {
	    set_deh_offset((deh + 1), DOT_DOT_OFFSET);
	    name_in_entry (deh + 1, 1)[0] = '.';
	    name_in_entry (deh + 1, 1)[1] = '.';
	}
    }

    end = item + ih_item_len (ih);
    deh += ih_entry_count (ih);
    entries = (char *)deh;
    total_entry_len = ih_item_len (ih) - DEH_SIZE * ih_entry_count (ih);
    i = ih_entry_count (ih);

    bad_entries = 0;
    do {
	i --;
	deh --;
	name_len = prob_name (fs, &entries, total_entry_len, deh_offset (deh));
	if (!name_len) {
	    if (!bad_entries) {
                set_deh_location(deh, entries - item);
	    } else {
                set_deh_location(deh, deh_location((deh + 1)) + 1 );
	    }
	    bad_entries ++;
	    
	    /*fsck_log ("verify_directory_item: entry %d: in string \'%s\' there is no substring matching hash %ld\n",
	      i, bad_name (entries, total_entry_len), masked_offset);*/
	    mark_de_bad (deh);
	    continue;
	}
	bad_entries = 0;
	/*fsck_log ("verify_directory_item: entry %d: found \"%s\" name matching hash %ld\n",
	  i, bad_name (entries, name_len), masked_offset);*/
	
	/* 'entries' points now to the name which match given offset -
           so, set deh_location */
        set_deh_location(deh, entries - item);
	deh->deh_state = 0;
	mark_de_visible (deh);
	
	entries += name_len;
	total_entry_len = end - entries;
	/* skip padding zeros */
	while (!*entries) {
	    entries ++;
	    total_entry_len --;
	}
	/* 'entries' points now at the place where next (previous)
           entry should start */
    } while ((char *)deh != item);
    
    
    /* fixme: this will not work if all entries are to be deleted */
    for (i = 0; i < ih_entry_count (ih); i ++, deh ++) {
	deh = (struct reiserfs_de_head *)B_I_PITEM (bh, ih) + i;
	if (de_bad (deh)) {
	    if (ih_entry_count (ih) == 1) {
		delete_item (fs, bh, i);
		break;
	    } else {
		cut_entry (fs, bh, item_num, i);
	    }
	    i --;
	}
/*
  fsck_log ("verify_directory_item: %d-th entry is to be deleted: "
  "\"%s\" does not match to hash %lu\n", 
  i, bad_name (name_in_entry (deh, i), name_length (ih, deh, i)),
  deh_offset (deh));
*/
    }
    
    fsck_log ("%d entries were deleted\n", entry_count - ih_entry_count (ih));
    mark_buffer_dirty (bh);

    
    return 0;

#endif
}


/* do this on pass 0 with every leaf marked used */

/* FIXME: we can improve fixing of broken keys: we can ssfe direct items which
   go after stat data and have broken keys */
static void pass0_correct_leaf (reiserfs_filsys_t fs,
				struct buffer_head * bh)
{
    int i, j;
    struct item_head * ih;
    __u32 * ind_item;
    unsigned long unfm_ptr;
    int dirty = 0;

 start_again:

    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < node_item_number (bh); i ++, ih ++) {
	if (ih->ih_key.k_dir_id == 0 || ih->ih_key.k_objectid == 0) {
	    /* sometimes stat datas get k_objectid==0 or k_dir_id==0 */
	    if (i == (node_item_number (bh) - 1)) {
		/* */
		if (i == 0) {
		    fsck_log ("block %lu: item %d: (%H) is alone in the block\n",
			      bh->b_blocknr, i, ih);
		    return;
		}
		/* delete last item */
		delete_item (fs, bh, i - 1);
		return;
	    }

	    /* there is next item: if it is not stat data - take its k_dir_id
               and k_objectid. if key order will be still wrong - the changed
               item will be deleted */
	    if (!is_stat_data_ih (ih + 1)) {
		fsck_log ("block %lu: item %d: (%H) fixed to ", bh->b_blocknr, i, ih);
		ih->ih_key.k_dir_id = (ih + 1)->ih_key.k_dir_id;
		ih->ih_key.k_objectid = (ih + 1)->ih_key.k_objectid;
		set_offset (KEY_FORMAT_1, &ih->ih_key, 0);
		set_type (KEY_FORMAT_1, &ih->ih_key, TYPE_STAT_DATA);
		fsck_log ("(%H)\n", ih);
		dirty = 1;
	    } else if (i == 0) {
		delete_item (fs, bh, i);
		goto start_again;
	    }
	}

	/* this recovers corruptions like the below: 
	   1774 1732 0 0
	   116262638 1732 1 3
	   1774 1736 0 0 */
	if (i && is_stat_data_ih (ih - 1) && !is_stat_data_ih (ih)) {
	    if (ih->ih_key.k_objectid != (ih - 1)->ih_key.k_objectid ||
		ih->ih_key.k_dir_id != (ih - 1)->ih_key.k_dir_id ||
		get_offset (&ih->ih_key) != 1) {
		if (is_direntry_ih (ih)) {
		    fsck_log ("block %lu: item %d: no \".\" entry found in "
			      "the first item of a directory\n", bh->b_blocknr, i);
		} else {
		    fsck_log ("block %lu: item %d: (%H) fixed to ", 
			  bh->b_blocknr, i, ih);
		    ih->ih_key.k_dir_id = (ih - 1)->ih_key.k_dir_id;
		    ih->ih_key.k_objectid = (ih - 1)->ih_key.k_objectid;
		    
		    if (ih_item_len (ih - 1) == SD_SIZE) {
			/* stat data is new, therefore this item is new too */
			set_offset (KEY_FORMAT_2, &(ih->ih_key), 1);
			if (ih_entry_count (ih) != 0xffff)
			    set_type (KEY_FORMAT_2, &(ih->ih_key), TYPE_INDIRECT);
			else
			    set_type (KEY_FORMAT_2, &(ih->ih_key), TYPE_DIRECT);
			set_ih_key_format (ih, KEY_FORMAT_2);
		    } else {
			/* stat data is old, therefore this item is old too */
			set_offset (KEY_FORMAT_1, &(ih->ih_key), 1);
			if (ih_entry_count (ih) != 0xffff)
			    set_type (KEY_FORMAT_1, &(ih->ih_key), TYPE_INDIRECT);
			else
			    set_type (KEY_FORMAT_1, &(ih->ih_key), TYPE_DIRECT);
			set_ih_key_format (ih, KEY_FORMAT_1);
		    }
		    fsck_log ("%H\n", ih);
		    dirty = 1;
		}
	    }
	}

	/* FIXME: corruptions like:
	   56702 66802 1 2
	   56702 65536 0 0
	   56702 66803 1 2
	   do not get recovered (both last items will be deleted) */
	/* delete item if it is not in correct order of object items */
	if (i && not_of_one_file (&ih->ih_key, &(ih - 1)->ih_key) &&
	    !is_stat_data_ih (ih)) {
	    fsck_log ("block %lu: item %d: %H follows non stat item %H - deleted\n",
		      bh->b_blocknr, i, ih, ih - 1);
	    delete_item (fs, bh, i);
	    goto start_again;
	}

	if (i &&  comp_keys (&(ih - 1)->ih_key, &ih->ih_key) != -1) {
	    /* previous item has key not smaller than the key of currect item */
	    if (is_stat_data_ih (ih - 1) && !is_stat_data_ih (ih)) {
		/* fix key of stat data such as if it was stat data of that item */
		fsck_log ("pass0: block %lu: %d-th item %k is out of order, made a stat data of %d-th (%k)\n",
			  bh->b_blocknr, i - 1, &(ih - 1)->ih_key, i, &ih->ih_key);
		(ih - 1)->ih_key.k_dir_id = ih->ih_key.k_dir_id;
		(ih - 1)->ih_key.k_objectid = ih->ih_key.k_objectid;
		set_offset (KEY_FORMAT_1, &(ih - 1)->ih_key, 0);
		set_type (KEY_FORMAT_1, &(ih - 1)->ih_key, TYPE_STAT_DATA);
		dirty = 1;
	    } else {
		/* ok, we have to delete one of these two - decide which one */
		int retval;

		/* something will be deleted */
		dirty = 1;
		retval = upper_correct (bh, ih - 1, i - 1);
		switch (retval) {
		case 0:
		    /* delete upper item */
		    fsck_log ("pass0: block %lu: %d-th (upper) item (%k) is out of order, deleted\n",
			      bh->b_blocknr, i - 1, &(ih - 1)->ih_key);
		    delete_item (fs, bh, i - 1);
		    goto start_again;

		case 1:
		    /* delete lower item */
		    fsck_log ("pass0: block %lu: %d-th (lower) item (%k) is out of order, deleted\n",
			      bh->b_blocknr, i, &ih->ih_key);
		    delete_item (fs, bh, i);
		    goto start_again;

		default:
		    /* upper item was the first item of a node */
		}

		retval = lower_correct (bh, ih, i);
		switch (retval) {
		case 0:
		    /* delete lower item */
		    fsck_log ("pass0: block %lu: %d-th (lower) item (%k) is out of order, deleted\n",
			      bh->b_blocknr, i, &ih->ih_key);
		    delete_item (fs, bh, i);
		    goto start_again;

		case 1:
		    /* delete upper item */
		    fsck_log ("pass0: block %lu: %d-th (upper) item (%k) is out of order, deleted\n",
			      bh->b_blocknr, i - 1, &(ih - 1)->ih_key);
		    delete_item (fs, bh, i - 1);
		    goto start_again;

		default:
		    /* there wer only two items in a node, so we could not
                       decide what to delete, go and ask user */
		}
		fsck_log ("pass0: which of these items looks better (other will be deleted)?\n"
			  "%H\n%H\n", ih - 1, ih);
		if (fsck_user_confirmed (fs, "1 or 2?", "1\n", 1))
		    delete_item (fs, bh, i - 1);
		else
		    delete_item (fs, bh, i);
		goto start_again;
	    }
	}

	if (is_stat_data_ih (ih) && (ih_item_len (ih) != SD_SIZE &&
				     ih_item_len (ih) != SD_V1_SIZE)) {
	    fsck_log ("pass0: block %lu, stat data of wrong length %H - deleted\n",
		      bh, ih);
	    delete_item (fs, bh, i);
	    goto start_again;
	}

	dirty += correct_key_format (ih);

	if (is_stat_data_ih (ih)) {
	    ;/*correct_stat_data (fs, bh, i);*/
	}

	if (is_direntry_ih (ih)) {
	    verify_directory_item (fs, bh, i);
	    continue;
	}

	if (!is_indirect_ih (ih))
	    continue;
	
	ind_item = (__u32 *)B_I_PITEM (bh, ih);
	for (j = 0; j < I_UNFM_NUM (ih); j ++) {
	    unfm_ptr = le32_to_cpu (ind_item [j]);
	    if (!unfm_ptr)
		continue;
	    
	    if (fsck_mode (fs) == FSCK_ZERO_FILES) {
		/* FIXME: this is temporary mode of fsck */
		ind_item [j] = 0;
		reiserfs_bitmap_clear_bit (fsck_new_bitmap(fs), unfm_ptr);
		tmp_zeroed ++;
		dirty = 1;
		continue;
	    }

	    if (not_data_block (fs, unfm_ptr) || /* journal area or bitmap or super block */
		unfm_ptr >= SB_BLOCK_COUNT (fs)) {/* garbage in pointer */

		stats (fs)->wrong_pointers ++;
		/*
		fsck_log ("pass0: %d-th pointer (%lu) in item %k (leaf block %lu) is wrong\n",
			  j, unfm_ptr, &ih->ih_key, bh->b_blocknr);
		*/
		ind_item [j] = 0;
		dirty = 1;
		continue;
	    }
#if 0
	    if (!was_block_used (unfm_ptr)) {
	      /* this will get to a pool of allocable blocks */
	      ind_item [j] = 0;
	      dirty = 1;
	      stat_wrong_pointer_found (fs);
	      continue;
	    }
#endif
	    /* mark block in bitmaps of unformatted nodes */
	    register_unfm (unfm_ptr);
	}
    }

    /* mark all objectids in use */
    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < node_item_number (bh); i ++, ih ++) {
	mark_objectid_really_used (proper_id_map (fs), le32_to_cpu (ih->ih_key.k_dir_id));
	mark_objectid_really_used (proper_id_map (fs), le32_to_cpu (ih->ih_key.k_objectid));
    }

    if (node_item_number (bh) < 1) {
	/* pass 1 will skip this */
	stats(fs)->all_contents_removed ++;
	fsck_log ("pass0: block %lu got all items deleted\n",
		  bh->b_blocknr);
    } else {
	/* pass1 will use this bitmap */
	pass0_mark_leaf (bh->b_blocknr);

    }
    if (dirty) {
	stats(fs)->leaves_corrected ++;
	mark_buffer_dirty (bh);
    }
}


static int is_bad_sd (struct item_head * ih, char * item)
{
    struct stat_data * sd = (struct stat_data *)item;

    if (le32_to_cpu(ih->ih_key.u.k_offset_v1.k_offset) || le32_to_cpu(ih->ih_key.u.k_offset_v1.k_uniqueness)) {
	reiserfs_warning (stderr, "Bad SD? %H\n", ih);
	return 1;
    }

    if (ih_item_len (ih) == SD_V1_SIZE) {
	/* looks like old stat data */
	if (ih_key_format (ih) != KEY_FORMAT_1)
	    fsck_log ("item %H has wrong format\n", ih);
	return 0;
    }

    if (!S_ISDIR (sd_v2_mode(sd)) && !S_ISREG(sd_v2_mode(sd)) &&
	!S_ISCHR (sd_v2_mode(sd)) && !S_ISBLK(sd_v2_mode(sd)) &&
	!S_ISLNK (sd_v2_mode(sd)) && !S_ISFIFO(sd_v2_mode(sd)) &&
	!S_ISSOCK(sd_v2_mode(sd))) {	
	/*fsck_log ("file %k unexpected mode encountered 0%o\n", &ih->ih_key, sd_v2_mode(sd))*/;
    }
    return 0;
}


int is_bad_directory (struct item_head * ih, char * item, int dev, int blocksize)
{
    int i;
    char * name;
    int namelen, entrylen;
    struct reiserfs_de_head * deh = (struct reiserfs_de_head *)item;
    __u32 prev_offset = 0;
    __u16 prev_location = ih_item_len (ih);
    int min_entry_size = 1;/* we have no way to understand whether the
                              filesystem were created in 3.6 format or
                              converted to it. So, we assume that minimal name
                              length is 1 */

    if (ih_item_len (ih) / (DEH_SIZE + min_entry_size) < ih_entry_count (ih))
	/* entry count is too big */
	return 1;

    for (i = 0; i < ih_entry_count (ih); i ++, deh ++) {
	entrylen = entry_length(ih, deh, i);
	if (entrylen > REISERFS_MAX_NAME_LEN (blocksize)) {
	    return 1;
	}
	if (deh_offset (deh) <= prev_offset) {
	    return 1;
	}
	prev_offset = deh_offset (deh);

	if (deh_location(deh) + entrylen != prev_location) {
	    return 1;
	}
	prev_location = deh_location (deh);

	namelen = name_length (ih, deh, i);
	name = name_in_entry (deh, i);
	if (!is_properly_hashed (fs, name, namelen, deh_offset (deh))) {
	    return 1;
	}
    }
    return 0;
}


/* change incorrect block adresses by 0. Do not consider such item as incorrect */
static int is_bad_indirect (struct item_head * ih, char * item, int dev, int blocksize)
{
    int i;
    int bad = 0;
    int blocks;

    if (ih_item_len(ih) % UNFM_P_SIZE) {
	fsck_log ("is_bad_indirect: indirect item of %H of invalid length\n", ih);
	return 1;
    }

    blocks = SB_BLOCK_COUNT (fs);
  
    for (i = 0; i < I_UNFM_NUM (ih); i ++) {
	__u32 * ind = (__u32 *)item;

	if (le32_to_cpu (ind[i]) >= blocks) {
	    bad ++;
	    fsck_log ("is_bad_indirect: %d-th pointer of item %H looks bad (%lu)\n",
		      i, ih, le32_to_cpu (ind [i]));
	    continue;
	}
    }
    return bad;
}


/* this is used by pass1.c:save_item and check.c:is_leaf_bad */
int is_bad_item (struct buffer_head * bh, struct item_head * ih, char * item)
{
    int blocksize, dev;

    blocksize = bh->b_size;
    dev = bh->b_dev;

    // FIXME: refuse transparently bad items
    if (ih->ih_key.k_dir_id == ih->ih_key.k_objectid)
	return 1;
    if (!ih->ih_key.k_dir_id || !ih->ih_key.k_objectid)
	return 1;

    if (is_stat_data_ih(ih))
	return is_bad_sd (ih, item);

    if (is_direntry_ih (ih))
	return is_bad_directory (ih, item, dev, blocksize);

    if (is_indirect_ih (ih))
	return is_bad_indirect (ih, item, dev, blocksize);

    if (is_direct_ih (ih))
	return 0;

    return 1;
}


int is_leaf_bad (struct buffer_head * bh)
{
    int i;
    struct item_head * ih;
    int bad = 0;

    assert (is_leaf_node (bh));

    for (i = 0, ih = B_N_PITEM_HEAD (bh,  0); i < B_NR_ITEMS (bh); i ++, ih ++) {
	if (is_bad_item (bh, ih, B_I_PITEM (bh, ih))) {
	    fsck_log ("is_leaf_bad: block %lu: %d-th item (%H) is bad\n",
		      bh->b_blocknr, i, ih);
	    bad = 1;
	    continue;
	}

	if (i && bad_pair (fs, bh, i)) {
	    fsck_log ("is_leaf_bad: block %luL %d-th item (%H) and "
		      "the next one (%H) are in wrong order\n",
		     bh->b_blocknr, i - 1, ih - 1, ih);
	    bad = 1;
	}
    }

    return bad;
}


static void go_through (reiserfs_filsys_t fs)
{
    struct buffer_head * bh;
    int i;
    int what_node;
    unsigned long done = 0, total;

    if (fsck_mode (fs) == DO_TEST) {
	/* just to test pass0_correct_leaf */
	bh = bread (fs->s_dev, stats(fs)->test, fs->s_blocksize);

	/*
	if (is_leaf_bad (bh)) {
	    fsck_progress ("###############  bad #################\n");
	}
	*/
	pass0_correct_leaf (fs, bh);
	
	print_block (stdout, fs, bh, 3, -1, -1);

	if (is_leaf_bad (bh)) {
	    fsck_progress ("############### still bad #################\n");
	}
	brelse (bh);
	reiserfs_free (fs);
	exit(4);
    }


    total = reiserfs_bitmap_ones (fsck_disk_bitmap (fs));
    fsck_progress ("\nPass 0 (%lu (of %lu) blocks will be read):\n",
		   total, SB_BLOCK_COUNT (fs));


    for (i = 0; i < SB_BLOCK_COUNT (fs); i ++) {
	if (!is_to_be_read (fs, i))
	    continue;

	print_how_far (&done, total, 1, fsck_quiet (fs));

	bh = bread (fs->s_dev, i, fs->s_blocksize);
	if (!bh) {
	    /* we were reading one block at time, and failed, so mark
	       block bad */
	    fsck_progress ("pass0: reading block %lu failed\n", i);
	    continue;
	}

	if (not_data_block (fs, i))
	    reiserfs_panic ("not data block found");
	
	stats (fs)->analyzed ++;
	what_node = who_is_this (bh->b_data, fs->s_blocksize);
	if ( what_node != THE_LEAF ) {
	    brelse (bh);
	    continue;
	}
	pass0_correct_leaf (fs, bh);
	brelse (bh);
    }


#if 0
    for (i = 0; i < SB_BLOCK_COUNT (fs); i += nr_to_read) {
	to_scan = how_many_to_scan (fs, i, nr_to_read);
	if (to_scan) {
	    print_how_far (&done, total, to_scan, fsck_quiet (fs));

	    /* at least one of nr_to_read blocks is to be checked */
	    bbh = bread (fs->s_dev, i / nr_to_read, fs->s_blocksize * nr_to_read);
	    if (bbh) {
		for (j = 0; j < nr_to_read; j ++) {
		    if (!is_to_be_read (fs, i + j))
			continue;

		    if (not_data_block (fs, i + j))
			reiserfs_panic ("not data block found");

		    stats (fs)->analyzed ++;

		    data = bbh->b_data + j * fs->s_blocksize;
		    what_node = who_is_this (data, fs->s_blocksize);
		    if ( what_node != THE_LEAF ) {
			continue;
		    }

		    /* the node looks like a leaf, but it still can be
		       not perfect */
		    bh = make_buffer (fs->s_dev, i + j, fs->s_blocksize, data);

		    /*printf ("block %lu .. ", bh->b_blocknr);fflush(stdout);*/
		    pass0_correct_leaf (fs, bh);
		    /*printf ("ok\n");fflush(stdout);*/

		    brelse (bh);
		}

		if (buffer_dirty (bbh))
		    bwrite (bbh);
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


    /* just in case */
    mark_objectid_really_used (proper_id_map (fs), REISERFS_ROOT_OBJECTID);

    fsck_progress ("\n");

    if (fsck_save_leaf_bitmap (fs)) {
	reiserfs_bitmap_save (stats (fs)->new_bitmap_file_name, leaves_bitmap);
    }
}


/* this makes a map of blocks which can be allocated when fsck will continue: */
static void find_allocable_blocks (reiserfs_filsys_t fs)
{
    int i;
 

    fsck_progress ("Looking for allocable blocks .. ");
    stats (fs)->all_blocks = SB_BLOCK_COUNT (fs);

    /* find how many leaves are not pointed by any indirect items */
    for (i = 0; i < SB_BLOCK_COUNT (fs); i ++) {
	if (not_data_block (fs, i))
	    continue;

#if 0
	if (!was_block_used (i)) {
	    /* marked free in the on-disk bitmap - so it is allocable */
	    make_allocable (i);
	    stat_allocable_found (fs);
	    continue;
	}
#endif

	if (pass0_is_leaf (i)) {
	    /* block looks like a reiserfs leaf */
	    stats(fs)->leaves ++;
	    if (pass0_is_good_unfm (i) || pass0_is_bad_unfm (i))
		/* leaf to which one or more indirect items point to */
		stats(fs)->pointed_leaves ++;
	}

	if (pass0_is_good_unfm (i) && pass0_is_bad_unfm (i))
	    die ("find_allocable_blocks: bad and good unformatted");

	if (pass0_is_good_unfm (i)) {
	    /* blocks which were pointed only once */
	    stats(fs)->pointed ++;
	    stats(fs)->pointed_once ++;
	    continue;
	}
	if (pass0_is_bad_unfm (i)) {
	    /* blocks pointed more than once */
	    stats(fs)->pointed ++;
	    stats(fs)->pointed_more_than_once ++;
	    continue;
	}

	/* blocks which marked used but are not leaves and are not
	   pointed (internals in short) get into bitmap of allocable
	   blocks */
	if (!pass0_is_leaf (i)) {
	    make_allocable (i);
	    stats(fs)->allocable ++;
	}
    }
    fsck_progress ("ok\n");
}

#if 0
int are_there_used_leaves (unsigned long from, int count)
{
    int i;
    int used;

    used = 0;
    for (i = 0; i < count; i ++) {
	if ((SB_BLOCK_COUNT (fs) > from + i) &&
	    pass0_is_leaf (from + i))
	    used ++;
    }
    return used;
}
#endif

int is_used_leaf (unsigned long block)
{
    return pass0_is_leaf (block);
}


int how_many_leaves_were_there (void)
{
    return stats (fs)->leaves;
}

/* these are used to correct uformatted node pointers */
int is_bad_unformatted (unsigned long block)
{
    return pass0_is_bad_unfm (block);
}


/* this is for check only. With this we make sure that all pointers we
   put into tree on pass 1 do not point to leaves (FIXME), do not
   point to journal, bitmap, etc, do not point out of fs boundary and
   are marked used in on-disk bitmap */
int still_bad_unfm_ptr_1 (unsigned long block)
{
    if (!block)
	return 0;
    if (pass0_is_leaf (block))
	return 1;
    if (pass0_is_bad_unfm (block) && !is_bad_unfm_in_tree_once (block))
	return 1;
    if (not_data_block (fs, block))
	return 1;
    /*
    if (!was_block_used (block))
	return 1;
    */
    if (block >= stats (fs)->all_blocks)
	return 1;
    return 0;
    
}


/* pointers to data block which get into tree are checked with this */
int still_bad_unfm_ptr_2 (unsigned long block)
{
    if (!block)
	return 0;
    if (is_block_used (block))
	return 1;
    if (block >= stats (fs)->all_blocks)
	return 1;
    return 0;
}


/* these are used to allocate blocks for tree building */
int are_there_allocable_blocks (int amout_needed)
{
    if (reiserfs_bitmap_zeros (fsck_allocable_bitmap (fs)) < amout_needed) {
	int zeros = 0, i;
	
	fsck_progress ("Hmm, there are not enough allocable blocks, checking bitmap...");fflush (stdout);
	for (i = 0; i < fsck_allocable_bitmap (fs)->bm_bit_size; i ++)
	    if (!reiserfs_bitmap_test_bit (fsck_allocable_bitmap (fs), i))
		zeros ++;
	fsck_progress ("there are %d zeros, btw\n", zeros);
	return 0;
    }
    return 1;
}


unsigned long alloc_block (void)
{
    unsigned long block = 0; /* FIXME: start point could be used */

    if (reiserfs_bitmap_find_zero_bit (fsck_allocable_bitmap (fs), &block)) {
	die ("alloc_block: allocable blocks counter is wrong");
	return 0;
    }
    reiserfs_bitmap_set_bit (fsck_allocable_bitmap (fs), block);
    return block;
}


void make_allocable (unsigned long block)
{
    reiserfs_bitmap_clear_bit (fsck_allocable_bitmap (fs), block);
}


unsigned long how_many_uninsertables_were_there (void)
{
    return stats (fs)->uninsertable_leaves;
}


unsigned long how_many_items_were_saved (void)
{
    return stats (fs)->saved_on_pass1;
}


static void choose_hash_function (reiserfs_filsys_t fs)
{
    unsigned long max;
    int hash_code;
    int i;

    max = 0;
    hash_code = func2code (0);

    for (i = 0; i < stats (fs)->hash_amount; i ++) {
	/* remember hash whihc got more hits */
	if (stats (fs)->hash_hits [i] > max) {
	    hash_code = i;
	    max = stats (fs)->hash_hits [i];
	}

	if (stats (fs)->hash_hits [i])
	    fsck_log ("%s got %lu hits\n", code2name (i),
		      stats (fs)->hash_hits [i]);
    }
    if (max == 0) {
	/* no names were found. take either super block value or
           default */
	reiserfs_hash (fs) = code2func (rs_hash (fs->s_rs));
	if (!reiserfs_hash (fs))
	    reiserfs_hash (fs) = code2func (DEFAULT_HASH);
	return;
    }

    /* compare the most appropriate hash with the hash set in super block */
    if (hash_code != rs_hash (fs->s_rs)) {
	fsck_progress ("Selected hash (%s) does not match to one set in super block (%s).\n",
		       code2name (hash_code), code2name (rs_hash (fs->s_rs)));
	/*
	if (!fsck_user_confirmed (fs, "Overwrite?(Yes)", "Yes", 1)) {
	    fsck_progress ("Not confirmed\n");
	    exit (4);
	}
	*/
	set_hash (fs->s_rs, hash_code);
    } else {
	fsck_progress ("\t%s hash is selected\n", code2name (hash_code));
    }

    reiserfs_hash (fs) = code2func (hash_code);
}


int pass_0 (reiserfs_filsys_t fs)
{
    if (fsck_log_file (fs) != stderr)
	/* this is just to separate warnings in the log file */
	fsck_log ("####### Pass 0 #######\n");

    if (fsck_mode (fs) == FSCK_ZERO_FILES) {
	reiserfs_bitmap_fill (fsck_new_bitmap (fs));
	fsck_progress ("Zeroing existing files - all blocks marked used\n");
    }

    make_aux_bitmaps (fs);

    /* pass0 gathers statistics about hash hits */
    hash_hits_init (fs);
    
    /* scan the partition */
    go_through (fs);

    /* find blocks which can be allocated */
    find_allocable_blocks (fs);

    if (fsck_mode (fs) == FSCK_ZERO_FILES) {
	/* flush bitmaps and exit */
	fsck_progress ("Zeroing existing files - zeroed %lu blocks\n", tmp_zeroed);
	reiserfs_flush_bitmap (fsck_new_bitmap (fs), fs);
	reiserfs_close (fs);
	exit (0);
    }


    choose_hash_function (fs);

    stage_report (0, fs);
    return 0;
}


#if 0

/* node looks like a leaf (block head and ih_item_length & ih_location
   of item_head array are correct. This function recovers (tries to) node's key
   table and directory items. */
static void recover_leaf (reiserfs_filsys_t fs, struct buffer_head * bh)
{
    int i;
    struct item_head * ih;

    /* mark transparently corrupted items - bad */
    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < node_item_number (bh); i ++, ih ++) {
	if (type_unknown (&ih->ih_key) ||
	    ih->ih_key.k_dir_id == 0 ||
	    ih->ih_key.k_objectid) {
	    mark_ih_bad (ih);
	    continue;
	}
    }
}

#endif

