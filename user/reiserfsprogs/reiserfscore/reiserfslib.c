/*
 *  Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */

#include "includes.h"


/* fixme: this assumes that journal start and journal size are set
   correctly */
static void check_first_bitmap (reiserfs_filsys_t fs, char * bitmap)
{
    int i;
    int bad;

    bad = 0;
    for (i = 0; i < rs_journal_start (fs->s_rs) +
	     rs_journal_size (fs->s_rs) + 1; i ++) {
	if (!test_bit (i, bitmap)) {
	    bad = 1;
	    /*reiserfs_warning ("block %d is marked free in the first bitmap, fixed\n", i);*/
	    /*set_bit (i, bitmap);*/
	}
    }
    if (bad)
	reiserfs_warning (stderr, "reiserfs_open: first bitmap looks corrupted\n");
}


/* read bitmap blocks */
void reiserfs_read_bitmap_blocks (reiserfs_filsys_t fs)
{
	struct reiserfs_super_block * rs = fs->s_rs;
	struct buffer_head * bh = SB_BUFFER_WITH_SB(fs);
	int fd = fs->s_dev;
	unsigned long block;
	int i;
	
	/* read bitmaps, and correct a bit if necessary */
	SB_AP_BITMAP (fs) = getmem (sizeof (void *) * rs_bmap_nr (rs));
	for (i = 0, block = bh->b_blocknr + 1;
	     i < rs_bmap_nr (rs); i ++) {
		SB_AP_BITMAP (fs)[i] = bread (fd, block, fs->s_blocksize);
		if (!SB_AP_BITMAP (fs)[i]) {
		    	reiserfs_warning (stderr, "reiserfs_open: bread failed reading bitmap #%d (%lu)\n", i, block);
			SB_AP_BITMAP (fs)[i] = getblk (fd, block, fs->s_blocksize);
			memset (SB_AP_BITMAP (fs)[i]->b_data, 0xff, fs->s_blocksize);
			set_bit (BH_Uptodate, &SB_AP_BITMAP (fs)[i]->b_state);
		}
		
		/* all bitmaps have to have itself marked used on it */
		if (bh->b_blocknr == 16) {
			if (!test_bit (block % (fs->s_blocksize * 8), SB_AP_BITMAP (fs)[i]->b_data)) {
				reiserfs_warning (stderr, "reiserfs_open: bitmap %d was marked free\n", i);
				/*set_bit (block % (fs->s_blocksize * 8), SB_AP_BITMAP (fs)[i]->b_data);*/
			}
		} else {
			/* bitmap not spread over partition: fixme: does not
			   work when number of bitmaps => 32768 */
			if (!test_bit (block, SB_AP_BITMAP (fs)[0]->b_data)) {
			    	reiserfs_warning (stderr, "reiserfs_open: bitmap %d was marked free\n", i);
				/*set_bit (block, SB_AP_BITMAP (fs)[0]->b_data);*/
			}
		}

		if (i == 0) {
			/* first bitmap has to have marked used super block
			   and journal areas */
			check_first_bitmap (fs, SB_AP_BITMAP (fs)[i]->b_data);
		}

		block = (bh->b_blocknr == 16 ? ((i + 1) * fs->s_blocksize * 8) : (block + 1));
    }
}


void reiserfs_free_bitmap_blocks (reiserfs_filsys_t fs)
{
	int i;
	
    /* release bitmaps if they were read */
    if (SB_AP_BITMAP (fs)) {
		for (i = 0; i < SB_BMAP_NR (fs); i ++)
			brelse (SB_AP_BITMAP (fs) [i]);
		freemem (SB_AP_BITMAP (fs));
	}

}

/* read super block and bitmaps. fixme: only 4k blocks, pre-journaled format
   is refused */
reiserfs_filsys_t reiserfs_open (char * filename, int flags, int *error, void * vp)
{
    reiserfs_filsys_t fs;
    struct buffer_head * bh;
    struct reiserfs_super_block * rs;
    int fd, i;
    
    fd = open (filename, flags | O_LARGEFILE);
    if (fd == -1) {
	if (error)
	    *error = errno;
	return 0;
    }

    fs = getmem (sizeof (*fs));
    fs->s_dev = fd;
    fs->s_vp = vp;
    asprintf (&fs->file_name, "%s", filename);

    /* reiserfs super block is either in 16-th or in 2-nd 4k block of the
       device */
    for (i = 16; i > 0; i -= 14) {
	bh = bread (fd, i, 4096);
	if (!bh) {
	    reiserfs_warning (stderr, "reiserfs_open: bread failed reading block %d\n", i);
	} else {
	    rs = (struct reiserfs_super_block *)bh->b_data;
	    
	    if (is_reiser2fs_magic_string (rs) || is_reiserfs_magic_string (rs))
		goto found;

	    /* reiserfs signature is not found at the i-th 4k block */
	    brelse (bh);
	}
    }

    reiserfs_warning (stderr, "reiserfs_open: neither new nor old reiserfs format "
		      "found on %s\n", filename);
    if (error)
	*error = 0;
    return fs;

 found:

    /* fixme: we could make some check to make sure that super block looks
       correctly */
    fs->s_version = is_reiser2fs_magic_string (rs) ? REISERFS_VERSION_2 :
	REISERFS_VERSION_1;
    fs->s_blocksize = rs_blocksize (rs);
    fs->s_hash_function = code2func (rs_hash (rs));
    SB_BUFFER_WITH_SB (fs) = bh;
    fs->s_rs = rs;
    fs->s_flags = flags; /* O_RDONLY or O_RDWR */
    fs->s_vp = vp;

    reiserfs_read_bitmap_blocks(fs);
	
    return fs;

}


int no_reiserfs_found (reiserfs_filsys_t fs)
{
    return (fs->s_blocksize == 0) ? 1 : 0;
}


int new_format (reiserfs_filsys_t fs)
{
    return fs->s_sbh->b_blocknr != 2;
}


int spread_bitmaps (reiserfs_filsys_t fs)
{
    return fs->s_sbh->b_blocknr != 2;
}


void reiserfs_reopen (reiserfs_filsys_t fs, int flag)
{
    close (fs->s_dev);
    fs->s_dev = open (fs->file_name, flag | O_LARGEFILE);
    if (fs->s_dev == -1)
	die ("reiserfs_reopen: could not reopen device: %m");
}


int filesystem_dirty (reiserfs_filsys_t fs)
{
    return fs->s_dirt;
}


void mark_filesystem_dirty (reiserfs_filsys_t fs)
{
    fs->s_dirt = 1;
}


/* flush all changes made on a filesystem */
void reiserfs_flush (reiserfs_filsys_t fs)
{
    flush_buffers ();
}


/* free all memory involved into manipulating with filesystem */
void reiserfs_free (reiserfs_filsys_t fs)
{
    reiserfs_free_bitmap_blocks(fs);
    
    /* release super block and memory used by filesystem handler */
    brelse (SB_BUFFER_WITH_SB (fs));
    
    free_buffers ();

    free (fs->file_name);
    freemem (fs);
}


void reiserfs_close (reiserfs_filsys_t fs)
{
    reiserfs_flush (fs);
    reiserfs_free (fs);
}


int reiserfs_new_blocknrs (reiserfs_filsys_t fs, 
			   unsigned long * free_blocknrs, unsigned long start, int amount_needed)
{
    if (fs->block_allocator)
	return fs->block_allocator (fs, free_blocknrs, start, amount_needed);
    die ("block allocator is not defined\n");
    return 0;
}


int reiserfs_free_block (reiserfs_filsys_t fs, unsigned long block)
{
    if (fs->block_deallocator)
	return fs->block_deallocator (fs, block);
    die ("block allocator is not defined\n");
    return 0;
}


typedef int (comp_function_t) (void * key1, void * key2);

inline int _bin_search (void * key, void * base, int num, int width, __u32 *ppos, comp_function_t comp_func)
{
    int rbound, lbound, j;

    if (num == 0) {
	/* objectid map may be 0 elements long */
        *ppos = 0;
        return ITEM_NOT_FOUND;
    }

    lbound = 0;
    rbound = num - 1;

    for (j = (rbound + lbound) / 2; lbound <= rbound; j = (rbound + lbound) / 2) {
	switch (comp_func ((void *)((char *)base + j * width), key ) ) {
	case -1:/* second is greater */
	    lbound = j + 1;
	    continue;

	case 1: /* first is greater */
	    if (j == 0) {
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

#if 0
static inline int _bin_search (void * key, void * base, int num, int width, __u32 *ppos)
{
    __u32 rbound, lbound, j;

    lbound = 0;
    rbound = num - 1;
    for (j = (rbound + lbound) / 2; lbound <= rbound; j = (rbound + lbound) / 2) {
	switch (comp_keys ((void *)((char *)base + j * width), key)) {
	case -1:/* second is greater */
	    lbound = j + 1;
	    continue;

	case 1: /* first is greater */
	    if (j == 0) {
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
#endif

static int _search_by_key (reiserfs_filsys_t fs, struct key * key, struct path * path)
{
    struct buffer_head * bh;
    unsigned long block = SB_ROOT_BLOCK (fs);
    struct path_element * curr;
    int retval;
    
    path->path_length = ILLEGAL_PATH_ELEMENT_OFFSET;
    while (1) {
	curr = PATH_OFFSET_PELEMENT (path, ++ path->path_length);
	bh = curr->pe_buffer = bread (fs->s_dev, block, fs->s_blocksize);
        if (bh == 0) {
	    path->path_length --;
	    pathrelse (path);
	    return ITEM_NOT_FOUND;
	}
	retval = _bin_search (key, B_N_PKEY (bh, 0), B_NR_ITEMS (bh),
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
    printf ("search_by_key: you can not get here\n");
    return ITEM_NOT_FOUND;
}


static int comp_dir_entries (void * p1, void * p2)
{
    __u32 deh_offset;
    __u32 * off1, * off2;

    off1 = p1;
    off2 = p2;
    deh_offset = le32_to_cpu (*off1);

    if (deh_offset < *off2)
	return -1;
    if (deh_offset > *off2)
	return 1;
    return 0;
}


static struct key * _get_rkey (struct path * path)
{
    int pos, offset = path->path_length;
    struct buffer_head * bh;

    if (offset < FIRST_PATH_ELEMENT_OFFSET)
	die ("_get_rkey: illegal offset in the path (%d)", offset);

    while (offset-- > FIRST_PATH_ELEMENT_OFFSET) {
	if (! buffer_uptodate (PATH_OFFSET_PBUFFER (path, offset)))
	    die ("_get_rkey: parent is not uptodate");

	/* Parent at the path is not in the tree now. */
	if (! B_IS_IN_TREE (bh = PATH_OFFSET_PBUFFER (path, offset)))
	    die ("_get_rkey: buffer on the path is not in tree");

	/* Check whether position in the parrent is correct. */
	if ((pos = PATH_OFFSET_POSITION (path, offset)) > B_NR_ITEMS (bh))
	    die ("_get_rkey: invalid position (%d) in the path", pos);

	/* Check whether parent at the path really points to the child. */
	if (B_N_CHILD_NUM (bh, pos) != PATH_OFFSET_PBUFFER (path, offset + 1)->b_blocknr)
	    die ("_get_rkey: invalid block number (%d). Must be %d",
		 B_N_CHILD_NUM (bh, pos), PATH_OFFSET_PBUFFER (path, offset + 1)->b_blocknr);
	
	/* Return delimiting key if position in the parent is not the last one. */
	if (pos != B_NR_ITEMS (bh))
	    return B_N_PDELIM_KEY (bh, pos);
    }
    
    /* there is no right delimiting key */
    return 0;
}


/* NOTE: this only should be used to look for keys who exists */
int _search_by_entry_key (reiserfs_filsys_t fs, struct key * key, 
			  struct path * path)
{
    struct buffer_head * bh;
    int item_pos;
    struct item_head * ih;
    struct key tmpkey;

    if (_search_by_key (fs, key, path) == ITEM_FOUND) {
        path->pos_in_item = 0;
        return POSITION_FOUND;
    }

    bh = get_bh (path);
    item_pos = get_item_pos (path);
    ih = get_ih (path);

    if (item_pos == 0) {
	/* key is less than the smallest key in the tree */
	if (not_of_one_file (&(ih->ih_key), key))
	    /* there are no items of that directory */
	    return DIRECTORY_NOT_FOUND;

	if (!is_direntry_ih (ih))
	    reiserfs_panic ("_search_by_entry_key: found item is not of directory type %H",
			    ih);

	/* key we looked for should be here */
        path->pos_in_item = 0;
	return POSITION_NOT_FOUND;
    }

    /* take previous item */
    item_pos --;
    ih --;
    PATH_LAST_POSITION (path) --;

    if (not_of_one_file (&(ih->ih_key), key) || !is_direntry_ih (ih)) {
        /* previous item belongs to another object or is stat data, check next
           item */

	item_pos ++;
	PATH_LAST_POSITION (path) ++;

        if (item_pos < B_NR_ITEMS (bh)) {
	    /* next item is in the same node */
	    ih ++;
            if (not_of_one_file (&(ih->ih_key), key)) {
		/* there are no items of that directory */
                path->pos_in_item = 0;
                return DIRECTORY_NOT_FOUND;
            }

            if (!is_direntry_ih (ih))
		reiserfs_panic ("_search_by_entry_key: %k is not a directory",
				key);
        } else {
	    /* next item is in right neighboring node */
            struct key * next_key = _get_rkey (path);

            if (next_key == 0 || not_of_one_file (next_key, key)) {
                /* there are no items of that directory */
                path->pos_in_item = 0;
                return DIRECTORY_NOT_FOUND;
            }

            if (!is_direntry_key (next_key))
		reiserfs_panic ("_search_by_entry_key: %k is not a directory",
				key);

            /* we got right delimiting key - search for it - the entry will be
	       pasted in position 0 */
            copy_key (&tmpkey, next_key);
            pathrelse (path);
            if (_search_by_key (fs, &tmpkey, path) != ITEM_FOUND || PATH_LAST_POSITION (path) != 0)
                reiserfs_panic ("_search_by_entry_key: item corresponding to delimiting key %k not found",
				&tmpkey);
        }

        /* next item is the part of this directory */
        path->pos_in_item = 0;
        return POSITION_NOT_FOUND;
    }


    /* previous item is part of desired directory */
    if (_bin_search (&(key->u.k_offset_v1.k_offset), B_I_DEH (bh, ih), ih_entry_count (ih),
		     DEH_SIZE, &(path->pos_in_item), comp_dir_entries) == ITEM_FOUND)
	return POSITION_FOUND;

    return POSITION_NOT_FOUND;
}


static void _init_tb_struct (struct tree_balance * tb, reiserfs_filsys_t fs,
			     struct path * path, int size)
{
    memset (tb, '\0', sizeof(struct tree_balance));
    tb->tb_sb = fs;
    tb->tb_path = path;

    PATH_OFFSET_PBUFFER(path, ILLEGAL_PATH_ELEMENT_OFFSET) = NULL;
    PATH_OFFSET_POSITION(path, ILLEGAL_PATH_ELEMENT_OFFSET) = 0;
    tb->insert_size[0] = size;
}


int reiserfs_remove_entry (reiserfs_filsys_t fs, struct key * key)
{
    struct path path;
    struct tree_balance tb;
    struct item_head * ih;
    struct reiserfs_de_head * deh;

    if (_search_by_entry_key (fs, key, &path) != POSITION_FOUND) {
	pathrelse (&path);
	return 1;
    }

    ih = get_ih (&path);
    if (ih_entry_count (ih) == 1) {
	_init_tb_struct (&tb, fs, &path, -(IH_SIZE + ih_item_len (ih)));
	if (fix_nodes (M_DELETE, &tb, 0) != CARRY_ON) {
	    unfix_nodes (&tb);
	    return 1;
	}
	do_balance (&tb, 0, 0, M_DELETE, 0);
	return 0;
    }

    deh = B_I_DEH (get_bh (&path), ih) + path.pos_in_item;
    _init_tb_struct (&tb, fs, &path, -(DEH_SIZE + entry_length (ih, deh, path.pos_in_item)));
    if (fix_nodes (M_CUT, &tb, 0) != CARRY_ON) {
	unfix_nodes (&tb);
	return 1;
    }
    do_balance (&tb, 0, 0, M_CUT, 0);
    return 0;
}



void reiserfs_paste_into_item (reiserfs_filsys_t fs, struct path * path,
			       const void * body, int size)
{
    struct tree_balance tb;
  
    _init_tb_struct (&tb, fs, path, size);

    if (fix_nodes (M_PASTE, &tb, 0/*ih*/) != CARRY_ON)
	reiserfs_panic ("reiserfs_paste_into_item: fix_nodes failed");

    do_balance (&tb, 0, body, M_PASTE, 0/*zero num*/);
}


void reiserfs_insert_item (reiserfs_filsys_t fs, struct path * path,
			   struct item_head * ih, const void * body)
{
    struct tree_balance tb;
    
    _init_tb_struct (&tb, fs, path, IH_SIZE + ih_item_len(ih));
    if (fix_nodes (M_INSERT, &tb, ih) != CARRY_ON)
	die ("reiserfs_insert_item: fix_nodes failed");

    do_balance (&tb, ih, body, M_INSERT, 0/*zero num*/);
}


/*===========================================================================*/

static __u32 hash_value (reiserfs_filsys_t fs, char * name)
{
    __u32 res;

    if (!strcmp (name, "."))
	return DOT_OFFSET;
    if (!strcmp (name, ".."))
	return DOT_DOT_OFFSET;

    res = reiserfs_hash (fs) (name, strlen (name));    
    res = GET_HASH_VALUE(res);
    if (res == 0)
	res = 128;

    return res;
}



/* returns 0 if name is not found in a directory and objectid of
   pointed object otherwise and returns minimal not used generation
   counter.  dies if found object is not a directory. */
int reiserfs_find_entry (reiserfs_filsys_t fs, struct key * dir, char * name, 
			 int * min_gen_counter)
{
    struct key entry_key;
    int retval;
    int i;
    INITIALIZE_PATH (path);
    struct item_head * ih;
    struct reiserfs_de_head * deh;
    struct key * rdkey;
    __u32 hash;

    entry_key.k_dir_id = cpu_to_le32(dir->k_dir_id);
    entry_key.k_objectid = cpu_to_le32(dir->k_objectid);
    hash = hash_value (fs, name);
    set_type_and_offset (KEY_FORMAT_1, &entry_key, hash, TYPE_DIRENTRY);    
    *min_gen_counter = 0;

    if (_search_by_entry_key (fs, &entry_key, &path) == DIRECTORY_NOT_FOUND) {
	pathrelse (&path);
	return 0;
    }

    do {
	ih = get_ih (&path);
	deh = B_I_DEH (get_bh (&path), ih) + path.pos_in_item;
	for (i = path.pos_in_item; i < ih_entry_count (ih); i ++, deh ++) {
	    if (GET_HASH_VALUE (deh_offset (deh)) != GET_HASH_VALUE (hash)) {
		/* all entries having the same hash were scanned */
		pathrelse (&path);
		return 0;
	    }

	    if (GET_GENERATION_NUMBER (deh_offset (deh)) == *min_gen_counter)
		(*min_gen_counter) ++;

	    if (!memcmp (name_in_entry (deh, i), name, strlen (name))) {
		pathrelse (&path);
		return deh_objectid (deh) ? deh_objectid (deh) : 1;
	    }
	}

	rdkey = _get_rkey (&path);
	if (!rdkey || not_of_one_file (rdkey, dir)) {
	    pathrelse (&path);
	    return 0;
	}
	
	if (!is_direntry_key (rdkey))
	    reiserfs_panic ("reiserfs_find_entry: can not find name in broken directory yet");

	/* next item is the item of the directory we are looking name in */
	if (GET_HASH_VALUE (get_offset (rdkey)) != hash) {
	    /* but there is no names with given hash */
	    pathrelse (&path);
	    return 0;
	}

	/* first name of that item may be a name we are looking for */
	entry_key = *rdkey;
	pathrelse (&path);
	retval = _search_by_entry_key (fs, &entry_key, &path);
	if (retval != POSITION_FOUND)
	    reiserfs_panic ("reiserfs_find_entry: wrong delimiting key in the tree");

    } while (1);
    
    return 0;
}


/* compose directory entry: dir entry head and name itself */
char * make_entry (char * entry, char * name, struct key * key, __u32 offset)
{
    struct reiserfs_de_head * deh;

    if (!entry)
	entry = getmem (DEH_SIZE + ROUND_UP (strlen (name)));

    memset (entry, 0, DEH_SIZE + ROUND_UP (strlen (name)));
    deh = (struct reiserfs_de_head *)entry;
    deh->deh_location = 0; /* Safe if 0 */
    set_deh_offset(deh, offset);
    deh->deh_state = 0; /* Safe if 0 */
    mark_de_visible (deh);

    /* key of object entry will point to */
    deh->deh_dir_id = key->k_dir_id; /* both little endian */
    deh->deh_objectid = key->k_objectid; /* both little endian */

    memcpy ((char *)(deh + 1), name, strlen (name));
    return entry;
}


/* add new name into a directory. If it exists in a directory - do
   nothing */
int reiserfs_add_entry (reiserfs_filsys_t fs, struct key * dir, char * name,
			 struct key * key, int fsck_need)
{
    struct item_head entry_ih = {{0,}, };
    char * entry;
    int retval;
    INITIALIZE_PATH(path);
    int gen_counter;
    int item_len;
    __u32 hash;

    if (reiserfs_find_entry (fs, dir, name, &gen_counter))
	return 0;

    /* compose entry key to look for its place in the tree */
    entry_ih.ih_key.k_dir_id = cpu_to_le32 (dir->k_dir_id);
    entry_ih.ih_key.k_objectid = cpu_to_le32 (dir->k_objectid);
    hash = hash_value (fs, name) + gen_counter;
    if (!strcmp (name, "."))
	hash = DOT_OFFSET;
    if (!strcmp (name, ".."))
	hash = DOT_DOT_OFFSET;
    set_type_and_offset (KEY_FORMAT_1, &(entry_ih.ih_key),
			 hash, TYPE_DIRENTRY);
    set_ih_key_format (&entry_ih, KEY_FORMAT_1);
    set_entry_count (&entry_ih, 1);
    if (SB_VERSION (fs) == REISERFS_VERSION_2)
	item_len = DEH_SIZE + ROUND_UP (strlen (name));
    else
	item_len = DEH_SIZE + strlen (name);
    set_ih_item_len (&entry_ih, item_len);

    /* fsck may need to insert item which was not reached yet */
    set_ih_fsck_need( &entry_ih, fsck_need );

    entry = make_entry (0, name, key, get_offset (&(entry_ih.ih_key)));

    retval = _search_by_entry_key (fs, &(entry_ih.ih_key), &path);
    switch (retval) {
    case POSITION_NOT_FOUND:
	reiserfs_paste_into_item (fs, &path, entry, item_len);
	break;

    case DIRECTORY_NOT_FOUND:
        set_deh_location( (struct reiserfs_de_head *)entry, DEH_SIZE );
	reiserfs_insert_item (fs, &path, &entry_ih, entry);
	break;

    default:
	reiserfs_panic ("reiserfs_add_entry: looking for %k (inserting name \"%s\") "
			"search_by_entry_key returned %d",
			&(entry_ih.ih_key), name, retval);
    }

    freemem (entry);
    return item_len;
}


void copy_key (void * to, void * from)
{
    memcpy (to, from, KEY_SIZE);
}


void copy_short_key (void * to, void * from)
{
    memcpy (to, from, SHORT_KEY_SIZE);
}


void copy_item_head(void * p_v_to, void * p_v_from)
{
    memcpy (p_v_to, p_v_from, IH_SIZE);
}
