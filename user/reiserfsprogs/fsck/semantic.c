/*
 * Copyright 1996-1999 Hans Reiser
 */
#include "fsck.h"


/* the k_dir_id and k_objectid members are endian swapped in main() */
struct key root_dir_key = {REISERFS_ROOT_PARENT_OBJECTID,
			   REISERFS_ROOT_OBJECTID, {{0, 0},}};
struct key parent_root_dir_key = {0, REISERFS_ROOT_PARENT_OBJECTID, {{0, 0},}};
struct key lost_found_dir_key = {REISERFS_ROOT_OBJECTID, 0, {{0, 0}, }};


struct path_key
{
    struct short_key
    {
        __u32 k_dir_id;
        __u32 k_objectid;
    } key;
    struct path_key * next, * prev;
};

struct path_key * head_key = NULL;
struct path_key * tail_key = NULL;

void check_path_key(struct key * key)
{
    struct path_key * cur = head_key;

    while(cur != NULL)
    {
        if (!comp_short_keys(&cur->key, key))
            die("\nsemantic check: loop found %k", key);
        cur = cur->next;
    }
}

void add_path_key(struct key * key)
{
    check_path_key(key);

    if (tail_key == NULL)
    {
        tail_key = getmem(sizeof(struct path_key));
        head_key = tail_key;
        tail_key->prev = NULL;
    }else{
        tail_key->next = getmem(sizeof(struct path_key));
        tail_key->next->prev = tail_key;
        tail_key = tail_key->next;
    }
    copy_short_key (&tail_key->key, key);
    tail_key->next = NULL;
}

void del_path_key()
{
    if (tail_key == NULL)
        die("wrong path_key structure");

    if (tail_key->prev == NULL)
    {
        freemem(tail_key);
        tail_key = head_key = NULL;
    }else{
        tail_key = tail_key->prev;
        freemem(tail_key->next);
        tail_key->next = NULL;
    }
}

/* semantic pass progress */
static void print_name (char * dir_name, int len)
{
    int i;

    if (fsck_quiet (fs))
	return;
    printf("/");
    for (i = 0; i<len; i++, dir_name++)
        printf ("%c", *dir_name);
    fflush (stdout);
}

static void erase_name (int len)
{
    int i;

    if (fsck_quiet (fs))
	return;
    for (i = 0; i<=len; i++)
        printf("\b");
    for (i = 0; i<=len; i++)
        printf(" ");
    for (i = 0; i<=len; i++)
        printf("\b");
    fflush (stdout);
}


void get_set_sd_field (int field, struct item_head * ih, void * sd,
		       void * value, int set)
{
    if (ih_key_format (ih) == KEY_FORMAT_1) {
	struct stat_data_v1 * sd_v1 = sd;

	switch (field) {
	case GET_SD_MODE:
	    if (set)
		set_sd_v1_mode(sd_v1, *(__u16 *)value );
	    else
		*(__u16 *)value = sd_v1_mode(sd_v1);
	    break;

	case GET_SD_SIZE:
	    /* value must point to 64 bit int */
	    if (set)
		set_sd_v1_size(sd_v1, *(__u64 *)value);
	    else
		*(__u64 *)value = sd_v1_size(sd_v1);
	    break;

	case GET_SD_BLOCKS:
	    if (set)
		set_sd_v1_blocks(sd_v1, *(__u32 *)value);
	    else
		*(__u32 *)value = sd_v1_blocks(sd_v1);
	    break;

	case GET_SD_NLINK:
	    /* value must point to 32 bit int */
	    if (set)
		set_sd_v1_nlink(sd_v1, *(__u32 *)value);
	    else
		*(__u32 *)value = sd_v1_nlink(sd_v1);
	    break;

	case GET_SD_FIRST_DIRECT_BYTE:
	    if (set)
		set_sd_v1_first_direct_byte(sd_v1, *(__u32 *)value);
	    else
		*(__u32 *)value = sd_v1_first_direct_byte(sd_v1);
	    break;
	    
	default:
	    reiserfs_panic ("get_set_sd_field: unknown field of old stat data");
	}
    } else {
	struct stat_data * sd_v2 = sd;

	switch (field) {
	case GET_SD_MODE:
	    if (set)
		set_sd_v2_mode(sd_v2, *(__u16 *)value);
	    else
		*(__u16 *)value = sd_v2_mode(sd_v2);
	    break;

	case GET_SD_SIZE:
	    if (set)
		set_sd_v2_size(sd_v2, *(__u64 *)value);
	    else
		*(__u64 *)value = sd_v2_size(sd_v2);
	    break;

	case GET_SD_BLOCKS:
	    if (set)
		set_sd_v2_blocks(sd_v2, *(__u32 *)value);
	    else
		*(__u32 *)value = sd_v2_blocks(sd_v2);
	    break;

	case GET_SD_NLINK:
	    if (set)
		set_sd_v2_nlink(sd_v2, *(__u32 *)value);
	    else
		*(__u32 *)value = sd_v2_nlink(sd_v2);
	    break;

	case GET_SD_FIRST_DIRECT_BYTE:
	default:
	    reiserfs_panic ("get_set_sd_field: unknown field of new stat data");
	}
    }
}



/* *size is "real" file size, sd_size - size from stat data */
static int wrong_st_size (struct key * key, loff_t max_file_size, int blocksize,
			  __u64 * size, __u64 sd_size, int is_dir)
{
    if (sd_size <= max_file_size) {
	if (sd_size == *size)
	    return 0;

	if (is_dir) {
	    /* directory size must match to the sum of length of its entries */
	    fsck_log ("dir %K has wrong sd_size %Ld, has to be %Ld\n",
		      key, sd_size, *size);
	    return 1;
	}

	if (sd_size > *size) {
	    /* size in stat data can be bigger than size calculated by items */
	    if (fsck_fix_non_critical (fs)) {
		/* but it -o is given - fix that */
		fsck_log ("file %K has too big file size sd_size %Ld - fixed to %Ld\n",
			  key, sd_size, *size);
		stats(fs)->fixed_sizes ++;
		return 1;
	    }
	    *size = sd_size;
	    return 0;
	}
	
	if (!(*size % blocksize)) {
	    /* last item is indirect */
	    if (((sd_size & ~(blocksize - 1)) == (*size - blocksize)) && sd_size % blocksize) {
		/* size in stat data is correct */
		*size = sd_size;
		return 0;
	    }
	} else {
	    /* last item is a direct one */
	    if (!(*size % 8)) {
		if (((sd_size & ~7) == (*size - 8)) && sd_size % 8) {
		    /* size in stat data is correct */
		    *size = sd_size;
		    return 0;
		}
	    }
	}
    }

    fsck_log ("file %K has wrong sd_size %Ld, has to be %Ld\n",
	      key, sd_size, *size);
    stats(fs)->fixed_sizes ++;
    return 1;
}


/* sd_blocks is 32 bit only */
static int wrong_st_blocks (struct key * key, __u32 blocks, __u32 sd_blocks, int is_dir)
{
    if (blocks == sd_blocks)
	return 0;

    if (!is_dir || blocks != _ROUND_UP (sd_blocks, fs->s_blocksize / 512)) {
	/*fsck_log ("%s %K has wrong sd_blocks %d, has to be %d\n",
	  is_dir ? "dir" : "file", key, sd_blocks, blocks);*/
	return 1;
    } else
	return 0;
}


/* only regular files and symlinks may have items but stat
   data. Symlink shold have body */
static int wrong_mode (struct key * key, mode_t * mode, __u64 real_size)
{
    if (!fsck_fix_non_critical (fs))
	return 0;

    if (ftypelet (*mode) != '?') {
	/* mode looks reasonable */
	if (S_ISREG (*mode) || S_ISLNK (*mode))
	    return 0;
	
	/* device, pipe, socket have no items */
	if (!real_size)
	    return 0 ;
    }
    /* there are items, so change file mode to regular file. Otherwise
       - file bodies do not get deleted */
    fsck_log ("file %K (%M) has body, mode fixed to %M\n",
	      key, *mode, (S_IFREG | 0600));
    *mode = (S_IFREG | 0600);
    return 1;
}


/* key is a key of last file item */
static int wrong_first_direct_byte (struct key * key, int blocksize, 
				    __u32 * first_direct_byte,
				    __u32 sd_first_direct_byte, __u32 size)
{
    if (!size || is_indirect_key (key)) {
	/* there is no direct item */
	*first_direct_byte = NO_BYTES_IN_DIRECT_ITEM;
	if (sd_first_direct_byte != NO_BYTES_IN_DIRECT_ITEM) {
	    return 1;
	}
	return 0;
    }

    /* there is direct item */
    *first_direct_byte = (get_offset (key) & ~(blocksize - 1)) + 1;
    if (*first_direct_byte != sd_first_direct_byte) {
	fsck_log ("file %k has wrong first direct byte %d, has to be %d\n",
		  key, sd_first_direct_byte, *first_direct_byte);
	return 1;
    }
    return 0;
}

/* return values for check_regular_file and check_semantic_tree */
#define OK 0
#define STAT_DATA_NOT_FOUND -1
#define DIRECTORY_HAS_NO_ITEMS -2
#define RELOCATED -3



/* delete all items (but directory ones) with the same key 'ih' has
   (including stat data of not a directory) and put them back at the
   other place */
void relocate_dir (struct item_head * ih, int change_ih)
{
    struct key key;
    struct key * rkey;
    struct path path;
    struct item_head * path_ih;
    struct si * si;
    __u32 new_objectid;


    /* starting with the leftmost one - look for all items of file,
       store them and delete */
    key = ih->ih_key;
    set_type_and_offset (KEY_FORMAT_1, &key, SD_OFFSET, TYPE_STAT_DATA);

    si = 0;
    while (1) {
	usearch_by_key (fs, &key, &path);
	if (get_item_pos (&path) == B_NR_ITEMS (get_bh (&path))) {
	    rkey = uget_rkey (&path);
	    if (rkey && !not_of_one_file (&key, rkey)) {
		/* file continues in the right neighbor */
		key = *rkey;
		pathrelse (&path);
		continue;
	    }
	    /* there is no more items of a directory */
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
	if ((is_stat_data_ih (path_ih) && not_a_directory (get_item (&path))) ||
	    is_direct_ih (path_ih) || is_indirect_ih (path_ih)) {
	    /* item of not a directory found. Leave it in the
               tree. FIXME: should not happen */
	    key = path_ih->ih_key;
	    set_offset (KEY_FORMAT_1, &key, get_offset (&key) + 1);
	    pathrelse (&path);
	    continue;
	}

	/* directory stat data ro directory item */
	si = save_and_delete_file_item (si, &path);
    }


    if (!si) {
	fsck_progress ("relocate_dir: no directory %K items found\n", &key);
	return;
    }


    /* get new objectid for relocation or get objectid with which file
       was relocated already */
    new_objectid = objectid_for_relocation (&ih->ih_key);
    ih->ih_key.k_objectid = new_objectid;

    /* put all items removed back into tree */
    while (si) { /* XXX JDM CHECK THIS */
	fsck_log ("relocate_dir: move %H to ", &si->si_ih);
	si->si_ih.ih_key.k_objectid = new_objectid;
	fsck_log ("%H\n", &si->si_ih);
	if (get_offset (&(si->si_ih.ih_key)) == DOT_OFFSET) {
	    /* fix "." entry to point to a directtory properly */
	    struct reiserfs_de_head * deh;

	    deh = (struct reiserfs_de_head *)si->si_dnm_data;
	    deh->deh_objectid = new_objectid;
	}
	insert_item_separately (&(si->si_ih), si->si_dnm_data, 1/*was in tree*/);
	si = remove_saved_item (si);
    }
}



/* path is path to stat data. If file will be relocated - new_ih will contain
   a key file was relocated with */
int rebuild_check_regular_file (struct path * path, void * sd,
				struct item_head * new_ih)
{
    int is_new_file;
    struct key key, sd_key;
    mode_t mode;
    __u32 nlink;
    __u64 real_size, saved_size;
    __u32 blocks, saved_blocks;	/* proper values and value in stat data */
    __u32 first_direct_byte, saved_first_direct_byte;

    struct buffer_head * bh;
    struct item_head * ih;
    int fix_sd;
    int symlnk = 0;
    int retval;

    retval = OK;

    /* stat data of a file */
    ih = get_ih (path);
    bh = get_bh (path);

    if (new_ih) {
	/* this objectid is used already */
	*new_ih = *ih;
	pathrelse (path);
	relocate_file (new_ih, 1);
	stats(fs)->oid_sharing_files_relocated ++;
	retval = RELOCATED;
	if (usearch_by_key (fs, &(new_ih->ih_key), path) == ITEM_NOT_FOUND)
	    reiserfs_panic ("rebuild_check_regular_file: could not find stat data of relocated file");
	/* stat data is marked unreachable again due to relocation, fix that */
	ih = get_ih (path);
	bh = get_bh (path);
	mark_item_reachable (ih, bh);
	sd = get_item (path);
    }

    /* check and set nlink first */
    get_sd_nlink (ih, sd, &nlink);
    nlink ++;
    set_sd_nlink (ih, sd, &nlink);
    mark_buffer_dirty (bh);

    if (nlink > 1)
	return OK;

    /* firts name of a file found */
    if (ih_item_len (ih) == SD_SIZE)
	is_new_file = 1;
    else
	is_new_file = 0;

    get_sd_mode (ih, sd, &mode);
    get_sd_size (ih, sd, &saved_size);
    get_sd_blocks (ih, sd, &saved_blocks);
    if (!is_new_file)
	get_sd_first_direct_byte (ih, sd, &saved_first_direct_byte);
    
    /* we met this file first time */
    if (S_ISREG (mode)) {
	stats(fs)->regular_files ++;
    } else if (S_ISLNK (mode)) {
	symlnk = 1;
	stats(fs)->symlinks ++;
    } else {
	stats(fs)->others ++;
    }


    key = ih->ih_key; /*??*/
    sd_key = key; /*??*/
    pathrelse (path);
    
    if (are_file_items_correct (&key, is_new_file ? KEY_FORMAT_2 : KEY_FORMAT_1, 
				&real_size, &blocks, 1/*mark items reachable*/,
				symlnk, saved_size) != 1) {
	/* unpassed items will be deleted in pass 4 as they left unaccessed */
	stats(fs)->broken_files ++;
    }
    
    fix_sd = 0;
    
    fix_sd += wrong_mode (&sd_key, &mode, real_size);
    if (!is_new_file)
	fix_sd += wrong_first_direct_byte (&key, fs->s_blocksize,
					   &first_direct_byte, saved_first_direct_byte, real_size);
    fix_sd += wrong_st_size (&sd_key, is_new_file ? MAX_FILE_SIZE_V2 : MAX_FILE_SIZE_V1, 
			     fs->s_blocksize, &real_size, saved_size, 0/*not dir*/);
    if (!is_new_file && (S_ISREG (mode) || S_ISLNK (mode)))
	/* old stat data shares sd_block and sd_dev. We do not want to wipe
	   put sd_dev for device files */
	fix_sd += wrong_st_blocks (&sd_key, blocks, saved_blocks, 0/*not dir*/);
    
    if (fix_sd) {
	/* find stat data and correct it */
	if (usearch_by_key (fs, &sd_key, path) != ITEM_FOUND)
	    die ("check_regular_file: stat data not found");
	
	bh = get_bh (path);
	ih = get_ih (path);
	sd = get_item (path);
	set_sd_size (ih, sd, &real_size);
	set_sd_blocks (ih, sd, &blocks);
	set_sd_mode (ih, sd, &mode);
	if (!is_new_file)
	    set_sd_first_direct_byte (ih, sd, &first_direct_byte);
	mark_buffer_dirty (bh);
    }

    return retval;
}


static int is_rootdir_key (struct key * key)
{
    if (comp_keys (key, &root_dir_key))
	return 0;
    return 1;
}


/* returns buffer, containing found directory item.*/
static char * get_next_directory_item (struct key * key, /* on return this
                                                            will contain key
                                                            of next item in
                                                            the tree */
				       struct key * parent,
				       struct item_head * ih,/*not in tree*/
				       int * pos_in_item)
{
    INITIALIZE_PATH (path);
    char * dir_item;
    struct key * rdkey;
    struct buffer_head * bh;
    struct reiserfs_de_head * deh;
    int i;
    int retval;


    if ((retval = usearch_by_entry_key (fs, key, &path)) != POSITION_FOUND) {
      die ("get_next_directory_item: %k is not found", key);
    }
#if 0
	if (get_offset (key) != DOT_OFFSET)
	    /* we always search for existing key, but "." */
	    die ("get_next_directory_item: %k is not found", key);
	
	pathrelse (&path);

	if (fsck_mode (fs) == FSCK_CHECK) {
	    fsck_log ("get_next_directory_item: directory has no \".\" entry %k\n",
		      key);
	    pathrelse (&path);
	    return 0;
	}

 	fsck_log ("making \".\" and/or \"..\" for %K\n", key);
	reiserfs_add_entry (fs, key, ".", key, 1 << IH_Unreachable);
	reiserfs_add_entry (fs, key, "..", parent, 1 << IH_Unreachable);


	/* we have fixed a directory, search its first item again */
	usearch_by_entry_key (fs, key, &path);
    }
#endif

    /* leaf containing directory item */
    bh = PATH_PLAST_BUFFER (&path);
    *pos_in_item = path.pos_in_item;
    *ih = *get_ih (&path);
    deh = B_I_DEH (bh, ih);

    /* make sure, that ".." exists as well */
    if (get_offset (key) == DOT_OFFSET) {
	if (ih_entry_count (ih) < 2) {
	    fsck_progress ("1. Does this ever happen?\n");
	    pathrelse (&path);
	    return 0;
	}
	if (name_length (ih, deh + 1, 1) != 2 ||
	    strncmp (name_in_entry (deh + 1, 1), "..", 2)) {
	    fsck_progress ("2. Does this ever happen?\n");
	    fsck_log ("get_next_directory_item: \"..\" not found in %H\n", ih);
	    pathrelse (&path);
	    return 0;
	}
    }

    /* mark hidden entries as visible, set "." and ".." correctly */
    deh += *pos_in_item; 
    for (i = *pos_in_item; i < ih_entry_count (ih); i ++, deh ++) {
	int namelen;
	char * name;

	name = name_in_entry (deh, i);
	namelen = name_length (ih, deh, i);
	if (de_hidden (deh))
	    reiserfs_panic ("get_next_directory_item: item %k: hidden entry %d \'%.*s\'\n",
			    key, i, namelen, name);

	if (deh_offset(deh) == DOT_OFFSET) {
	    if (not_of_one_file (&(deh->deh_dir_id), key))
		//deh->deh_objectid != REISERFS_ROOT_PARENT_OBJECTID)/*????*/ {
		reiserfs_panic ("get_next_directory_item: wrong \".\" found %k\n", key);
	}

	if (deh_offset(deh) == DOT_DOT_OFFSET) {
	    /* set ".." so that it points to the correct parent directory */
	    if (comp_short_keys (&(deh->deh_dir_id), parent) &&
		deh_objectid(deh) != REISERFS_ROOT_PARENT_OBJECTID)/*???*/ {
		/* FIXME */
		fsck_log ("get_next_directory_item: %k: \"..\" pointes to [%K], "
			      "should point to [%K]",
			      key, (struct key *)(&(deh->deh_dir_id)), parent);
		if (fsck_mode (fs) == FSCK_REBUILD) {
		    deh->deh_dir_id = parent->k_dir_id; /* both le */
		    deh->deh_objectid = parent->k_objectid; /* both le */
		    mark_buffer_dirty (bh);
		    fsck_log (" - fixed\n");
		} else
		    fsck_log ("\n");
		
	    }
	}
    }

    /* copy directory item to the temporary buffer */
    dir_item = getmem (ih_item_len (ih)); 
    memcpy (dir_item, B_I_PITEM (bh, ih), ih_item_len (ih));


    /* next item key */
    if (PATH_LAST_POSITION (&path) == (B_NR_ITEMS (bh) - 1) &&
	(rdkey = uget_rkey (&path)))
	copy_key (key, rdkey);
    else {
	key->k_dir_id = 0;
	key->k_objectid = 0;
    }

    if (fsck_mode (fs) != FSCK_CHECK)
        mark_item_reachable (get_ih (&path), bh);
    pathrelse (&path);

    return dir_item;
}


// get key of an object pointed by direntry and the key of the entry itself
static void get_object_key (struct reiserfs_de_head * deh, struct key * key, 
			    struct key * entry_key, struct item_head * ih)
{
    key->k_dir_id = deh->deh_dir_id;
    key->k_objectid = deh->deh_objectid;
    key->u.k_offset_v1.k_offset = cpu_to_le32(SD_OFFSET);
    key->u.k_offset_v1.k_uniqueness = cpu_to_le32(V1_SD_UNIQUENESS);

    entry_key->k_dir_id = ih->ih_key.k_dir_id;
    entry_key->k_objectid = ih->ih_key.k_objectid;
    entry_key->u.k_offset_v1.k_offset = deh->deh_offset;
    entry_key->u.k_offset_v1.k_uniqueness = cpu_to_le32(DIRENTRY_UNIQUENESS);
}


/* check recursively the semantic tree. Returns OK if entry points to good
   object, STAT_DATA_NOT_FOUND if stat data was not found or RELOCATED when
   file was relocated because its objectid was already marked as used by
   another file */
int rebuild_semantic_pass (struct key * key, struct key * parent, int dot_dot,
			   struct item_head * new_ih)
{
    struct path path;
    void * sd;
    int is_new_dir;
    __u32 nlink;
    struct buffer_head * bh;
    struct item_head * ih;
    int retval, retval1;
    char * dir_item;
    int pos_in_item;
    struct item_head tmp_ih;
    struct key item_key, entry_key, object_key;
    __u64 dir_size;
    __u32 blocks;
    __u64 saved_size;
    __u32 saved_blocks;
    int fix_sd;
    int relocate;
    

    retval = OK;

 start_again: /* when directory was relocated */

    if (!KEY_IS_STAT_DATA_KEY (key))
	reiserfs_panic ("rebuild_semantic_pass: key %k must be key of a stat data",
			key);

    /* look for stat data of an object */
    if (usearch_by_key (fs, key, &path) == ITEM_NOT_FOUND) {
	pathrelse (&path);
	if (is_rootdir_key (key))
	    /* root directory has to exist at this point */
	    reiserfs_panic ("rebuild_semantic_pass: root directory not found");

	return STAT_DATA_NOT_FOUND;
    }


    /* stat data has been found */
    bh = get_bh (&path);
    ih = get_ih (&path);
    sd = get_item(&path);

    /* */
    get_sd_nlink (ih, sd, &nlink);

    relocate = 0;
    if (!nlink) {
	/* we reached the stat data for the first time */
	if (is_objectid_really_used (semantic_id_map (fs), ih->ih_key.k_objectid, &pos_in_item)) {
	    /* calculate number of found files/dirs who are using objectid
	       which is used by another file */
	    stats(fs)->oid_sharing ++;
	    if (fsck_fix_non_critical (fs))
		/* this works for files only */
		relocate = 1;
	} else
	    mark_objectid_really_used (semantic_id_map (fs), ih->ih_key.k_objectid);

	mark_item_reachable (ih, bh);
    }


    if (not_a_directory (sd)) {
	retval = rebuild_check_regular_file (&path, sd, relocate ? new_ih : 0);
	pathrelse (&path);
	return retval;
    }

    if (relocate) {
	if (!new_ih)
	    reiserfs_panic ("rebuild_semantic_pass: can not relocate %K",
			    &ih->ih_key);
	*new_ih = *ih;
	pathrelse (&path);
	stats(fs)->oid_sharing_dirs_relocated ++;
	relocate_dir (new_ih, 1);
	*key = new_ih->ih_key;
	retval = RELOCATED;
	goto start_again;
    }

    /* stat data of a directory found */
    if (nlink) {
	/* we saw this directory already */
	if (!dot_dot) {
	    /* this name is not ".."  - and hard links are not allowed on
               directories */
	    pathrelse (&path);
	    return STAT_DATA_NOT_FOUND;
	} else {
	    /* ".." found */
	    nlink ++;
	    set_sd_nlink (ih, sd, &nlink);
	    mark_buffer_dirty (bh);
	    pathrelse (&path);
	    return OK;
	}
    }


    /* we see the directory first time */
    stats(fs)->directories ++;
    nlink = 2;
    if (key->k_objectid == REISERFS_ROOT_OBJECTID)
	nlink ++;
    set_sd_nlink (ih, sd, &nlink);
    mark_buffer_dirty (bh);
    
    if (ih_item_len (ih) == SD_SIZE)
	is_new_dir = 1;
    else
	is_new_dir = 0;

    /* release path pointing to stat data */
    pathrelse (&path);


    /* make sure that "." and ".." exist */
    reiserfs_add_entry (fs, key, ".", key, 1 << IH_Unreachable);
    reiserfs_add_entry (fs, key, "..", parent, 1 << IH_Unreachable);

    item_key = *key;
    item_key.u.k_offset_v1.k_offset = cpu_to_le32(DOT_OFFSET);
    item_key.u.k_offset_v1.k_uniqueness = cpu_to_le32(DIRENTRY_UNIQUENESS);

    /* save stat data's size and st_blocks */
    get_sd_size (ih, sd, &saved_size);
    get_sd_blocks (ih, sd, &saved_blocks);	
    
    dir_size = 0;
    while ((dir_item = get_next_directory_item (&item_key, parent, &tmp_ih, &pos_in_item)) != 0) {
	/* dir_item is copy of the item in separately allocated memory,
	   item_key is a key of next item in the tree */
	int i;
	struct reiserfs_de_head * deh = (struct reiserfs_de_head *)dir_item + pos_in_item;
	
	
	for (i = pos_in_item; i < ih_entry_count (&tmp_ih); i ++, deh ++) {
	    char * name;
	    int namelen;
	    struct item_head relocated_ih;
	    
	    name = name_in_entry (deh, i);
	    namelen = name_length (&tmp_ih, deh, i);
	    
	    if (is_dot (name, namelen)) {
		dir_size += DEH_SIZE + entry_length (&tmp_ih, deh, i);
		continue;
	    }

	    print_name (name, namelen);
	    
	    if (!is_properly_hashed (fs, name, namelen, deh_offset (deh)))
		reiserfs_panic ("rebuild_semantic_pass: name has to be hashed properly");
	    
	    get_object_key (deh, &object_key, &entry_key, &tmp_ih);
	    
	    retval1 = rebuild_semantic_pass (&object_key, key, is_dot_dot (name, namelen), &relocated_ih);
    
	    erase_name (namelen);
	    
	    switch (retval1) {
	    case OK:
		dir_size += DEH_SIZE + entry_length (&tmp_ih, deh, i);
		break;

	    case STAT_DATA_NOT_FOUND:
	    case DIRECTORY_HAS_NO_ITEMS:
		if (get_offset (&entry_key) == DOT_DOT_OFFSET && object_key.k_objectid == REISERFS_ROOT_PARENT_OBJECTID) {
		    /* ".." of root directory can not be found */
		    dir_size += DEH_SIZE + entry_length (&tmp_ih, deh, i);
		    continue;
		}
		fsck_log ("name \"%.*s\" in directory %K points to nowhere %K - removed\n",
			  namelen, name, &tmp_ih.ih_key, (struct key *)&(deh->deh_dir_id));
		reiserfs_remove_entry (fs, &entry_key);
		stats(fs)->deleted_entries ++;
		break;
		
	    case RELOCATED:
		/* file was relocated, update key in corresponding directory entry */
		if (_search_by_entry_key (fs, &entry_key, &path) != POSITION_FOUND) {
		    fsck_progress ("could not find name of relocated file\n");
		} else {
		    /* update key dir entry points to */
		    struct reiserfs_de_head * tmp_deh;
		    
		    tmp_deh = B_I_DEH (get_bh (&path), get_ih (&path)) + path.pos_in_item;
		    fsck_log ("name \"%.*s\" of dir %K pointing to %K updated to point to ",
			      namelen, name, &tmp_ih.ih_key, &tmp_deh->deh_dir_id);
		    tmp_deh->deh_dir_id = cpu_to_le32 (relocated_ih.ih_key.k_dir_id); /* both le */
		    tmp_deh->deh_objectid = cpu_to_le32 (relocated_ih.ih_key.k_objectid); /* both le */
		    fsck_log ("%K\n",  &tmp_deh->deh_dir_id);
		    mark_buffer_dirty (get_bh (&path));
		}
		dir_size += DEH_SIZE + entry_length (&tmp_ih, deh, i);
		pathrelse (&path);
		break;
	    }
	} /* for */
	
	freemem (dir_item);
	
	if (not_of_one_file (&item_key, key))
	    /* next key is not of this directory */
	    break;
	
    } /* while (dir_item) */
    
    
    if (dir_size == 0)
	/* FIXME: is it possible? */
	return DIRECTORY_HAS_NO_ITEMS;
    
    /* calc correct value of sd_blocks field of stat data */
    blocks = dir_size2st_blocks (fs->s_blocksize, dir_size);
    
    fix_sd = 0;
    fix_sd += wrong_st_blocks (key, blocks, saved_blocks, 1/*dir*/);
    fix_sd += wrong_st_size (key, is_new_dir ? MAX_FILE_SIZE_V2 : MAX_FILE_SIZE_V1,
			     fs->s_blocksize, &dir_size, saved_size, 1/*dir*/);
    
    if (fix_sd) {
	/* we have to fix either sd_size or sd_blocks, so look for stat data again */
	if (usearch_by_key (fs, key, &path) != ITEM_FOUND)
	    die ("rebuild_semantic_pass: stat data not found");
	    
	bh = get_bh (&path);
	ih = get_ih (&path);
	sd = get_item (&path);
	
	set_sd_size (ih, sd, &dir_size);
	set_sd_blocks (ih, sd, &blocks);
	mark_buffer_dirty (bh);
	pathrelse (&path);
    }
    
    return retval;
}


int is_dot (char * name, int namelen)
{
    return (namelen == 1 && name[0] == '.') ? 1 : 0;
}


int is_dot_dot (char * name, int namelen)
{
    return (namelen == 2 && name[0] == '.' && name[1] == '.') ? 1 : 0;
}


int not_a_directory (void * sd)
{
    /* mode is at the same place and of the same size in both stat
       datas (v1 and v2) */
    struct stat_data_v1 * sd_v1 = sd;

    return !(S_ISDIR (sd_v1_mode(sd_v1)));
}




void zero_nlink (struct item_head * ih, void * sd)
{
    int zero = 0;

    if (ih_item_len (ih) == SD_V1_SIZE && ih_key_format (ih) != KEY_FORMAT_1) {
	fsck_log ("zero_nlink: %H had wrong keys format %d, fixed to %d",
		  ih, ih_key_format (ih), KEY_FORMAT_1);
	set_ih_key_format (ih, KEY_FORMAT_1);
    }
    if (ih_item_len (ih) == SD_SIZE && ih_key_format (ih) != KEY_FORMAT_2) {
	fsck_log ("zero_nlink: %H had wrong keys format %d, fixed to %d",
		  ih, ih_key_format (ih), KEY_FORMAT_2);
	set_ih_key_format (ih, KEY_FORMAT_2);
    }

    set_sd_nlink (ih, sd, &zero);
}


/* inserts new or old stat data of a directory (unreachable, nlinks == 0) */
void create_dir_sd (reiserfs_filsys_t fs, 
		    struct path * path, struct key * key)
{
    struct item_head ih;
    struct stat_data sd;
    int key_format;

    if (SB_VERSION(fs) == REISERFS_VERSION_2)
	key_format = KEY_FORMAT_2;
    else
	key_format = KEY_FORMAT_1;

    make_dir_stat_data (fs->s_blocksize, key_format, key->k_dir_id,
			key->k_objectid, &ih, &sd);

    /* set nlink count to 0 and make the item unreachable */
    zero_nlink (&ih, &sd);
    mark_item_unreachable (&ih);

    reiserfs_insert_item (fs, path, &ih, &sd);
}


static void make_sure_root_dir_exists (reiserfs_filsys_t fs)
{
    INITIALIZE_PATH (path);

    /* is there root's stat data */
    if (usearch_by_key (fs, &root_dir_key, &path) == ITEM_NOT_FOUND) {	
	create_dir_sd (fs, &path, &root_dir_key);
	mark_objectid_really_used (proper_id_map (fs), REISERFS_ROOT_OBJECTID);
    } else
	pathrelse (&path);

    /* add "." and ".." if any of them do not exist. Last two
       parameters say: 0 - entry is not added on lost_found pass and 1
       - mark item unreachable */
    reiserfs_add_entry (fs, &root_dir_key, ".", &root_dir_key, 
			1 << IH_Unreachable);
    reiserfs_add_entry (fs, &root_dir_key, "..", &parent_root_dir_key, 
			1 << IH_Unreachable);
}


/* mkreiserfs should have created this */
static void make_sure_lost_found_exists (reiserfs_filsys_t fs)
{
    int retval;
    INITIALIZE_PATH (path);
    int gen_counter;

    /* look for "lost+found" in the root directory */
    lost_found_dir_key.k_objectid = reiserfs_find_entry (fs, &root_dir_key,
							 "lost+found", &gen_counter);
    if (!lost_found_dir_key.k_objectid) {
	lost_found_dir_key.k_objectid = get_unused_objectid (fs);
	if (!lost_found_dir_key.k_objectid) {
	    fsck_progress ("make_sure_lost_found_exists: could not get objectid"
			   " for \"/lost+found\", will not link lost files\n");
	    return;
	}
    }

    /* look for stat data of "lost+found" */
    retval = usearch_by_key (fs, &lost_found_dir_key, &path);
    if (retval == ITEM_NOT_FOUND)
	create_dir_sd (fs, &path, &lost_found_dir_key);
    else {
	if (not_a_directory (get_item (&path))) {
	    fsck_progress ("make_sure_lost_found_exists: \"/lost+found\" is "
			   "not a directory, will not link lost files\n");
	    lost_found_dir_key.k_objectid = 0;
	    pathrelse (&path);
	    return;
	}
	pathrelse (&path);
    }

    /* add "." and ".." if any of them do not exist */
    reiserfs_add_entry (fs, &lost_found_dir_key, ".", &lost_found_dir_key,
			1 << IH_Unreachable);
    reiserfs_add_entry (fs, &lost_found_dir_key, "..", &root_dir_key, 
			1 << IH_Unreachable);

    reiserfs_add_entry (fs, &root_dir_key, "lost+found", &lost_found_dir_key, 
			1 << IH_Unreachable);

    return;
}


/* this is part of rebuild tree */
void pass_3_semantic (void)
{
    fsck_progress ("Pass 3 (semantic):\n");

    /* when warnings go not to stderr - separate then in the log */
    if (fsck_log_file (fs) != stderr)
	fsck_log ("####### Pass 3 #########\n");
    
    if (!fs->s_hash_function)
	reiserfs_panic ("Hash function should be selected already");

    make_sure_root_dir_exists (fs);
    make_sure_lost_found_exists (fs);

    /* link all relocated files into root directory */
    link_relocated_files ();

    rebuild_semantic_pass (&root_dir_key, &parent_root_dir_key, 0/*!dot_dot*/, 0/*reloc_ih*/);
    stage_report (3, fs);

}


/* path is path to stat data. If file will be relocated - new_ih will contain
   a key file was relocated with */
static int check_check_regular_file (struct path * path, void * sd)
{
    int is_new_file;
    struct key key, sd_key;
    mode_t mode;
    __u32 nlink;
    __u64 real_size, saved_size;
    __u32 blocks, saved_blocks;	/* proper values and value in stat data */
    __u32 first_direct_byte, saved_first_direct_byte;

    struct buffer_head * bh;
    struct item_head * ih;
    int fix_sd;
    int symlnk = 0;


    ih = get_ih (path);
    bh = get_bh (path);

    if (ih_item_len (ih) == SD_SIZE)
	is_new_file = 1;
    else
	is_new_file = 0;


    get_sd_nlink (ih, sd, &nlink);
    get_sd_mode (ih, sd, &mode);
    get_sd_size (ih, sd, &saved_size);
    get_sd_blocks (ih, sd, &saved_blocks);
    if (!is_new_file)
	get_sd_first_direct_byte (ih, sd, &saved_first_direct_byte);

    if (S_ISREG (mode)) {
	/* fixme: this could be wrong due to hard links */
	stats(fs)->regular_files ++;
    } else if (S_ISLNK (mode)) {
	symlnk = 1;
	stats(fs)->symlinks ++;
    } else {
	stats(fs)->others ++;
    }


    key = ih->ih_key; /*??*/
    sd_key = key; /*??*/
    pathrelse (path);

    if (are_file_items_correct (&key, is_new_file ? KEY_FORMAT_2 : KEY_FORMAT_1, 
				&real_size, &blocks, 0/*do not mark items reachable*/,
				symlnk, saved_size) != 1) {
	fsck_log ("check_regular_file: broken file found %K\n", key);
    } else {
	fix_sd = 0;
    
	fix_sd += wrong_mode (&sd_key, &mode, real_size);
	if (!is_new_file)
	    fix_sd += wrong_first_direct_byte (&key, fs->s_blocksize,
					       &first_direct_byte, saved_first_direct_byte, real_size);
	fix_sd += wrong_st_size (&sd_key, is_new_file ? MAX_FILE_SIZE_V2 : MAX_FILE_SIZE_V1, 
				 fs->s_blocksize, &real_size, saved_size, 0/*not dir*/);
	if (!is_new_file && (S_ISREG (mode) || S_ISLNK (mode)))
	    /* old stat data shares sd_block and sd_dev. We do not want to wipe
	       put sd_dev for device files */
	    fix_sd += wrong_st_blocks (&sd_key, blocks, saved_blocks, 0/*not dir*/);
	
	if (fix_sd && fsck_fix_fixable (fs)) {
	    /* find stat data and correct it */
	    if (usearch_by_key (fs, &sd_key, path) != ITEM_FOUND)
		die ("check_regular_file: stat data not found");
	    
	    bh = get_bh (path);
	    ih = get_ih (path);
	    sd = get_item (path);
	    set_sd_size (ih, sd, &real_size);
	    set_sd_blocks (ih, sd, &blocks);
	    set_sd_mode (ih, sd, &mode);
	    if (!is_new_file)
		set_sd_first_direct_byte (ih, sd, &first_direct_byte);
	    mark_buffer_dirty (bh);
	}
    }
    return OK;
}


/* semantic pass of --check */
static int check_semantic_pass (struct key * key, struct key * parent)
{
    struct path path;
    void * sd;
    int is_new_dir;
    struct buffer_head * bh;
    struct item_head * ih;
    int retval;
    char * dir_item;
    int pos_in_item;
    struct item_head tmp_ih;
    struct key next_item_key, entry_key, object_key;
    __u64 dir_size = 0;
    __u32 blocks;
    __u64 saved_size;
    __u32 saved_blocks;
    int fix_sd;
	

    if (!KEY_IS_STAT_DATA_KEY (key))
	die ("check_semantic_pass: key must be key of a stat data");

    /* look for stat data of an object */
    if (usearch_by_key (fs, key, &path) == ITEM_NOT_FOUND) {
	pathrelse (&path);
	return STAT_DATA_NOT_FOUND;
    }

    /* stat data has been found */
    sd = get_item(&path);

    if (not_a_directory (sd)) {
	retval = check_check_regular_file (&path, sd);
	pathrelse (&path);
	return retval;
    }

    ih = get_ih (&path);
    /* directory stat data found */
    if (ih_item_len (ih) == SD_SIZE)
	is_new_dir = 1;
    else
	is_new_dir = 0;

    /* save stat data's size and st_blocks */
    get_sd_size (ih, sd, &saved_size);
    get_sd_blocks (ih, sd, &saved_blocks);

    /* release path pointing to stat data */
    pathrelse (&path);

    stats(fs)->directories ++;
    next_item_key = *key;
    next_item_key.u.k_offset_v1.k_offset = cpu_to_le32(DOT_OFFSET);
    next_item_key.u.k_offset_v1.k_uniqueness = cpu_to_le32(DIRENTRY_UNIQUENESS);


    dir_size = 0;
    while ((dir_item = get_next_directory_item (&next_item_key, parent, &tmp_ih, &pos_in_item)) != 0) {
	/* dir_item is copy of the item in separately allocated memory,
	   item_key is a key of next item in the tree */
	int i;
	struct reiserfs_de_head * deh = (struct reiserfs_de_head *)dir_item + pos_in_item;
	
	
	for (i = pos_in_item; i < ih_entry_count (&tmp_ih); i ++, deh ++) {
	    char * name;
	    int namelen;
	    
	    name = name_in_entry (deh, i);
	    namelen = name_length (&tmp_ih, deh, i);
	    
	    print_name (name, namelen);
	    
	    if (!is_properly_hashed (fs, name, namelen, deh_offset (deh))) {
		fsck_log ("check_semantic_pass: hash mismatch detected (%.*s)\n", namelen, name);
	    }
	    get_object_key (deh, &object_key, &entry_key, &tmp_ih);
	    
	    if (is_dot (name, namelen) || is_dot_dot (name, namelen)) {
		/* do not go through "." and ".." */
		retval = OK;
	    } else {
		add_path_key (&object_key);
		retval = check_semantic_pass (&object_key, key);
		del_path_key ();
	    }
	    
	    erase_name (namelen);
	    
	    /* check what check_semantic_tree returned */
	    switch (retval) {
	    case OK:
		dir_size += DEH_SIZE + entry_length (&tmp_ih, deh, i);
		break;
		
	    case STAT_DATA_NOT_FOUND:
		fsck_log ("check_semantic_pass: name \"%.*s\" in directory %K points to nowhere",
			  namelen, name, &tmp_ih.ih_key);
		if (fsck_fix_fixable (fs)) {
		    reiserfs_remove_entry (fs, &entry_key);
		    stats(fs)->deleted_entries ++;
		    fsck_log (" - removed");
		}
		fsck_log ("\n");
		    break;
		    
	    case DIRECTORY_HAS_NO_ITEMS:
		fsck_log ("check_semantic_pass: name \"%.*s\" in directory %K points dir without body\n",
			  namelen, name, &tmp_ih.ih_key);
		/* fixme: stat data should be deleted as well */
		/*
		  if (fsck_fix_fixable (fs)) {
		  reiserfs_remove_entry (fs, &entry_key);
		  stats(fs)->deleted_entries ++;
		  fsck_log (" - removed");
		  }
		  fsck_log ("\n");*/
		break;
		
	    case RELOCATED:
		/* fixme: we could also relocate file */
		reiserfs_panic ("check_semantic_pass: relocation in check mode is not ready");
	    }
	} /* for */
	
	freemem (dir_item);
	
	if (not_of_one_file (&next_item_key, key))
	    /* next key is not of this directory */
	    break;
	
    } /* while (dir_item) */
    
    
    if (dir_size == 0)
	/* FIXME: is it possible? */
	return DIRECTORY_HAS_NO_ITEMS;
    
    /* calc correct value of sd_blocks field of stat data */
    blocks = dir_size2st_blocks (fs->s_blocksize, dir_size);
    
    fix_sd = 0;
    fix_sd += wrong_st_blocks (key, blocks, saved_blocks, 1/*dir*/);
    fix_sd += wrong_st_size (key, is_new_dir ? MAX_FILE_SIZE_V2 : MAX_FILE_SIZE_V1,
			     fs->s_blocksize, &dir_size, saved_size, 1/*dir*/);
    
    if (fix_sd && fsck_fix_fixable (fs)) {
	/* we have to fix either sd_size or sd_blocks, so look for stat data again */
	if (usearch_by_key (fs, key, &path) != ITEM_FOUND)
	    die ("check_semantic_tree: stat data not found");
	
	bh = get_bh (&path);
	ih = get_ih (&path);
	sd = get_item (&path);
	
	set_sd_size (ih, sd, &dir_size);
	set_sd_blocks (ih, sd, &blocks);
	mark_buffer_dirty (bh);
	pathrelse (&path);
    }
    
    return OK;
}


/* called when --check is given */
void semantic_check (void)
{
    fsck_progress ("Checking Semantic tree...");

    if (check_semantic_pass (&root_dir_key, &parent_root_dir_key) != OK)
        die ("check_semantic_tree: no root directory found");

    fsck_progress ("ok\n");

}



