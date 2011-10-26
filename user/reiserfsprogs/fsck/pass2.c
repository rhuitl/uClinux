/*
 * Copyright 1996-2001 Hans Reiser
 */

#include "fsck.h"


/* on pass2 we take leaves which could not be inserted into tree
   during pass1 and insert each item separately. It is possible that
   items of different objects with the same key can be found. We treat
   that in the following way: we put it into tree with new key and
   link it into /lost+found directory with name made of dir,oid. When
   coming item is a directory - we delete object from the tree, put it
   back with different key, link it to /lost+found directory and
   insert directory as it is */

/* relocation rules: we have an item (it is taken from "non-insertable"
   leaf). It has original key yet. We check to see if object with this
   key is remapped. Object can be only remapped if it is not a piece
   of directory */


/* in list of this structures we store what has been
   relocated. Directories can not be reallocated. */
struct relocated {
    unsigned long old_dir_id;
    unsigned long old_objectid;
    unsigned long new_objectid;
    mode_t mode;
    struct relocated * next;
}; /* in disk byte order */


/* all relocated files will be linked into lost+found directory at the
   beginning of semantic pass */
struct relocated * relocated_list;


/* return objectid the object has to be remapped with */
/* returns little endian objectid */
__u32 objectid_for_relocation (struct key * key)
{
    struct relocated * cur;

    cur = relocated_list;

    while (cur) {
	if (cur->old_dir_id == key->k_dir_id &&
	    cur->old_objectid == key->k_objectid)
	    /* object is relocated already */
	    return cur->new_objectid;
	cur = cur->next;
    }

    cur = getmem (sizeof (struct relocated));
    cur->old_dir_id = key->k_dir_id;
    cur->old_objectid = key->k_objectid;
    cur->new_objectid = get_unused_objectid (fs);
    cur->next = relocated_list;
    relocated_list = cur;
    fsck_log ("relocation: (%K) is relocated to (%lu, %lu)."
	      "look for it in the lost+found\n",
	      key, key_dir_id(key), le32_to_cpu(cur->new_objectid));
    return cur->new_objectid;
}


/* this item is in tree. All unformatted pointer are correct. Do not
   check them */
static void save_item_2 (struct si ** head, struct item_head * ih, 
			 char * item, __u32 blocknr)
{
    struct si * si, * cur;

    si = getmem (sizeof (*si));
    si->si_dnm_data = getmem (ih_item_len(ih));
    /*si->si_blocknr = blocknr;*/
    memcpy (&(si->si_ih), ih, IH_SIZE);
    memcpy (si->si_dnm_data, item, ih_item_len(ih));

    if (*head == 0)
	*head = si;
    else {
	cur = *head;
	while (cur->si_next)
	    cur = cur->si_next;
	cur->si_next = si;
    }
    return;
}


struct si * save_and_delete_file_item (struct si * si, struct path * path)
{
    struct buffer_head * bh = PATH_PLAST_BUFFER (path);
    struct item_head * ih = PATH_PITEM_HEAD (path);

    save_item_2 (&si, ih, B_I_PITEM (bh, ih), bh->b_blocknr);

    /* delete item temporary - do not free unformatted nodes */
    reiserfsck_delete_item (path, 1/*temporary*/);
    return si;
}


/* check whether there are any directory items with this key */
static int should_relocate (struct item_head * ih)
{
    struct key key;
    struct key * rkey;
    struct path path;
    struct item_head * path_ih;


    /* starting with the leftmost item with this key */
    key = ih->ih_key;
    set_type_and_offset (KEY_FORMAT_1, &key, SD_OFFSET, TYPE_STAT_DATA);

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
	    (is_direntry_ih (path_ih))) {
	    /* item of directory found. so, we have to relocate the file */
	    pathrelse (&path);
	    return 1;
	}
	key = path_ih->ih_key;
	set_offset (KEY_FORMAT_1, &key, get_offset (&key) + 1);
	pathrelse (&path);
    }
    return 0;
}


/* delete all items (but directory ones) with the same key 'ih' has
   (including stat data of not a directory) and put them back at the
   other place */
void relocate_file (struct item_head * ih, int change_ih)
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
	    (is_direntry_ih (path_ih))) {
	    /* item of directory found. Leave it in the tree */
	    key = path_ih->ih_key;
	    set_offset (KEY_FORMAT_1, &key, get_offset (&key) + 1);
	    pathrelse (&path);
	    continue;
	}

	si = save_and_delete_file_item (si, &path);
    }


    if (si || change_ih) {
	int moved_items;
	struct key old, new;

	/* get new objectid for relocation or get objectid with which file
	   was relocated already */
	new_objectid = objectid_for_relocation (&ih->ih_key);
	if (change_ih)
	    ih->ih_key.k_objectid = new_objectid;

	moved_items = 0;

	/* put all items removed back into tree */
	while (si) {
	    /*fsck_log ("relocate_file: move %H to ", &si->si_ih);*/
	    old = si->si_ih.ih_key;
	    si->si_ih.ih_key.k_objectid = new_objectid;
	    new = si->si_ih.ih_key;
	    /*fsck_log ("%H\n", &si->si_ih);*/
	    insert_item_separately (&(si->si_ih), si->si_dnm_data, 1/*was in tree*/);
	    si = remove_saved_item (si);
	    moved_items ++;
	}
	if (moved_items)
	    fsck_log ("relocate_file: %d items of file %K moved to %K\n",
		      moved_items, &old, &new);
    }
}


/* this works for both new and old stat data */
#define st_mode(sd) le16_to_cpu(((struct stat_data *)(sd))->sd_mode)

#define st_mtime_v1(sd) le32_to_cpu(((struct stat_data_v1 *)(sd))->sd_mtime)
#define st_mtime_v2(sd) le32_to_cpu(((struct stat_data *)(sd))->sd_mtime)

static void overwrite_stat_data (struct item_head * new_ih,
				 void * new_item, struct path * path)
{
    if (stat_data_v1 (new_ih)) {
	if (st_mtime_v1 (new_item) > st_mtime_v1 (get_item (path))) {
	    memcpy (get_item (path), new_item, SD_V1_SIZE);
	    mark_buffer_dirty (get_bh (path));
	}
    } else {
	if (st_mtime_v2 (new_item) > st_mtime_v2 (get_item (path))) {
	    memcpy (get_item (path), new_item, SD_SIZE);
	    mark_buffer_dirty (get_bh (path));
	}
    }
    return;
}


/* insert sd item if it does not exist, overwrite it otherwise */
static void put_sd_into_tree (struct item_head * new_ih, char * new_item)
{
    struct path path;
    
    if (!not_a_directory (new_item)) {
	/* new item is a stat data of a directory. So we have to
           relocate all items which have the same short key and are of
           not a directory */
	relocate_file (new_ih, 0/*do not change new_ih*/);
    } else {
	/* new item is a stat data of something else but directory. If
           there are items of directory - we have to relocate the file */
	if (should_relocate (new_ih))
	    relocate_file (new_ih, 1/*change new_ih*/);
    }
    
    /* if we will have to insert item into tree - it is ready */
    zero_nlink (new_ih, new_item);
    mark_item_unreachable (new_ih);
    
    /* we are sure now that if we are inserting stat data of a
       directory - there are no items with the same key which are not
       items of a directory, and that if we are inserting stat data is
       of not a directory - it either has new key already or there are
       no items with this key which are items of a directory */
    if (usearch_by_key (fs, &(new_ih->ih_key), &path) == ITEM_FOUND) {
	/* this stat data is found */
        if (ih_key_format (get_ih(&path)) != ih_key_format (new_ih)) {
	    /* in tree stat data and a new one are of different
               formats */
	    fsck_log ("put_sd_into_tree: inserting stat data %K (%M)..",
		      &(new_ih->ih_key), st_mode (new_item));
	    if (stat_data_v1 (new_ih)) {
		/* sd to be inserted is of V1, where as sd in the tree
                   is of V2 */
		fsck_log ("found newer in the tree (%M), skip inserting\n",
			  st_mode (get_item (&path)));
	    } else {
		/* the stat data in the tree is sd_v1 */
		fsck_log ("older sd (%M) is replaced with it\n",
			  st_mode (get_item (&path)));
		reiserfsck_delete_item (&path, 0/*not temporary*/);
		
		usearch_by_key (fs, &new_ih->ih_key, &path);
		reiserfsck_insert_item (&path, new_ih, new_item);
	    }
	} else {
	    /* both stat data are of the same version */
	    overwrite_stat_data (new_ih, new_item, &path);
	    pathrelse (&path);
	}
	return;
    }
    
    /* item not found, insert a new one */
    reiserfsck_insert_item (&path, new_ih, new_item);
}


/* this tries to put each item entry to the tree, if there is no items
   of the directory, insert item containing 1 entry */
static void put_directory_item_into_tree (struct item_head * comingih, char * item)
{
    struct reiserfs_de_head * deh;
    int i;
    char * buf;
    char * name;
    int namelen;

    /* if there are anything ith this key but a directory - move it
       somewhere else */
    relocate_file (comingih, 0/* do not change ih */);

    deh = (struct reiserfs_de_head *)item;

    for (i = 0; i < ih_entry_count (comingih); i ++, deh ++) {
	name = name_in_entry (deh, i);
	namelen = name_length (comingih, deh, i);

	if (!is_properly_hashed (fs, name, namelen, deh_offset (deh)))
	    reiserfs_panic ("put_directory_item_into_tree: should be hashed properly ()");

	asprintf (&buf, "%.*s", namelen, name);
	/* 1 for fsck is important: if there is no any items of this
           directory in the tree yet - new item will be inserted
           marked not reached */
	reiserfs_add_entry (fs, &(comingih->ih_key), buf, (struct key *)&(deh->deh_dir_id), 1/*fsck_need*/);
	free (buf);
    }

    /* make a directory */
}


/* relocated files get added into lost+found with slightly different names */
static void link_one (struct relocated * file)
{
    char * name;
    struct key obj_key;

    asprintf (&name, "%lu,%lu", file->old_dir_id, file->new_objectid);
    obj_key.k_dir_id = file->old_dir_id;
    obj_key.k_objectid = file->new_objectid;

    /* 0 for fsck_need does not mean too much - it would make effect
       if there were no this directory yet. But /lost_found is there
       already */
    reiserfs_add_entry (fs, &lost_found_dir_key, name, &obj_key, 0/*fsck_need*/);
    stats(fs)->relocated ++;
    free (name);
}


void link_relocated_files (void)
{
    struct relocated * tmp;
    int count;
    
    count = 0;
    while (relocated_list) {
	link_one (relocated_list);
	tmp = relocated_list;
	relocated_list = relocated_list->next;
	freemem (tmp);
	count ++;
    }
}


void insert_item_separately (struct item_head * ih,
			     char * item, int was_in_tree)
{
    if (ih->ih_key.k_dir_id == ih->ih_key.k_objectid)
	reiserfs_panic ("insert_item_separately: can not insert bad item %H", ih);
    
    if (is_stat_data_ih (ih)) {
	put_sd_into_tree (ih, item);
    } else if (is_direntry_ih (ih)) {
	put_directory_item_into_tree (ih, item);
    } else {
	if (should_relocate (ih))
	    relocate_file (ih, 1/*change new_ih*/);
	
	reiserfsck_file_write (ih, item, was_in_tree);
    }
}


static void put_items (struct buffer_head * bh)
{
    int i;
    struct item_head * ih;

    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < B_NR_ITEMS (bh); i ++, ih ++) {
	if (i && bad_pair (fs, bh, i)) {
	    /* skip item if it is in wrong order */
	    continue;
	}
	insert_item_separately (ih, B_I_PITEM (bh, ih), 0/*was in tree*/);
    }
}


/* uninsertable blocks are marked by 0s in uninsertable_leaf_bitmap
   during the pass 1. They must be not in the tree */
void pass_2_take_bad_blocks_put_into_tree (void)
{
    struct buffer_head * bh;
    unsigned long j;
    unsigned long bb_counter = 0;
    int what_node;


    if (!stats(fs)->uninsertable_leaves)
	return;

    if (fsck_log_file (fs) != stderr)
	fsck_log ("####### Pass 2 #######\n");

    fsck_progress ("\nPass2:\n");

    j = 0;
    while (reiserfs_bitmap_find_zero_bit (uninsertable_leaf_bitmap, &j) == 0) {
	bh = bread (fs->s_dev, j, fs->s_blocksize);
	if (bh == 0) {
	    fsck_log ("pass_2_take_bad_blocks_put_into_tree: "
		      "unable to read %lu block on device 0x%x\n",
		      j, fs->s_dev);
	    goto next;
	}
	
	if (is_block_used (bh->b_blocknr)) {
	    fsck_log ("pass_2_take_bad_blocks_put_into_tree: "
		      "block %d can not be in tree\n", bh->b_blocknr);
	    goto next;
	}
	/* this must be leaf */
	what_node = who_is_this (bh->b_data, fs->s_blocksize);
	if (what_node != THE_LEAF) { // || B_IS_KEYS_LEVEL(bh)) {
	    fsck_log ("take_bad_blocks_put_into_tree: buffer (%b %z) must contain leaf\n", bh, bh);
	    goto next;
	}

	/*fsck_log ("block %lu is being inserted\n", bh->b_blocknr);*/
	put_items (bh);
	
	print_how_far (&bb_counter, stats(fs)->uninsertable_leaves, 1, fsck_quiet (fs));
	
    next:
	brelse (bh);
	j ++;
    }

    fsck_progress ("\n");


    if (bb_counter != stats(fs)->uninsertable_leaves)
	die ("take_bad_blocks_put_into_tree: found bad block %d, must be %d", 
	     bb_counter, stats(fs)->uninsertable_leaves);

}
