/*
 * Copyright 1996, 1997, 1998 Hans Reiser
 */
#include "fsck.h"


void get_next_key (struct path * path, int i, struct key * key)
{
    struct buffer_head * bh = PATH_PLAST_BUFFER (path);
    struct key * rkey;


    if (i < B_NR_ITEMS (bh) - 1) {
	/* next item is in this block */
	copy_key (key, B_N_PKEY (bh, i + 1));
	return;
    }

    rkey = uget_rkey (path);
    if (rkey) {
	/* got next item key from right delimiting key */
	copy_key (key, rkey);
    } else {
	/* there is no next item */
	memset (key, 0xff, KEY_SIZE);
    }
}


int pass_4_check_unaccessed_items (void)
{
    struct key key;
    struct path path;
    int i;
    struct buffer_head * bh;
    struct item_head * ih;
    unsigned long items;

    path.path_length = ILLEGAL_PATH_ELEMENT_OFFSET;
    key = root_dir_key;
    
    fsck_progress ("Pass 4 - ");
    items = 0;

    while (usearch_by_key (fs, &key, &path) == ITEM_FOUND) {
	bh = PATH_PLAST_BUFFER (&path);

	/* print ~ how many leaves were scanned and how fast it was */
	if (!fsck_quiet (fs))
	    print_how_fast (0, items++, 50);

	for (i = get_item_pos (&path), ih = get_ih (&path); i < B_NR_ITEMS (bh); i ++, ih ++) {


	    if (!is_item_reachable (ih)) {

		get_next_key (&path, i, &key);

		stats(fs)->deleted_items ++;
	
		PATH_LAST_POSITION (&path) = i;
		reiserfsck_delete_item (&path, 0);

		goto cont;
	    }
	}
	get_next_key (&path, i - 1, &key);
	pathrelse (&path);

    cont:
    }

    pathrelse (&path);

    fsck_progress ("done\n");
    stage_report (4, fs);

    return 0;
}
