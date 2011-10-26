/*
 * Copyright 2000-2001 Hans Reiser
 */

#include "fsck.h"


/* fixme: search_by_key is not needed after any add_entry */
static __u64 _look_for_lost (reiserfs_filsys_t fs, int link_lost_dirs)
{
    struct key key, prev_key, * rdkey;
    INITIALIZE_PATH (path);
    int item_pos;
    struct buffer_head * bh;
    struct item_head * ih;
    unsigned long leaves;
    int is_it_dir;
    static int lost_files = 0; /* looking for lost dirs we calculate amount of
				  lost files, so that when we will look for
				  lost files we will be able to stop when
				  there are no lost files anymore */
    int retval;
    __u64 size;

    key = root_dir_key;

    if (!link_lost_dirs && !lost_files) {
	/* we have to look for lost files but we know already that there are
           no any */
	return 0;
    }
	
    fsck_progress ("Looking for lost %s:\n", link_lost_dirs ? "directories" : "files");
    leaves = 0;

    /* total size of added entries */
    size = 0;
    while (1) {
	retval = usearch_by_key (fs, &key, &path);
	/* fixme: we assume path ends up with a leaf */
	bh = get_bh (&path);
	item_pos = get_item_pos (&path);
	if (retval != ITEM_FOUND) {
	    if (item_pos == node_item_number (bh)) {
		rdkey = uget_rkey (&path);
		if (!rdkey) {
		    pathrelse (&path);
		    break;
		}
		key = *rdkey;
		pathrelse (&path);
		continue;
	    }
	    /* we are on the item in the buffer */
	}

	/* print ~ how many leaves were scanned and how fast it was */
	if (!fsck_quiet (fs))
	    print_how_fast (0, leaves++, 50);

	for (ih = get_ih (&path); item_pos < node_item_number (bh); item_pos ++, ih ++) {
	    if (is_item_reachable (ih))
		continue;

	    /* found item which can not be reached */
	    if (!is_direntry_ih (ih) && !is_stat_data_ih (ih)) {
		continue;
	    }

	    if (is_direntry_ih (ih)) {
		/* if this directory has no stat data - try to recover it */
		struct key sd;
		struct path tmp;

		sd = ih->ih_key;
		set_type_and_offset (KEY_FORMAT_1, &sd, SD_OFFSET, TYPE_STAT_DATA);
		if (usearch_by_key (fs, &sd, &tmp) == ITEM_FOUND) {
		    /* should not happen - because if there were a stat data -
                       we would have done with the whole directory */
		    pathrelse (&tmp);
		    continue;
		}
		stats(fs)->dir_recovered ++;
		create_dir_sd (fs, &tmp, &sd);
		key = sd;
		pathrelse (&path);
		goto cont;
	    }


	    /* stat data marked "not having name" found */
	    is_it_dir = ((not_a_directory (B_I_PITEM (bh,ih))) ? 0 : 1);

	    if (is_it_dir) {
		struct key tmp_key;
		INITIALIZE_PATH (tmp_path);
		struct item_head * tmp_ih;

		/* there is no need to link empty lost directories into /lost+found */
		tmp_key = ih->ih_key;
		set_type_and_offset (KEY_FORMAT_1, &tmp_key, 0xffffffff, TYPE_DIRENTRY);
		usearch_by_key (fs, &tmp_key, &tmp_path);
		tmp_ih = get_ih (&tmp_path);
		tmp_ih --;
		if (not_of_one_file (&tmp_key, tmp_ih))
		    reiserfs_panic ("not directory found");
		if (!is_direntry_ih (tmp_ih) ||
		    (deh_offset (B_I_DEH (get_bh (&tmp_path), ih) + 
		     ih_entry_count (tmp_ih) - 1) == DOT_DOT_OFFSET)) {
		    /* last directory item is either stat data or empty
                       directory item - do not link this dir into lost+found */
		    stats(fs)->empty_lost_dirs ++;
		    pathrelse (&tmp_path);
		    continue;
		}
		pathrelse (&tmp_path);
	    }

	    if (link_lost_dirs && !is_it_dir) {
		/* we are looking for directories and it is not a dir */
		lost_files ++;
		continue;
	    }

	    stats(fs)->lost_found ++;

	    {
		struct key obj_key = {0, 0, {{0, 0},}};
		char * lost_name;
		struct item_head tmp_ih;
		int pos_in_map;

		/* key to continue */
		key = ih->ih_key;
		key.k_objectid ++;

		tmp_ih = *ih;
		if (is_objectid_really_used (semantic_id_map (fs), ih->ih_key.k_objectid,
					     &pos_in_map)) {
		    /* objectid is used, relocate an object */
		    stats(fs)->oid_sharing ++;
		    if (fsck_fix_non_critical (fs)) {
			if (is_it_dir) {
			    relocate_dir (&tmp_ih, 1);
			    stats(fs)->oid_sharing_dirs_relocated ++;
			} else {
			    relocate_file (&tmp_ih, 1);
			    stats(fs)->oid_sharing_files_relocated ++;
			}
		    }
		} else {
		    if (!is_it_dir)
			mark_objectid_really_used (semantic_id_map (fs), ih->ih_key.k_objectid);
		}

		asprintf (&lost_name, "%u_%u", le32_to_cpu (tmp_ih.ih_key.k_dir_id),
			 le32_to_cpu (tmp_ih.ih_key.k_objectid));

		/* entry in lost+found directory will point to this key */
		obj_key.k_dir_id = tmp_ih.ih_key.k_dir_id;
		obj_key.k_objectid = tmp_ih.ih_key.k_objectid;


		pathrelse (&path);
		
		/* 0 does not mean anyting - item w/ "." and ".." already
		   exists and reached, so only name will be added */
		size += reiserfs_add_entry (fs, &lost_found_dir_key, lost_name, &obj_key, 0/*fsck_need*/);

		if (is_it_dir) {
		    /* fixme: we hope that if we will try to pull all the
		       directory right now - then there will be less
		       lost_found things */
		    fsck_progress ("\tChecking lost dir \"%s\":", lost_name);
		    rebuild_semantic_pass (&obj_key, &lost_found_dir_key, /*dot_dot*/0, /*reloc_ih*/0);
		    fsck_progress ("ok\n");
		    stats(fs)->lost_found_dirs ++;
		} else {
		    if (usearch_by_key (fs, &obj_key, &path) != ITEM_FOUND)
			reiserfs_panic ("look_for_lost: lost file stat data %K not found",
					&obj_key);

		    /* check_regular_file does not mark stat data reachable */
		    mark_item_reachable (get_ih (&path), get_bh (&path));
		    mark_buffer_dirty (get_bh (&path));

		    rebuild_check_regular_file (&path, get_item (&path), 0/*reloc_ih*/);
		    pathrelse (&path);

		    stats(fs)->lost_found_files ++;
		    lost_files --;
		}

		free (lost_name);
		goto cont;
	    }
	} /* for */

	prev_key = key;
	get_next_key (&path, item_pos - 1, &key);
	if (comp_keys (&prev_key, &key) != -1)
	    reiserfs_panic ("pass_3a: key must grow 2: prev=%k next=%k",
			    &prev_key, &key);
	pathrelse (&path);

    cont:
	if (!link_lost_dirs && !lost_files) {
	    break;
	}
    }

    pathrelse (&path);

#if 0
    /* check names added we just have added to/lost+found. Those names are
       marked DEH_Lost_found flag */
    fsck_progress ("Checking lost+found directory.."); fflush (stdout);
    check_semantic_tree (&lost_found_dir_key, &root_dir_key, 0, 1/* lost+found*/);
    fsck_progress ("ok\n");
#endif

    if (!link_lost_dirs && lost_files)
	fsck_log ("look_for_lost: %d files seem to left not linked to lost+found\n",
		  lost_files);

    return size;

}


void pass_3a_look_for_lost (reiserfs_filsys_t fs)
{
    INITIALIZE_PATH (path);
    struct item_head * ih;
    void * sd;
    __u64 size, sd_size;
    __u32 blocks;

    fsck_progress ("Pass 3a (looking for lost files):\n");

    /* when warnings go not to stderr - separate then in the log */
    if (fsck_log_file (fs) != stderr)
	fsck_log ("####### Pass 3a (lost+found pass) #########\n");


    /* look for lost dirs first */
    size = _look_for_lost (fs, 1);

    /* link files which are still lost */
    size += _look_for_lost (fs, 0);

    /* update /lost+found sd_size and sd_blocks (nlink is correct already) */
    if (usearch_by_key (fs, &lost_found_dir_key, &path) != ITEM_FOUND)
	reiserfs_panic ("look_for_lost: /lost+found stat data %K not found",
			&lost_found_dir_key);
    ih = get_ih (&path);
    sd = get_item (&path);
    get_sd_size (ih, sd, &sd_size);
    size += sd_size;
    blocks = dir_size2st_blocks (fs->s_blocksize, size);

    set_sd_size (ih, sd, &size);
    set_sd_blocks (ih, sd, &blocks);
    mark_buffer_dirty (get_bh (&path));
    pathrelse (&path);
    
    stage_report (0x3a, fs);
}

