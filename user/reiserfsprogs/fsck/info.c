
/*
 * Copyright 1996-1999 Hans Reiser
 */
#include "fsck.h"
#include <stdarg.h>


int fsck_user_confirmed (reiserfs_filsys_t fs, char * q, char * a, int default_answer)
{
    if (!fsck_interactive (fs))
	return default_answer;
    
    return user_confirmed (q, a);
}


void stage_report (int pass, reiserfs_filsys_t fs)
{
    FILE * fp;
    struct fsck_data * stat;

    stat = stats (fs);
    fp = stderr;
    
    switch (pass) {
    case 0:
	fsck_progress ("\tRead blocks (but not data blocks) %lu\n", stat->analyzed);
	stat->analyzed = 0;
	fsck_progress ("\t\tLeaves among those %lu\n", stat->leaves);
	if (stat->leaves_corrected)
	    fsck_progress ("\t\t\t- corrected leaves %lu\n", stat->leaves_corrected);
	if (stat->all_contents_removed)
	    fsck_progress ("\t\t\t- eaves all contents of which could not be saved and deleted %lu\n", stat->all_contents_removed);
	if (stat->pointed_leaves)
	    fsck_progress ("\t\t\t- leaves pointed by indirect items %lu\n", stat->pointed_leaves);
	if (stat->pointed)
	    fsck_progress ("\t\tBlocks pointed by indirect items %lu\n", stat->pointed);
	if (stat->pointed_once)
	    fsck_progress ("\t\t\t- once %lu\n", stat->pointed_once);
	if (stat->pointed_more_than_once)
	    fsck_progress ("\t\t\t- more than once %lu\n", stat->pointed_more_than_once);
	if (stat->wrong_pointers)
	    fsck_progress ("\t\t\t- pointers to wrong area of filesystem (zeroed) %lu\n", stat->wrong_pointers);
	/* pass1 will calculate how many pointers were zeeros there */
	stat->wrong_pointers = 0;
	fsck_progress ("\t\tObjectids found %lu\n", proper_id_map (fs)->objectids_marked);

	/*fsck_progress ("\tblocks marked free %lu\n", stat->free);*/
	fsck_progress ("\tallocable %lu blocks\n", stat->allocable);
	break;

    case 1:
	fsck_progress ("\t%lu leaves read\n", stat->analyzed);
	fsck_progress ("\t\t%lu inserted\n", stat->inserted_leaves);
	if (stat->uninsertable_leaves)
	    fsck_progress ("\t\t%lu not inserted\n", stat->uninsertable_leaves);
	if (stat->saved_on_pass1)
	    fsck_progress ("\tSaved %lu items\n", stat->saved_on_pass1);
	if (stat->wrong_pointers)
	    fsck_progress ("\tPointers to leaves or non-unique (zeroed) %lu\n",
			   stat->wrong_pointers);
	break;

    case 2:
	if (stat->shared_objectids)
	    fsck_progress ("\t%lu shared objectids\n", stat->shared_objectids);
	if (stat->relocated)
	    fsck_progress ("\tFiles relocated because of key conflicts w/ a directory %lu\n",
			   stat->relocated);
	if (stat->rewritten)
	    fsck_progress ("\tFiles rewritten %lu\n",
			   stat->rewritten);
	return;

    case 3: /* semantic pass */
	fsck_progress ("\tFiles found: %ld\n", stat->regular_files);
	fsck_progress ("\tDirectories found: %ld\n", stat->directories);
	if (stat->symlinks)
	    fsck_progress ("\tSymlinks found: %ld\n", stat->symlinks);
	if (stat->others)
	    fsck_progress ("\tOthers: %ld\n", stat->others);
	if (stat->fixed_sizes)
	    fsck_progress ("\tFiles with fixed size: %ld\n", stat->fixed_sizes);
	if (stat->oid_sharing)
	    fsck_progress ("\tObjects having used objectids: %lu\n", stat->oid_sharing);
	if (stat->oid_sharing_files_relocated)
	    fsck_progress ("\t\tfiles fixed %lu\n", stat->oid_sharing_files_relocated);
	if (stat->oid_sharing_dirs_relocated)
	    fsck_progress ("\t\tdirs fixed %lu\n", stat->oid_sharing_dirs_relocated);
	stat->oid_sharing = 0;
	stat->oid_sharing_files_relocated = 0;
	stat->oid_sharing_dirs_relocated = 0;
	break;

    case 0x3a: /* looking for lost files */
	if (stat->lost_found)
	    fsck_progress ("\tObjects without names %lu\n",
			   stat->lost_found);
	if (stat->empty_lost_dirs)
	    fsck_progress ("\tEmpty lost dirs removed %lu\n",
			   stat->empty_lost_dirs);
	if (stat->lost_found_dirs)
	    fsck_progress ("\tDirs linked to /lost+found: %lu\n",
			   stat->lost_found_dirs);
	if (stat->dir_recovered)
	    fsck_progress ("\t\tDirs without stat data found %lu\n",
			   stat->dir_recovered);

	if (stat->lost_found_files)
	    fsck_progress ("\tFiles linked to /lost+found %lu\n",
			   stat->lost_found_files);
	if (stat->oid_sharing)
	    fsck_progress ("\tObjects having used objectids: %lu\n", stat->oid_sharing);
	if (stat->oid_sharing_files_relocated)
	    fsck_progress ("\t\tfiles fixed %lu\n", stat->oid_sharing_files_relocated);
	if (stat->oid_sharing_dirs_relocated)
	    fsck_progress ("\t\tdirs fixed %lu\n", stat->oid_sharing_dirs_relocated);
	break;

    case 4: /* removing of unreachable */
	if (stat->deleted_items)
	    fsck_progress ("\tDeleted unreachable items %lu\n",
			   stat->deleted_items);
	break;
    }

    if (!fsck_user_confirmed (fs, "Continue? (Yes):", "Yes\n", 1)) {
	reiserfs_close (fs);
	exit (0);
    }
}


