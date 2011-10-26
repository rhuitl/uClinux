/*
 * Copyright 1996-2000  Hans Reiser
 */
#include "fsck.h"
#include <getopt.h>

#include "../version.h"

extern struct key root_dir_key;
extern struct key parent_root_dir_key;
extern struct key lost_found_dir_key;



#define print_usage_and_exit() die ("Usage: %s [options] "\
" device\n"\
"\n"\
"Options:\n\n"\
"  --check\t\tconsistency checking (default)\n"\
"  --rebuild-sb\t\tsuper block checking and rebuilding if needed\n"\
"  --rebuild-tree\tforce fsck to rebuild filesystem from scratch\n"\
"  \t\t\t(takes a long time)\n"\
"  --interactive, -i\tmake fsck to stop after every stage\n"\
"  -l | --logfile logfile\n"\
"  \t\t\tmake fsck to complain to specifed file\n"\
"  -b | --scan-marked-in-bitmap file\n"\
"  \t\t\tbuild tree of blocks marked in the bitmapfile\n"\
"  -c | --create-bitmap-file\n"\
"  \t\t\tsave bitmap of found leaves\n"\
"  -x | --fix-fixable\tfix corruptions which can be fixed w/o --rebuild-tree\n"\
"  -o | --fix-non-critical\n"\
"  \t\t\tfix strange modes, file sizes to real size and\n"\
"  \t\t\trelocate files using busy objectids\n"\
"  -q | --quiet\t\tno speed info\n"\
"  -n | --nolog\t\t suppresses all logs\n"\
"  -V\t\t\tprints version and exits\n"\
"  -a\t\t\tmakes fsck to do nothing\n"\
"  -p\t\t\tdo nothing, exist for compatibility with fsck(8)\n"\
"  -r\n", argv[0]);




/* fsck is called with one non-optional argument - file name of device
   containing reiserfs. This function parses other options, sets flags
   based on parsing and returns non-optional argument */
static char * parse_options (struct fsck_data * data, int argc, char * argv [])
{
    int c;
    static int mode = FSCK_CHECK;

    data->scan_area = USED_BLOCKS;
    while (1) {
	static struct option options[] = {
	    /* modes */
	    {"check", no_argument, &mode, FSCK_CHECK},
	    {"rebuild-sb", no_argument, &mode, FSCK_SB},
	    {"rebuild-tree", no_argument, &mode, FSCK_REBUILD},
/*
	    {"fast-rebuild", no_argument, &opt_fsck_mode, FSCK_FAST_REBUILD},
*/

	    /* options */
	    {"logfile", required_argument, 0, 'l'},
	    {"interactive", no_argument, 0, 'i'},
	    {"fix-fixable", no_argument, 0, 'x'},
	    {"fix-non-critical", no_argument, 0, 'o'},
	    {"quiet", no_argument, 0, 'q'},
	    {"nolog", no_argument, 0, 'n'},
	    
	    /* if file exists ad reiserfs can be load of it - only
               blocks marked used in that bitmap will be read */
	    {"scan-marked-in-bitmap", required_argument, 0, 'b'},

	    /* */
	    {"create-leaf-bitmap", required_argument, 0, 'c'},

	    /* all blocks will be read */
	    {"scan-whole-partition", no_argument, 0, 'S'},
	    
	    /* special option: will mark free blocks used, zero all
               unformatted node pointers and mark them free */
	    {"zero-files", no_argument, &mode, FSCK_ZERO_FILES},
	    {0, 0, 0, 0}
	};
	int option_index;
      
	c = getopt_long (argc, argv, "iql:b:Sc:xoVaprt:n",
			 options, &option_index);
	if (c == -1)
	    break;
	
	switch (c) {
	case 0:
	    /* long option specifying fsck mode is found */
	    break;

	case 'i': /* --interactive */
	    data->options |= OPT_INTERACTIVE;
	    break;

	case 'q': /* --quiet */
	    data->options |= OPT_QUIET;
	    break;

	case 'l': /* --logfile */
	    asprintf (&data->log_file_name, "%s", optarg);
	    data->log = fopen (optarg, "w");
	    if (!data->log)
		fprintf (stderr, "reiserfsck: could not open \'%s\': %m", optarg);

	    break;

	case 'b': /* --scan-marked-in-bitmap */
	    /* will try to load a bitmap from a file and read only
               blocks marked in it. That bitmap could be created by
               previous run of reiserfsck with -c */
	    asprintf (&data->bitmap_file_name, "%s", optarg);
	    data->scan_area = EXTERN_BITMAP;
	    break;

	case 'S': /* --scan-whole-partition */
	    data->scan_area = ALL_BLOCKS;
	    break;

	case 'c': /* --create-leaf-bitmap */
	    asprintf (&data->new_bitmap_file_name, "%s", optarg);
	    data->options |= OPT_SAVE_EXTERN_BITMAP;
	    break;
	    
	case 'x': /* --fix-fixable */
	    data->options |= OPT_FIX_FIXABLE;
	    break;

	case 'o': /* --fix-non-critical */
	    data->options |= OPT_FIX_NON_CRITICAL;
	    break;

	case 'n': /* --nolog */
	    data->options |= OPT_SILENT;
	    break;

	case 'V':
	case 'p': /* these say reiserfsck to do nothing */
	case 'r':
	case 'a':
	    mode = DO_NOTHING;
	    break;

	case 't':
	    mode = DO_TEST;
	    data->test = atoi (optarg);
	    break;

	default:
	    print_usage_and_exit();
	}
    }

    if (optind != argc - 1 && mode != DO_NOTHING)
	/* only one non-option argument is permitted */
	print_usage_and_exit();
    
    data->mode = mode;
    if (!data->log)
	data->log = stderr;
    
    return argv[optind];
}


reiserfs_filsys_t fs;



static void reset_super_block (reiserfs_filsys_t fs)
{
    set_free_blocks (fs->s_rs, SB_BLOCK_COUNT (fs));
    set_root_block (fs->s_rs, ~0);
    set_tree_height (fs->s_rs, ~0);

    /* make file system invalid unless fsck done () */
    set_state (fs->s_rs, REISERFS_ERROR_FS);


    if (is_reiser2fs_magic_string (fs->s_rs)) {
	set_version (fs->s_rs, REISERFS_VERSION_2);
    }
    if (is_reiserfs_magic_string (fs->s_rs)) {
	set_version (fs->s_rs, REISERFS_VERSION_1);
    }

    /* can be not set yet. If so, hash function will be set when first dir
       entry will be found */
    fs->s_hash_function = code2func (rs_hash (fs->s_rs));

    /* objectid map is not touched */

    mark_buffer_dirty (fs->s_sbh);
    bwrite (fs->s_sbh);

}


reiserfs_bitmap_t uninsertable_leaf_bitmap;

int g_blocks_to_read;


/* on-disk bitmap is read, fetch it. create new bitmap, mark used blocks which
   are always used (skipped, super block, journal area, bitmaps), create other
   auxiliary bitmaps */
static void init_bitmaps (reiserfs_filsys_t fs)
{
    unsigned long i;
    unsigned long block_count;
    unsigned long tmp;

    block_count = SB_BLOCK_COUNT (fs);

    switch (stats (fs)->scan_area) {
    case ALL_BLOCKS:
	fsck_disk_bitmap (fs) = reiserfs_create_bitmap (block_count);
	reiserfs_bitmap_fill (fsck_disk_bitmap (fs));
	fsck_progress ("Whole device (%d blocks) is to be scanned\n", 
		       reiserfs_bitmap_ones (fsck_disk_bitmap (fs)));	
	break;

    case USED_BLOCKS:
	fsck_progress ("Loading on-disk bitmap .. ");
	fsck_disk_bitmap (fs) = reiserfs_create_bitmap (block_count);
	reiserfs_fetch_disk_bitmap (fsck_disk_bitmap (fs), fs);
	fsck_progress ("%d bits set - done\n", 
		       reiserfs_bitmap_ones (fsck_disk_bitmap (fs)));
	break;

    case EXTERN_BITMAP:
	fsck_disk_bitmap (fs) = reiserfs_bitmap_load (stats (fs)->bitmap_file_name);
	if (!fsck_disk_bitmap (fs))
	    reiserfs_panic ("could not load fitmap from \"%s\"", 
			    stats (fs)->bitmap_file_name);
	break;

    default:
	reiserfs_panic ("No area to scan specified");
    }


    /* pass 0 will skip super block and journal areas and bitmap blocks, find
       how many blocks have to be read */
    tmp = 0;
    for (i = 0; i <= fs->s_sbh->b_blocknr; i ++) {
	if (!reiserfs_bitmap_test_bit (fsck_disk_bitmap (fs), i))
	    continue;
	reiserfs_bitmap_clear_bit (fsck_disk_bitmap (fs), i);
	tmp ++;
    }

    /* unmark bitmaps */
    for (i = 0; i < rs_bmap_nr (fs->s_rs); i ++) {
	unsigned long block;

	block = SB_AP_BITMAP (fs)[i]->b_blocknr;
	if (!reiserfs_bitmap_test_bit (fsck_disk_bitmap (fs), block))
	    continue;
	reiserfs_bitmap_clear_bit (fsck_disk_bitmap (fs), block);
	tmp ++;	
    }

    /* unmark journal area */
    for (i = rs_journal_start (fs->s_rs);
	 i <= rs_journal_start (fs->s_rs) + rs_journal_size (fs->s_rs); i ++) {
	if (!reiserfs_bitmap_test_bit (fsck_disk_bitmap (fs), i))
	    continue;
	reiserfs_bitmap_clear_bit (fsck_disk_bitmap (fs), i);
	tmp ++;	
    }
    reiserfs_warning (stderr, "Skipping %d blocks (super block, journal, "
		      "bitmaps) %d blocks will be read\n",
		      tmp, reiserfs_bitmap_ones (fsck_disk_bitmap (fs)));

#if 0	
    {
	int tmp = 0;
	int tmp2 = 0;
	int tmp3 = 0;
	int j;

	for (i = 0; i < block_count; i += 32) {
	    if (i + 32 < block_count && !*(int *)&(fsck_disk_bitmap (fs)->bm_map[i/8])) {
		tmp2 ++;
		continue;
	    }
	    tmp3 ++;
	    for (j = 0; j < 32 && ((i + j) < block_count); j ++) {
		if (!reiserfs_bitmap_test_bit (fsck_disk_bitmap (fs), i + j))
		    continue;
		if (not_data_block (fs, i + j)) {
		    reiserfs_bitmap_clear_bit (fsck_disk_bitmap (fs), i + j);
		    tmp ++;
		    continue;
		}
	    }
	}
	/*
	for (i = 0; i < block_count; i ++) {
	    if (!fsck_disk_bitmap (fs)->bm_map[i / 8])
		continue;
	    if (!reiserfs_bitmap_test_bit (fsck_disk_bitmap (fs), i))
		continue;
	    if (not_data_block (fs, i)) {

	    if (reiserfs_bitmap_test_bit (fsck_disk_bitmap (fs), i))
		tmp ++;
		reiserfs_bitmap_clear_bit (fsck_disk_bitmap (fs), i);
		continue;
	    }
	}
*/
	reiserfs_warning (stderr, "%d not data blocks cleared (skipped %d checked %d)\n", tmp, tmp2, tmp3);
    }
#endif


    fsck_new_bitmap (fs) = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));

    /* mark_block_used skips 0, ste the bit explicitly */
    reiserfs_bitmap_set_bit (fsck_new_bitmap (fs), 0);

    /* mark other skipped blocks and super block used */
    for (i = 1; i <= SB_BUFFER_WITH_SB (fs)->b_blocknr; i ++)
	mark_block_used (i);

    /* mark bitmap blocks as used */
    for (i = 0; i < SB_BMAP_NR (fs); i ++)
	mark_block_used (SB_AP_BITMAP (fs)[i]->b_blocknr);

    /* mark journal area as used */
    for (i = 0; i < JOURNAL_BLOCK_COUNT + 1; i ++)
	mark_block_used (i + SB_JOURNAL_BLOCK (fs));


    uninsertable_leaf_bitmap = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));
    reiserfs_bitmap_fill (uninsertable_leaf_bitmap);
    
    fsck_allocable_bitmap (fs) = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));
    reiserfs_bitmap_fill (fsck_allocable_bitmap (fs));

}



#define REBUILD_WARNING \
"\nThis is an experimental version of reiserfsck, MAKE A BACKUP FIRST!\n\
Don't run this program unless something is broken. \n\
Some types of random FS damage can be recovered\n\
from by this program, which basically throws away the internal nodes\n\
of the tree and then reconstructs them.  This program is for use only\n\
by the desperate, and is of only beta quality.  Email\n\
reiserfs@devlinux.com with bug reports. \nWill rebuild the filesystem tree\n"

/* 
   warning #2
   you seem to be running this automatically.  you are almost
   certainly doing it by mistake as a result of some script that
   doesn't know what it does.  doing nothing, rerun without -p if you
   really intend to do this.  */

void warn_what_will_be_done (struct fsck_data * data)
{
    fsck_progress ("\n");

    /* warn about fsck mode */
    switch (data->mode) {
    case FSCK_CHECK:
	fsck_progress ("Will read-only check consistency of the partition\n");
	if (data->options & OPT_FIX_FIXABLE)
	    fsck_progress ("\tWill fix what can be fixed w/o --rebuild-tree\n");
	break;

    case FSCK_SB:
	fsck_progress ("Will check SB and rebuild if it is needed\n");
	break;

    case FSCK_REBUILD:
    {
	fsck_progress (REBUILD_WARNING);
	if (data->options & OPT_INTERACTIVE)
	    fsck_progress ("\tWill stop after every stage and ask for "
			   "confirmation before continuing\n");
	if (data->options & OPT_SAVE_EXTERN_BITMAP)
	    fsck_progress ("Will save list of found leaves in '%s'\n",
			   data->new_bitmap_file_name);
	if (data->bitmap_file_name)
	    fsck_progress ("\tWill try to load bitmap of leaves from file '%s'\n",
			   data->bitmap_file_name);
	if (data->options & OPT_FIX_NON_CRITICAL)
	    fsck_progress ("\tWill fix following non-critical things:\n"
			   "\t\tunknown file modes will be set to regular files\n"
			   "\t\tfile sizes will be set to real file size\n"
			   "\t\tfiles sharing busy inode number will be relocated\n");
	break;
    }

    case FSCK_ZERO_FILES:
	fsck_progress ("Will zero existing files and mark free blocks as used\n");
    }

    fsck_progress ("Will put log info to '%s'\n", (data->log != stderr) ?
		   data->log_file_name : "stderr");

    if (!user_confirmed ("Do you want to run this program?[N/Yes] (note need to type Yes):", "Yes\n"))
	exit (0);
}


static void start_rebuild (reiserfs_filsys_t fs)
{
    reset_super_block (fs);
    init_bitmaps (fs);

    proper_id_map (fs) = init_id_map ();
    semantic_id_map (fs) = init_id_map ();
}


/* called before semantic pass starts */
static void end_rebuilding (reiserfs_filsys_t fs)
{
    reiserfs_flush_bitmap (fsck_new_bitmap (fs), fs);
    flush_objectid_map (proper_id_map (fs), fs);
    set_fsck_state (fs->s_rs, TREE_IS_BUILT);
    set_free_blocks (fs->s_rs, reiserfs_bitmap_zeros (fsck_new_bitmap (fs)));

    mark_buffer_dirty (SB_BUFFER_WITH_SB (fs));
    
    /* write all dirty blocks */
    fsck_progress ("Syncing.."); fflush (stdout);
    reiserfs_flush (fs);
    fsck_progress ("done\n"); fflush (stdout);

    /* release what will not be needed */
    reiserfs_delete_bitmap (fsck_disk_bitmap (fs));
    reiserfs_delete_bitmap (fsck_allocable_bitmap (fs));

    /* FIXME: could be not a bitmap */
    reiserfs_delete_bitmap (uninsertable_leaf_bitmap);

    if (fsck_user_confirmed (fs, "Tree building completed. "
			     "You can stop now and restart from this point later "
			     "(this is probably not what you need). Do you want to stop? ",
			     "Yes\n", 0/*default*/)) {
	reiserfs_close (fs);
        exit (4);
    }
}


static int skip_rebuilding (reiserfs_filsys_t fs)
{
    if (fsck_state (fs->s_rs) == TREE_IS_BUILT) {
	if (fsck_user_confirmed (fs, "S+ tree of filesystem looks built. Skip rebuilding? ", "Yes\n", 0/*default*/)) {
	    
	    fsck_new_bitmap (fs) = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));
	    reiserfs_fetch_disk_bitmap (fsck_new_bitmap (fs), fs);

	    proper_id_map (fs) = init_id_map ();
	    fetch_objectid_map (proper_id_map (fs), fs);

	    semantic_id_map (fs) = init_id_map ();
	    
	    return 1;
	}
    }
    return 0;
}


static void start_continuing (reiserfs_filsys_t fs)
{
    fsck_allocable_bitmap (fs) = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));
    reiserfs_bitmap_copy (fsck_allocable_bitmap (fs), fsck_new_bitmap (fs));
}


static void the_end (reiserfs_filsys_t fs)
{
    reiserfs_flush_bitmap (fsck_new_bitmap (fs), fs);
    flush_objectid_map (proper_id_map (fs), fs);
    set_fsck_state (fs->s_rs, 0);
    set_free_blocks (fs->s_rs, reiserfs_bitmap_zeros (fsck_new_bitmap (fs)));
    set_state (fs->s_rs, REISERFS_VALID_FS);
    mark_buffer_dirty (SB_BUFFER_WITH_SB (fs));

    /* write all dirty blocks */
    fsck_progress ("Syncing.."); fflush (stderr);
    reiserfs_flush (fs);
    sync ();
    fsck_progress ("done\n"); fflush (stderr);

    reiserfs_delete_bitmap (fsck_new_bitmap (fs));

    free_id_map (&proper_id_map(fs));
    if (semantic_id_map(fs))
	free_id_map (&semantic_id_map(fs));
    
    reiserfs_close (fs);
    fsck_progress ("Done\n"); fflush (stderr);
}


static void rebuild_tree (reiserfs_filsys_t fs)
{
    if (is_mounted (fs->file_name)) {
	fsck_progress ("rebuild_tree: can not rebuild tree of mounted filesystem\n");
	return;
    }

    reiserfs_reopen (fs, O_RDWR);

    /* FIXME: for regular file take care of of file size */

    /* rebuild starts with journal replaying */
    reiserfs_replay_journal (fs);


    if (!skip_rebuilding (fs)) {
	fsck_progress ("Rebuilding..\n");
	start_rebuild (fs);

	pass_0 (fs);
    
	/* passes 1 and 2. building of the tree */
	pass_1_pass_2_build_the_tree ();

	end_rebuilding (fs);
    }

    /* re-building of filesystem tree is now separated of sematic pass of the
       fsck */
    start_continuing (fs);

    /* 3. semantic pass */
    pass_3_semantic ();
    
    /* if --lost+found is set - link unaccessed directories to lost+found
       directory */
    pass_3a_look_for_lost (fs);
    
    /* 4. look for unaccessed items in the leaves */
    pass_4_check_unaccessed_items ();

    the_end (fs);

}


static void zero_files (reiserfs_filsys_t fs)
{
    init_bitmaps (fs);
    reiserfs_reopen (fs, O_RDWR);
    pass_0 (fs);
}


/* check umounted or read-only mounted filesystems only */
static void check_fs (reiserfs_filsys_t fs)
{
    if (!is_mounted (fs->file_name)) {
	/* filesystem is not mounted, replay journal before checking */
	reiserfs_reopen (fs, O_RDWR);

	reiserfs_replay_journal (fs);

	reiserfs_reopen (fs, O_RDONLY);
    } else {
	/* filesystem seems mounted. we do not check filesystems mounted with
           r/w permissions */
	if (!is_mounted_read_only (fs->file_name)) {
	    fsck_progress ("Device %s is mounted w/ write permissions, can not check it\n",
			   fs->file_name);
	    reiserfs_close (fs);
	    exit (0);
	}
	fsck_progress ("Filesystem seems mounted read-only. Skipping journal replay..\n");

	if (fsck_fix_fixable (fs)) {
	    fsck_progress ("--fix-fixable ignored\n");
	    stats(fs)->options &= ~OPT_FIX_FIXABLE;
	}
    }

    fsck_disk_bitmap (fs) = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));
    reiserfs_fetch_disk_bitmap (fsck_disk_bitmap (fs), fs);

    if (fsck_fix_fixable (fs))
	reiserfs_reopen (fs, O_RDWR);

    /*proper_id_map (fs) = init_id_map ();*/
    semantic_id_map (fs) = init_id_map ();

    check_fs_tree (fs);

    semantic_check ();

    reiserfs_delete_bitmap (fsck_disk_bitmap (fs));
    /*free_id_map (proper_id_map (fs));*/
    free_id_map (&semantic_id_map (fs));
    reiserfs_close (fs);
}


#include <sys/resource.h>

int main (int argc, char * argv [])
{
    char * file_name;
    struct fsck_data * data;
    struct rlimit rlim = {0xffffffff, 0xffffffff};

    print_banner ("reiserfsck");


    /* initially assigned in semantic.c, but non-constant initializers are
    * illegal - jdm */
    root_dir_key.k_dir_id = cpu_to_le32(root_dir_key.k_dir_id);
    root_dir_key.k_objectid = cpu_to_le32(root_dir_key.k_objectid);
    parent_root_dir_key.k_dir_id = cpu_to_le32(parent_root_dir_key.k_dir_id);
    parent_root_dir_key.k_objectid = cpu_to_le32(parent_root_dir_key.k_objectid);
    lost_found_dir_key.k_dir_id = cpu_to_le32(lost_found_dir_key.k_dir_id);
    lost_found_dir_key.k_objectid = cpu_to_le32(lost_found_dir_key.k_objectid);

    /* this is only needed (and works) when running under 2.4 on regural files */
    if (setrlimit (RLIMIT_FSIZE, &rlim) == -1) {
	reiserfs_warning (stderr, "could not setrlimit: %m");
    }

    data = getmem (sizeof (struct fsck_data));

    file_name = parse_options (data, argc, argv);

    if (data->mode == DO_NOTHING) {
	freemem (data);
	return 0;
    }

    warn_what_will_be_done (data); /* and ask confirmation Yes */
    fs = reiserfs_open (file_name, O_RDONLY, 0, data);
    if (!fs)
	die ("reiserfsck: could not open filesystem on \"%s\"", file_name);


    if (fsck_mode (fs) == FSCK_SB) {
	reiserfs_reopen (fs, O_RDWR);
	rebuild_sb (fs);
	reiserfs_close (fs);
	return 0;
    }

    if (no_reiserfs_found (fs)) {
	fsck_progress ("reiserfsck: --rebuild-sb may restore reiserfs super block\n");
	reiserfs_close (fs);
	return 0;
    }


    fs->block_allocator = reiserfsck_reiserfs_new_blocknrs;
    fs->block_deallocator = reiserfsck_reiserfs_free_block;



    if (fsck_mode (fs) == FSCK_CHECK) {
	check_fs (fs);
	return 0;
    }

#ifdef FAST_REBUILD_READY /* and tested */
    if (opt_fsck_mode == FSCK_FAST_REBUILD) {
	__u32 root_block = SB_ROOT_BLOCK(fs);
	reopen_read_write (file_name);
	printf ("Replaying log..");
	reiserfs_replay_journal (fs);
	printf ("done\n");
	if (opt_fsck == 1)
	    printf ("ReiserFS : checking %s\n",file_name);
	else
	    printf ("Rebuilding..\n");

	
	reset_super_block (fs);
	SB_DISK_SUPER_BLOCK(fs)->s_root_block = cpu_to_le32 (root_block);
	init_bitmaps (fs);

	/* 1,2. building of the tree */
	recover_internal_tree(fs);

	/* 3. semantic pass */
	pass3_semantic ();

	/* if --lost+found is set - link unaccessed directories to
           lost+found directory */
       look_for_lost (fs);

	/* 4. look for unaccessed items in the leaves */
	pass4_check_unaccessed_items ();
	
	end_fsck ();
    }
#endif /* FAST REBUILD READY */


    if (fsck_mode (fs) == FSCK_ZERO_FILES)
	zero_files (fs);

    if (fsck_mode (fs) != FSCK_REBUILD && fsck_mode (fs) != DO_TEST)
	return 0;


    /* the --rebuild-tree is here */
    rebuild_tree (fs);
    return 0;

}
