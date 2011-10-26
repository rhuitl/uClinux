/*
 * Copyright 1996-2001 Hans Reiser
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <asm/types.h>
#include <sys/vfs.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <asm/types.h>
#include <assert.h>

#include "io.h"
#include "misc.h"
#include "reiserfs_lib.h"




/* main.c */
extern reiserfs_filsys_t fs;
extern reiserfs_bitmap_t uninsertable_leaf_bitmap;
int main (int argc, char * argv []);


/*
 * modes
 */
#define DO_NOTHING 0 /* -a specified */
#define FSCK_CHECK 1
#define FSCK_SB 2
#define FSCK_REBUILD 3

/* temporary */
#define FSCK_ZERO_FILES 4
#define DO_TEST 5

/*
#define FSCK_FAST_REBUILD 4
*/


/* 
 * options
 */
#define OPT_INTERACTIVE 1
#define OPT_FIX_FIXABLE 2 /* not default yet */
#define OPT_FIX_NON_CRITICAL 4   /* not default yet */
#define OPT_QUIET 8
#define OPT_SAVE_EXTERN_BITMAP 16
#define OPT_SILENT 32

extern int g_blocks_to_read;

/* pass 0 and 1 read the device NR_TO_READ block in time */
#define NR_TO_READ 8

/* pass0.c */
int pass_0 (reiserfs_filsys_t);
int are_there_used_leaves (unsigned long from, int count);
int is_used_leaf (unsigned long block);
int how_many_leaves_were_there (void);
int is_bad_unformatted (unsigned long block);
int is_good_unformatted (unsigned long block);
void mark_good_unformatted (unsigned long block);
int are_there_allocable_blocks (int amout_needed);
unsigned long alloc_block (void);
void make_allocable (unsigned long block);
void register_uninsertable (unsigned long block);
unsigned long how_many_uninsertables_were_there (void);
void register_saved_item (void);
unsigned long how_many_items_were_saved (void);
int still_bad_unfm_ptr_1 (unsigned long block);
int still_bad_unfm_ptr_2 (unsigned long block);
void make_alloc_bitmap (struct super_block * s);

#define __is_marked(name,block) reiserfs_bitmap_test_bit (name##_bitmap, block)
#define __mark(name,block) reiserfs_bitmap_set_bit (name##_bitmap, block)
#define __unmark(name,block) reiserfs_bitmap_clear_bit (name##_bitmap, block)

/* unformatted in tree */
extern reiserfs_bitmap_t bad_unfm_in_tree_once_bitmap;
#define is_bad_unfm_in_tree_once(block) __is_marked (bad_unfm_in_tree_once, block)
#define mark_bad_unfm_in_tree_once(block) __mark (bad_unfm_in_tree_once, block)



/* pass1.c */
void pass_1_pass_2_build_the_tree (void);
struct buffer_head * make_buffer (int dev, int blocknr, int size, char * data);
void build_the_tree (void);
extern int g_unaccessed_items;
int is_item_reachable (struct item_head * ih);
void mark_item_reachable (struct item_head * ih, struct buffer_head * bh);
void mark_item_unreachable (struct item_head * ih);
void rebuild_sb (reiserfs_filsys_t fs);
struct si * remove_saved_item (struct si * si);


/* pass2.c */
void insert_item_separately (struct item_head * ih, char * item,
			     int was_in_tree);
struct si * save_and_delete_file_item (struct si * si, struct path * path);
void take_bad_blocks_put_into_tree (void);
void rewrite_object (struct item_head * ih, int do_remap);
void pass_2_take_bad_blocks_put_into_tree (void);
/*int is_remapped (struct item_head * ih);*/
void link_relocated_files (void);
void relocate_file (struct item_head * ih, int change_ih);
void relocate_dir (struct item_head * ih, int change_ih);
__u32 objectid_for_relocation (struct key * key);

/* file.c */
struct si {
    struct item_head si_ih;
    char * si_dnm_data;
    struct si * si_next;
    __u32 si_blocknr;

    // changed by XB;
    struct si * last_known;
};
void put_saved_items_into_tree (struct si *);
int reiserfsck_file_write (struct item_head * ih, char * item, int);
int are_file_items_correct (struct key * key, int key_version, __u64 * size, __u32 * blocks, int mark_passed_items, 
			    int symlink, __u64 symlink_size);


/* semantic.c */
extern struct key root_dir_key;
extern struct key parent_root_dir_key;
extern struct key lost_found_dir_key;
void pass_3_semantic (void);
void semantic_check (void);
int check_semantic_tree (struct key * key, struct key * parent, int is_dot_dot, int lost_found, struct item_head * new_ih);
void zero_nlink (struct item_head * ih, void * sd);
int not_a_directory (void * sd);
int is_dot_dot (char * name, int namelen);
int is_dot (char * name, int namelen);
void create_dir_sd (reiserfs_filsys_t fs, 
		    struct path * path, struct key * key);
int rebuild_check_regular_file (struct path * path, void * sd,
				struct item_head * new_ih);
int rebuild_semantic_pass (struct key * key, struct key * parent, int is_dot_dot,
			   struct item_head * new_ih);

/*  access to stat data fields */
void get_set_sd_field (int field, struct item_head * ih, void * sd,
		       void * value, int set);
#define GET_SD_MODE 0
#define GET_SD_SIZE 1
#define GET_SD_NLINK 2
#define GET_SD_BLOCKS 3
#define GET_SD_FIRST_DIRECT_BYTE 4

#define get_sd_mode(ih,sd,pmode) get_set_sd_field (GET_SD_MODE, ih, sd, pmode, 0/*get*/)
#define set_sd_mode(ih,sd,pmode) get_set_sd_field (GET_SD_MODE, ih, sd, pmode, 1/*set*/)

#define get_sd_size(ih,sd,psize) get_set_sd_field (GET_SD_SIZE, ih, sd, psize, 0/*get*/)
#define set_sd_size(ih,sd,psize) get_set_sd_field (GET_SD_SIZE, ih, sd, psize, 1/*set*/)

#define get_sd_blocks(ih,sd,pblocks) get_set_sd_field (GET_SD_BLOCKS, ih, sd, pblocks, 0/*get*/)
#define set_sd_blocks(ih,sd,pblocks) get_set_sd_field (GET_SD_BLOCKS, ih, sd, pblocks, 1/*set*/)

#define get_sd_nlink(ih,sd,pnlink) get_set_sd_field (GET_SD_NLINK, ih, sd, pnlink, 0/*get*/)
#define set_sd_nlink(ih,sd,pnlink) get_set_sd_field (GET_SD_NLINK, ih, sd, pnlink, 1/*set*/)

#define get_sd_first_direct_byte(ih,sd,pfdb) get_set_sd_field (GET_SD_FIRST_DIRECT_BYTE, ih, sd, pfdb, 0/*get*/)
#define set_sd_first_direct_byte(ih,sd,pfdb) get_set_sd_field (GET_SD_FIRST_DIRECT_BYTE, ih, sd, pfdb, 1/*set*/)



/* lost+found.c */
void pass_3a_look_for_lost (reiserfs_filsys_t s);


/* pass4.c */
void get_next_key (struct path * path, int i, struct key * key);
int pass_4_check_unaccessed_items (void);


/* check.c */
int is_leaf_bad (struct buffer_head * bh);
int is_internal_bad (struct buffer_head * bh);
int is_bad_item (struct buffer_head * bh, struct item_head *, char *);
/*int check_file_system (void);*/
void reiserfsck_check_pass1 (void);
void reiserfsck_check_after_all (void);
/*char * bad_name (char * name, int namelen);*/
/* to test result of direcotry item recovering on pass 0 */
int is_bad_directory (struct item_head * ih, char * item, int dev, int blocksize);


//extern int bad_block_number (struct super_block * s, blocknr_t block);

/* check_tree.c */
void check_fs_tree (struct super_block * s);
int check_sb (struct super_block * s);
int bad_pair (struct super_block * s, struct buffer_head * bh, int i);
int bad_leaf_2 (struct super_block * s, struct buffer_head * bh);



/* ustree.c */
void init_tb_struct (struct tree_balance * tb, struct super_block  * s, struct path * path, int size);
void reiserfsck_paste_into_item (struct path * path, const char * body, int size);
void reiserfsck_insert_item (struct path * path, struct item_head * ih, const char * body);
void reiserfsck_delete_item (struct path * path, int temporary);
void reiserfsck_cut_from_item (struct path * path, int cut_size);
typedef	int (comp_function_t)(void * key1, void * key2);
typedef	int (comp3_function_t)(void * key1, void * key2, int version);
/*typedef int (comp_function_t)(struct key * key1, struct key * key2);*/
int ubin_search_id(__u32 * id, __u32 * base, __u32 number, __u32 * pos);
int usearch_by_key (struct super_block * s, struct key * key, struct path * path);
int usearch_by_key_3 (struct super_block * s, struct key * key, struct path * path, int * repeat, int stop_level,
		      comp3_function_t comp_func, int version);		
int usearch_by_entry_key (struct super_block * s, struct key * key, struct path * path);
int usearch_by_position (struct super_block * s, struct key * key, int version, struct path * path);
struct key * uget_lkey (struct path * path);
struct key * uget_rkey (struct path * path);

typedef int do_after_read_t (struct super_block * s, struct buffer_head **, int h);
typedef int do_on_full_path_t (struct super_block * s, struct buffer_head **, int);
void pass_through_tree (struct super_block *, do_after_read_t, do_on_full_path_t);

//int comp_keys_3 (void * key1, void * key2);
//int comp_dir_entries (void * key1, void * key2);
inline int ubin_search (void * key, void * base, int num, int width, __u32 *ppos, comp_function_t comp_func);


/* bitmap.c */
int reiserfsck_reiserfs_new_blocknrs (reiserfs_filsys_t fs,
				      unsigned long * pblocknrs,
				      unsigned long start_from,
				      int amount_needed);
int reiserfsck_reiserfs_free_block (reiserfs_filsys_t fs, unsigned long block);
struct buffer_head * reiserfsck_get_new_buffer (unsigned long start);
int is_block_used (unsigned long block);
int is_to_be_read (reiserfs_filsys_t fs, unsigned long block);
void mark_block_used (unsigned long block);
void mark_block_uninsertable (unsigned long block);
int is_block_uninsertable (unsigned long block);


/* objectid.c */
int is_objectid_used (struct super_block * s, __u32 objectid);
void mark_objectid_as_used (struct super_block * s, __u32 objectid);
void mark_objectid_as_free (struct super_block * s, __u32 objectid);
__u32 get_unused_objectid (struct super_block * s);

struct id_map * init_id_map (void);
void free_id_map (struct id_map **);
int is_objectid_really_used (struct id_map *, __u32 id, int * ppos);
int mark_objectid_really_used (struct id_map *, __u32 id);
void flush_objectid_map (struct id_map * map, reiserfs_filsys_t fs);
void fetch_objectid_map (struct id_map * map, reiserfs_filsys_t fs);


/* segments.c */
struct overwritten_unfm_segment {
    int ous_begin;
    int ous_end;
    struct overwritten_unfm_segment * ous_next;  
};
struct overwritten_unfm * look_for_overwritten_unfm (__u32);
struct overwritten_unfm_segment * find_overwritten_unfm (unsigned long unfm, int length, struct overwritten_unfm_segment * segment_to_init);
int get_unoverwritten_segment (struct overwritten_unfm_segment * list_head, struct overwritten_unfm_segment * unoverwritten_segment);
void save_unfm_overwriting (unsigned long unfm, struct item_head * direct_ih);
void free_overwritten_unfms (void);
void mark_formatted_pointed_by_indirect (__u32);
int is_formatted_pointed_by_indirect (__u32);



struct id_map {
    __u32 * m_begin; /* pointer to map area */
    unsigned long m_used_slots_count;
    int m_page_count; /* objectid map expands by one page at
                         time. This is size of objectid map size in
                         pages */
    unsigned long objectids_marked; /* number of objectids marked used
                                       in a map */
};			


struct fsck_data {
    unsigned long all_blocks; /* super block's block count */

    /* pass 0 */
    unsigned long analyzed;		/* blocks marked used (not data not included) */
    unsigned long free;		/* free blocks */
    unsigned long not_data;	/* super block, bitmap, journal */
    unsigned long leaves;	/* blocks looking like reiserfs leaves */
    unsigned long pointed_leaves;
    unsigned long pointed;	/* by indirect items */
    unsigned long pointed_once;
    unsigned long pointed_more_than_once;
    unsigned long allocable;
    unsigned long wrong_pointers; /* out of range or pointers to free
                                     area */
    unsigned long leaves_corrected;
    unsigned long all_contents_removed;

    /* pass 1, 2 */
    unsigned long read_leaves;
    unsigned long uninsertable_leaves;
    unsigned long inserted_leaves;
    unsigned long shared_objectids;
    unsigned long saved_on_pass1;
    unsigned long relocated;
    unsigned long rewritten;

    /* stat of semantic pass */
    unsigned long regular_files;
    unsigned long broken_files; /* files having stat data and broken body */
    unsigned long directories;
    unsigned long symlinks;
    unsigned long others;
    unsigned long fixed_sizes;
    unsigned long deleted_entries; /* entries pointing to nowhere */
    unsigned long oid_sharing; /* files relocated due to objectid sharing */
    unsigned long oid_sharing_files_relocated; /* relocated files */
    unsigned long oid_sharing_dirs_relocated; /* relocated dirs */
    unsigned long lost_found;
    unsigned long empty_lost_dirs;
    unsigned long lost_found_dirs;
    unsigned long dir_recovered;
    unsigned long lost_found_files;

    /* pass 4 */
    unsigned long deleted_items; /* items which were not touched by
                                    semantic pass */
  
    /* objectid maps */
    struct id_map * proper_id_map;
    struct id_map * semantic_id_map; /* this objectid map is used to
                                        cure objectid sharing problem */

    /* bitmaps */
    reiserfs_bitmap_t on_disk_bitmap;
    reiserfs_bitmap_t new_bitmap;
    reiserfs_bitmap_t allocable_bitmap;

    char * bitmap_file_name;
    char * new_bitmap_file_name;

    unsigned short mode;
    unsigned long options;

    /* log file name and handle */
    char * log_file_name;
    FILE * log;

    /* hash hits stat */
    int hash_amount;
    unsigned long * hash_hits;

#define USED_BLOCKS 1
#define EXTERN_BITMAP 2
#define ALL_BLOCKS 3
    int scan_area;
    int test;
};


#define stats(s) ((struct fsck_data *)((s)->s_vp))

#define proper_id_map(s) stats(s)->proper_id_map
#define semantic_id_map(s) stats(s)->semantic_id_map

#define fsck_disk_bitmap(s) stats(s)->on_disk_bitmap
#define fsck_new_bitmap(s) stats(s)->new_bitmap
#define fsck_allocable_bitmap(s) stats(s)->allocable_bitmap

#define fsck_interactive(fs) (stats(fs)->options & OPT_INTERACTIVE)
#define fsck_fix_fixable(fs) (stats(fs)->options & OPT_FIX_FIXABLE)

/* change unknown modes (corrupted) to mode of regular files, fix file
   sizes which are bigger than a real file size, relocate files with
   shared objectids (this slows fsck down (when there are too many
   files sharing the same objectid), it will also remove other names
   pointing to this file */
#define fsck_fix_non_critical(fs) (stats(fs)->options & OPT_FIX_NON_CRITICAL)
#define fsck_quiet(fs)	(stats(fs)->options & OPT_QUIET)
#define fsck_silent(fs)	(stats(fs)->options & OPT_SILENT)

#define fsck_save_leaf_bitmap(fs) (stats(fs)->options & OPT_SAVE_EXTERN_BITMAP)

#define fsck_mode(fs) (stats(fs)->mode)
#define fsck_log_file(fs) (stats(fs)->log)


/* ?? */
extern inline int change_version (int version)
{
   return (version == 1)?0:1;
}


int fsck_user_confirmed (reiserfs_filsys_t fs, char * q, char * a, int default_answer);
void stage_report (int, reiserfs_filsys_t fs);

/* journal.c */
int reiserfs_replay_journal (struct super_block * s);


#define fsck_log(fmt, list...) \
{\
if (!fsck_silent (fs))\
    reiserfs_warning (fsck_log_file (fs), fmt, ## list);\
}

#define fsck_progress(fmt, list...) \
{\
reiserfs_warning (stderr, fmt, ## list);\
fflush (stderr);\
}
