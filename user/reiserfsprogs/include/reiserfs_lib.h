/*
 *  Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */

#ifndef REISERFS_LIB_H
#define REISERFS_LIB_H

typedef struct super_block * reiserfs_filsys_t;

#include "reiserfs_fs.h"

struct _bitmap {
    unsigned long bm_byte_size;
    unsigned long bm_bit_size;
    char * bm_map;
    unsigned long bm_set_bits;
};

typedef struct _bitmap * reiserfs_bitmap_t;

struct super_block {
    int s_version;		/* on-disk format version */
    reiserfs_bitmap_t bitmap;	/* copy of reiserfs on-disk bitmap */
    
    int s_dev; /* descriptor of opened block device file */
    int s_blocksize;
    struct buffer_head ** s_ap_bitmap; /* array of buffers containing bitmap
                                          blocks */
    struct buffer_head * s_sbh;  /* buffer containing super block */
    struct reiserfs_super_block * s_rs; /* pointer to its b_data */
    int s_dirt;
    hashf_t s_hash_function; /* pointer to function which is used to sort
				names in directory. It is set by reiserfs_open
				if it is set in the super block, otherwise it
				is set by first is_properly_hashed */
    char * file_name;	/* file name of underlying device */
    int s_flags;
    void * s_vp;
    int (*block_allocator) (reiserfs_filsys_t fs, 
			    unsigned long * free_blocknrs,
			    unsigned long start, int amount_needed);
    int (*block_deallocator) (reiserfs_filsys_t fs, unsigned long block);
};


/* reiserfslib.c */

reiserfs_filsys_t reiserfs_open (char * filename, int flags, int * error, void * vp);
void reiserfs_read_bitmap_blocks (reiserfs_filsys_t);
void reiserfs_free_bitmap_blocks (reiserfs_filsys_t);
int no_reiserfs_found (reiserfs_filsys_t fs);
void reiserfs_reopen (reiserfs_filsys_t fs, int flags);
void reiserfs_flush (reiserfs_filsys_t fs);
void reiserfs_free (reiserfs_filsys_t fs);
void reiserfs_close (reiserfs_filsys_t fs);
int reiserfs_new_blocknrs (reiserfs_filsys_t fs, 
			   unsigned long * free_blocknrs, unsigned long start,
			   int amount_needed);
int reiserfs_free_block (reiserfs_filsys_t fs, unsigned long block);
int spread_bitmaps (reiserfs_filsys_t fs);
int filesystem_dirty (reiserfs_filsys_t fs);
void mark_filesystem_dirty (reiserfs_filsys_t fs);

void reiserfs_paste_into_item (reiserfs_filsys_t fs, struct path * path,
			       const void * body, int size);
void reiserfs_insert_item (reiserfs_filsys_t fs, struct path * path,
			   struct item_head * ih, const void * body);

int reiserfs_find_entry (reiserfs_filsys_t fs, struct key * dir, char * name,
			 int * min_gen_counter);
int reiserfs_add_entry (reiserfs_filsys_t fs, struct key * dir, char * name,
			struct key * key, int fsck_need);

int _search_by_entry_key (reiserfs_filsys_t fs, struct key * key, 
			  struct path * path);
void copy_key (void * to, void * from);
void copy_short_key (void * to, void * from);
void copy_item_head(void * p_v_to, void * p_v_from);
int comp_keys (void * k1, void * k2);
int  comp_short_keys (void * p_s_key1, void * p_s_key2);
int comp_items (struct item_head  * p_s_ih, struct path * p_s_path);


/* bitmap.c */

reiserfs_bitmap_t reiserfs_create_bitmap (unsigned int bit_count);
int reiserfs_expand_bitmap (reiserfs_bitmap_t bm, unsigned int bit_count);
void reiserfs_delete_bitmap (reiserfs_bitmap_t bm);
void reiserfs_bitmap_copy (reiserfs_bitmap_t to, reiserfs_bitmap_t from);
int reiserfs_bitmap_compare (reiserfs_bitmap_t bm1, reiserfs_bitmap_t bm2);
void reiserfs_bitmap_set_bit (reiserfs_bitmap_t bm, unsigned int bit_number);
void reiserfs_bitmap_clear_bit (reiserfs_bitmap_t bm, unsigned int bit_number);

int reiserfs_bitmap_test_bit (reiserfs_bitmap_t bm, unsigned int bit_number);
int reiserfs_bitmap_find_zero_bit (reiserfs_bitmap_t bm, unsigned long * start);
int reiserfs_fetch_disk_bitmap (reiserfs_bitmap_t bm, reiserfs_filsys_t fs);
int reiserfs_flush_bitmap (reiserfs_bitmap_t bm, reiserfs_filsys_t fs);
void reiserfs_bitmap_zero (reiserfs_bitmap_t bm);
void reiserfs_bitmap_fill (reiserfs_bitmap_t bm);
int reiserfs_bitmap_ones (reiserfs_bitmap_t bm);
int reiserfs_bitmap_zeros (reiserfs_bitmap_t bm);

void reiserfs_bitmap_save (char * filename, reiserfs_bitmap_t bm);
reiserfs_bitmap_t reiserfs_bitmap_load (char * filename);
void reiserfs_bitmap_invert (reiserfs_bitmap_t bm);


int reiserfs_remove_entry (reiserfs_filsys_t fs, struct key * key);



/* node_formats.c */

#define THE_LEAF 1
#define THE_INTERNAL 2
#define THE_SUPER 3
#define THE_JDESC 4
#define THE_UNKNOWN 5

int is_reiserfs_magic_string (struct reiserfs_super_block * rs);
int is_reiser2fs_magic_string (struct reiserfs_super_block * rs);
int is_prejournaled_reiserfs (struct reiserfs_super_block * rs);
int does_desc_match_commit (struct reiserfs_journal_desc *desc, 
			    struct reiserfs_journal_commit *commit);
int who_is_this (char * buf, int blocksize);
int journal_size (struct super_block * s);
int not_data_block (struct super_block * s, unsigned long block);
int not_journalable (reiserfs_filsys_t fs, unsigned long block);
int block_of_bitmap (reiserfs_filsys_t fs, unsigned long block);
int block_of_journal (reiserfs_filsys_t fs, unsigned long block);
int is_tree_node (struct buffer_head * bh, int level);
int is_properly_hashed (reiserfs_filsys_t fs,
			char * name, int namelen, __u32 offset);
int dir_entry_bad_location (struct reiserfs_de_head * deh, 
			    struct item_head * ih, int first);
void make_dir_stat_data (int blocksize, int key_format, 
			 __u32 dirid, __u32 objectid, 
			 struct item_head * ih, void * sd);
void make_empty_dir_item_v1 (char * body, __u32 dirid, __u32 objid,
			     __u32 par_dirid, __u32 par_objid);
void make_empty_dir_item (char * body, __u32 dirid, __u32 objid,
			  __u32 par_dirid, __u32 par_objid);


typedef void (*item_action_t) (struct buffer_head * bh, struct item_head * ih);
typedef void (*item_head_action_t) (struct item_head * ih);

void for_every_item (struct buffer_head * bh, item_head_action_t action,
		     item_action_t * actions);
int key_format (const struct key * key);
loff_t get_offset (const struct key * key);
int uniqueness2type (__u32 uniqueness);
__u32 type2uniqueness (int type);
int get_type (const struct key * key);
char * key_of_what (const struct key * key);
int type_unknown (struct key * key);
void set_type (int format, struct key * key, int type);
void set_offset (int format, struct key * key, loff_t offset);
void set_type_and_offset (int format, struct key * key, loff_t offset, int type);


typedef int (*check_unfm_func_t) (reiserfs_filsys_t fs, __u32);
int is_it_bad_item (reiserfs_filsys_t, struct item_head *, char *,
		    check_unfm_func_t, int bad_dir);


#define hash_func_is_unknown(fs) ((fs)->s_hash_function == 0)
#define reiserfs_hash(fs) ((fs)->s_hash_function)

int known_hashes (void);
char * code2name (int code);
int func2code (hashf_t func);
hashf_t code2func (int code);
int find_hash_in_use (char * name, int namelen, __u32 hash_value_masked, int code_to_try_first);

int entry_length (struct item_head * ih, struct reiserfs_de_head * deh,
		  int pos_in_item);
char * name_in_entry (struct reiserfs_de_head * deh, int pos_in_item);
int name_length (struct item_head * ih,
		 struct reiserfs_de_head * deh, int pos_in_item);




/* prints.c */
void print_indirect_item (FILE * fp, struct buffer_head * bh, int item_num);
void print_block (FILE * fp, reiserfs_filsys_t, struct buffer_head * bh, ...);//int print_mode, int first, int last);
void reiserfs_warning (FILE * fp, const char * fmt, ...);
char ftypelet (mode_t mode);

#define reiserfs_panic(fmt, list...) \
{\
	fprintf (stderr, "%s %d %s\n", __FILE__, __LINE__, __FUNCTION__);\
	reiserfs_warning (stderr, fmt, ## list);\
	exit(4);\
}

#endif /* REISERFS_LIB_H */

