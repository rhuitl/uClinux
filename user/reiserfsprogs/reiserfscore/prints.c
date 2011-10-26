/*
 * Copyright 1996, 1997, 1998 Hans Reiser, see reiserfs/README for licensing and copyright details
 */

#include "includes.h"
#include <stdarg.h>
#include <limits.h>
#ifndef EMBED
#include <printf.h>
#endif


#ifndef EMBED

static int _arginfo (const struct printf_info *info, size_t n,
		     int *argtypes)
{
    if (n > 0)
	argtypes[0] = PA_POINTER;
    return 1;
}


#if 0
static int _arginfo2 (const struct printf_info *info, size_t n,
		     int *argtypes)
{
    if (n > 0)
	argtypes[0] = PA_INT;
    return 1;
}
#endif


#define FPRINTF \
    if (len == -1) {\
	return -1;\
    }\
    len = fprintf (stream, "%*s",\
		   info->left ? -info->width : info->width, buffer);\
    free (buffer);\
    return len;\


/* %z */
static int print_block_head (FILE * stream,
			     const struct printf_info *info,
			     const void *const *args)
{
    const struct buffer_head * bh;
    char * buffer;
    int len;

    bh = *((const struct buffer_head **)(args[0]));
    len = asprintf (&buffer, "level=%d, nr_items=%d, free_space=%d rdkey",
		    B_LEVEL (bh), B_NR_ITEMS (bh), node_free_space (bh));
    FPRINTF;
}


/* %K */
static int print_short_key (FILE * stream,
			    const struct printf_info *info,
			    const void *const *args)
{
    const struct key * key;
    char * buffer;
    int len;

    key = *((const struct key **)(args[0]));
    len = asprintf (&buffer, "%u %u", key_dir_id(key), key_objectid(key));
    FPRINTF;
}


/* %k */
static int print_key (FILE * stream,
		      const struct printf_info *info,
		      const void *const *args)
{
    const struct key * key;
    char * buffer;
    int len;

    key = *((const struct key **)(args[0]));
    len = asprintf (&buffer, "%u %u 0x%Lx %s",  
		    key_dir_id(key),
                    key_objectid(key),
                    get_offset (key),
                    key_of_what (key));
    FPRINTF;
}


/* %H */
static int print_item_head (FILE * stream,
			    const struct printf_info *info,
			    const void *const *args)
{
    const struct item_head * ih;
    char * buffer;
    int len;

    ih = *((const struct item_head **)(args[0]));
    len = asprintf (&buffer, "%u %u 0x%Lx %s, "
		    "len %u, entry count %u, fsck need %u, format %s",
		    le32_to_cpu(ih->ih_key.k_dir_id),
                    le32_to_cpu(ih->ih_key.k_objectid), 
		    get_offset (&ih->ih_key), key_of_what (&ih->ih_key),
		    ih_item_len(ih), ih_entry_count (ih), 
                    ih_fsck_need(ih),
		    ih_key_format (ih) == KEY_FORMAT_2 ? "new" : 
		    ((ih_key_format (ih) == KEY_FORMAT_1) ? "old" : "BAD"));
    FPRINTF;
}


static int print_disk_child (FILE * stream,
			     const struct printf_info *info,
			     const void *const *args)
{
    const struct disk_child * dc;
    char * buffer;
    int len;

    dc = *((const struct disk_child **)(args[0]));
    len = asprintf (&buffer, "[dc_number=%u, dc_size=%u]", dc_block_number(dc),
		    dc_size(dc));
    FPRINTF;
}

#endif

char ftypelet (mode_t mode)
{
    if (S_ISBLK (mode))
	return 'b';
    if (S_ISCHR (mode))
	return 'c';
    if (S_ISDIR (mode))
	return 'd';
    if (S_ISREG (mode))
	return '-';
    if (S_ISFIFO (mode))
	return 'p';
    if (S_ISLNK (mode))
	return 'l';
    if (S_ISSOCK (mode))
	return 's';
    return '?';
}

#ifndef EMBED

static int rwx (FILE * stream, mode_t mode)
{
    return fprintf (stream, "%c%c%c",
		    (mode & S_IRUSR) ? 'r' : '-',
		    (mode & S_IWUSR) ? 'w' : '-',
		    (mode & S_IXUSR) ? 'x' : '-');
}


/* %M */
static int print_sd_mode (FILE * stream,
			  const struct printf_info *info,
			  const void *const *args)
{
    int len = 0;
    mode_t mode;

    mode = *(mode_t *)args[0];
    len = fprintf (stream, "%c", ftypelet (mode));
    len += rwx (stream, (mode & 0700) << 0);
    len += rwx (stream, (mode & 0070) << 3);
    len += rwx (stream, (mode & 0007) << 6);
    return len;
}

#endif /* EMBED */


void reiserfs_warning (FILE * fp, const char * fmt, ...)
{
    static int registered = 0;
    va_list args;

#ifndef EMBED
    if (!registered) {
	registered = 1;
	
	register_printf_function ('K', print_short_key, _arginfo);
	register_printf_function ('k', print_key, _arginfo);
	register_printf_function ('H', print_item_head, _arginfo);
	register_printf_function ('b', print_block_head, _arginfo);
	register_printf_function ('y', print_disk_child, _arginfo);
	register_printf_function ('M', print_sd_mode, _arginfo);
    }
#endif

    va_start (args, fmt);
    vfprintf (fp, fmt, args);
    va_end (args);
}


static char * vi_type (struct virtual_item * vi)
{
    static char *types[]={"directory", "direct", "indirect", "stat data"};

    if (vi->vi_type & VI_TYPE_STAT_DATA)
	return types[3];
    if (vi->vi_type & VI_TYPE_INDIRECT)
	return types[2];
    if (vi->vi_type & VI_TYPE_DIRECT)
	return types[1];
    if (vi->vi_type & VI_TYPE_DIRECTORY)
	return types[0];

    reiserfs_panic ("vi_type: 6000: unknown type (0x%x)", vi->vi_type);
    return NULL;
}


void print_virtual_node (struct virtual_node * vn)
{
    int i, j;
  
    printf ("VIRTUAL NODE CONTAINS %d items, has size %d,%s,%s, ITEM_POS=%d POS_IN_ITEM=%d MODE=\'%c\'\n",
	    vn->vn_nr_item, vn->vn_size,
	    (vn->vn_vi[0].vi_type & VI_TYPE_LEFT_MERGEABLE )? "left mergeable" : "", 
	    (vn->vn_vi[vn->vn_nr_item - 1].vi_type & VI_TYPE_RIGHT_MERGEABLE) ? "right mergeable" : "",
	    vn->vn_affected_item_num, vn->vn_pos_in_item, vn->vn_mode);


    for (i = 0; i < vn->vn_nr_item; i ++) {
	printf ("%s %d %d", vi_type (&vn->vn_vi[i]), i, vn->vn_vi[i].vi_item_len);
	if (vn->vn_vi[i].vi_entry_sizes)
	{
	    printf ("It is directory with %d entries: ", vn->vn_vi[i].vi_entry_count);
	    for (j = 0; j < vn->vn_vi[i].vi_entry_count; j ++)
		printf ("%d ", vn->vn_vi[i].vi_entry_sizes[j]);
	}
	printf ("\n");
    }
}


void print_path (struct tree_balance * tb, struct path * path)
{
    int offset = path->path_length;
    struct buffer_head * bh;

    printf ("Offset    Bh     (b_blocknr, b_count) Position Nr_item\n");
    while ( offset > ILLEGAL_PATH_ELEMENT_OFFSET ) {
	bh = PATH_OFFSET_PBUFFER (path, offset);
	printf ("%6d %10p (%9lu, %7d) %8d %7d\n", offset, 
		bh, bh ? bh->b_blocknr : 0, bh ? bh->b_count : 0,
		PATH_OFFSET_POSITION (path, offset), bh ? B_NR_ITEMS (bh) : -1);
	
	offset --;
    }
}


#if 0
void print_de (struct reiserfs_dir_entry * de)
{
    reiserfs_warning ("entry key: [%k], object_key: [%u %u], b_blocknr=%lu, item_num=%d, pos_in_item=%d\n",
		      &de->de_entry_key, de->de_dir_id, de->de_objectid,
		      de->de_bh->b_blocknr, de->de_item_num, de->de_entry_num);
}

static char * item_type (struct item_head * ih)
{
    static char * types[] = {
        "SD", "DIR", "DRCT", "IND", "???"
    };

    if (I_IS_STAT_DATA_ITEM(ih))
        return types[0];
    if (I_IS_DIRECTORY_ITEM(ih))
        return types[1];
    if (I_IS_DIRECT_ITEM(ih))
        return types[2];
    if (I_IS_INDIRECT_ITEM(ih))
        return types[3];
    return types[4];
}

#endif


void print_directory_item (FILE * fp, reiserfs_filsys_t fs,
			   struct buffer_head * bh, struct item_head * ih)
{
    int i;
    int namelen;
    struct reiserfs_de_head * deh;
    char * name;
/*    static char namebuf [80];*/

    if (!I_IS_DIRECTORY_ITEM (ih))
	return;

    //printk ("\n%2%-25s%-30s%-15s%-15s%-15s\n", "    Name", "length", "Object key", "Hash", "Gen number", "Status");
    reiserfs_warning (fp, "%3s: %-25s%s%-22s%-12s%s\n", "###", "Name", "length", "    Object key", "   Hash", "Gen number");
    deh = B_I_DEH (bh, ih);
    for (i = 0; i < ih_entry_count (ih); i ++, deh ++) {
	if (dir_entry_bad_location (deh, ih, i == 0 ? 1 : 0)) {
	    reiserfs_warning (fp, "%3d: wrong entry location %u, deh_offset %u\n",
			      i, deh_location (deh), deh_offset (deh));
	    continue;
	}
	if (i && dir_entry_bad_location (deh - 1, ih, ((i - 1) == 0) ? 1 : 0))
	    /* previous entry has bad location so we can not calculate entry
               length */
	    namelen = 25;
	else
	    namelen = name_length (ih, deh, i);

	name = name_in_entry (deh, i);
	reiserfs_warning (fp, "%3d: \"%-25.*s\"(%3d)%20K%12d%5d, loc %u, state %x %s\n", 
			  i, namelen, name, namelen,
                          /* this gets converted in print_short_key() */
			  (struct key *)&(deh->deh_dir_id),
			  GET_HASH_VALUE (deh_offset(deh)),
                          GET_GENERATION_NUMBER (deh_offset(deh)),
			  deh_location (deh), deh_state(deh),
			  fs ? (is_properly_hashed (fs, name, namelen, deh_offset (deh)) ? "" : "(BROKEN)") : "??");
    }
}


//
// printing of indirect item
//
static void start_new_sequence (__u32 * start, int * len, __u32 new)
{
    *start = new;
    *len = 1;
}


static int sequence_finished (__u32 start, int * len, __u32 new)
{
    if (start == INT_MAX)
	return 1;

    if (start == 0 && new == 0) {
	(*len) ++;
	return 0;
    }
    if (start != 0 && (start + *len) == new) {
	(*len) ++;
	return 0;
    }
    return 1;
}

static void print_sequence (FILE * fp, __u32 start, int len)
{
    if (start == INT_MAX)
	return;

    if (len == 1)
	reiserfs_warning (fp, " %d", start);
    else
	reiserfs_warning (fp, " %d(%d)", start, len);
}


void print_indirect_item (FILE * fp, struct buffer_head * bh, int item_num)
{
    struct item_head * ih;
    int j;
    __u32 * unp, prev = INT_MAX;
    int num;

    ih = B_N_PITEM_HEAD (bh, item_num);
    unp = (__u32 *)B_I_PITEM (bh, ih);

    if (ih_item_len(ih) % UNFM_P_SIZE)
	reiserfs_warning (fp, "print_indirect_item: invalid item len");  

    reiserfs_warning (fp, "%d pointers\n[ ", I_UNFM_NUM (ih));
    for (j = 0; j < I_UNFM_NUM (ih); j ++) {
	if (sequence_finished (prev, &num, unp[j])) {
	    print_sequence (fp, prev, num);
	    start_new_sequence (&prev, &num, unp[j]);
	}
    }
    print_sequence (fp, prev, num);
    reiserfs_warning (fp, "]\n");
}


#ifndef NO_STRFTIME
char timebuf[256];
#endif

char * timestamp (time_t t)
{
#ifndef NO_STRFTIME
    strftime (timebuf, 256, "%m/%d/%Y %T", localtime (&t));
    return timebuf;
#else
	return(asctime(localtime(&t)));
#endif
}

static int print_stat_data (FILE * fp, struct buffer_head * bh, struct item_head * ih, int alltimes)
{
    int retval;
    

    /* we can not figure out whether it is new stat data or old by key_format
       macro. Stat data's key looks identical in both formats */
    if (ih_key_format (ih) == KEY_FORMAT_1) {
        struct stat_data_v1 * sd_v1 = (struct stat_data_v1 *)B_I_PITEM (bh, ih);
	reiserfs_warning (fp, "(OLD SD), mode %M, size %u, nlink %u, uid %d, FDB %d, mtime %s blocks %d", 
		sd_v1_mode(sd_v1), sd_v1_size(sd_v1), sd_v1_nlink(sd_v1),
                sd_v1_uid(sd_v1), sd_v1_first_direct_byte(sd_v1), timestamp
                (sd_v1_mtime(sd_v1)), sd_v1_blocks(sd_v1));
	retval = (S_ISLNK (sd_v1_mode(sd_v1))) ? 1 : 0;
        if (alltimes)
            reiserfs_warning (fp, "%s %s\n", timestamp (sd_v1_ctime(sd_v1)),
                timestamp (sd_v1_atime(sd_v1)));
    } else {
        struct stat_data * sd = (struct stat_data *)B_I_PITEM (bh, ih);
	reiserfs_warning (fp, "(NEW SD), mode %M, size %Lu, nlink %u, mtime %s blocks %d", 
		sd_v2_mode(sd), sd_v2_size(sd), sd_v2_nlink(sd),
		timestamp (sd_v2_mtime(sd)), sd_v2_blocks(sd));
	retval = (S_ISLNK (sd_v2_mode(sd))) ? 1 : 0;
        if (alltimes)
            reiserfs_warning (fp, "%s %s\n", timestamp (sd_v2_ctime(sd)),
                timestamp (sd_v2_atime(sd)));
    }

    reiserfs_warning (fp, "\n");
    return retval;
}


/* this prints internal nodes (4 keys/items in line) (dc_number,
   dc_size)[k_dirid, k_objectid, k_offset, k_uniqueness](dc_number,
   dc_size)...*/
static int print_internal (FILE * fp, struct buffer_head * bh, int first, int last)
{
    struct key * key;
    struct disk_child * dc;
    int i;
    int from, to;

    if (!is_internal_node (bh))
	return 1;

    if (first == -1) {
	from = 0;
	to = B_NR_ITEMS (bh);
    } else {
	from = first;
	to = last < B_NR_ITEMS (bh) ? last : B_NR_ITEMS (bh);
    }

    reiserfs_warning (fp, "INTERNAL NODE (%ld) contains %b\n",  bh->b_blocknr, bh);

    dc = B_N_CHILD (bh, from);
    reiserfs_warning (fp, "PTR %d: %y ", from, dc);

    for (i = from, key = B_N_PDELIM_KEY (bh, from), dc ++; i < to; i ++, key ++, dc ++) {
	reiserfs_warning (fp, "KEY %d: %20k PTR %d: %20y ", i, key, i + 1, dc);
	if (i && i % 4 == 0)
	    reiserfs_warning (fp, "\n");
    }
    reiserfs_warning (fp, "\n");
    return 0;
}



static int is_symlink = 0;
static int print_leaf (FILE * fp, reiserfs_filsys_t fs, struct buffer_head * bh,
		       int print_mode, int first, int last)
{
    struct block_head * blkh;
    struct item_head * ih;
    int i;
    int from, to;

    if (!is_leaf_node (bh))
	return 1;

    blkh = B_BLK_HEAD (bh);
    ih = B_N_PITEM_HEAD (bh,0);

    reiserfs_warning (fp, "\n===================================================================\n");
    reiserfs_warning (fp, "LEAF NODE (%ld) contains %b\n", bh->b_blocknr, bh);

    if (!(print_mode & PRINT_LEAF_ITEMS)) {
	reiserfs_warning (fp, "FIRST ITEM_KEY: %k, LAST ITEM KEY: %k\n",
			   &(ih->ih_key), &((ih + blkh_nr_item(blkh) - 1)->ih_key));
	return 0;
    }

    if (first < 0 || first > blkh_nr_item(blkh) - 1) 
	from = 0;
    else 
	from = first;

    if (last < 0 || last > blkh_nr_item(blkh))
	to = blkh_nr_item(blkh);
    else
	to = last;


    reiserfs_warning (fp,
		       "-------------------------------------------------------------------------------\n"
		       "|###|type|ilen|f/sp| loc|fmt|fsck|                   key                      |\n"
		       "|   |    |    |e/cn|    |   |need|                                            |\n");
    for (i = from; i < to; i++) {
	reiserfs_warning (fp,
			   "-------------------------------------------------------------------------------\n"
			  "|%3d|%30H|\n", i, ih + i);

	if (I_IS_STAT_DATA_ITEM(ih+i) && print_mode & PRINT_ITEM_DETAILS) {
	    is_symlink = print_stat_data (fp, bh, ih + i, 0/*all times*/);
	    continue;
	}

	if (I_IS_DIRECTORY_ITEM(ih+i) && print_mode & PRINT_ITEM_DETAILS) {
	    print_directory_item (fp, fs, bh, ih+i);
	    continue;
	}

	if (I_IS_INDIRECT_ITEM(ih+i) && print_mode & PRINT_ITEM_DETAILS) {
	    print_indirect_item (fp, bh, i);
	    continue;
	}

	if (I_IS_DIRECT_ITEM(ih+i)) {
	    int j = 0;
	    if (is_symlink || print_mode & PRINT_DIRECT_ITEMS) {
		reiserfs_warning (fp, "\"");
		while (j < ih_item_len(&(ih[i]))) {
		    if (B_I_PITEM(bh,ih+i)[j] == 10)
			reiserfs_warning (fp, "\\n");
		    else
			reiserfs_warning (fp, "%c", B_I_PITEM(bh,ih+i)[j]);
		    j ++;
		}
		reiserfs_warning (fp, "\"\n");
	    }
	    continue;
	}
    }
    reiserfs_warning (fp, "===================================================================\n");
    return 0;
}



/* return 1 if this is not super block */
static int print_super_block (FILE * fp, struct buffer_head * bh)
{
    struct reiserfs_super_block * rs = (struct reiserfs_super_block *)(bh->b_data);
    int skipped, data_blocks;
    
    if (is_reiser2fs_magic_string (rs))
	reiserfs_warning (fp, "Super block of format 3.6 found on the 0x%x in block %ld\n", 
			   bh->b_dev, bh->b_blocknr);
    else if (is_reiserfs_magic_string (rs))
	reiserfs_warning (fp, "Super block of format 3.5 found on the 0x%x in block %ld\n",
			  bh->b_dev, bh->b_blocknr);
    else if (is_prejournaled_reiserfs (rs)) {
	reiserfs_warning (fp, "Prejournaled reiserfs super block found. Not supported here. Use proper tools instead\n");
	return 1;
    } else
	// no reiserfs signature found in the block
	return 1;

    reiserfs_warning (fp, "Block count %u\n", rs_block_count (rs));
    reiserfs_warning (fp, "Blocksize %d\n", rs_blocksize (rs));
    reiserfs_warning (fp, "Free blocks %u\n", rs_free_blocks (rs));
    skipped = bh->b_blocknr; // FIXME: this would be confusing if
    // someone stores reiserfs super block in reiserfs ;)
    data_blocks = rs_block_count (rs) - skipped - 1 -
	rs_bmap_nr (rs) - (rs_journal_size (rs) + 1) - rs_free_blocks (rs);
    reiserfs_warning (fp, "Busy blocks (skipped %d, bitmaps - %d, journal blocks - %d\n"
	    "1 super blocks, %d data blocks\n", 
	    skipped, rs_bmap_nr (rs), 
	    (rs_journal_size (rs) + 1), data_blocks);
    reiserfs_warning (fp, "Root block %u\n", rs_root_block (rs));
    reiserfs_warning (fp, "Journal block (first) %d\n", rs_journal_start (rs));
    reiserfs_warning (fp, "Journal dev %d\n", rs->s_v1.s_journal_dev);    
    reiserfs_warning (fp, "Journal orig size %d\n", rs_journal_size (rs));
    reiserfs_warning (fp, "Filesystem state %s\n", (rs_state(rs) == REISERFS_VALID_FS) ? "VALID" : "ERROR");
    if (fsck_state (rs) == TREE_IS_BUILT)
	reiserfs_warning (fp, "fsck pass 2 completion code set\n");
 
#if 0
    __u32 s_journal_trans_max ;           /* max number of blocks in a transaction.  */
    __u32 s_journal_block_count ;         /* total size of the journal. can change over time  */
    __u32 s_journal_max_batch ;           /* max number of blocks to batch into a trans */
    __u32 s_journal_max_commit_age ;      /* in seconds, how old can an async commit be */
    __u32 s_journal_max_trans_age ;       /* in seconds, how old can a transaction be */
#endif
    reiserfs_warning (fp, "Tree height %d\n", rs_tree_height (rs));
    reiserfs_warning (fp, "Hash function used to sort names: %s\n",
		      code2name (rs_hash (rs)));
    reiserfs_warning (fp, "Objectid map size %d, max %d\n", rs_objectid_map_size (rs),
		       rs_objectid_map_max_size (rs));
    reiserfs_warning (fp, "Version %d\n", rs_version (rs));
    return 0;
}


static int print_desc_block (FILE * fp, struct buffer_head * bh)
{
    struct reiserfs_journal_desc * desc;

    desc = (struct reiserfs_journal_desc *)(bh->b_data);

    if (memcmp(desc->j_magic, JOURNAL_DESC_MAGIC, 8))
	return 1;

    reiserfs_warning (fp, "Desc block %lu (j_trans_id %ld, j_mount_id %ld, j_len %ld)",
		       bh->b_blocknr, desc->j_trans_id, desc->j_mount_id, desc->j_len);

    return 0;
}


void print_block (FILE * fp, reiserfs_filsys_t fs, 
		  struct buffer_head * bh, ...)//int print_mode, int first, int last)
{
    va_list args;
    int mode, first, last;
    
    va_start (args, bh);

    if ( ! bh ) {
	reiserfs_warning (stderr, "print_block: buffer is NULL\n");
	return;
    }

    mode = va_arg (args, int);
    first = va_arg (args, int);
    last = va_arg (args, int);
    if (print_desc_block (fp, bh))
	if (print_super_block (fp, bh))
	    if (print_leaf (fp, fs, bh, mode, first, last))
		if (print_internal (fp, bh, first, last))
		    reiserfs_warning (fp, "Block %ld contains unformatted data\n", bh->b_blocknr);
}


void print_tb (int mode, int item_pos, int pos_in_item, struct tree_balance * tb, char * mes)
{
  int h = 0;
  int i;
  struct buffer_head * tbSh, * tbFh;


  if (!tb)
    return;

  printf ("\n********************** PRINT_TB for %s *******************\n", mes);
  printf ("MODE=%c, ITEM_POS=%d POS_IN_ITEM=%d\n", mode, item_pos, pos_in_item);
  printf ("*********************************************************************\n");

  printf ("* h *    S    *    L    *    R    *   F   *   FL  *   FR  *  CFL  *  CFR  *\n");
/*
01234567890123456789012345678901234567890123456789012345678901234567890123456789
       1        2         3         4         5         6         7         8
  printk ("*********************************************************************\n");
*/
  
  
  for (h = 0; h < sizeof(tb->insert_size) / sizeof (tb->insert_size[0]); h ++) {
    if (PATH_H_PATH_OFFSET (tb->tb_path, h) <= tb->tb_path->path_length && 
	PATH_H_PATH_OFFSET (tb->tb_path, h) > ILLEGAL_PATH_ELEMENT_OFFSET) {
      tbSh = PATH_H_PBUFFER (tb->tb_path, h);
      tbFh = PATH_H_PPARENT (tb->tb_path, h);
    } else {
      /*      printk ("print_tb: h=%d, PATH_H_PATH_OFFSET=%d, path_length=%d\n", 
	      h, PATH_H_PATH_OFFSET (tb->tb_path, h), tb->tb_path->path_length);*/
      tbSh = 0;
      tbFh = 0;
    }
    printf ("* %d * %3ld(%2d) * %3ld(%2d) * %3ld(%2d) * %5ld * %5ld * %5ld * %5ld * %5ld *\n",
	    h, 
	    (tbSh) ? (tbSh->b_blocknr):(-1),
	    (tbSh) ? tbSh->b_count : -1,
	    (tb->L[h]) ? (tb->L[h]->b_blocknr):(-1),
	    (tb->L[h]) ? tb->L[h]->b_count : -1,
	    (tb->R[h]) ? (tb->R[h]->b_blocknr):(-1),
	    (tb->R[h]) ? tb->R[h]->b_count : -1,
	    (tbFh) ? (tbFh->b_blocknr):(-1),
	    (tb->FL[h]) ? (tb->FL[h]->b_blocknr):(-1),
	    (tb->FR[h]) ? (tb->FR[h]->b_blocknr):(-1),
	    (tb->CFL[h]) ? (tb->CFL[h]->b_blocknr):(-1),
	    (tb->CFR[h]) ? (tb->CFR[h]->b_blocknr):(-1));
  }

  printf ("*********************************************************************\n");


  /* print balance parameters for leaf level */
  h = 0;
  printf ("* h * size * ln * lb * rn * rb * blkn * s0 * s1 * s1b * s2 * s2b * curb * lk * rk *\n");
  printf ("* %d * %4d * %2d * %2d * %2d * %2d * %4d * %2d * %2d * %3d * %2d * %3d * %4d * %2d * %2d *\n",
	  h, tb->insert_size[h], tb->lnum[h], tb->lbytes, tb->rnum[h],tb->rbytes, tb->blknum[h], 
	  tb->s0num, tb->s1num,tb->s1bytes,  tb->s2num, tb->s2bytes, tb->cur_blknum, tb->lkey[h], tb->rkey[h]);


/* this prints balance parameters for non-leaf levels */
  do {
    h++;
    printf ("* %d * %4d * %2d *    * %2d *    * %2d *\n",
    h, tb->insert_size[h], tb->lnum[h], tb->rnum[h], tb->blknum[h]);
  } while (tb->insert_size[h]);

  printf ("*********************************************************************\n");


  /* print FEB list (list of buffers in form (bh (b_blocknr, b_count), that will be used for new nodes) */
  h = 0;
  for (i = 0; i < sizeof (tb->FEB) / sizeof (tb->FEB[0]); i ++)
    printf ("%s%p (%lu %d)", i == 0 ? "FEB list: " : ", ", tb->FEB[i], tb->FEB[i] ? tb->FEB[i]->b_blocknr : 0,
	    tb->FEB[i] ? tb->FEB[i]->b_count : 0);
  printf ("\n");

  printf ("********************** END OF PRINT_TB *******************\n\n");

}


static void print_bmap_block (FILE * fp, int i, struct buffer_head * bmap, int blocks, int silent)
{
    int j, k;
    int bits = bmap->b_size * 8;
    int zeros = 0, ones = 0;
  
    reiserfs_warning (fp, "#%d: block %lu: ", i, bmap->b_blocknr);

    if (test_bit (0, bmap->b_data)) {
	/* first block addressed by this bitmap block is used */
	ones ++;
	if (!silent)
	    reiserfs_warning (fp, "Busy (%d-", i * bits);
	for (j = 1; j < blocks; j ++) {
	    while (test_bit (j, bmap->b_data)) {
		ones ++;
		if (j == blocks - 1) {
		    if (!silent)
			reiserfs_warning (fp, "%d)\n", j + i * bits);
		    goto end;
		}
		j++;
	    }
	    if (!silent)
		reiserfs_warning (fp, "%d) Free(%d-", j - 1 + i * bits, j + i * bits);

	    while (!test_bit (j, bmap->b_data)) {
		zeros ++;
		if (j == blocks - 1) {
		    if (!silent)
			reiserfs_warning (fp, "%d)\n", j + i * bits);
		    goto end;
		}
		j++;
	    }
	    if (!silent)
		reiserfs_warning (fp, "%d) Busy(%d-", j - 1 + i * bits, j + i * bits);

	    j --;
	end:
	}
    } else {
	/* first block addressed by this bitmap is free */
	zeros ++;
	if (!silent)
	    reiserfs_warning (fp, "Free (%d-", i * bits);
	for (j = 1; j < blocks; j ++) {
	    k = 0;
	    while (!test_bit (j, bmap->b_data)) {
		k ++;
		if (j == blocks - 1) {
		    if (!silent)
			reiserfs_warning (fp, "%d)\n", j + i * bits);
		    zeros += k;
		    goto end2;
		}
		j++;
	    }
	    zeros += k;
	    if (!silent)
		reiserfs_warning (fp, "%d) Busy(%d-", j - 1 + i * bits, j + i * bits);
	    
	    k = 0;
	    while (test_bit (j, bmap->b_data)) {
		ones ++;
		if (j == blocks - 1) {
		    if (!silent)
			reiserfs_warning (fp, "%d)\n", j + i * bits);
		    ones += k;
		    goto end2;
		}
		j++;
	    }
	    ones += k;
	    if (!silent)
		reiserfs_warning (fp, "%d) Free(%d-", j - 1 + i * bits, j + i * bits);
	
	    j --;
	end2:
	}
    }

    reiserfs_warning (fp, "used %d, free %d\n", ones, zeros);
}


/* if silent == 1, do not print details */
void print_bmap (FILE * fp, reiserfs_filsys_t s, int silent)
{
    int bmapnr = SB_BMAP_NR (s);
    int i;
    int blocks = s->s_blocksize * 8; /* adressed by bitmap */

    reiserfs_warning (fp, "Bitmap blocks are:\n");
    for (i = 0; i < bmapnr; i ++) {

	if (i == bmapnr - 1)
	    if (SB_BLOCK_COUNT (s) % (s->s_blocksize * 8))
		blocks = SB_BLOCK_COUNT (s) % (s->s_blocksize * 8);
	print_bmap_block (fp, i, SB_AP_BITMAP(s)[i], blocks, silent);
    }

    /* check unused part of last bitmap */
    {
	int bad_unused_bitmap = 0;
	int ones;

	ones = s->s_blocksize * 8 - SB_BLOCK_COUNT (s) % (s->s_blocksize * 8);
	if (ones == s->s_blocksize * 8)
	    ones = 0;
      
	for (i = s->s_blocksize * 8; --i >= blocks; )
	    if (!test_bit (i, SB_AP_BITMAP (s)[bmapnr - 1]->b_data))
		bad_unused_bitmap ++;

	if (bad_unused_bitmap) {
	    reiserfs_warning (fp, "Unused part of bitmap is wrong: should be %d ones, found %d zeros\n",
			       ones, bad_unused_bitmap);
	}
    }
    
}



void print_objectid_map (FILE * fp, reiserfs_filsys_t fs)
{
    int i;
    struct reiserfs_super_block * rs;
    __u32 * omap;

    rs = fs->s_rs;
    if (fs->s_version == REISERFS_VERSION_2)
	omap = (__u32 *)(rs + 1);
    else if (fs->s_version == REISERFS_VERSION_1)
	omap = (__u32 *)((struct reiserfs_super_block_v1 *)rs + 1);
    else {
	reiserfs_warning (fp, "print_objectid_map: proper signature is not found\n");
	return;
    }
	
    reiserfs_warning (fp, "Map of objectids (super block size %d)\n", (char *)omap - (char *)rs);
      
    for (i = 0; i < SB_OBJECTID_MAP_SIZE (fs); i ++) {
	if (i % 2 == 0)
	    reiserfs_warning (fp, "busy(%u-%u) ", omap[i], omap[i+1] - 1); 
	else
	    reiserfs_warning (fp, "free(%u-%u) ", 
			       omap[i], ((i+1) == SB_OBJECTID_MAP_SIZE (fs)) ? -1 : omap[i+1] - 1);
    }

    reiserfs_warning (fp, "\nObject id array has size %d (max %d):", SB_OBJECTID_MAP_SIZE (fs), 
		       SB_OBJECTID_MAP_MAXSIZE (fs));
  
    for (i = 0; i < SB_OBJECTID_MAP_SIZE (fs); i ++)
	reiserfs_warning (fp, "%s%u ", i % 2 ? "" : "*", omap[i]); 
    reiserfs_warning (fp, "\n");

}

#if 0
/* the below is from fileutils-4.0-66 (shortened) */

/* Look at read, write, and execute bits in BITS and set
   flags in CHARS accordingly.  */

static void
rwx (short unsigned int bits, char *chars)
{
  chars[0] = (bits & S_IRUSR) ? 'r' : '-';
  chars[1] = (bits & S_IWUSR) ? 'w' : '-';
  chars[2] = (bits & S_IXUSR) ? 'x' : '-';
}

/* snip */

/* Return a character indicating the type of file described by
   file mode BITS:
   'd' for directories
   'b' for block special files
   'c' for character special files
   'l' for symbolic links
   's' for sockets
   'p' for fifos
   '-' for regular files
   '?' for any other file type.  */

static char
ftypelet (long int bits)
{
#ifdef S_ISBLK
  if (S_ISBLK (bits))
    return 'b';
#endif
  if (S_ISCHR (bits))
    return 'c';
  if (S_ISDIR (bits))
    return 'd';
  if (S_ISREG (bits))
    return '-';
#ifdef S_ISFIFO
  if (S_ISFIFO (bits))
    return 'p';
#endif
#ifdef S_ISLNK
  if (S_ISLNK (bits))
    return 'l';
#endif
#ifdef S_ISSOCK
  if (S_ISSOCK (bits))
    return 's';
#endif

  return '?';
}

/* Like filemodestring, but only the relevant part of the `struct stat'
   is given as an argument.  */

static void
mode_string (short unsigned int mode, char *str)
{
  str[0] = ftypelet ((long) mode);
  rwx ((mode & 0700) << 0, &str[1]);
  rwx ((mode & 0070) << 3, &str[4]);
  rwx ((mode & 0007) << 6, &str[7]);
}


char * st_mode2string (short unsigned int mode, char * buf)
{
    mode_string (mode, buf);
    buf[10] = 0;
    return buf;
}


#endif



#ifdef EMBED

int asprintf (char **bufp, const char * fmt, ...)
{
    va_list args;
	int		n;

	*bufp = malloc(500);
	if (!bufp)
		return(0);
    va_start (args, fmt);
    n = snprintf (*bufp, 500, fmt, args);
    va_end (args);
	return(n);
}

#endif
