/*
 * Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */
#include "debugreiserfs.h"

reiserfs_filsys_t fs;

#define print_usage_and_exit() die ("Usage: %s [-b block-to-print][-idc] device\n\
-i Causes to print all items of a leaf\n\
-d                 content of directory items\n\
-c                 content of direct items\n\
-m                 bitmap blocks\n\
-t\n\
-C\n\
-p\n\
-s                 \n\
-n                 scan for name\n\
-p [filename]\n\
-P [filename]\n\
..etc\n", argv[0]);



#if 1
struct reiserfs_fsstat {
    int nr_internals;
    int nr_leaves;
    int nr_files;
    int nr_directories;
    int nr_unformatted;
} g_stat_info;
#endif


int mode = DO_DUMP;

/*
 *  options
 */
int opt_print_regular_file_content = 0;/* -c */
int opt_print_details = 0;	/* -d */
int opt_print_leaf_items = 0;	/* -i */
int opt_print_objectid_map = 0;	/* -o */
int opt_print_block_map = 0;	/* -m */
int opt_print_journal;		/* -j */

/* when you want print one block specify -b # */
int opt_block_to_print = -1;

/* when you want to corrupt block specify -C # */
int opt_block_to_corrupt = -1;

int opt_pack = 0;
int opt_quiet = 0;

int print_mode (void)
{
    int mode = 0;

    if (opt_print_leaf_items == 1)
	mode |= PRINT_LEAF_ITEMS;
    if (opt_print_details == 1)
	mode |= (PRINT_LEAF_ITEMS | PRINT_ITEM_DETAILS);
    if (opt_print_regular_file_content == 1)
	mode |= (PRINT_LEAF_ITEMS | PRINT_DIRECT_ITEMS);
    return mode;
}


static void print_disk_tree (reiserfs_filsys_t fs, int block_nr)
{
    struct buffer_head * bh;

    bh = bread (fs->s_dev, block_nr, fs->s_blocksize);
    if (!bh) {
	die ("Could not read block %d\n", block_nr);
    }
    if (is_internal_node (bh)) {
	int i;
	struct disk_child * dc;

	g_stat_info.nr_internals ++;
	print_block (stdout, fs, bh, print_mode (), -1, -1);
      
	dc = B_N_CHILD (bh, 0);
	for (i = 0; i <= B_NR_ITEMS (bh); i ++, dc ++)
	    print_disk_tree (fs, dc_block_number(dc));
      
    } else if (is_leaf_node (bh)) {
	g_stat_info.nr_leaves ++;
	print_block (stdout, fs, bh, print_mode (), -1, -1);
    } else {
	print_block (stdout, fs, bh, print_mode (), -1, -1);
	die ("print_disk_tree: bad block type");
    }
    brelse (bh);
}



void pack_one_block (reiserfs_filsys_t fs, unsigned long block);
static void print_one_block (reiserfs_filsys_t fs, int block)
{
    struct buffer_head * bh;
    
    if (test_bit (block % (fs->s_blocksize * 8), 
		  SB_AP_BITMAP (fs)[block / (fs->s_blocksize * 8)]->b_data))
	fprintf (stderr, "%d is used in true bitmap\n", block);
    else
	fprintf (stderr, "%d is free in true bitmap\n", block);
    
    bh = bread (fs->s_dev, block, fs->s_blocksize);
    if (!bh) {
	printf ("print_one_block: bread fialed\n");
	return;
    }

    if (opt_pack) {
	pack_one_block (fs, bh->b_blocknr);
	brelse (bh);
	return;
    }

    if (who_is_this (bh->b_data, fs->s_blocksize) != THE_UNKNOWN)
	print_block (stdout, fs, bh, PRINT_LEAF_ITEMS | PRINT_ITEM_DETAILS | 
		     (opt_print_regular_file_content == 1 ? PRINT_DIRECT_ITEMS : 0), -1, -1);
    else
	printf ("Looks like unformatted\n");
    brelse (bh);
    return;
}


static void corrupt_clobber_hash (char * name, struct item_head * ih, 
				  struct reiserfs_de_head * deh)
{
    printf ("\tCorrupting deh_offset of entry \"%s\" of [%u %u]\n", name,
	    le32_to_cpu(ih->ih_key.k_dir_id),
            le32_to_cpu(ih->ih_key.k_objectid));
    set_deh_offset(deh, 700);
}


/* this reads list of desired corruptions from stdin and perform the
   corruptions. Format of that list:
   A hash_code
   C name objectid     - 'C'ut entry 'name' from directory item with 'objectid'
   H name objectid     - clobber 'H'hash of entry 'name' of directory 'objectid'
   I item_num pos_in_item  make pos_in_item-th slot of indirect item to point out of device
   O item_num          - destroy item 'O'rder - make 'item_num'-th to have key bigger than 'item_num' + 1-th item
   D item_num          - 'D'elete item_num-th item
   S item_num value    - change file size (item_num-th item must be stat data)
   F item_num value    - change sd_first_direct_byte of stat data
   J item_num objectid
   E name objectid new - change entry's deh_objectid to new
   P                   - print the block
*/
static void do_corrupt_one_block (reiserfs_filsys_t fs, int block)
{
    struct buffer_head * bh;
    int i, j;
    struct item_head * ih;
    int item_num;
    char * line = 0;
    int n = 0;
    char code, name [100];
    __u32 objectid, new_objectid;
    int value;
    int hash_code;
    int pos_in_item;

    if (test_bit (block % (fs->s_blocksize * 8), 
		  SB_AP_BITMAP (fs)[block / (fs->s_blocksize * 8)]->b_data))
	fprintf (stderr, "%d is used in true bitmap\n", block);
    else
	fprintf (stderr, "%d is free in true bitmap\n", block);
    
    bh = bread (fs->s_dev, block, fs->s_blocksize);
    if (!bh) {
	printf ("corrupt_one_block: bread fialed\n");
	return;
    }

    if (who_is_this (bh->b_data, fs->s_blocksize) != THE_LEAF) {
	printf ("Can not corrupt not a leaf node\n");
	brelse (bh);
	return;
    }

    printf ("Corrupting block %lu..\n", bh->b_blocknr);

    while (getline (&line, &n, stdin) != -1) {
	switch (line[0]) {
	case '#':
	case '\n':
	    continue;
	case '?':
	    printf ("A hash_code     - reset hAsh code in super block\n"
		    "C name objectid - Cut entry 'name' from directory item with 'objectid'\n"
		    "H name objectid - clobber Hash of entry 'name' of directory 'objectid'\n"
		    "I item_num pos_in_item  make pos_in_tem-th slot of Indirect item to point out of device\n"
		    "O item_num      - destroy item Order - make 'item_num'-th to have key bigger than 'item_num' + 1-th item\n"
		    "D item_num      - Delete item_num-th item\n"
		    "S item_num value - change file Size (item_num-th item must be stat data)\n"
		    "F item_num value - change sd_First_direct_byte of stat data\n"
		    "J item_num objectid - set 'obJectid' of 'item_num'-th item\n"
		    "E name objectid objectid - set deh_objectid of an entry to objectid\n");

	    continue;

	case 'P':
	    print_block (stderr, fs, bh, 3, -1, -1);
	    break;
	    
	case 'A':
	    /* corrupt hash record in super block */
	    if (sscanf (line, "%c %d\n", &code, &hash_code) != 2) {
		printf ("Wrong format \'%c\'\n", line [0]);
		continue;
	    }
	    break;
	    
	case 'C': /* cut entry */
	case 'H': /* make hash wrong */
	    if (sscanf (line, "%c %s %u\n", &code, name, &objectid) != 3) {
		printf ("Wrong format \'%c\'\n", line [0]);
		continue;
	    }
	    break;

	case 'J': /* set objectid : used to simulate objectid sharing problem */
	    if (sscanf (line, "%c %d %d\n", &code, &item_num, &objectid) != 3) {
		printf ("Wrong format \'%c\'\n", line [0]);
		continue;
	    }
	    break;

	case 'E': /* set objectid : used to simulate objectid sharing problem */
	    if (sscanf (line, "%c %s %u %d\n", &code, name, &objectid, &new_objectid) != 4) {
		printf ("Wrong format \'%c\'\n", line [0]);
		continue;
	    }
	    break;

	case 'I': /* break unformatted node pointer */
	    if (sscanf (line, "%c %d %d\n", &code, &item_num, &pos_in_item) != 3) {
		printf ("Wrong format \'%c\'\n", line [0]);
		continue;
	    }
	    break;
	    
	case 'D': /* delete item */
	case 'O': /* make item out of order */
	    if (sscanf (line, "%c %d\n", &code, &item_num) != 2) {
		printf ("Wrong format \'%c\'\n", line [0]);
		continue;
	    }
	    break;
	    
	case 'S': /* corrupt st_size */
	case 'F': /*         st_first_direct_byte */
	    if (sscanf (line, "%c %d %d\n", &code, &item_num, &value) != 3) {
		printf ("Wrong format \'%c\'\n", line [0]);
		continue;
	    }
	    break;
	}
	
	if (code == 'A') {
	    reiserfs_warning (stderr, "Changing %s to %s\n", code2name (rs_hash (fs->s_rs)),
			       code2name (hash_code));
	    set_hash (fs->s_rs, hash_code);
	    mark_buffer_dirty (fs->s_sbh);
	    continue;
	}

	ih = B_N_PITEM_HEAD (bh, 0);
	for (i = 0; i < node_item_number (bh); i ++, ih ++) {
	    struct reiserfs_de_head * deh;

	    if (code == 'I' && i == item_num) {
		if (!is_indirect_ih (ih) || pos_in_item >= I_UNFM_NUM (ih)) {
		    reiserfs_warning (stderr, "Not an indirect item or there is "
				       "not so many unfm ptrs in it\n");
		    continue;
		}
		* ((__u32 *)B_I_PITEM (bh, ih) + pos_in_item) = SB_BLOCK_COUNT(fs) + 100;
		mark_buffer_dirty (bh);
		goto cont;
	    }

	    if (code == 'J' && i == item_num) {
		ih->ih_key.k_objectid = objectid;
		mark_buffer_dirty (bh);
		goto cont;
	    }

	    if (code == 'S' && i == item_num) {
		/* fixme: old stat data only */
		struct stat_data_v1 * sd;

		sd = (struct stat_data_v1 *)B_I_PITEM (bh, ih); 
		reiserfs_warning (stderr, "Changing sd_size of %k from %d to %d\n",
				   &ih->ih_key, sd_v1_size(sd), value);
                set_sd_v1_size( sd, value );
		mark_buffer_dirty (bh);
		goto cont;		
	    }

	    if (code == 'F' && i == item_num) {
		/* fixme: old stat data only */
		struct stat_data_v1 * sd;

		sd = (struct stat_data_v1 *)B_I_PITEM (bh, ih); 
		reiserfs_warning (stderr, "Changing sd_first_direct_byte of %k from %d to %d\n",
				   &ih->ih_key, sd_v1_first_direct_byte(sd), value);		
		set_sd_v1_first_direct_byte( sd, value );
		mark_buffer_dirty (bh);
		goto cont;		
	    }

	    if (code == 'D' && i == item_num) {
		delete_item (fs, bh, item_num);
		mark_buffer_dirty (bh);
		goto cont;
	    }

	    if (code == 'O' && i == item_num) {
		/* destroy item order */
		struct key * key;
		if (i == node_item_number (bh) - 1) {
		    printf ("can not destroy order\n");
		    continue;
		}
		key = &(ih + 1)->ih_key;
		ih->ih_key.k_dir_id = cpu_to_le32(
                    le32_to_cpu(key->k_dir_id) + 1 );
		mark_buffer_dirty (bh);
	    }

	    if ( le32_to_cpu(ih->ih_key.k_objectid) != objectid ||
                 !is_direntry_ih (ih))
		continue;

	    deh = B_I_DEH (bh, ih);

	    for (j = 0; j < ih_entry_count (ih); j ++, deh ++) {
		/* look for proper entry */
		if (name_length (ih, deh, j) != strlen (name) ||
		    strncmp (name, name_in_entry (deh, j), strlen (name)))
		    continue;

		/* ok, required entry found, make a corruption */
		switch (code) {
		case 'C': /* cut entry */
		    cut_entry (fs, bh, i, j, 1);
		    mark_buffer_dirty (bh);

		    if (!B_IS_IN_TREE (bh)) {
			printf ("NOTE: block is deleted from the tree\n");
			exit (0);
		    }
		    goto cont;
		    break;

		case 'H': /* clobber hash */
		    corrupt_clobber_hash (name, ih, deh);
		    goto cont;
		    break;

		case 'E': /* change entry's deh_objectid */
		    set_deh_objectid(deh, new_objectid);
		    break;

		default:
		    printf ("Unknown command found\n");
		}
		mark_buffer_dirty (bh);
	    }
	}
    cont:
    }
    free (line);
    printf ("Done\n");
    brelse (bh);
    return;
}


/* this reads stdin and recover file of given key:  */
/* the input has to be in the follwong format:
   K dirid objectid
   N name
   B blocknumber
   ..
   then recover_file will read every block, look there specified file and put it into
*/
static void do_recover (reiserfs_filsys_t fs)
{
    char name [100];
    char * line = 0;
    int n = 0;
    int fd;
    struct key key = {0, 0, };
    struct buffer_head * bh;
    struct item_head * ih;
    unsigned long block;
    char code;
    loff_t recovered = 0;
    int i, j;
    reiserfs_bitmap_t bitmap;
    int used, not_used;

    bitmap = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));
    reiserfs_fetch_disk_bitmap (bitmap, fs);
    /* we check how many blocks recoverd items point to are free or used */
    used = 0;
    not_used = 0;

    fd = 0;
    while (getline (&line, &n, stdin) != -1) {
	if (line [0] == '#' || line [0] == '\n')
	    continue;
	switch (line [0]) {
	case 'K':
	    /* get a key of file which is to be recovered */
	    if (sscanf (line, "%c %u %u\n", &code, &key.k_dir_id, &key.k_objectid) != 3) {
		die ("recover_file: wrong input K format");
	    }
	    printf ("Recovering file (%u, %u)\n", key.k_dir_id, key.k_objectid);

            key.k_dir_id = le32_to_cpu( key.k_dir_id );
            key.k_objectid = le32_to_cpu( key.k_objectid );
	    break;

	case 'N':
	    /* get a file name */
	    recovered = 0;
	    if (sscanf (line, "%c %s\n", &code, name) != 2) {
		die ("recover_file: wrong input N format");
	    }
	    fd = open (name, O_RDWR | O_CREAT | O_EXCL, 0644);
	    if (fd == -1)
		die ("recover_file: could not create file %s: %s",
		     name,strerror (errno));
	    printf ("Recovering file %s..\n", name);
	    break;

	case 'B':
	    if (!fd)
		die ("recover_file: file name is not specified");
	    if (sscanf (line, "%c %lu\n", &code, &block) != 2) {
		die ("recover_file: wrong input B format");
	    }
	    bh = bread (fs->s_dev, block, fs->s_blocksize);
	    if (!bh) {
		printf ("reading block %lu failed\n", block);
		continue;
	    }

	    printf ("working with block %lu..\n", block);

	    ih = B_N_PITEM_HEAD (bh, 0);
	    for (i = 0; i < node_item_number (bh); i ++, ih ++) {
		__u32 * indirect;
		struct buffer_head * tmp_bh;

		if (!is_indirect_ih (ih) || key.k_dir_id != ih->ih_key.k_dir_id ||
		    key.k_objectid != ih->ih_key.k_objectid)
		    continue;

		indirect = (__u32 *)B_I_PITEM (bh, ih);
		for (j = 0; j < I_UNFM_NUM (ih); j ++) {
		    block = le32_to_cpu (indirect [j]);
		    if (!block)
			continue;
		    tmp_bh = bread (fs->s_dev, block, fs->s_blocksize);
		    if (!tmp_bh) {
			printf ("reading block %Lu failed\n", (loff_t)block * fs->s_blocksize);
			continue;
		    }
		    if (lseek64 (fd, get_offset (&ih->ih_key) + j * fs->s_blocksize - 1,
				 SEEK_SET) == (loff_t)-1) {
			printf ("llseek failed to pos %Ld\n", (loff_t)block * fs->s_blocksize);
			brelse (tmp_bh);
			continue;
		    }
		    if (reiserfs_bitmap_test_bit (bitmap, block))
			used ++;
		    else
			not_used ++;
		    /*printf ("block of file %Ld gets block %lu\n",
		      (get_offset (&ih->ih_key) - 1) / fs->s_blocksize + j, block);*/
		    if (write (fd, tmp_bh->b_data, tmp_bh->b_size) != tmp_bh->b_size) {
			printf ("write failed to pos %Ld\n", (loff_t)block * fs->s_blocksize);
			brelse (tmp_bh);
			continue;
		    }
		    recovered += fs->s_blocksize;
		    brelse (tmp_bh);
		}
	    }
	    brelse (bh);
	    break;
	}
    }
    printf ("recover_file: %Ld bytes recovered of file %s, key %u %u, %d blocks are free and %d are used\n",
	    recovered, name, le32_to_cpu(key.k_dir_id),
            le32_to_cpu(key.k_objectid), not_used, used);
}


/* debugreiserfs -p or -P compresses reiserfs meta data: super block, journal,
   bitmap blocks and blocks looking like leaves. It may save "bitmap" of
   blocks they packed in the file of special format. Reiserfsck can then load
   "bitmap" saved in that file and build the tree of blocks marked used in
   that "bitmap" */
char * where_to_save;


static char * parse_options (int argc, char * argv [])
{
    int c;
    char * tmp;
  
    while ((c = getopt (argc, argv, "b:C:icdmoMp:P:l:jsnrtu:q")) != EOF) {
	switch (c) {
	case 'b':	/* print a single node */
	    opt_block_to_print = strtol (optarg, &tmp, 0);
	    if (*tmp)
		die ("parse_options: bad block number");
	    break;
	case 'C':
	    mode = DO_CORRUPT;
	    opt_block_to_corrupt = strtol (optarg, &tmp, 0);
	    if (*tmp)
		die ("parse_options: bad block number");
	    break;
	    
	case 'p':
	    mode = DO_PACK;
	    if (optarg)
		/* save bitmap of packed blocks in the file 'optarg' */
		asprintf (&where_to_save, "%s", optarg);
	    break;

	case 'P':
	    /* scan whole device and pack all blocks looking like a leaf */
	    mode = DO_PACK_ALL;
	    fprintf (stderr, "optarg %s\n", optarg);
	    if (optarg)
		/* save bitmap of packed blocks in the file 'optarg' */
		asprintf (&where_to_save, "%s", optarg);
	    break;

	case 'i':	/* print items of a leaf */
	    opt_print_leaf_items = 1; break;

	case 'd':	/* print directories */
	    opt_print_details = 1; break;

	case 'c':	/* print contents of a regular file */
	    opt_print_regular_file_content = 1; break;

	case 'o':	/* print a objectid map */
	    opt_print_objectid_map = 1; break;

	case 'm':	/* print a block map */
	    opt_print_block_map = 1;  break;

	case 'M':	/* print a block map with details */
	    opt_print_block_map = 2;  break;

	case 'j':
	    opt_print_journal = 1; break; /* print journal */
	    
	case 's':
	    mode = DO_SCAN; break; /* read the device and print what reiserfs blocks were found */

	case 'n':
	    mode = DO_SCAN_FOR_NAME; break;

	case 'r':
	    mode = DO_RECOVER; break;

	case 't':
	    mode = DO_TEST; break;

	case 'q':
	    /* this makes packing to not show speed info during -p or -P */
	    opt_quiet = 1;
	    break;
	}
    }
    if (optind != argc - 1)
	/* only one non-option argument is permitted */
	print_usage_and_exit();
  
    return argv[optind];
}



/* print all valid transactions and found dec blocks */
static void print_journal (struct super_block * s)
{
    struct buffer_head * d_bh, * c_bh;
    struct reiserfs_journal_desc * desc ;
    struct reiserfs_journal_commit *commit ;
    int end_journal;
    int start_journal;
    int i, j;
    int first_desc_block = 0;
    int wrapped = 0;
    int valid_transactions = 0;

    start_journal = SB_JOURNAL_BLOCK (s);
    end_journal = start_journal + JOURNAL_BLOCK_COUNT;
    reiserfs_warning (stdout, "Start scanning from %d\n", start_journal);

    d_bh = 0;
    desc = 0;
    for (i = start_journal; i < end_journal; i ++) {
	d_bh = bread (s->s_dev, i, s->s_blocksize);
	if (who_is_this (d_bh->b_data, d_bh->b_size) == THE_JDESC) {
	    int commit_block;

	    if (first_desc_block == 0)
		/* store where first desc block found */
		first_desc_block = i;

	    print_block (stdout, s, d_bh); /* reiserfs_journal_desc structure will be printed */
	    desc = (struct reiserfs_journal_desc *)(d_bh->b_data);

	    commit_block = d_bh->b_blocknr + desc->j_len + 1;
	    if (commit_block >= end_journal) {
		reiserfs_warning (stdout, "-- wrapped?");
		wrapped = 1;
		break;
	    }

	    c_bh = bread (s->s_dev, commit_block, s->s_blocksize);
	    commit = bh_commit (c_bh);
	    if (does_desc_match_commit (desc, commit)) {
		reiserfs_warning (stdout, "commit block %d (trans_id %ld, j_len %ld) does not match\n", commit_block,
				  commit->j_trans_id, commit->j_len);
		brelse (c_bh) ;
		brelse (d_bh);
		continue;
	    }

	    valid_transactions ++;
	    reiserfs_warning (stdout, "(commit block %d) - logged blocks (", commit_block);
#if 1
	    for (j = 0; j < desc->j_len; j ++) {
		unsigned long block;

		if (j < JOURNAL_TRANS_HALF)
		    block = le32_to_cpu (desc->j_realblock[j]);
		else
		    block = le32_to_cpu (commit->j_realblock[i - JOURNAL_TRANS_HALF]);
			
		if (not_journalable (s, block))
		    reiserfs_warning (stdout, " xxxx");
		else {
		    reiserfs_warning (stdout, " %ld", desc->j_realblock[j]);
		    if (block_of_bitmap (s, desc->j_realblock[j]))
			reiserfs_warning (stdout, "(bmp)");
		}
		if (j && (j + 1) % 10 == 0)
		    reiserfs_warning (stdout, "\n");
	    }
#endif
	    reiserfs_warning (stdout, ")\n");
	    i += desc->j_len + 1;
	    brelse (c_bh);
	}
	brelse (d_bh);
    }
    
    if (wrapped) {
	c_bh = bread (s->s_dev, first_desc_block - 1, s->s_blocksize);
	commit = bh_commit (c_bh);
	if (does_desc_match_commit (desc, commit)) {
	    reiserfs_warning (stdout, "No! commit block %d (trans_id %ld, j_len %ld) does not match\n",
			       first_desc_block - 1, commit->j_trans_id, commit->j_len);
	} else {
	    reiserfs_warning (stdout, "Yes! (commit block %d) - logged blocks (\n", first_desc_block - 1);
#if 1
	    for (j = 0; j < desc->j_len; j ++) {
		unsigned long block;

		if (j < JOURNAL_TRANS_HALF)
		    block = le32_to_cpu (desc->j_realblock[j]);
		else
		    block = le32_to_cpu (commit->j_realblock[i - JOURNAL_TRANS_HALF]);
			
		if (not_journalable (s, block))
		    reiserfs_warning (stdout, " xxxx");
		else {
		    reiserfs_warning (stdout, " %ld", desc->j_realblock[j]);
		    if (block_of_bitmap (s, desc->j_realblock[j]))
			reiserfs_warning (stdout, "(bmp)");
		}
	    }
#endif
	    reiserfs_warning (stdout, "\n");
	}
	brelse (c_bh) ;
	brelse (d_bh);
    }

    reiserfs_warning (stdout, "%d valid transactions found\n", valid_transactions);

    {
	struct buffer_head * bh;
	struct reiserfs_journal_header * j_head;

	bh = bread (s->s_dev, SB_JOURNAL_BLOCK (s) + rs_journal_size (s->s_rs),
		    s->s_blocksize);
	j_head = (struct reiserfs_journal_header *)(bh->b_data);

	reiserfs_warning (stdout, "#######################\nJournal header:\n"
			  "j_last_flush_trans_id %ld\n"
			  "j_first_unflushed_offset %ld\n"
			  "j_mount_id %ld\n", j_head->j_last_flush_trans_id, j_head->j_first_unflushed_offset,
			  j_head->j_mount_id);
	brelse (bh);
    }
}


void pack_partition (reiserfs_filsys_t fs);

static void do_pack (reiserfs_filsys_t fs)
{
    if (opt_block_to_print != -1)
	pack_one_block (fs, opt_block_to_print);
    else
	pack_partition (fs);
	
}

/* FIXME: statistics does not work */
static void do_dump_tree (reiserfs_filsys_t fs)
{
    if (opt_block_to_print != -1) {
	print_one_block (fs, opt_block_to_print);
	return;
    }

    print_block (stdout, fs, SB_BUFFER_WITH_SB (fs));
    
    if (opt_print_journal)
	print_journal (fs);
    
    if (opt_print_objectid_map == 1)
	print_objectid_map (stdout, fs);
    
    if (opt_print_block_map)
	print_bmap (stdout, fs, opt_print_block_map == 1 ? 1 : 0);
    
    if (opt_print_regular_file_content || opt_print_details ||
	opt_print_leaf_items) {
	print_disk_tree (fs, SB_ROOT_BLOCK (fs));
	
	/* print the statistic */
	printf ("File system uses %d internal + %d leaves + %d unformatted nodes = %d blocks\n",
		g_stat_info.nr_internals, g_stat_info.nr_leaves, g_stat_info.nr_unformatted, 
		g_stat_info.nr_internals + g_stat_info.nr_leaves + g_stat_info.nr_unformatted);
    }
}

FILE * log;

static void look_for_key (struct buffer_head * bh, struct key * key)
{
    int i, j;
    struct item_head * ih;
    struct reiserfs_de_head *deh;

    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < B_NR_ITEMS (bh); i ++, ih ++) {
	if (ih->ih_key.k_dir_id == key->k_dir_id || (int) le32_to_cpu(key->k_dir_id) == -1 &&
	    ih->ih_key.k_objectid == key->k_objectid) {
	    fprintf (log, "block %lu has item of file %u %u (item %d)\n",
		     bh->b_blocknr, key_dir_id(key), key_objectid(key), i);
	    return;
	}
	if (!is_direntry_ih (ih))
	    continue;
	deh = B_I_DEH (bh, ih);
	for (j = 0; j < ih_entry_count (ih); j ++, deh ++) {
	    if ((deh->deh_dir_id == key->k_dir_id || (int) le32_to_cpu(key->k_dir_id) == -1) &&
		deh->deh_objectid == key->k_objectid) {
		reiserfs_warning (log, "dir item %d (%H) of block %lu has "
				  "entry (%d-th) %.*s pointing to %K\n",
				  i, ih, bh->b_blocknr, j,
				  name_length (ih, deh, j), name_in_entry (deh, j), key);
	    }
	}	
    }
    return;
}


static void look_for_name (struct buffer_head * bh, char * name)
{
    int i, j;
    struct item_head * ih;
    struct reiserfs_de_head * deh;
    int namelen;
    char * p;

    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < B_NR_ITEMS (bh); i ++, ih ++) {
	if (!is_direntry_ih (ih))
	    continue;
	deh = B_I_DEH (bh, ih);
	for (j = 0; j < ih_entry_count (ih); j ++, deh ++) {
	    p = name_in_entry (deh, j);
	    namelen = name_length (ih, deh, j);
	    if (namelen == strlen (name) && !strncmp (name, p, namelen)) {
		fprintf (log, "block %lu, item %d, entry %d is %s\n", bh->b_blocknr, i, j, name);fflush (log);
	    }
	}
    }
    return;
}




static void do_scan (reiserfs_filsys_t fs)
{
    unsigned long i;
    struct buffer_head * bh;
    int type;
    char * answer = 0;
    size_t n = 0;
    struct key key = {0, 0, };
    unsigned long done, total;
    reiserfs_bitmap_t bitmap;


    bitmap = reiserfs_bitmap_load (".bitmap");
    total = reiserfs_bitmap_ones (bitmap);
/*
    bitmap = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));
    reiserfs_fetch_disk_bitmap (bitmap, fs);
*/

    log = fopen ("scan.log", "w+");

    if (mode == DO_SCAN_FOR_NAME) {
	printf ("What name do you want to look for?");
	getline (&answer, &n, stdin);
	answer [strlen (answer) - 1] = 0;
	printf ("Looking for name \"%s\"..\n", answer);
	key.k_dir_id = le32_to_cpu(1);
    } else {
	printf ("What key do you want to find: dirid?");
	getline (&answer, &n, stdin);
	key.k_dir_id = atoi (answer);
	printf ("objectid?");
	getline (&answer, &n, stdin);
	key.k_objectid = atoi (answer);
	printf ("looking for (%u %u)\n", key.k_dir_id, key.k_objectid);
        key.k_dir_id = cpu_to_le32(key.k_dir_id);
        key.k_objectid = cpu_to_le32(key.k_objectid);
    }

    done = 0;
    for (i = 0; i < SB_BLOCK_COUNT (fs); i ++) {
	if (!reiserfs_bitmap_test_bit (bitmap, i))
	    continue;
	bh = bread (fs->s_dev, i, fs->s_blocksize);
	if (!bh) {
	    printf ("could not read block %lu\n", i);
	    continue;
	}
	type = who_is_this (bh->b_data, bh->b_size);
	switch (type) {
	case THE_JDESC:
	    if (! le32_to_cpu(key.k_dir_id))
		printf ("block %lu is journal descriptor\n", i);
	    break;
	case THE_SUPER:
	    if (! le32_to_cpu(key.k_dir_id))
		printf ("block %lu is reiserfs super block\n", i);
	    break;
	case THE_INTERNAL:
	    if (! le32_to_cpu(key.k_dir_id))
		printf ("block %lu is reiserfs internal node\n", i);
	    break;
	case THE_LEAF:
	    if (mode == DO_SCAN_FOR_NAME) {
		look_for_name (bh, answer);
	    } else if ( le32_to_cpu(key.k_dir_id)) {
		look_for_key (bh, &key);
	    } else {
		printf ("block %lu is reiserfs leaf node\n", i);
	    }
	    break;
	}
	brelse (bh);
	print_how_far (&done, total, 1, 0);
    }
}



#if 0
static void do_test (reiserfs_filsys_t fs, unsigned long block)
{
    struct buffer_head * bh;

    fprintf (stderr, "=========== BLock %lu ============\n", block);
    bh = bread (fs->s_dev, block, fs->s_blocksize);
    if (!bh)
	die ("do_test: bread failed");
    if (is_leaf_bad (bh))
	fprintf (stderr, "\n######### BAD before repairing ############\n");
    else
	fprintf (stderr, "\n========= OK before repairing ==================\n");
    print_block (fs, bh, 3, -1, -1);

    fprintf (stderr, "\n>>> repairing >>>>........\n\n");

    /* function to test */pass0_correct_leaf (fs, bh);
    if (is_leaf_bad (bh))
	fprintf (stderr, "\n######### still BAD after repairing ############\n");
    else
	fprintf (stderr, "\n========= OK  after repairing ==================\n");
    print_block (fs, bh, 3, -1, -1);
    brelse (bh);
}
#endif

static void do_test (reiserfs_filsys_t fs)
{
    struct key root_dir_key = {REISERFS_ROOT_PARENT_OBJECTID,
			       REISERFS_ROOT_OBJECTID, {{0, 0},}};
    int gen_counter;

    if (reiserfs_find_entry (fs, &root_dir_key, "lost+found", &gen_counter))
	reiserfs_add_entry (fs, &root_dir_key, "lost+found", &root_dir_key, 0);
}


/* FIXME: need to open reiserfs filesystem first */
int main (int argc, char * argv[])
{
    char * file_name;
    int error;

    print_banner ("debugreiserfs");
 
    file_name = parse_options (argc, argv);

    fs = reiserfs_open (file_name, O_RDONLY, &error, 0);
    if (!fs) {
	fprintf (stderr, "\n\ndumpreiserfs: can not open reiserfs on \"%s\": %s\n\n",
		 file_name, error ? strerror (error) : "there is no one");
	return 0;
    }

    switch (mode) {
    case DO_PACK:
    case DO_PACK_ALL:
	do_pack (fs);
	break;

    case DO_CORRUPT:
	reiserfs_reopen (fs, O_RDWR);
	do_corrupt_one_block (fs, opt_block_to_corrupt);
	break;

    case DO_DUMP:
	do_dump_tree (fs);
	break;

    case DO_SCAN:
    case DO_SCAN_FOR_NAME:
	do_scan (fs);
	break;

    case DO_RECOVER:
	do_recover (fs);
	break;

    case DO_TEST:
    {
	do_test (fs);

#if 0
	int i;
	int arr[] = {53033};

	if (opt_block_to_print != -1) {
	    do_test (fs, opt_block_to_print);
	    break;
	}	    

bad blocks found on Joop partition

53033, 
179201, 
844702,
844913,
877768,
879067,
907631,
925323,
2241275,
2241343,
2241397,
2241511,
2241553,
2241635,
2241644,
2241654,
2241711,
2241721,
2241727,
2241740,
2241762,
2241766,
2241770,
2241812,
2241820,
2241827,
2241831,
2241878,
2241886,
2241971
	};
	/* blocks containing broken directory items on Joop's filesystem */
	int arr[] = {/*53033,*/ 838396/*, 1597036*//*, 1919589, 2715962*/};
 
	
	
	for (i = 0; i < sizeof (arr) / sizeof (arr[0]); i ++)
	    do_test (fs, arr[i]);
	break;
#endif

    }
    }

    reiserfs_close (fs);
    return 0;
}
