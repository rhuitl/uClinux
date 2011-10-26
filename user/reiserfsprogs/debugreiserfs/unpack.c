/*
 * Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */
  
#include "debugreiserfs.h"
#include <sys/resource.h>


#define print_usage_and_exit() die ("Usage: %s [-v] [-b filename] device\n\
-v		prints blocks number of every block unpacked\n\
-b filename	makes unpack to save bitmap of blocks unpacked\n", argv[0]);



/* when super block gets unpacked for the first time - create a bitmap
   and mark in it what have been unpacked. Save that bitmap at the end */
reiserfs_bitmap_t what_unpacked = 0;


int unpacked, data_blocks_unpacked;

int verbose = 0;



static void unpack_offset (struct packed_item * pi, struct item_head * ih)
{
    if (pi->mask & OFFSET_BITS_64) {
	__u64 v64;

	if (ih_key_format (ih) != KEY_FORMAT_2)
	    die ("unpack_offset: key format is not set or wrong");
	fread64 (&v64);
	set_offset (KEY_FORMAT_2, &ih->ih_key, v64);
	return;
    }

    if (pi->mask & OFFSET_BITS_32) {
	__u32 v32;

	fread32 (&v32);
	set_offset (ih_key_format (ih), &ih->ih_key, v32);
	return;
    }

    // offset is 0
    return;
}


static void unpack_type (struct packed_item * pi, struct item_head * ih)
{
    if (pi->mask & DIRECT_ITEM)
	set_type (ih_key_format (ih), &ih->ih_key, TYPE_DIRECT);
    else if (pi->mask & STAT_DATA_ITEM)
	set_type (ih_key_format (ih), &ih->ih_key, TYPE_STAT_DATA);
    else if (pi->mask & INDIRECT_ITEM)
	set_type (ih_key_format (ih), &ih->ih_key, TYPE_INDIRECT);
    else if (pi->mask & DIRENTRY_ITEM)
	set_type (ih_key_format (ih), &ih->ih_key, TYPE_DIRENTRY);
    else
	reiserfs_panic (0, "%h, mask 0%o\n", ih, pi->mask);
}


/* direntry item comes in the following format: 
   entry count - 16 bits
   for each entry
      mask - 8 bits
      entry length - 16 bits
      entry itself
      deh_objectid - 32 bits
      	maybe deh_dir_id (32 bits)
	maybe gencounter (16)
	maybe deh_state (16)
*/
static void unpack_direntry (struct packed_item * pi, struct buffer_head * bh,
			     struct item_head * ih, hashf_t hash_func)
{
    __u16 entry_count, namelen, gen_counter, entry_len;
    __u8 mask;
    int i;
    struct reiserfs_de_head * deh;
    int location;
    char * item;

    if (!hash_func)
	die ("unpack_direntry: hash function is not set");

    fread16 (&entry_count);
    set_entry_count (ih, entry_count);

    item = bh->b_data + ih_location (ih);
    deh = (struct reiserfs_de_head *)item;
    location = pi->item_len;
    for (i = 0; i < entry_count; i ++, deh ++) {
	fread8 (&mask);
	fread16 (&entry_len);
	location -= entry_len;
        set_deh_location(deh, location);
	fread (item + location, entry_len, 1, stdin);

	/* find name length */
	if (*(item + location + entry_len - 1))
	    namelen = entry_len;
	else
	    namelen = strlen (item + location);

	fread32 (&deh->deh_objectid);
	if (mask & HAS_DIR_ID)
	    fread32 (&deh->deh_dir_id);
	else
	    deh->deh_dir_id = ih->ih_key.k_objectid; /* Both little endian, safe */
	if (*(item + location) == '.' && namelen == 1)
	    /* old or new "." */
            set_deh_offset( deh, DOT_OFFSET );
	else if (*(item + location) == '.' && *(item + location + 1) == '.' && namelen == 2)
	    /* old or new ".." */
            set_deh_offset( deh, DOT_DOT_OFFSET );
	else
            set_deh_offset( deh, GET_HASH_VALUE (hash_func (item + location,
							 namelen)));
	if (mask & HAS_GEN_COUNTER) {
	    fread16 (&gen_counter);
            set_deh_offset( deh, deh_offset(deh) | gen_counter );
	}

	if (mask & HAS_STATE)
	    fread16 (&deh->deh_state);
	else
	    deh->deh_state = (1 << DEH_Visible);
    }

    return;
}


/* struct packed_item is already unpacked */
static void unpack_stat_data (struct packed_item * pi, struct buffer_head * bh,
			      struct item_head * ih)
{
    set_entry_count (ih, 0xffff);

    if (ih_key_format (ih) == KEY_FORMAT_1) {
	/* stat data comes in the following format:
	   if this is old stat data:
	   mode - 16 bits
	   nlink - 16 bits
	   size - 32 bits
	   blocks/rdev - 32 bits
	   maybe first_direct byte 32 bits
	*/
	struct stat_data_v1 * sd;

	sd = (struct stat_data_v1 *)B_I_PITEM (bh, ih);
	memset (sd, 0, sizeof (sd));

	fread16 (&sd->sd_mode);
	fread16 (&sd->sd_nlink);
	fread32 (&sd->sd_size);
	fread32 (&sd->u.sd_blocks);
	
	if (pi->mask & WITH_SD_FIRST_DIRECT_BYTE) {
	    fread32 (&sd->sd_first_direct_byte);
	} else {
	    sd->sd_first_direct_byte = 0xffffffff;
	}
    } else {
	/* for new stat data
	   mode - 16 bits
	   nlink in either 16 or 32 bits
	   size in either 32 or 64 bits
	   blocks - 32 bits
	*/
	struct stat_data * sd;

	sd = (struct stat_data *)B_I_PITEM (bh, ih);
	memset (sd, 0, sizeof (sd));
	
	fread16 (&sd->sd_mode);

	if (pi->mask & NLINK_BITS_32) {
	    fread32 (&sd->sd_nlink);
	} else {
	    __u16 nlink16;

	    fread16 (&nlink16);
	    sd->sd_nlink = nlink16;
	}

	if (pi->mask & SIZE_BITS_64) {
	    fread64 (&sd->sd_size);
	} else {
	    __u32 size32;

	    fread32 (&size32);
	    sd->sd_size = size32;
	}

	fread32 (&sd->sd_blocks);
    }

    return;
}


/* indirect item comes either in packed form or as is. ih_free_space
   can go first */
static void unpack_indirect (struct packed_item * pi, struct buffer_head * bh,
			     struct item_head * ih)
{
    __u32 * ind_item, * end;
    int i;
    __u16 v16;

    v16 = 0;
    if (pi->mask & ENTRY_COUNT)
	fread16 (&v16);

    set_entry_count (ih, v16);

    ind_item = (__u32 *)B_I_PITEM (bh, ih);
    if (pi->mask & WHOLE_INDIRECT) {
	fread (ind_item, pi->item_len, 1, stdin);
	return;
    }

    end = ind_item + I_UNFM_NUM (ih);
    while (ind_item < end) {
	fread32 (ind_item);
	fread16 (&v16);
	for (i = 1; i < v16; i ++) {
	    if (ind_item[0])
		ind_item [i] = ind_item[0] + i;
	    else
		ind_item [i] = 0;
	}
	ind_item += i;
    }
    return;
}


// FIXME: we have no way to preserve symlinks
static void unpack_direct (struct packed_item * pi, struct buffer_head * bh,
			   struct item_head * ih)
{
    set_entry_count (ih, 0xffff);
    memset (bh->b_data + ih_location (ih), 'a', pi->item_len);
    return;
}


static void unpack_leaf (int dev, hashf_t hash_func)
{
    static int unpacked_leaves = 0;
    struct buffer_head * bh;
    struct packed_item pi;
    struct item_head * ih;
    int i;
    __u16 v16;
    __u32 v32;
    
    /* block number */
    fread32 (&v32);


    /* item number */
    fread16 (&v16);

    if (verbose)
	fprintf (stderr, "leaf %d\n", v32);

    
 
    bh = getblk (dev, v32, 4096);
    if (!bh)
	die ("unpack_leaf: getblk failed");

    set_node_item_number (bh, v16);
    set_node_level (bh, DISK_LEAF_NODE_LEVEL);
    set_node_free_space (bh, bh->b_size - BLKH_SIZE);
    

    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < v16; i ++, ih ++) {
#if 0
	fread32 (&v32);
	if (v32 != ITEM_START_MAGIC)
	    die ("unpack_leaf: no start item magic found: block %lu, item %i",
		 bh->b_blocknr, i);
#endif	

	fread (&pi, sizeof (struct packed_item), 1, stdin);
	
	/* dir_id - if it is there */
	if (pi.mask & DIR_ID) {
	    fread32 (&v32);
	    ih->ih_key.k_dir_id = v32;
	} else {
	    if (!i)
		die ("unpack_leaf: dir_id is not set");
	    ih->ih_key.k_dir_id = (ih - 1)->ih_key.k_dir_id;
	}

	/* object_id - if it is there */
	if (pi.mask & OBJECT_ID) {
	    fread32 (&v32);
	    ih->ih_key.k_objectid = v32;
	} else {
	    if (!i)
		die ("unpack_leaf: object_id is not set");
	    ih->ih_key.k_objectid = (ih - 1)->ih_key.k_objectid;
	}

	// we need to set item format before offset unpacking
	set_ih_key_format (ih, (pi.mask & NEW_FORMAT) ? KEY_FORMAT_2 : KEY_FORMAT_1);

	// offset
	unpack_offset (&pi, ih);

	/* type */
	unpack_type (&pi, ih);

	/* item length and item location */
	set_ih_item_len (ih, pi.item_len);
	set_ih_location (ih, (i ? ih_location (ih - 1) : bh->b_size) - pi.item_len);

	// item itself
	if (is_direct_ih (ih)) {
	    unpack_direct (&pi, bh, ih);
	} else if (is_indirect_ih (ih)) {
	    unpack_indirect (&pi, bh, ih);
	} else if (is_direntry_ih (ih)) {
	    unpack_direntry (&pi, bh, ih, hash_func);
	} else if (is_stat_data_ih (ih)) {
	    unpack_stat_data (&pi, bh, ih);
	}
	set_node_free_space (bh, node_free_space (bh) - (IH_SIZE + ih_item_len (ih)));
#if 0
	fread32 (&v32);
	if (v32 != ITEM_END_MAGIC)
	    die ("unpack_leaf: no end item magic found: block %lu, item %i",
		 bh->b_blocknr, i);
#endif
    }

    fread16 (&v16);
    if (v16 != LEAF_END_MAGIC)
	die ("unpack_leaf: wrong end signature found - %x, block %lu", 
	     v16, bh->b_blocknr);

    mark_buffer_uptodate (bh, 1);
    mark_buffer_dirty (bh);
    bwrite (bh);
    /*
    if (!not_data_block (bh->b_blocknr))
	data_blocks_unpacked ++;
    */
    brelse (bh);

    if (what_unpacked)
	reiserfs_bitmap_set_bit (what_unpacked, bh->b_blocknr);
    unpacked ++;

    if (!(++ unpacked_leaves % 10))
	fprintf (stderr, "#");
}


static void unpack_full_block (int dev, int blocksize)
{
    static int full_blocks_unpacked = 0;
    __u32 block;
    struct buffer_head * bh;

    fread32 (&block);

    if (verbose)
	fprintf (stderr, "full #%d\n", block);

    bh = getblk (dev, block, blocksize);
    if (!bh)
	die ("unpack_full_block: getblk failed");

    fread (bh->b_data, bh->b_size, 1, stdin);

    if (who_is_this (bh->b_data, bh->b_size) == THE_SUPER && !what_unpacked) {
	unsigned long blocks;
	
	blocks = rs_block_count ((struct reiserfs_super_block *)(bh->b_data));
	fprintf (stderr, "There were %lu blocks on the device\n", blocks);
	what_unpacked = reiserfs_create_bitmap (blocks);
    }

    mark_buffer_uptodate (bh, 1);
    mark_buffer_dirty (bh);
    bwrite (bh);
/*
    if (!not_data_block (bh->b_blocknr))
	data_blocks_unpacked ++;
*/
    brelse (bh);

    if (what_unpacked)
	reiserfs_bitmap_set_bit (what_unpacked, block);
    unpacked ++;

    if (!(++ full_blocks_unpacked % 50))
	fprintf (stderr, ".");
}


/* just skip bitmaps of unformatted nodes */
static void unpack_unformatted_bitmap (int dev, int blocksize)
{
    __u16 bmap_num;
    __u32 block_count;
    int i;
    char * buf;
 
    fread16 (&bmap_num);
    fread32 (&block_count);
    
    buf = malloc (blocksize);
    if (!buf)
	reiserfs_panic ("unpack_unformatted_bitmap: malloc failed: %m");

    for (i = 0; i < bmap_num; i ++) {
	if (fread (buf, blocksize, 1, stdin) != 1)
	    reiserfs_panic ("unpack_unformatted_bitmap: "
			    "could not read bitmap #%d: %m", i);
    }
    free (buf);
}


// read packed reiserfs partition metadata from stdin
void unpack_partition (int dev)
{
    __u32 magic32;
    __u16 magic16;
    __u16 blocksize;
    
    fread32 (&magic32);
    if (magic32 != REISERFS_SUPER_MAGIC)
	die ("unpack_partition: reiserfs magic number not found");
    
    fread16 (&blocksize);
    
    if (verbose)
	fprintf (stderr, "Blocksize %d\n", blocksize);
    
    while (!feof (stdin)) {
	char c[2];

	fread (c, 1, 1, stdin);
	switch (c[0]) {
	case '.':
	    if (verbose)
		fprintf (stderr, "\".\" skipped\n");
	    continue;

	case '1':
	    fread (c, 1, 1, stdin); /* that was 100%, read in first 0 */
	case '2':
	case '4':
	case '6':
	case '8':
	    fread (c, 1, 1, stdin);
	case '0':
	    fread (c + 1, 1, 1, stdin); /* read % */
		
	    if (c[0] != '0' || c[1] != '%')
		die ("0%% expected\n");

	    if (verbose)
		fprintf (stderr, "0%% skipped\n");
	    continue;
	}

	fread (c + 1, 1, 1, stdin);
	magic16 = *(__u16 *)c;
	/*fread16 (&magic16);*/
	
	switch (magic16 & 0xff) {
	case LEAF_START_MAGIC:
	    unpack_leaf (dev, code2func (magic16 >> 8));
	    break;
	    
	case FULL_BLOCK_START_MAGIC:
	    unpack_full_block (dev, blocksize);
	    break;

	case UNFORMATTED_BITMAP_START_MAGIC:
	    fprintf (stderr, "\nBitmap of unformatted - ignored\n");
	    unpack_unformatted_bitmap (dev, blocksize);
	    break;
	    
	case END_MAGIC:
	    break;

	default:
	    die ("unpack_partition: bad magic found - %x", magic16 & 0xff);
	}
    }

    fprintf (stderr, "Unpacked %d (%d) blocks\n", unpacked, what_unpacked ? reiserfs_bitmap_ones (what_unpacked) : 0);


    /*    fclose (block_list);*/
}


int main (int argc, char ** argv)
{
    int fd;
    int c;
    char * filename = ".bitmap";
    struct rlimit lim = {0xffffffff, 0xffffffff};

    print_banner ("unpack");

    /* with this 2.4.0-test9's file_write does not send SIGXFSZ */
    if (setrlimit (RLIMIT_FSIZE, &lim)) {
	fprintf  (stderr, "sertlimit failed: %m\n");
    }

    while ((c = getopt (argc, argv, "vb:")) != EOF) {
	switch (c) {
	case 'v':
	    verbose = 1;
	case 'b':
	    asprintf (&filename, "%s", optarg);
	    break;
	}
    }
    if (optind != argc - 1)
	/* only one non-option argument is permitted */
	print_usage_and_exit();

    if (is_mounted (argv[optind]))
	reiserfs_panic ("%s seems mounted, umount it first\n", argv[optind]);
  
    fd = open (argv[optind], O_RDWR | O_LARGEFILE);
    if (fd == -1) {
	perror ("open failed");
	return 0;
    }

    unpack_partition (fd);

    if (what_unpacked && filename)
	reiserfs_bitmap_save (filename, what_unpacked);

    close (fd);
    return 0;
}
