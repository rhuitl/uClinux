/*
 * Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */

#include "debugreiserfs.h"





reiserfs_bitmap_t what_to_pack;
reiserfs_bitmap_t what_packed;

int packed_leaves, bad_leaves, full_blocks, internals, descs, full_of_journal;


/* these are to calculate compression */
unsigned long sent; /* how many bytes sent to stdout */
unsigned long had_to_be_sent; /* how many bytes were to be sent */



static void pack_key (struct packed_item * pi, struct item_head * ih)
{
    if (pi->mask & DIR_ID) {
	fwrite32 (&ih->ih_key.k_dir_id);
	sent += sizeof (__u32);
    }

    if (pi->mask & OBJECT_ID) {
	fwrite32 (&ih->ih_key.k_objectid);
	sent += sizeof (__u32);
    }

    if (pi->mask & OFFSET_BITS_64) {
	__u64 offset;

	offset = get_offset (&ih->ih_key);
	fwrite64 (&offset);
	sent += sizeof (__u64);
    }

    if (pi->mask & OFFSET_BITS_32) {
	__u32 offset;

	offset = get_offset (&ih->ih_key);
	fwrite32 (&offset);
	sent += sizeof (__u32);
    }
}


static void pack_direct (struct packed_item * pi, struct buffer_head * bh, 
			  struct item_head * ih)
{
    pi->mask |= DIRECT_ITEM;

    /* send packed item header to stdout */
    fwrite (pi, sizeof (*pi), 1, stdout);
    sent += sizeof (*pi);
    
    /* send key components which are to be sent */
    pack_key (pi, ih);
}


/* if there is at least one extent longer than 2 - it is worth packing */
static int should_pack_indirect (__u32 * ind_item, int unfm_num)
{
    int i, len;

    for (i = 1, len = 1; i < unfm_num; i ++) {
	if ((!ind_item [i] && !ind_item [i - 1]) || /* hole continues */
	    ind_item [i] == ind_item [i - 1] + 1) { /* subsequent blocks */
	    len ++;
	    if (len > 2)
		return 1;
	} else {
	    /* sequence of blocks or hole broke */
	    len = 1;
	}
    }
    return 0;
}


/* indirect item can be either packed using "extents" (when it is
   worth doing) or be stored as is. Size of item in packed form is not
   stored. Unpacking will stop when full item length is reached */
static void pack_indirect (struct packed_item * pi, struct buffer_head * bh, 
			   struct item_head * ih)
{
    int i;
    __u32 * ind_item;
    __u16 len;

    pi->mask |= INDIRECT_ITEM;
    if (ih_entry_count (ih))
	pi->mask |= ENTRY_COUNT;
    
    ind_item = (__u32 *)B_I_PITEM (bh, ih);
    if (!should_pack_indirect (ind_item, I_UNFM_NUM (ih)))
	pi->mask |= WHOLE_INDIRECT;
    
    /* send packed item header to stdout */
    fwrite (pi, sizeof (*pi), 1, stdout);
    sent += sizeof (*pi);

    /* send key components which are to be sent */
    pack_key (pi, ih);

    if (pi->mask & ENTRY_COUNT) {
	__u16 ih_free_space;

	ih_free_space = ih_entry_count (ih);
	fwrite16 (&ih_free_space);
	sent += sizeof (__u16);
    }

    if (pi->mask & WHOLE_INDIRECT) {
	fwrite (ind_item, ih_item_len (ih), 1, stdout);
	sent += ih_item_len (ih);
	return;
    }

    fwrite32 (&ind_item [0]);
    sent += sizeof (__u32);
    for (i = 1, len = 1; i < I_UNFM_NUM (ih); i ++) {
	if ((!ind_item [i] && !ind_item [i - 1]) || /* hole continues */
	    ind_item [i] == ind_item[ i - 1] + 1) { /* subsequent blocks */
	    len ++;
	} else {
	    fwrite16 (&len);
	    fwrite32 (&ind_item[i]);
	    sent += (sizeof (__u32) + sizeof (__u16));
	    len = 1;
	}
    }
    fwrite16 (&len);
    sent += sizeof (__u16);

    return;
}


/* directory item is packed:
   entry count - 16 bits
   for each entry
   	mask (8 bits) - it shows whether there are any of (deh_dir_id, gen counter, deh_state)
	entry length 16 bits
	entry itself
	deh_objectid - 32 bits
		maybe deh_dir_id (32 bits)
		maybe gencounter (16)
		maybe deh_state (16)
*/
static void pack_direntry (reiserfs_filsys_t fs, struct packed_item * pi,
			   struct buffer_head * bh,
			   struct item_head * ih)
{
    int i;
    struct reiserfs_de_head * deh;
    struct packed_dir_entry pe;
    __u16 entry_count, gen_counter;


    pi->mask |= (DIRENTRY_ITEM | ENTRY_COUNT);

    /* send packed item header to stdout */
    fwrite (pi, sizeof (*pi), 1, stdout);
    sent += sizeof (*pi);

    /* send key components which are to be sent */
    pack_key (pi, ih);

    /* entry count is sent unconditionally */
    entry_count = ih_entry_count (ih);
    fwrite16 (&entry_count);

    deh = B_I_DEH (bh, ih);
    for (i = 0; i < entry_count; i ++, deh ++) {
	pe.entrylen = entry_length (ih, deh, i);
	pe.mask = 0;
	if (deh_dir_id (deh) != le32_to_cpu (ih->ih_key.k_objectid))
	    /* entry points to name of another directory, store deh_dir_id */
	    pe.mask |= HAS_DIR_ID;

	gen_counter = GET_GENERATION_NUMBER (deh_offset (deh));
	if (gen_counter != 0)
	    /* store generation counter if it is != 0 */
	    pe.mask |= HAS_GEN_COUNTER;

	if ( deh_state(deh) != 4)
	    /* something unusual in deh_state. Store it */
	    pe.mask |= HAS_STATE;

	fwrite8 (&pe.mask);
	fwrite16 (&pe.entrylen);
	fwrite (name_in_entry (deh, i), pe.entrylen, 1, stdout);
	fwrite32 (&(deh->deh_objectid));
	sent += (sizeof (__u8) + sizeof (__u16) + pe.entrylen + sizeof (__u32));
	
	if (pe.mask & HAS_DIR_ID) {
	    fwrite32 (&deh->deh_dir_id);
	    sent += sizeof (__u32);
	}

	if (pe.mask & HAS_GEN_COUNTER) {
	    fwrite16 (&gen_counter);
	    sent += sizeof (__u16);
	}

	if (pe.mask & HAS_STATE) {
	    fwrite16 (&deh->deh_state);
	    sent += sizeof (__u16);
	}
    }
}


static void pack_stat_data (struct packed_item * pi, struct buffer_head * bh,
			    struct item_head * ih)
{
    pi->mask |= STAT_DATA_ITEM;

    if (stat_data_v1 (ih)) {
	/* for old stat data: we take
	   mode - 16 bits
	   nlink - 16 bits
	   size - 32 bits
	   blocks/rdev - 32 bits
	   maybe first_direct byte 32 bits
	*/
	struct stat_data_v1 * sd_v1;

	sd_v1 = (struct stat_data_v1 *)B_I_PITEM (bh, ih);
	if (sd_v1->sd_first_direct_byte != 0xffffffff)
	    pi->mask |= WITH_SD_FIRST_DIRECT_BYTE;

	/* we are done with packed_item send packed it to stdout */
	fwrite (pi, sizeof (*pi), 1, stdout);
	sent += sizeof (*pi);
	
	/* send key components which are to be sent */
	pack_key (pi, ih);
	
	fwrite16 (&sd_v1->sd_mode);
	fwrite16 (&sd_v1->sd_nlink);
	fwrite32 (&sd_v1->sd_size);
	fwrite32 (&sd_v1->u.sd_blocks);
	sent += (sizeof (__u16) * 2 + sizeof (__u32) * 2);
	if (pi->mask & WITH_SD_FIRST_DIRECT_BYTE) {
	    fwrite32 (&sd_v1->sd_first_direct_byte);
	    sent += sizeof (__u32);
	}
    } else {
	/* for new stat data
	   mode - 16 bits
	   nlink in either 16 or 32 bits
	   size in either 32 or 64 bits
	   blocks - 32 bits
	*/
	struct stat_data * sd;
	__u16 nlink16;
	__u32 nlink32, size32;
	__u64 size64;

	sd = (struct stat_data *)B_I_PITEM (bh, ih);
	if (sd->sd_nlink > 0xffff) {
	    pi->mask |= NLINK_BITS_32;
	    nlink32 = sd->sd_nlink;
	} else {
	    nlink16 = sd->sd_nlink;
	}
	if (sd->sd_size > 0xffffffff) {
	    pi->mask |= SIZE_BITS_64;
	    size64 = sd->sd_size;
	} else {
	    size32 = sd->sd_size;
	}

	/* we are done with packed_item send packed it to stdout */
	fwrite (pi, sizeof (*pi), 1, stdout);
	sent += sizeof (*pi);

	/* send key components which are to be sent */
	pack_key (pi, ih);

	fwrite16 (&sd->sd_mode);
	sent += sizeof (__u16);
	if (pi->mask & NLINK_BITS_32) {
	    fwrite32 (&nlink32);
	    sent += sizeof (__u32);
	} else {
	    fwrite16 (&nlink16);	
	    sent += sizeof (__u16);
	}

	if (pi->mask & SIZE_BITS_64) {
	    fwrite64 (&size64);
	    sent += sizeof (__u64);
	} else {
	    fwrite32 (&size32);
	    sent += sizeof (__u32);
	}
    
	fwrite32 (&sd->sd_blocks);
	sent += sizeof (__u32);
    }
}


static void pack_full_block (reiserfs_filsys_t fs, struct buffer_head * bh)
{
    __u16 magic;
    __u32 block;

    magic = FULL_BLOCK_START_MAGIC;
    fwrite16 (&magic);

    block = bh->b_blocknr;
    fwrite32 (&block);
    
    fwrite (bh->b_data, 4096, 1, stdout);
    sent += 4096;
    had_to_be_sent += 4096;

    full_blocks ++;
    
    if (who_is_this (bh->b_data, bh->b_size) == THE_JDESC)
	descs ++;
    if (who_is_this (bh->b_data, bh->b_size) == THE_INTERNAL)
	internals ++;
    if (block_of_journal (fs, bh->b_blocknr))
	full_of_journal ++;
}


/* unformatted node pointer is considered bad when it points either to blocks
   of journal, bitmap blocks, super block or is transparently out of range of
   disk block numbers */
static int check_unfm_ptr (reiserfs_filsys_t fs, __u32 block)
{
    if (block >= SB_BLOCK_COUNT (fs))
        return 1;

    if (not_data_block (fs, block))
        return 1;

    return 0;
}


/* we only pack leaves which do not have any corruptions */
static int can_pack_leaf (reiserfs_filsys_t fs, struct buffer_head * bh)
{
    int i;
    struct item_head * ih;

    ih = B_N_PITEM_HEAD (bh, 0);
    for (i = 0; i < node_item_number (bh); i ++, ih ++) {
	if (is_it_bad_item (fs, ih, B_I_PITEM (bh, ih), check_unfm_ptr, 1/*bad dir*/))
	    return 0;
    }
    return 1;
}


/* pack leaf only if all its items are correct: keys are correct,
   direntries are hashed properly and hash function is defined,
   indirect items are correct, stat data ?, */
static void pack_leaf (reiserfs_filsys_t fs, struct buffer_head * bh)
{
    int i;
    struct item_head * ih;
    struct packed_item pi;
    __u16 v16;

    if (!can_pack_leaf (fs, bh)) {
	/* if something looks suspicious in this leaf - pack whole block */
	pack_full_block (fs, bh);
	fprintf (stderr, "leaf %lu is bad\n", bh->b_blocknr);
	bad_leaves ++;
	return;
    }

    /* start magic in low 8 bits, hash code in high 8 bits */
    v16 = (LEAF_START_MAGIC | (func2code (fs->s_hash_function) << 8));
    fwrite16 (&v16);
    
    /* block number */
    fwrite32 (&bh->b_blocknr);

    /* item number */
    v16 = node_item_number (bh);
    fwrite16 (&v16);

    ih = B_N_PITEM_HEAD (bh, 0);

    for (i = 0; i < node_item_number (bh); i ++, ih ++) {
#if 0
	v32 = ITEM_START_MAGIC;
	fwrite32 (&v32);
#endif

	pi.mask = 0;
	pi.item_len = ih_item_len (ih);

	// format
	if (ih_key_format (ih) == KEY_FORMAT_2)
	    pi.mask |= NEW_FORMAT;

	// k_dir_id
	if (!i || (i && ih->ih_key.k_dir_id != (ih - 1)->ih_key.k_dir_id)) {
	    /* if item is first in the leaf or if previous item has different
               k_dir_id - store it */
	    pi.mask |= DIR_ID;
	}
	// k_object_id
	if (!i || (i && ih->ih_key.k_objectid != (ih - 1)->ih_key.k_objectid)) {
	    /* if item is first in the leaf or if previous item has different
               k_objectid - store it */
	    pi.mask |= OBJECT_ID;
	}

	/* store offset if it is != 0 in 32 or 64 bits */
	if (get_offset (&ih->ih_key)) {
	    if (get_offset (&ih->ih_key) > 0xffffffffULL)
		pi.mask |= OFFSET_BITS_64;
	    else
		pi.mask |= OFFSET_BITS_32;
	}

	if (is_direct_ih (ih)) {
	    pack_direct (&pi, bh, ih);
	} else if (is_indirect_ih (ih))
	    pack_indirect (&pi, bh, ih);
	else if (is_direntry_ih (ih))
	    pack_direntry (fs, &pi, bh, ih);
	else if (is_stat_data_ih (ih))
	    pack_stat_data (&pi, bh, ih);
	else
	    die ("pack_leaf: unknown item found");
#if 0
	v32 = ITEM_END_MAGIC;
	fwrite32 (&v32);
#endif
    }

    v16 = LEAF_END_MAGIC;
    fwrite16 (&v16);

    packed_leaves ++;
    had_to_be_sent += 4096;

    return;
}


static int can_pack_internal (reiserfs_filsys_t fs, struct buffer_head * bh)
{
    return 0;
}


/* pack internal node as a full block */
static void pack_internal (reiserfs_filsys_t fs, struct buffer_head * bh)
{
    if (!can_pack_internal (fs, bh)) {
	pack_full_block (fs, bh);
	return;
    }

    reiserfs_panic ("pack_internal: packing code is not ready");
}


static int how_many_to_pack (reiserfs_filsys_t fs, unsigned long first, int count)
{
    int i;
    int used;

    used = 0;
    for (i = 0; i < count; i ++) {
	if ((SB_BLOCK_COUNT (fs) > (first + i)) &&
	    reiserfs_bitmap_test_bit (what_to_pack, first + i))
	    used ++;
    }
    return used;
}


/* packed blocks are marked free in the bitmap*/
static void send_block (reiserfs_filsys_t fs, struct buffer_head * bh)
{
    int type;


    if ((type = who_is_this (bh->b_data, bh->b_size)) != THE_LEAF) {
	if (type == THE_INTERNAL) {
	    pack_internal (fs, bh);
	} else if (!not_data_block (fs, bh->b_blocknr)) {
	    /* unformatted */
	    return;
	} else
	    /* bitmaps, super block, blocks of journal - not leaves */
	    pack_full_block (fs, bh);
    } else
	pack_leaf (fs, bh);

    reiserfs_bitmap_set_bit (what_packed, bh->b_blocknr);
    reiserfs_bitmap_clear_bit (what_to_pack, bh->b_blocknr);
}


/* super block, journal, bitmaps */
static void pack_frozen_data (reiserfs_filsys_t fs)
{
    int i;
    struct buffer_head * bh;

    /* super block */
    reiserfs_warning (stderr, "super block..");fflush (stderr);
    send_block (fs, fs->s_sbh);
    reiserfs_warning (stderr, "ok\nbitmaps..(%d).. ", SB_BMAP_NR (fs));
    fflush (stderr);

    /* bitmaps */ 
    for (i = 0; i < SB_BMAP_NR (fs); i ++) {
	send_block (fs, SB_AP_BITMAP (fs)[i]);
    }

    reiserfs_warning (stderr, "ok\njournal (from %lu to %lu)..",
		      rs_journal_start (fs->s_rs),
		      rs_journal_start (fs->s_rs) + rs_journal_size (fs->s_rs));
    fflush (stderr);
    /* journal */
    for (i = rs_journal_start (fs->s_rs); 
	 i <= rs_journal_start (fs->s_rs) + rs_journal_size (fs->s_rs);
	 i ++) {
	bh = bread (fs->s_dev, i, fs->s_blocksize);
	send_block (fs, bh);
	brelse (bh);
    }
    reiserfs_warning (stderr, "ok\n");fflush (stderr);
}


/* pack all "not data blocks" and correct leaf */
void pack_partition (reiserfs_filsys_t fs)
{
    int i, j;
    struct buffer_head tmp, * bh;
    int nr_to_read = BLOCKS_PER_READ;
    __u32 magic32;
    __u16 blocksize;
    __u16 magic16;
    unsigned long done = 0, total;
    

    magic32 = REISERFS_SUPER_MAGIC;
    fwrite32 (&magic32);
    
    blocksize = fs->s_blocksize;
    fwrite16 (&blocksize);

    tmp.b_size = blocksize;
    
    /* will save information about what packed here */
    what_packed = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));

    /* will get information about what is to be packed */
    what_to_pack = reiserfs_create_bitmap (SB_BLOCK_COUNT (fs));
    if (!what_to_pack)
	die ("pack_partition: could not create bitmap");
    if (mode == DO_PACK) {
	/* read blocks marked used and pack them */
	reiserfs_fetch_disk_bitmap (what_to_pack, fs);
	reiserfs_warning (stderr, "Packing blocks marked used on the device %d\n",
			  reiserfs_bitmap_ones (what_to_pack));
    } else {
	reiserfs_bitmap_fill (what_to_pack);
	reiserfs_warning (stderr, "Packing all blocks of the device %d\n",
			  reiserfs_bitmap_ones (what_to_pack));	    
    }


    /* super block, journal, bitmaps */
    pack_frozen_data (fs);

    reiserfs_warning (stderr, 
		      "Super block, bitmaps, journal - %d blocks - done, %d blocks left\n",
		      reiserfs_bitmap_ones (what_packed), reiserfs_bitmap_ones (what_to_pack));
    total = reiserfs_bitmap_ones (what_to_pack);

    for (i = 0; i < SB_BLOCK_COUNT (fs); i += nr_to_read) {
	int to_pack;

	to_pack = how_many_to_pack (fs, i, nr_to_read);
	if (to_pack) {
	    print_how_far (&done, total, to_pack, opt_quiet);

	    bh = bread (fs->s_dev, i / nr_to_read, blocksize * nr_to_read);
	    if (bh) {
		for (j = 0; j < nr_to_read; j ++) {
		    if (reiserfs_bitmap_test_bit (what_to_pack, i + j)) {
			tmp.b_data = bh->b_data + j * tmp.b_size;
			tmp.b_blocknr = i + j;
			send_block (fs, &tmp);
		    }
		}
		brelse (bh);
	    } else {
		/* bread failed */
		if (nr_to_read != 1) {
		    /* we tryied to read bunch of blocks. Try to read them by one */
		    nr_to_read = 1;
		    i --;
		    continue;
		} else {
		    /* we were reading one block at time, and failed, so mark
                       block bad */
		    reiserfs_warning (stderr, "could not read block %lu\n", i);
		}
	    }

	}
    }
    
    magic16 = END_MAGIC;
    fwrite16 (&magic16);
    
    fprintf (stderr, "Packed\n\tleaves %d\n"
	     "\tfull blocks %d\n"
	     "\t\tof journal %d\n"
	     "\t\tcorrupted leaves %d\n"
	     "\t\tinternals %d\n"
	     "\t\tdescriptors %d\n",
	     packed_leaves, full_blocks, full_of_journal, bad_leaves, internals, descs);
    fprintf (stderr, "data packed with ratio %.2f\n", (double)sent / had_to_be_sent);

    if (where_to_save)
	reiserfs_bitmap_save (where_to_save, what_packed);
}



    
void pack_one_block (reiserfs_filsys_t fs, unsigned long block)
{
    __u32 magic32;
    __u16 magic16;
    struct buffer_head * bh;

    // reiserfs magic
    magic32 = REISERFS_SUPER_MAGIC;
    fwrite32 (&magic32);

    // blocksize
    fwrite16 (&fs->s_blocksize);
    
    bh = bread (fs->s_dev, block, fs->s_blocksize);

    if (who_is_this (bh->b_data, bh->b_size) == THE_LEAF)
	pack_leaf (fs, bh);
    else
	pack_full_block (fs, bh);

    brelse (bh);

    // end magic
    magic16 = END_MAGIC;
    fwrite16 (&magic16);

    fprintf (stderr, "Packed\n\tleaves %d\n\tfull block %d\n\tcorrupted leaves %d\n",
	     packed_leaves, full_blocks, bad_leaves);
}


#if 0
//
// this test program has two modes: 'pack file blocknr'
// and 'unpack file'
// in the first mode blocknr-th 4k block of the 'file' will be packed out to stdout
// the the second mode standart input will be converted to the reiserfs leaf on 'file'
//
static int do_unpack (char * file)
{
    char * buf;
    int fd;

    fd = open (file, O_RDONLY);
    if (fd == -1) {
	perror ("open failed");
	return 0;
    }
    
    buf = malloc (4096);
    if (!buf) {
	perror ("malloc failed");
	return 0;
    }

    fread (buf, 4096, 1, stdin);
    if (!feof (stdin)) {
	printf ("fread returned not eof\n");
	return 0;
    }

    unpack_leaf (buf, fd);

    free (buf);
    close (fd);
    return 0;
}

static int do_pack (char * file, int block)
{
    int fd;
    struct buffer_head * bh;
    char * buf;
    int len;

    fprintf (stderr, "dumping block %d of the \"%s\"\n", block, file);

    fd = open (file, O_RDONLY);
    if (fd == -1) {
	perror ("open failed");
	return 0;
    }
    
    bh = bread (fd, block, 4096);
    if (!bh) {
	fprintf (stderr, "bread failed\n");
	return 0;
    }

    if (who_is_this (bh->b_data, bh->b_size) != THE_LEAF) {
	fprintf (stderr, "block %d is not a leaf\n", block);
	return 0;
    }

    len = pack_leaf (bh, buf);
    fwrite (buf, len, 1, stdout);

    free (buf);
    close (fd);
    return 0;
}


int main (int argc, char ** argv)
{
    if (argc == 3 && !strcmp (argv[1], "unpack"))
	return do_unpack (argv[2]);

    if (argc == 4 && !strcmp (argv[1], "pack"))
	return do_pack (argv[2], atoi (argv[3]));

    fprintf (stderr, "Usage: \n\t%s pack filename block\nor\n"
	     "\t%s unpack filename\n", argv[0], argv[0]);
    return 0;
}

#endif
