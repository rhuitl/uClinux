/* 
 * Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */
 
/*  
 * Written by Alexander Zarochentcev.
 * 
 * FS resize utility 
 *
 */

#include "resize.h"

int opt_force = 0;
int opt_verbose = 1;			/* now "verbose" option is default */
int opt_nowrite = 0;
int opt_safe = 0;

#if 0
/* Given a file descriptor and an offset, check whether the offset is
   a valid offset for the file - return 0 if it isn't valid or 1 if it
   is */
int valid_offset( int fd, loff_t offset )
{
    char ch;

    if (lseek64 (fd, offset, 0) < 0)
	return 0;

    if (read (fd, &ch, 1) < 1)
	return 0;

    return 1;
}
#endif

/* calculate the new fs size (in blocks) from old fs size and the string
   representation of new size */
static unsigned long calc_new_fs_size(unsigned long count, int bs,
				      char *bytes_str)
{
    long long int bytes;
    unsigned long blocks;
    int c;
	
    bytes = atoll(bytes_str);
    c = bytes_str[strlen(bytes_str) - 1];

    switch (c) {
    case 'G':
    case 'g':
	bytes *= 1024;
    case 'M':
    case 'm':
	bytes *= 1024;
    case 'K':
    case 'k':
	bytes *= 1024;
    }
	
    blocks = bytes / bs;

    if (bytes_str[0] == '+' || bytes_str[0] == '-')
	return (count + blocks);

    return blocks;
}

/* print some fs parameters */
static void sb_report(struct reiserfs_super_block * sb1,
		      struct reiserfs_super_block * sb2)
{
    printf(
	"ReiserFS report:\n"
	"blocksize             %d\n"
	"block count           %d (%d)\n"
	"free blocks           %d (%d)\n"
	"bitmap block count    %d (%d)\n", 
	rs_blocksize(sb1),
	rs_block_count(sb1), rs_block_count(sb2),
	rs_free_blocks(sb1), rs_free_blocks(sb2),
	rs_bmap_nr(sb1), rs_bmap_nr(sb2));
};

/* conditional bwrite */
static int bwrite_cond (struct buffer_head * bh)
{
    if(!opt_nowrite) { 
	mark_buffer_uptodate(bh,1);
	mark_buffer_dirty(bh);
	bwrite(bh);
    }
    return 0;
}


/* the first one of the mainest functions */
int expand_fs (reiserfs_filsys_t fs, unsigned long block_count_new) {
    int block_r, block_r_new;
    unsigned int bmap_nr_new, bmap_nr_old;
    int i;

    reiserfs_bitmap_t bmp;
    struct reiserfs_super_block * rs = fs->s_rs;

    reiserfs_reopen(fs, O_RDWR);
    set_state (fs->s_rs, REISERFS_ERROR_FS);
    bwrite_cond(SB_BUFFER_WITH_SB(fs));
	
    bmp = reiserfs_create_bitmap(rs_block_count(rs));
    if (!bmp)
	die ("cannot create bitmap\n");
    reiserfs_fetch_disk_bitmap(bmp, fs);
    reiserfs_free_bitmap_blocks(fs);
    if (reiserfs_expand_bitmap(bmp, block_count_new))
	die ("cannot expand bitmap\n");

    /* clean bits in old bitmap tail */
    for (i = rs_block_count(rs);
	 i < rs_bmap_nr(rs) * rs_blocksize(rs) * 8 && i < block_count_new;
	 i++) {
	reiserfs_bitmap_clear_bit(bmp, i);
    }
    
    /* count used bits in last bitmap block */
    block_r = rs_block_count(rs) - ((rs_bmap_nr(rs) - 1) * rs_blocksize(rs) * 8);

    /* count bitmap blocks in new fs */
    bmap_nr_new = (block_count_new - 1) / (rs_blocksize(rs) * 8) + 1;
    block_r_new = block_count_new - (bmap_nr_new - 1) * rs_blocksize(rs) * 8;

    bmap_nr_old = rs_bmap_nr(rs);
	
    /* update super block buffer*/
    set_free_blocks (rs, rs_free_blocks(rs) + block_count_new
		     - rs_block_count(rs) - (bmap_nr_new - rs_bmap_nr(rs)));
    set_block_count (rs, block_count_new);
    set_bmap_nr (rs, bmap_nr_new);

    reiserfs_read_bitmap_blocks(fs); 
    for (i = bmap_nr_old; i < bmap_nr_new; i++) /* fix new bitmap blocks */
	reiserfs_bitmap_set_bit(bmp, SB_AP_BITMAP(fs)[i]->b_blocknr);
    reiserfs_flush_bitmap(bmp, fs);
    
    return 0;
}

int main(int argc, char *argv[]) {
    char * bytes_count_str = NULL;
    char * devname;
    reiserfs_filsys_t fs;
    struct reiserfs_super_block * rs;
	
    int c;
    int error;

    struct reiserfs_super_block *sb_old;

    unsigned long block_count_new;

    print_banner ("resize_reiserfs");
	
    while ((c = getopt(argc, argv, "fvcqs:")) != EOF) {
	switch (c) {
	case 's' :
	    if (!optarg) 
		die("%s: Missing argument to -s option", argv[0]);		
	    bytes_count_str = optarg;
	    break;
	case 'f':
	    opt_force = 1;
	    break;		 
	case 'v':
	    opt_verbose++; 
	    break;
	case 'n':
	    /* no nowrite option at this moment */
	    /* opt_nowrite = 1; */
	    break;
	case 'c':
	    opt_safe = 1;
	    break;
	case 'q':
	    opt_verbose = 0;
	    break;
	default:
	    print_usage_and_exit ();
	}
    }

    if (optind == argc )
	print_usage_and_exit();
    devname = argv[optind];

    fs = reiserfs_open(devname, O_RDONLY, &error, 0);
    if (!fs)
	die ("%s: can not open '%s': %s", argv[0], devname, strerror(error));

    if (no_reiserfs_found (fs)) {
	die ("resize_reiserfs: no reiserfs found on the device");
    }
    if (!spread_bitmaps (fs)) {
	die ("resize_reiserfs: cannot resize reiserfs in old (not spread bitmap) format.\n");
    }

    rs = fs->s_rs;
	
    if(bytes_count_str) {	/* new fs size is specified by user */
	block_count_new = calc_new_fs_size(rs_block_count(rs), fs->s_blocksize, bytes_count_str);
    } else {		/* use whole device */
	block_count_new = count_blocks(devname, fs->s_blocksize, -1);
    }

    if (is_mounted (devname)) {
	reiserfs_close(fs);
	return resize_fs_online(devname, block_count_new);
    }	
	
    if (rs_state(rs) != REISERFS_VALID_FS)
	die ("%s: the file system isn't in valid state\n", argv[0]);
		
    if(!valid_offset(fs->s_dev, (loff_t) block_count_new * fs->s_blocksize - 1))
	die ("%s: %s too small", argv[0], devname);

    sb_old = 0;		/* Needed to keep idiot compiler from issuing false warning */
    /* save SB for reporting */
    if(opt_verbose) {
	sb_old = getmem(SB_SIZE);
	memcpy(sb_old, SB_DISK_SUPER_BLOCK(fs), SB_SIZE);
    }

    if (block_count_new == SB_BLOCK_COUNT(fs)) 
	die ("%s: Calculated fs size is the same as the previous one.", argv[0]);

    if (block_count_new > SB_BLOCK_COUNT(fs))
	expand_fs(fs, block_count_new);
    else
	shrink_fs(fs, block_count_new);

    if(opt_verbose) {
	sb_report(rs, sb_old);
	freemem(sb_old);
    }

    set_state (rs, REISERFS_VALID_FS);
    bwrite_cond(SB_BUFFER_WITH_SB(fs));
	
    if (opt_verbose) {
	printf("\nSyncing..");
	fflush(stdout);
    }
    reiserfs_close (fs);
    if (opt_verbose)
	printf("done\n");
	
    return 0;
}
