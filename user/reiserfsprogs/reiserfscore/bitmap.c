/* 
 * Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */
  
/*
 * 2000/10/26 - Initial version.
 */

#include <assert.h>
#include "includes.h"


/* create clean bitmap */
reiserfs_bitmap_t reiserfs_create_bitmap (unsigned int bit_count)
{
    reiserfs_bitmap_t bm;

    bm = getmem (sizeof (*bm));
    if (!bm)
	return 0;
    bm->bm_bit_size = bit_count;
    bm->bm_byte_size = (bit_count + 7) / 8;
    bm->bm_set_bits = 0;
    bm->bm_map = getmem (bm->bm_byte_size);
    if (!bm->bm_map) {
	freemem (bm);
	return 0;
    }

    return bm;
}

/* Expand existing bitmap.  Return non-zero if can't. FIXME: it is
   assumed that bit_count is new number of blocks to be addressed */
int reiserfs_expand_bitmap (reiserfs_bitmap_t bm, unsigned int bit_count)
{
    unsigned int byte_count = ((bit_count + 7) / 8);
    char * new_map;

    new_map = expandmem (bm->bm_map, bm->bm_byte_size,
			 byte_count - bm->bm_byte_size);

    if (!new_map) {
	return 1;
    }
    
    bm->bm_map = new_map;
    bm->bm_byte_size = byte_count;
    bm->bm_bit_size = bit_count;
    return 0;
}

/* bitmap destructor */
void reiserfs_delete_bitmap (reiserfs_bitmap_t bm)
{
    freemem(bm->bm_map);
    bm->bm_map = NULL;		/* to not reuse bitmap handle */
    bm->bm_bit_size = 0;
    bm->bm_byte_size = 0;
    freemem(bm);
}


void reiserfs_bitmap_copy (reiserfs_bitmap_t to, reiserfs_bitmap_t from)
{
    assert (to->bm_byte_size == from->bm_byte_size);
    memcpy (to->bm_map, from->bm_map, from->bm_byte_size);
    to->bm_bit_size = from->bm_bit_size;
    to->bm_set_bits = from->bm_set_bits;
}


int reiserfs_bitmap_compare (reiserfs_bitmap_t bm1, reiserfs_bitmap_t bm2)
{
    int bytes, bits;
    int i, diff;

    assert (bm1->bm_byte_size == bm2->bm_byte_size &&
	    bm1->bm_bit_size == bm2->bm_bit_size);

    diff = 0;

    /* compare full bytes */
    bytes = bm1->bm_bit_size / 8;
    if (memcmp (bm1->bm_map, bm2->bm_map, bytes)) {
	for (i = 0; i < bytes; i ++)
	    if (bm1->bm_map [i] != bm2->bm_map[i]) {
		printf ("byte %d: bm1: %x bm2 %x\n", i, bm1->bm_map[i], bm2->bm_map[i]);
		diff ++;
	    }
    }

    /* compare last byte of bitmap which can be used partially */
    bits = bm1->bm_bit_size % 8;
    if (bits) {
	int mask;

	mask = 255 >> (8 - bits);
	if ((bm1->bm_map [bytes] & mask) != (bm2->bm_map [bytes] & mask)) {
	    printf ("last byte %d: bm1: %x bm2 %x\n", bytes, bm1->bm_map[bytes], bm2->bm_map[bytes]);
	    diff ++;
	}
    }
    return diff;
}


void reiserfs_bitmap_set_bit (reiserfs_bitmap_t bm, unsigned int bit_number)
{
    assert(bit_number < bm->bm_bit_size);
    if (test_bit (bit_number, bm->bm_map))
	return;
    set_bit(bit_number, bm->bm_map);
    bm->bm_set_bits ++;
}


void reiserfs_bitmap_clear_bit (reiserfs_bitmap_t bm, unsigned int bit_number)
{
    assert(bit_number < bm->bm_bit_size);
    if (!test_bit (bit_number, bm->bm_map))
	return;
    clear_bit (bit_number, bm->bm_map);
    bm->bm_set_bits --;
}


int reiserfs_bitmap_test_bit (reiserfs_bitmap_t bm, unsigned int bit_number)
{
    if (bit_number >= bm->bm_bit_size)
	printf ("bit %u, bitsize %lu\n", bit_number, bm->bm_bit_size);
    assert(bit_number < bm->bm_bit_size);
    return test_bit(bit_number, bm->bm_map);
}


int reiserfs_bitmap_zeros (reiserfs_bitmap_t bm)
{
    return bm->bm_bit_size - bm->bm_set_bits;
}


int reiserfs_bitmap_ones (reiserfs_bitmap_t bm)
{
    return bm->bm_set_bits;
}


int reiserfs_bitmap_find_zero_bit (reiserfs_bitmap_t bm, unsigned long * start)
{
    unsigned int  bit_nr = *start;
    assert(*start < bm->bm_bit_size);

    bit_nr = find_next_zero_bit(bm->bm_map, bm->bm_bit_size, *start);

    if (bit_nr >= bm->bm_bit_size) { /* search failed */	
	return 1;
    }

    *start = bit_nr;
    return 0;
}


/* copy reiserfs filesystem bitmap into memory bitmap */
int reiserfs_fetch_disk_bitmap (reiserfs_bitmap_t bm, reiserfs_filsys_t fs)
{
    int i;
    int bytes;
    char * p;
    int unused_bits;

    reiserfs_warning (stderr, "Fetching on-disk bitmap..");
    assert (bm->bm_bit_size == SB_BLOCK_COUNT (fs));

    bytes = fs->s_blocksize;
    p = bm->bm_map;
    for (i = 0; i < SB_BMAP_NR (fs); i ++) {
	if ((i == (SB_BMAP_NR (fs) - 1)) && bm->bm_byte_size % fs->s_blocksize)
	    bytes = bm->bm_byte_size % fs->s_blocksize;

	memcpy (p, SB_AP_BITMAP (fs)[i]->b_data, bytes);
	p += bytes;
    }

    /* on disk bitmap has bits out of SB_BLOCK_COUNT set to 1, where as
       reiserfs_bitmap_t has those bits set to 0 */
    unused_bits = bm->bm_byte_size * 8 - bm->bm_bit_size;
    for (i = 0; i < unused_bits; i ++)
	clear_bit (bm->bm_bit_size + i, bm->bm_map);

    bm->bm_set_bits = 0;
    /* FIXME: optimize that */
    for (i = 0; i < bm->bm_bit_size; i ++)
	if (reiserfs_bitmap_test_bit (bm, i))
	    bm->bm_set_bits ++;

    /* unused part of last bitmap block is filled with 0s */
    if (bm->bm_bit_size % (fs->s_blocksize * 8))
	for (i = SB_BLOCK_COUNT (fs) % (fs->s_blocksize * 8); i < fs->s_blocksize * 8; i ++)
	    if (!test_bit (i, SB_AP_BITMAP (fs)[SB_BMAP_NR (fs) - 1]->b_data)) {
		reiserfs_warning (stderr, "fetch_bitmap: on-disk bitmap is not padded properly\n");
		break;
	    }
    
    reiserfs_warning (stderr, "done\n");
    return 0;
}


/* copy bitmap to buffers which hold on-disk bitmap */
int reiserfs_flush_bitmap (reiserfs_bitmap_t bm, reiserfs_filsys_t fs)
{
    int i;
    int bytes;
    char * p;

    bytes = fs->s_blocksize;
    p = bm->bm_map;
    for (i = 0; i < SB_BMAP_NR (fs); i ++) {
	if ((i == (SB_BMAP_NR (fs) - 1)) && (bm->bm_byte_size % fs->s_blocksize))
	    bytes = bm->bm_byte_size % fs->s_blocksize;

	memcpy (SB_AP_BITMAP (fs)[i]->b_data, p, bytes);
	mark_buffer_dirty (SB_AP_BITMAP (fs)[i]);
	
	p += bytes;
    }

    /* unused part of last bitmap block is filled with 0s */
    if (bm->bm_bit_size % (fs->s_blocksize * 8))
	for (i = bm->bm_bit_size % (fs->s_blocksize * 8); i < fs->s_blocksize * 8; i ++)
	    set_bit (i, SB_AP_BITMAP (fs)[SB_BMAP_NR (fs) - 1]->b_data);

    return 0;
}


void reiserfs_bitmap_zero (reiserfs_bitmap_t bm)
{
    memset (bm->bm_map, 0, bm->bm_byte_size);
    bm->bm_set_bits = 0;
}


void reiserfs_bitmap_fill (reiserfs_bitmap_t bm)
{
    memset (bm->bm_map, 0xff, bm->bm_byte_size);
    bm->bm_set_bits = bm->bm_bit_size;
}


/* format of bitmap saved in a file:
   magic number (32 bits)
   bm_bit_size (32 bits)
   number of ranges of used and free blocks (32 bits)
   number of contiguously used block, .. of free blocks, used, free, etc
   magic number (32 bits) */

#define BITMAP_START_MAGIC 374031
#define BITMAP_END_MAGIC 7786472

void reiserfs_bitmap_save (char * filename, reiserfs_bitmap_t bm)
{
    FILE * fp;
    __u32 v;
    int zeros;
    int count;
    int i;
    int extents;
    
    fp = fopen (filename, "w+");
    if (!fp) {
	reiserfs_warning (stderr, "reiserfs_bitmap_save: could not save bitmap in %s: %m",
			  filename);
	return;
    }

    reiserfs_warning (stderr, "Saving bitmap in \"%s\" .. ", filename); fflush (stderr);

    v = BITMAP_START_MAGIC;
    fwrite (&v, 4, 1, fp);

    v = bm->bm_bit_size;
    fwrite (&v, 4, 1, fp);

    /*printf ("SAVE: bit_size - %d\n", v);*/


    if (fseek (fp, 4, SEEK_CUR)) {
	reiserfs_warning (stderr, "reiserfs_bitmap_save: fseek failed: %m\n");
	fclose (fp);
	return;
    }

    zeros = 0;
    count = 0;
    extents = 0;
    for (i = 0; i < v; i ++) {
	if (reiserfs_bitmap_test_bit (bm, i)) {
	    if (zeros) {
		/* previous bit was not set, write amount of not set
                   bits, switch to count set bits */
		fwrite (&count, 4, 1, fp);
		/*printf ("SAVE: Free %d\n", count);*/
		extents ++;
		count = 1;
		zeros = 0;
	    } else {
		/* one more zero bit appeared */
		count ++;
	    }
	} else {
	    /* zero bit found */
	    if (zeros) {
		count ++;
	    } else {
		/* previous bit was set, write amount of set bits,
                   switch to count not set bits */
		fwrite (&count, 4, 1, fp);
		/*printf ("SAVE: Used %d\n", count);*/
		extents ++;
		count = 1;
		zeros = 1;
	    }
	}
    }

    fwrite (&count, 4, 1, fp);
    extents ++;
/*
    if (zeros)
	printf ("SAVE: Free %d\n", count);
    else	
	printf ("SAVE: Used %d\n", count);
*/

    v = BITMAP_END_MAGIC;
    fwrite (&v, 4, 1, fp);

    if (fseek (fp, 8, SEEK_SET)) {
	reiserfs_warning (stderr, "reiserfs_bitmap_save: fseek failed: %m");
	fclose (fp);
	return;
    }

    fwrite (&extents, 4, 1, fp);
    /*printf ("SAVE: extents %d\n", extents);*/
		
    fclose (fp);

    reiserfs_warning (stderr, "done\n"); fflush (stderr);
}


reiserfs_bitmap_t reiserfs_bitmap_load (char * filename)
{
    FILE * fp;
    __u32 v;
    int count;
    int i, j;
    int extents;
    int bit;
    reiserfs_bitmap_t bm;
    
    fp = fopen (filename, "r");
    if (!fp) {
	reiserfs_warning (stderr, "reiserfs_bitmap_load: fseek failed: %m\n");
	return 0;
    }

    fread (&v, 4, 1, fp);
    if (v != BITMAP_START_MAGIC) {
	reiserfs_warning (stderr, "reiserfs_bitmap_load: "
			  "no bitmap start magic found");	
	fclose (fp);
	return 0;
    }
	
    /* read bit size of bitmap */
    fread (&v, 4, 1, fp);

    bm = reiserfs_create_bitmap (v);
    if (!bm) {
	reiserfs_warning (stderr, "reiserfs_bitmap_load: creation failed");	
	fclose (fp);
	return 0;
    }
    
    reiserfs_warning (stderr, "Loading bitmap from %s .. ", filename); fflush (stderr);

    /*printf ("LOAD: bit_size - %d\n", v);*/

    fread (&extents, 4, 1, fp);

    /*printf ("LOAD: extents - %d\n", extents);*/

    bit = 0;
    for (i = 0; i < extents; i ++) {
	fread (&count, 4, 1, fp);
/*
	if (i % 2)
	    printf ("LOAD: Free %d\n", count);
	else
	    printf ("LOAD: Used %d\n", count);
*/
	for (j = 0; j < count; j ++, bit ++)
	    if (i % 2 == 0) {
		reiserfs_bitmap_set_bit (bm, bit);
	    }
    }

    fread (&v, 4, 1, fp);

    /*printf ("LOAD: Endmagic %d\n", v);*/

    fclose (fp);
    if (v != BITMAP_END_MAGIC) {
	reiserfs_warning (stderr, "reiserfs_bitmap_load: "
			  "no bitmap end magic found");
	return 0;
    }

    reiserfs_warning (stderr, "%d bits set - done\n", reiserfs_bitmap_ones (bm));
    fflush (stderr);
    return bm;
}


void reiserfs_bitmap_invert (reiserfs_bitmap_t bm)
{
    int i;

    reiserfs_warning (stderr, "Bitmap inverting..");fflush (stderr);
    for (i = 0; i < bm->bm_bit_size; i ++) {
	if (reiserfs_bitmap_test_bit (bm, i))
	    reiserfs_bitmap_clear_bit (bm, i);
	else
	    reiserfs_bitmap_set_bit (bm, i);
    }

    reiserfs_warning (stderr, "done\n");
}





