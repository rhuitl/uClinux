/*
 * Copyright 2000 by Hans Reiser, licensing governed by reiserfs/README
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <malloc.h>
#include <sys/types.h>
#include <asm/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef EMBED
#include <getopt.h>
#endif

#include "io.h"
#include "misc.h"
#include "reiserfs_lib.h"
#include "../version.h"



/*
 *  modes
 */
#define DO_DUMP 1  /* not a real dump, just printing to stdout contents of
                      tree nodes */
#define DO_CORRUPT 2 /* used to make filesystem corruption and then test fsck */
#define DO_SCAN 3
#define DO_SCAN_FOR_NAME 4
#define DO_RECOVER 5
#define DO_TEST 6
#define DO_PACK 7  /* -p extract meta data of reiserfs filesystem */
#define DO_PACK_ALL 8 /* -p */

extern int opt_quiet;
extern int mode;


// the leaf is stored in compact form: 
// start magic number
// block number __u32
// item number __u16
// struct packed_item
// ..
// end magic number

/* we store hash code in high byte of 16 bits */
#define LEAF_START_MAGIC 0xa5
#define LEAF_END_MAGIC 0x5a



#define FULL_BLOCK_START_MAGIC 0xb6
#define FULL_BLOCK_END_MAGIC 0x6b
#define UNFORMATTED_BITMAP_START_MAGIC 0xc7
#define UNFORMATTED_BITMAP_END_MAGIC 0x7c
#define END_MAGIC 0x8d
#define INTERNAL_START_MAGIC
#define INTERNAL_START_MAGIC


#define ITEM_START_MAGIC 0x476576
#define ITEM_END_MAGIC 0x2906504

/* flags in packed item mask */
#define NEW_FORMAT 1  // 0 here means - old format, 1 - new format
#define DIR_ID 2
#define OBJECT_ID 4
#define OFFSET_BITS_32 8
#define OFFSET_BITS_64 16
#define ENTRY_COUNT 32 // shows whether ih_free_space/ih_entry_count is stored

#define INDIRECT_ITEM 64
#define DIRENTRY_ITEM 128
#define DIRECT_ITEM 256
#define STAT_DATA_ITEM 512

#define ITEM_BODY 1024
#define WHOLE_INDIRECT 128
#define WITH_SD_FIRST_DIRECT_BYTE 8192 /* for old stat data first_direct_byte
                                          is stored */
#define NLINK_BITS_32 8192 /* nlinks stored in 32 bits */
#define SIZE_BITS_64 16384 /* size has to be stored in 64 bit */

struct packed_item {
    /*__u16 length;*/ // length of the area we store item in
    __u16 mask; // what is stored: dirid, objectid, 32 bit offset or 64 bit offset, type
    __u16 item_len;
};

#define HAS_DIR_ID 1
#define HAS_GEN_COUNTER 2
#define HAS_STATE 4
#define YURA 8
#define TEA 16
#define R5 32
struct packed_dir_entry {
    __u8 mask;
    __u16 entrylen;
};


#define fread8(pv) fread (pv, sizeof (__u8), 1, stdin)
#define fread16(pv) fread (pv, sizeof (__u16), 1, stdin)
#define fread32(pv) fread (pv, sizeof (__u32), 1, stdin)
#define fread64(pv) fread (pv, sizeof (__u64), 1, stdin)

#define fwrite8(pv) {\
if (fwrite (pv, sizeof (__u8), 1, stdout) != 1)\
    reiserfs_panic ("fwrite8 failed: %m");\
}
#define fwrite16(pv) {\
if (fwrite (pv, sizeof (__u16), 1, stdout) != 1)\
    reiserfs_panic ("fwrite16 failed: %m");\
}
#define fwrite32(pv) {\
if (fwrite (pv, sizeof (__u32), 1, stdout) != 1)\
    reiserfs_panic ("fwrite32 failed: %m");\
}
#define fwrite64(pv) {\
if (fwrite (pv, sizeof (__u64), 1, stdout) != 1)\
    reiserfs_panic ("fwrite64 failed: %m");\
}
/*
#define fwrite16(pv) fwrite (pv, sizeof (__u16), 1, stdout)
#define fwrite32(pv) fwrite (pv, sizeof (__u32), 1, stdout)
#define fwrite64(pv) fwrite (pv, sizeof (__u64), 1, stdout)
*/


#define BLOCKS_PER_READ 8
extern char * where_to_save;
