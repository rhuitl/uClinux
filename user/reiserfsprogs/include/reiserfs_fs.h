/*
 * Copyright 1996-2001 by Hans Reiser, licensing governed by reiserfs/README
 */
  
/*
 *  include/linux/reiser_fs.h
 *
 *  Reiser File System constants and structures
 *
 */



/* in reading the #defines, it may help to understand that they employ
 the following abbreviations:

B = Buffer
I = Item header
H = Height within the tree (should be changed to LEV)
N = Number of the item in the node
STAT = stat data
DEH = Directory Entry Header
EC = Entry Count
E = Entry number
UL = Unsigned Long
BLKH = BLocK Header
UNFM = UNForMatted node
DC = Disk Child
P = Path

These #defines are named by concatenating these abbreviations, where
first comes the arguments, and last comes the return value, of the
macro.

*/

#include <limits.h>
#include <endian.h>
#if __BYTE_ORDER != __LITTLE_ENDIAN
#define USE_ENDIAN_CONVERSION_MACROS
#endif

/* NEW_GET_NEW_BUFFER will try to allocate new blocks better */
/*#define NEW_GET_NEW_BUFFER*/
#define OLD_GET_NEW_BUFFER

/* n must be power of 2 */
#define _ROUND_UP(x,n) (((x)+(n)-1u) & ~((n)-1u))

// to be ok for alpha and others we have to align structures to 8 byte
// boundary.
// FIXME: do not change 4 by anything else: there is code which relies on that
#define ROUND_UP(x) _ROUND_UP(x,8LL)




/***************************************************************************/
/*                             SUPER BLOCK                                 */
/***************************************************************************/

#define UNSET_HASH 0 // read_super will guess about, what hash names
                     // in directories were sorted with
#define TEA_HASH  1
#define YURA_HASH 2
#define R5_HASH   3
#define DEFAULT_HASH R5_HASH


// can be used only to complete indirect to direct convertion and for
// nothing else
#define RESERVED_SPACE 20


/* super block of prejournalled version */
struct reiserfs_super_block_v0
{
    __u32 s_block_count;
    __u32 s_free_blocks;
    __u32 s_root_block;
    __u16 s_blocksize;
    __u16 s_oid_maxsize;
    __u16 s_oid_cursize;
    __u16 s_state;
    char s_magic[16];
    __u16 s_tree_height;
    __u16 s_bmap_nr;
    __u16 s_reserved;
};


/* this is the super from 3.5.X, where X >= 10 */
struct reiserfs_super_block_v1
{
    __u32 s_block_count;	/* blocks count         */
    __u32 s_free_blocks;        /* free blocks count    */
    __u32 s_root_block;         /* root block number    */
    __u32 s_journal_block;      /* journal block number    */
    __u32 s_journal_dev;        /* journal device number  */
    __u32 s_orig_journal_size; 	/* size of the journal on FS creation.  used to make sure they don't overflow it */
    __u32 s_journal_trans_max ; /* max number of blocks in a transaction.  */
    __u32 s_journal_block_count ; /* total size of the journal. can change over time  */
    __u32 s_journal_max_batch ;   /* max number of blocks to batch into a trans */
    __u32 s_journal_max_commit_age ; /* in seconds, how old can an async commit be */
    __u32 s_journal_max_trans_age ;  /* in seconds, how old can a transaction be */
    __u16 s_blocksize;               /* block size           */
    __u16 s_oid_maxsize;	/* max size of object id array, see get_objectid() commentary  */
    __u16 s_oid_cursize;	/* current size of object id array */
    __u16 s_state;              /* valid or error       */
    char s_magic[10];           /* reiserfs magic string indicates that file system is reiserfs */
    __u16 s_fsck_state;		/* when fsck managed to build the tree - it puts */
    __u32 s_hash_function_code;	/* indicate, what hash fuction is being use to sort names in a directory*/
    __u16 s_tree_height;        /* height of disk tree */
    __u16 s_bmap_nr;            /* amount of bitmap blocks needed to address each block of file system */
    __u16 s_version;
};

#define SB_SIZE_V1 (sizeof(struct reiserfs_super_block_v1)) /* 76 bytes */


/* Structure of super block on disk, a version of which in RAM is often
   accessed as s->u.reiserfs_sb.s_rs the version in RAM is part of a larger
   structure containing fields never written to disk.  */
struct reiserfs_super_block
{
    struct reiserfs_super_block_v1 s_v1;
    char s_unused[128] ;			/* zero filled by mkreiserfs */
};

#define SB_SIZE (sizeof(struct reiserfs_super_block)) /* 204 bytes */


typedef __u32 (*hashf_t) (const char *, int);






#define SB_BUFFER_WITH_SB(s) ((s)->s_sbh)
#define SB_AP_BITMAP(s) ((s)->s_ap_bitmap)

#define SB_DISK_SUPER_BLOCK(s) (&((s)->s_rs->s_v1))
#define SB_JOURNAL_BLOCK(s) le32_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_journal_block))
#define SB_JOURNAL_SIZE(s) le32_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_orig_journal_size))
#define SB_BLOCK_COUNT(s) le32_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_block_count))
#define SB_FREE_BLOCKS(s) le32_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_free_blocks))
#define SB_REISERFS_MAGIC(s) (SB_DISK_SUPER_BLOCK(s)->s_magic)
#define SB_ROOT_BLOCK(s) le32_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_root_block))
#define SB_TREE_HEIGHT(s) le16_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_tree_height))
#define SB_REISERFS_STATE(s) le16_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_state))
#define SB_VERSION(s) le16_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_version))
#define SB_BMAP_NR(s) le16_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_bmap_nr))
#define SB_OBJECTID_MAP_SIZE(s) le16_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_oid_cursize))
#define SB_OBJECTID_MAP_MAXSIZE(s) le16_to_cpu ((SB_DISK_SUPER_BLOCK(s)->s_oid_maxsize))

#define rs_blocksize(rs) le16_to_cpu ((rs)->s_v1.s_blocksize)
#define set_blocksize(rs,n) ((rs)->s_v1.s_blocksize = cpu_to_le16 (n))

#define rs_block_count(rs) le32_to_cpu ((rs)->s_v1.s_block_count)
#define set_block_count(rs,n) ((rs)->s_v1.s_block_count = cpu_to_le32 (n))

#define rs_journal_dev(rs) le32_to_cpu ((rs)->s_v1.s_journal_dev)
#define set_journal_dev(rs,n) ((rs)->s_v1.s_journal_dev = cpu_to_le32 (n))

#define rs_journal_start(rs) le32_to_cpu ((rs)->s_v1.s_journal_block)
#define set_journal_start(rs,n) ((rs)->s_v1.s_journal_block = cpu_to_le32 (n))

#define rs_journal_size(rs) le32_to_cpu((rs)->s_v1.s_orig_journal_size)
#define set_journal_size(rs,n) ((rs)->s_v1.s_orig_journal_size = cpu_to_le32(n))

#define rs_root_block(rs) le32_to_cpu ((rs)->s_v1.s_root_block)
#define set_root_block(rs,n) ((rs)->s_v1.s_root_block = cpu_to_le32 (n))

#define rs_tree_height(rs) le16_to_cpu ((rs)->s_v1.s_tree_height)
#define set_tree_height(rs,n) ((rs)->s_v1.s_tree_height = cpu_to_le16 (n))

#define rs_free_blocks(rs) le32_to_cpu ((rs)->s_v1.s_free_blocks)
#define set_free_blocks(rs,n) ((rs)->s_v1.s_free_blocks = cpu_to_le32 (n))

#define rs_bmap_nr(rs) le16_to_cpu ((rs)->s_v1.s_bmap_nr)
#define set_bmap_nr(rs,n) ((rs)->s_v1.s_bmap_nr = cpu_to_le16 (n))

#define rs_state(rs) le16_to_cpu ((rs)->s_v1.s_state)
#define set_state(rs,n) ((rs)->s_v1.s_state = cpu_to_le16 (n))

#define rs_objectid_map_size(rs) (le16_to_cpu ((rs)->s_v1.s_oid_cursize))
#define set_objectid_map_size(rs,n) ((rs)->s_v1.s_oid_cursize = cpu_to_le16 (n))

#define rs_objectid_map_max_size(rs) (le16_to_cpu ((rs)->s_v1.s_oid_maxsize))
#define set_objectid_map_max_size(rs,n) ((rs)->s_v1.s_oid_maxsize = cpu_to_le16 (n))

#define rs_hash(rs) (le32_to_cpu ((rs)->s_v1.s_hash_function_code))
#define set_hash(rs,n) ((rs)->s_v1.s_hash_function_code = cpu_to_le32 (n))

#define rs_version(rs) (le16_to_cpu ((rs)->s_v1.s_version))
#define set_version(rs,n) ((rs)->s_v1.s_version = cpu_to_le16 (n))

#define TREE_IS_BUILT 0xfaaf
#define fsck_state(rs) le16_to_cpu (((rs)->s_v1.s_fsck_state))
#define set_fsck_state(rs,n) ((rs)->s_v1.s_fsck_state = cpu_to_le16 (n))


#define sb_size(fs) (fs->s_version == REISERFS_VERSION_2) ? SB_SIZE : SB_SIZE_V1

/* struct stat_data* access macros */
/* v1 */
#define sd_v1_mode(sd)                 (le16_to_cpu((sd)->sd_mode))
#define set_sd_v1_mode(sd,n)           ((sd)->sd_mode = cpu_to_le16((n)))
#define sd_v1_nlink(sd)                (le16_to_cpu((sd)->sd_nlink))
#define set_sd_v1_nlink(sd,n)          ((sd)->sd_nlink = cpu_to_le16((n))) 
#define sd_v1_uid(sd)                  (le16_to_cpu((sd)->sd_uid))
#define set_sd_v1_uid(sd,n)            ((sd)->sd_uid = cpu_to_le16((n)))
#define sd_v1_gid(sd)                  (le16_to_cpu((sd)->sd_gid))
#define set_sd_v1_gid(sd,n)            ((sd)->sd_gid = cpu_to_le16((n)))
#define sd_v1_size(sd)                 (le32_to_cpu((sd)->sd_size))
#define set_sd_v1_size(sd,n)           ((sd)->sd_size = cpu_to_le32((n)))
#define sd_v1_atime(sd)                (le32_to_cpu((sd)->sd_atime))
#define set_sd_v1_atime(sd,n)          ((sd)->sd_atime = cpu_to_le32((n)))
#define sd_v1_mtime(sd)                (le32_to_cpu((sd)->sd_mtime))
#define set_sd_v1_mtime(sd,n)          ((sd)->sd_mtime = cpu_to_le32((n)))
#define sd_v1_ctime(sd)                (le32_to_cpu((sd)->sd_ctime))
#define set_sd_v1_ctime(sd,n)          ((sd)->sd_ctime = cpu_to_le32((n)))
#define sd_v1_blocks(sd)               (le32_to_cpu((sd)->u.sd_blocks))
#define set_sd_v1_blocks(sd,n)         ((sd)->u.sd_blocks = cpu_to_le32((n)))
#define sd_v1_rdev(sd)                 (le32_to_cpu((sd)->u.sd_rdev))
#define set_sd_v1_rdev(sd,n)           ((sd)->u.sd_rdev = cpu_to_le32((n)))
#define sd_v1_first_direct_byte(sd)    (le32_to_cpu((sd)->sd_first_direct_byte))
#define set_sd_v1_first_direct_byte(sd,n) \
                                 ((sd)->sd_first_direct_byte = cpu_to_le32((n)))
/* v2 */
#define sd_v2_mode(sd)                 (le16_to_cpu((sd)->sd_mode))
#define set_sd_v2_mode(sd,n)           ((sd)->sd_mode = cpu_to_le16((n)))
#define sd_v2_reserved(sd)             (le16_to_cpu((sd)->sd_reserved))
#define set_sd_v2_reserved(sd,n)       ((sd)->sd_reserved = cpu_to_le16((n)))
#define sd_v2_nlink(sd)                (le32_to_cpu((sd)->sd_nlink))
#define set_sd_v2_nlink(sd,n)          ((sd)->sd_nlink = cpu_to_le32((n))) 
#define sd_v2_size(sd)                 (le64_to_cpu((sd)->sd_size))
#define set_sd_v2_size(sd,n)           ((sd)->sd_size = cpu_to_le64((n)))
#define sd_v2_uid(sd)                  (le32_to_cpu((sd)->sd_uid))
#define set_sd_v2_uid(sd,n)            ((sd)->sd_uid = cpu_to_le32((n)))
#define sd_v2_gid(sd)                  (le32_to_cpu((sd)->sd_gid))
#define set_sd_v2_gid(sd,n)            ((sd)->sd_gid = cpu_to_le32((n)))
#define sd_v2_atime(sd)                (le32_to_cpu((sd)->sd_atime))
#define set_sd_v2_atime(sd,n)          ((sd)->sd_atime = cpu_to_le32((n)))
#define sd_v2_mtime(sd)                (le32_to_cpu((sd)->sd_mtime))
#define set_sd_v2_mtime(sd,n)          ((sd)->sd_mtime = cpu_to_le32((n)))
#define sd_v2_ctime(sd)                (le32_to_cpu((sd)->sd_ctime))
#define set_sd_v2_ctime(sd,n)          ((sd)->sd_ctime = cpu_to_le32((n)))
#define sd_v2_blocks(sd)               (le32_to_cpu((sd)->sd_blocks))
#define set_sd_v2_blocks(sd,n)         ((sd)->sd_blocks = cpu_to_le32((n)))
#define sd_v2_rdev(sd)                 (le32_to_cpu((sd)->u.sd_rdev))
#define set_sd_v2_rdev(sd,n)           ((sd)->u.sd_rdev = cpu_to_le32((n)))


/* ReiserFS leaves the first 64k unused, so that partition labels have enough
   space.  If someone wants to write a fancy bootloader that needs more than
   64k, let us know, and this will be increased in size.  This number must be
   larger than than the largest block size on any platform, or code will
   break.  -Hans */
#define REISERFS_DISK_OFFSET_IN_BYTES (64 * 1024)

/* the spot for the super in versions 3.5 - 3.5.11 (inclusive) */
#define REISERFS_OLD_DISK_OFFSET_IN_BYTES (8 * 1024)

/* prejournalled reiserfs had signature in the other place in super block */
#define REISERFS_SUPER_MAGIC_STRING_OFFSET_NJ 20

/* f_type of struct statfs will be set at this value by statfs(2) */
#define REISERFS_SUPER_MAGIC 0x52654973

/* various reiserfs signatures. We have 2 so far. ReIsErFs for the system
   which is not able to deal with long files and ReIsEr2Fs for another. Those
   signature should be looked for at the 64-th and at the 8-th 1k block of the
   device */
#define REISERFS_SUPER_MAGIC_STRING "ReIsErFs"
#define REISER2FS_SUPER_MAGIC_STRING "ReIsEr2Fs"



/* values for s_version field of struct reiserfs_super_block */
#define REISERFS_VERSION_1 0 /* old (short) super block, all keys in old
                                format */
#define REISERFS_VERSION_2 2 /* new super block, keys may be in new format */

/*
 * values for s_state field
 */
#define REISERFS_VALID_FS    1
#define REISERFS_ERROR_FS    2



/***************************************************************************/
/*                             JOURNAL                                     */
/***************************************************************************/

#define JOURNAL_DESC_MAGIC "ReIsErLB" /* ick.  magic string to find desc blocks in the journal */
#define JOURNAL_TRANS_MAX 1024   /* biggest possible single transaction, don't change for now (8/3/99) */

/* journal.c see journal.c for all the comments here */

#define JOURNAL_TRANS_HALF 1018   /* must be correct to keep the desc and commit structs at 4k */

/* first block written in a commit.  BUG, not 64bit safe */
struct reiserfs_journal_desc {
    __u32 j_trans_id ;			/* id of commit */
    __u32 j_len ;			/* length of commit. len +1 is the commit block */
    __u32 j_mount_id ;				/* mount id of this trans*/
    __u32 j_realblock[JOURNAL_TRANS_HALF] ; /* real locations for each block */
    char j_magic[12] ;
} ;

/* last block written in a commit BUG, not 64bit safe */
struct reiserfs_journal_commit {
    __u32 j_trans_id ;			/* must match j_trans_id from the desc block */
    __u32 j_len ;			/* ditto */
    __u32 j_realblock[JOURNAL_TRANS_HALF] ; /* real locations for each block */
    char j_digest[16] ;			/* md5 sum of all the blocks involved, including desc and commit. not used, kill it */
} ;

/* this header block gets written whenever a transaction is considered fully flushed, and is more recent than the
** last fully flushed transaction.  fully flushed means all the log blocks and all the real blocks are on disk,
** and this transaction does not need to be replayed.
*/
struct reiserfs_journal_header {
    __u32 j_last_flush_trans_id ;		/* id of last fully flushed transaction */
    __u32 j_first_unflushed_offset ;      /* offset in the log of where to start replay after a crash */
    __u32 j_mount_id ;
} ;


#define JOURNAL_BLOCK_COUNT 8192 /* number of blocks in the journal */



#define bh_desc(bh) ((struct reiserfs_journal_desc *)((bh)->b_data))
#define bh_commit(bh) ((struct reiserfs_journal_commit *)((bh)->b_data))


/***************************************************************************/
/*                       KEY & ITEM HEAD                                   */
/***************************************************************************/

struct offset_v1 {
    __u32 k_offset;
    __u32 k_uniqueness;
} __attribute__ ((__packed__));

struct offset_v2 {
    union {
        struct {
#ifndef USE_ENDIAN_CONVERSION_MACROS
    /* little endian */
            __u64 k_offset:60;
            __u64 k_type: 4; // TYPE_STAT_DATA | TYPE_INDIRECT | TYPE_DIRECT | TYPE_DIRENTRY
#else
    /* big endian */
            __u64 k_type: 4; // TYPE_STAT_DATA | TYPE_INDIRECT | TYPE_DIRECT | TYPE_DIRENTRY
            __u64 k_offset:60;
#endif
        } offset;
        __u64 em_offset;
    } u;
} __attribute__ ((__packed__));

#ifdef USE_ENDIAN_CONVERSION_MACROS
extern inline __u16 offset_v2_k_type( const struct offset_v2 *v2 )
{
    struct offset_v2 tmp;
    tmp.u.em_offset = le64_to_cpu( v2->u.em_offset );
    return tmp.u.offset.k_type;
}
 
extern inline void set_offset_v2_k_type( struct offset_v2 *v2, int type )
{
    struct offset_v2 tmp;
    tmp.u.em_offset = le64_to_cpu( v2->u.em_offset );
    tmp.u.offset.k_type = type;
    v2->u.em_offset = cpu_to_le64( tmp.u.em_offset );
}
 
extern inline loff_t offset_v2_k_offset( const struct offset_v2 *v2 )
{
    struct offset_v2 tmp;
    tmp.u.em_offset = le64_to_cpu( v2->u.em_offset );
    return tmp.u.offset.k_offset;
}
 
extern inline void set_offset_v2_k_offset( struct offset_v2 *v2, loff_t offset
){
    struct offset_v2 tmp;
    tmp.u.em_offset = le64_to_cpu( v2->u.em_offset );
    tmp.u.offset.k_offset = offset;
    v2->u.em_offset = cpu_to_le64( tmp.u.em_offset );
}
#else
# define offset_v2_k_type(v2)           ((v2)->u.offset.k_type)
# define set_offset_v2_k_type(v2,val)   ((v2)->u.offset.k_type = (val))
# define offset_v2_k_offset(v2)         ((v2)->u.offset.k_offset)
# define set_offset_v2_k_offset(v2,val) ((v2)->u.offset.k_offset = (val))
#endif


/* Key of the object drop determines its location in the S+tree, and is
   composed of 4 components */
struct key {
    __u32 k_dir_id;    /* packing locality: by default parent directory object
                          id */
    __u32 k_objectid;  /* object identifier */
    union {
	struct offset_v1 k_offset_v1;
	struct offset_v2 k_offset_v2;
    } __attribute__ ((__packed__)) u;
} __attribute__ ((__packed__));

#define key_dir_id(key)                 (le32_to_cpu((key)->k_dir_id))
#define set_key_dir_id(key,n)           ((key)->k_dir_id = cpu_to_le32((n)))
#define key_objectid(key)               (le32_to_cpu((key)->k_objectid))
#define set_key_objectid(key,n)         ((key)->k_objectid = cpu_to_le32((n)))


#define KEY_SIZE (sizeof(struct key))
#define SHORT_KEY_SIZE 8


// values for k_uniqueness field of the struct key
#define V1_SD_UNIQUENESS 0
#define V1_DIRENTRY_UNIQUENESS 500
#define DIRENTRY_UNIQUENESS 500
#define V1_DIRECT_UNIQUENESS 0xffffffff
#define V1_INDIRECT_UNIQUENESS 0xfffffffe
#define V1_UNKNOWN_UNIQUENESS 555

// values for k_type field of the struct key
#define TYPE_STAT_DATA 0
#define TYPE_INDIRECT 1
#define TYPE_DIRECT 2
#define TYPE_DIRENTRY 3 

#define TYPE_UNKNOWN 15


#define KEY_FORMAT_1 0
#define KEY_FORMAT_2 1






 /* Our function for comparing keys can compare keys of different
    lengths.  It takes as a parameter the length of the keys it is to
    compare.  These defines are used in determining what is to be
    passed to it as that parameter. */
#define REISERFS_FULL_KEY_LEN     4

#define REISERFS_SHORT_KEY_LEN    2


/* Everything in the filesystem is stored as a set of items.  The item head
   contains the key of the item, its free space (for indirect items) and
   specifies the location of the item itself within the block.  */

struct item_head
{
    struct key ih_key; 	/* Everything in the tree is found by searching for it based on its key.*/

    union {
	__u16 ih_free_space1; /* The free space in the last unformatted node of
				an indirect item if this is an indirect item.
				This equals 0xFFFF iff this is a direct item
				or stat data item. Note that the key, not this
				field, is used to determine the item type, and
				thus which field this union contains. */
	__u16 ih_entry_count; /* Iff this is a directory item, this field
				 equals the number of directory entries in the
				 directory item. */
    } __attribute__ ((__packed__)) u;
    __u16 ih_item_len;           /* total size of the item body */
    __u16 ih_item_location;      /* an offset to the item body within the
                                    block */
    union {
        struct {
#ifndef USE_ENDIAN_CONVERSION_MACROS                                            
            /* for little endian systems */
            __u16 key_format : 12; /* KEY_FORMAT_1 or KEY_FORMAT_2. This is not
                                    necessary, but we have space, let use it */
            __u16 fsck_need : 4;   /* fsck set here its flag (reachable/unreachable) */
#else
            /* for big endian systems */
            __u16 fsck_need : 4;   /* fsck set here its flag (reachable/unreachable) */
            __u16 key_format : 12; /* KEY_FORMAT_1 or KEY_FORMAT_2. This is not
                                    necessary, but we have space, let use it */
#endif
        } ih_format;
        __u16 em_ih_format; /* format used for endian manipulations */
    } ih_formats;
} __attribute__ ((__packed__));


/* size of item header     */
#define IH_SIZE (sizeof(struct item_head))


#define ih_item_len(ih) (le16_to_cpu((ih)->ih_item_len))
#define set_ih_item_len(ih,x) ((ih)->ih_item_len = cpu_to_le16 (x))

#define ih_location(ih) (le16_to_cpu ((ih)->ih_item_location))
#define set_ih_location(ih,x) ((ih)->ih_item_location = cpu_to_le16 (x))

#ifdef USE_ENDIAN_CONVERSION_MACROS
    /* UGH. This is an attempt to deal with the pain that is endian safe
    * bitfields. -jeff */
extern inline __u16 ih_key_format( const struct item_head *ih )
{
    struct item_head tmp;
    tmp.ih_formats.em_ih_format = le16_to_cpu( ih->ih_formats.em_ih_format );
    return tmp.ih_formats.ih_format.key_format;
}

extern inline void set_ih_key_format( struct item_head *ih, __u16 val )
{
    struct item_head tmp;
    tmp.ih_formats.em_ih_format = le16_to_cpu( ih->ih_formats.em_ih_format );
    tmp.ih_formats.ih_format.key_format = val;
    ih->ih_formats.em_ih_format = cpu_to_le16( tmp.ih_formats.em_ih_format );
}

extern inline __u16 ih_fsck_need( const struct item_head *ih )
{
    struct item_head tmp;
    tmp.ih_formats.em_ih_format = le16_to_cpu( ih->ih_formats.em_ih_format );
    return tmp.ih_formats.ih_format.fsck_need;
}

extern inline void set_ih_fsck_need( struct item_head *ih, __u16 val )
{
    struct item_head tmp;
    tmp.ih_formats.em_ih_format = le16_to_cpu( ih->ih_formats.em_ih_format );
    tmp.ih_formats.ih_format.fsck_need = val;
    ih->ih_formats.em_ih_format = cpu_to_le16( tmp.ih_formats.em_ih_format );
}
#else
# define ih_key_format(ih) ((ih)->ih_formats.ih_format.key_format)
# define set_ih_key_format(ih,val) ((ih)->ih_formats.ih_format.key_format = (val))
# define ih_fsck_need(ih) ((ih)->ih_formats.ih_format.fsck_need)
# define set_ih_fsck_need(ih,val) ((ih)->ih_formats.ih_format.fsck_need = (val))
#endif


// FIXME: ih_free_space does not appear to be very important, but we
// have to make sure that earlier version have no trouble when
// ih_free_space is 0
#define ih_free_space(ih) 0 // le16_to_cpu (ih->u.ih_free_space)
#define set_free_space(ih,val) ((ih)->u.ih_free_space1 = 0)//val)

//#define get_ih_free_space(ih) 0 //(ih_key_format (ih) == KEY_FORMAT ? 0 : ih_free_space (ih))
//#define set_ih_free_space(ih,val) // (ih_free_space (ih) = (ih_version (ih) == ITEM_VERSION_2 ? 0 : val))

#define ih_entry_count(ih) (le16_to_cpu ((ih)->u.ih_entry_count))
//#define set_ih_free_space(ih,x) ((ih)->u.ih_free_space = cpu_to_le16(x))
#define set_entry_count(ih,x) ((ih)->u.ih_entry_count = cpu_to_le16(x))

#define I_K_KEY_IN_ITEM(p_s_ih, p_s_key, n_blocksize) \
    ( ! not_of_one_file(p_s_ih, p_s_key) && \
          I_OFF_BYTE_IN_ITEM(p_s_ih, get_offset (p_s_key), n_blocksize) )

#define IH_Bad 0
#define IH_Unreachable 1

/* Bad item flag is set temporary by recover_leaf */
extern inline __u16 mark_ih_bad( struct item_head *ih )
{
    set_ih_fsck_need(ih, ih_fsck_need(ih) | IH_Bad );
    return ih_fsck_need(ih);
}

extern inline __u16 ih_bad( struct item_head *ih )
{
    __u16 tmp = ih_fsck_need(ih);
    return test_bit(IH_Bad, &tmp );
}

extern inline __u16 unmark_item_bad( struct item_head *ih )
{
    __u16 tmp = ih_fsck_need(ih);
    clear_bit( IH_Bad, &tmp );
    set_ih_fsck_need( ih, tmp );
    return tmp;
}

/* Unreachable bit is set on tree rebuilding and is cleared in semantic pass */
#define mark_ih_ok(ih) ((ih)->ih_formats.ih_format.fsck_need = 0) /* endian safe if 0 */
#define ih_reachable(ih) (!ih_fsck_need(ih) & IH_Unreachable)
#define mark_ih_unreachable(ih) (set_ih_fsck_need(ih, ih_fsck_need(ih) | IH_Unreachable))



/* maximal length of item */ 
#define MAX_ITEM_LEN(block_size) (block_size - BLKH_SIZE - IH_SIZE)
#define MIN_ITEM_LEN 1


/* object identifier for root dir */
#define REISERFS_ROOT_OBJECTID 2
#define REISERFS_ROOT_PARENT_OBJECTID 1
/*extern struct key root_key;*/


/* 
 * Picture represents a leaf of the S+tree
 *  ______________________________________________________
 * |      |  Array of     |                   |           |
 * |Block |  Object-Item  |      F r e e      |  Objects- |
 * | head |  Headers      |     S p a c e     |   Items   |
 * |______|_______________|___________________|___________|
 */

/* Header of a disk block.  More precisely, header of a formatted leaf
   or internal node, and not the header of an unformatted node. */
struct block_head {       
    __u16 blk_level;        /* Level of a block in the tree. */
    __u16 blk_nr_item;      /* Number of keys/items in a block. */
    __u16 blk_free_space;   /* Block free space in bytes. */
	__u16 blk_reserved;
    struct key not_used; /* Right delimiting key for this block
			    (supported for leaf level nodes only) */
};

#define BLKH_SIZE                    (sizeof(struct block_head))
#define blkh_level(blkh)             (le16_to_cpu((blkh)->blk_level))
#define set_blkh_level(blkh,v)       ((blkh)->blk_level = cpu_to_le16((v)))
#define blkh_nr_item(blkh)           (le16_to_cpu((blkh)->blk_nr_item))
#define set_blkh_nr_item(blkh,v)     ((blkh)->blk_nr_item = cpu_to_le16((v)))
#define blkh_free_space(blkh)        (le16_to_cpu((blkh)->blk_free_space))
#define set_blkh_free_space(blkh,v)  ((blkh)->blk_free_space = cpu_to_le16((v)))

/*
 * values for blk_type field
 */

#define FREE_LEVEL        0 /* Node of this level is out of the tree. */

#define DISK_LEAF_NODE_LEVEL  1 /* Leaf node level.                       */


#define is_leaf_block_head(buf) (blkh_level(((struct block_head *)(buf))) == DISK_LEAF_NODE_LEVEL)
#define is_internal_block_head(buf) \
((blkh_level(((struct block_head *)(buf))) > DISK_LEAF_NODE_LEVEL) &&\
 (blkh_level(((struct block_head *)(buf))) <= MAX_HEIGHT))


/* Given the buffer head of a formatted node, resolve to the block head of that node. */
#define B_BLK_HEAD(p_s_bh)  ((struct block_head *)((p_s_bh)->b_data))

/* Number of items that are in buffer. */
#define node_item_number(bh)	(blkh_nr_item( B_BLK_HEAD(bh)))
#define node_pointer_number(bh) (node_item_number(bh) + 1)
#define node_level(bh)		(blkh_level( B_BLK_HEAD(bh)))
#define node_free_space(bh)	(blkh_free_space( B_BLK_HEAD(bh)))

#define set_node_item_number(bh,n) (set_blkh_nr_item(B_BLK_HEAD(bh),(n)))
#define set_node_free_space(bh,n)  (set_blkh_free_space(B_BLK_HEAD(bh),(n)))
#define set_node_level(bh,n)       (set_blkh_level(B_BLK_HEAD(bh), (n)))
#define set_leaf_node_level(bh)    (set_node_level (bh, DISK_LEAF_NODE_LEVEL))

#define B_NR_ITEMS(bh)		node_item_number(bh)
#define B_LEVEL(bh)		node_level(bh)
#define B_FREE_SPACE(bh)	node_free_space(bh)


#define is_leaf_node(bh) is_leaf_block_head ((bh)->b_data)
#define is_internal_node(bh) is_internal_block_head ((bh)->b_data)






/***************************************************************************/
/*                             STAT DATA                                   */
/***************************************************************************/

/* Stat Data on disk (reiserfs version of UFS disk inode minus the address blocks) */

/* The sense of adding union to stat data is to keep a value of real number of
   blocks used by file.  The necessity of adding such information is caused by
   existing of files with holes.  Reiserfs should keep number of used blocks
   for file, but not calculate it from file size (that is not correct for
   holed files). Thus we have to add additional information to stat data.
   When we have a device special file, there is no need to get number of used
   blocks for them, and, accordingly, we doesn't need to keep major and minor
   numbers for regular files, which might have holes. So this field is being
   overloaded.  */

struct stat_data_v1 {
    __u16 sd_mode;	/* file type, permissions */
    __u16 sd_nlink;	/* number of hard links */
    __u16 sd_uid;		/* owner */
    __u16 sd_gid;		/* group */
    __u32 sd_size;	/* file size */
    __u32 sd_atime;	/* time of last access */
    __u32 sd_mtime;	/* time file was last modified  */
    __u32 sd_ctime;	/* time inode (stat data) was last changed (except
                           changes to sd_atime and sd_mtime) */
    union {
	__u32 sd_rdev;
	__u32 sd_blocks;	/* number of blocks file uses */
    } __attribute__ ((__packed__)) u;
    __u32 sd_first_direct_byte; /* first byte of file which is stored
				   in a direct item: except that if it
				   equals 1 it is a symlink and if it
				   equals MAX_KEY_OFFSET there is no
				   direct item.  The existence of this
				   field really grates on me. Let's
				   replace it with a macro based on
				   sd_size and our tail suppression
				   policy.  Someday.  -Hans */
} __attribute__ ((__packed__));
#define SD_V1_SIZE (sizeof(struct stat_data_v1))


/* this is used to check sd_size of stat data v1 */
#define MAX_FILE_SIZE_V1 0x7fffffff


// sd_first_direct_byte is set to this when there are no direct items in a
// file
#define NO_BYTES_IN_DIRECT_ITEM 0xffffffff


/* Stat Data on disk (reiserfs version of UFS disk inode minus the
   address blocks) */
struct stat_data {
    __u16 sd_mode;	/* file type, permissions */
    __u16 sd_reserved;
    __u32 sd_nlink;	/* 32 bit nlink! */
    __u64 sd_size;	/* 64 bit size!*/
    __u32 sd_uid;	/* 32 bit uid! */
    __u32 sd_gid;	/* 32 bit gid! */
    __u32 sd_atime;	/* time of last access */
    __u32 sd_mtime;	/* time file was last modified  */
    __u32 sd_ctime;	/* time inode (stat data) was last changed (except
                           changes to sd_atime and sd_mtime) */
    __u32 sd_blocks;
    union {
	__u32 sd_rdev;
      //__u32 sd_first_direct_byte; 
      /* first byte of file which is stored in a direct item: except that if
	 it equals 1 it is a symlink and if it equals ~(__u32)0 there is no
	 direct item.  The existence of this field really grates on me. Let's
	 replace it with a macro based on sd_size and our tail suppression
	 policy? */
  } __attribute__ ((__packed__)) u;
} __attribute__ ((__packed__));
//
// this is 44 bytes long
//
#define SD_SIZE (sizeof(struct stat_data))

// there are two ways: to check length of item or ih_version field
// (for old stat data it is set to 0 (KEY_FORMAT_1))
#define stat_data_v1(ih) (ih_key_format (ih) == KEY_FORMAT_1)

/* this is used to check sd_size of stat data v2: max offset which can
   be reached with a key of format 2 is 60 bits */
#define MAX_FILE_SIZE_V2 0xfffffffffffffffLL


/***************************************************************************/
/*                      DIRECTORY STRUCTURE                                */
/***************************************************************************/
/* 
   Picture represents the structure of directory items
   ________________________________________________
   |  Array of     |   |     |        |       |   |
   | directory     |N-1| N-2 | ....   |   1st |0th|
   | entry headers |   |     |        |       |   |
   |_______________|___|_____|________|_______|___|
                    <----   directory entries         ------>

 First directory item has k_offset component 1. We store "." and ".."
 in one item, always, we never split "." and ".." into differing
 items.  This makes, among other things, the code for removing
 directories simpler. */
#define SD_OFFSET  0
#define DOT_OFFSET 1
#define DOT_DOT_OFFSET 2

/* */
#define FIRST_ITEM_OFFSET 1

/*
   Q: How to get key of object pointed to by entry from entry?  

   A: Each directory entry has its header. This header has deh_dir_id
   and deh_objectid fields, those are key of object, entry points to */

/* NOT IMPLEMENTED:   
   Directory will someday contain stat data of object */



struct reiserfs_de_head
{
  __u32 deh_offset;  /* third component of the directory entry key */
  __u32 deh_dir_id;  /* objectid of the parent directory of the
			object, that is referenced by directory entry */
  __u32 deh_objectid;/* objectid of the object, that is referenced by
                        directory entry */
  __u16 deh_location;/* offset of name in the whole item */
  __u16 deh_state;   /* whether 1) entry contains stat data (for
			future), and 2) whether entry is hidden
			(unlinked) */
} __attribute__ ((__packed__));

#define DEH_SIZE                 sizeof(struct reiserfs_de_head)
#define deh_offset(deh)          (le32_to_cpu ((deh)->deh_offset))
#define set_deh_offset(deh,x)    ((deh)->deh_offset = cpu_to_le32((x)))
#define deh_dir_id(deh)          (le32_to_cpu ((deh)->deh_dir_id))
#define set_deh_dir_id(deh,x)    ((deh)->deh_dir_id = cpu_to_le32((x)))
#define deh_objectid(deh)        (le32_to_cpu ((deh)->deh_objectid))
#define set_deh_objectid(deh,x)  ((deh)->deh_objectid = cpu_to_le32((x)))
#define deh_location(deh)        (le16_to_cpu ((deh)->deh_location))
#define set_deh_location(deh,x)  ((deh)->deh_location = cpu_to_le16((x)))
#define deh_state(deh)           (le16_to_cpu ((deh)->deh_state))
#define set_deh_state(deh,x)     ((deh)->deh_offset = cpu_to_le16((x)))

/* empty directory contains two entries "." and ".." and their headers */
#define EMPTY_DIR_SIZE \
(DEH_SIZE * 2 + ROUND_UP (strlen (".")) + ROUND_UP (strlen ("..")))

/* old format directories have this size when empty */
#define EMPTY_DIR_SIZE_V1 (DEH_SIZE * 2 + 3)

#define DEH_Statdata 0			/* not used now */
#define DEH_Visible 2

#define DEH_Bad_offset 4 /* fsck marks entries to be deleted with this flag */
#define DEH_Bad_location 5

#ifdef __alpha__
# define ADDR_UNALIGNED_BITS  (5)
#endif
 
#ifdef ADDR_UNALIGNED_BITS
# define aligned_address(addr)           ((void *)((long)(addr) & ~((1UL << ADDR_UNALIGNED_BITS) - 1)))
# define unaligned_offset(addr)          (((int)((long)(addr) & ((1 << ADDR_UNALIGNED_BITS) - 1))) << 3)
# define set_bit_unaligned(nr, addr)     set_bit((nr) + unaligned_offset(addr), aligned_address(addr))
# define clear_bit_unaligned(nr, addr)   clear_bit((nr) + unaligned_offset(addr), aligned_address(addr))
# define test_bit_unaligned(nr, addr)    test_bit((nr) + unaligned_offset(addr), aligned_address(addr))
#else
# define set_bit_unaligned(nr, addr)     set_bit(nr, addr)
# define clear_bit_unaligned(nr, addr)   clear_bit(nr, addr)
# define test_bit_unaligned(nr, addr)    test_bit(nr, addr)
#endif

#if 0
extern inline void de_mark_state( struct reiserfs_de_head *deh, int bit )
{
    int state = deh_state(deh);
    set_bit_unaligned( bit, &state );
    set_deh_state( deh, state );
}
 
extern inline void de_clear_state( struct reiserfs_de_head *deh, int bit )
{
    int state = deh_state(deh);
    clear_bit_unaligned( bit, &state );
    set_deh_state( deh, state );
}
 
extern inline int de_test_state( struct reiserfs_de_head *deh, int bit )
{
    /* XXX JDM This must be 'int' and not __u16 - it will break */
    int state = deh_state( deh );
    return test_bit_unaligned( bit, &deh->deh_state );
}
#endif

#define de_mark_state(deh,bit)  (set_bit_unaligned( bit, &((deh)->deh_state)))
#define de_clear_state(deh,bit) (clear_bit_unaligned( bit, &((deh)->deh_state)))
#define de_test_state(deh,bit)  (test_bit_unaligned( bit, &((deh)->deh_state)))

#define mark_de_with_sd(deh)        de_mark_state( deh, DEH_Statdata )
#define mark_de_without_sd(deh)     de_clear_state( deh, DEH_Statdata )
#define mark_de_visible(deh)        de_mark_state( deh, DEH_Visible )
#define mark_de_hidden(deh)         de_clear_state( deh, DEH_Visible )
#define mark_de_lost_found(deh)	    de_mark_state( deh, DEH_Lost_Found );
#define unmark_de_lost_found(deh)   de_clear_state( deh, DEH_Lost_Found );
 
#define de_with_sd(deh)         de_test_state( deh, DEH_Statdata )
#define de_visible(deh)         de_test_state( deh, DEH_Visible )
#define de_hidden(deh)          (!(de_visible(deh)))

/* Bad means "hashed unproperly or/and invalid location" */
#define de_bad_location(deh) test_bit (DEH_Bad_location, &((deh)->deh_state))
#define mark_de_bad_location(deh) set_bit (DEH_Bad_location, &((deh)->deh_state))
#define mark_de_good_location(deh) clear_bit (DEH_Bad_location, &((deh)->deh_state))
#define de_bad_offset(deh) test_bit (DEH_Bad_offset, &((deh)->deh_state))
#define mark_de_bad_offset(deh) set_bit (DEH_Bad_offset, &((deh)->deh_state))

#define de_bad(deh) (de_bad_location(deh) || de_bad_offset(deh))


/* for directories st_blocks is number of 512 byte units which fit into dir
   size round up to blocksize */
#define dir_size2st_blocks(blocksize,size) \
((((size) + (blocksize) - 1) / (blocksize)) * ((blocksize) / 512))


/* array of the entry headers */
#define B_I_DEH(bh,ih) ((struct reiserfs_de_head *)(B_I_PITEM(bh,ih)))

#define REISERFS_MAX_NAME_LEN(block_size) (block_size - BLKH_SIZE - IH_SIZE - DEH_SIZE)	/* -SD_SIZE when entry will contain stat data */

/* this structure is used for operations on directory entries. It is
   not a disk structure. */
/* When reiserfs_find_entry or search_by_entry_key find directory
   entry, they return filled reiserfs_dir_entry structure */
struct reiserfs_dir_entry
{
    struct buffer_head * de_bh;
    int de_item_num;
    struct item_head * de_ih;
    int de_entry_num;
    struct reiserfs_de_head * de_deh;
    int de_entrylen;
    int de_namelen;
    char * de_name;
    char * de_gen_number_bit_string;

    __u32 de_dir_id;
    __u32 de_objectid;

    struct key de_entry_key;
};


/* hash value occupies 24 bits starting from 7 up to 30 */
#define GET_HASH_VALUE(offset) ((offset) & 0x7fffff80)
/* generation number occupies 7 bits starting from 0 up to 6 */
#define GET_GENERATION_NUMBER(offset) ((offset) & 0x0000007f)


/*
 * Picture represents an internal node of the reiserfs tree
 *  ______________________________________________________
 * |      |  Array of     |  Array of         |  Free     |
 * |block |    keys       |  pointers         | space     |
 * | head |      N        |      N+1          |           |
 * |______|_______________|___________________|___________|
 */

/***************************************************************************/
/*                      DISK CHILD                                         */
/***************************************************************************/
/* Disk child pointer: The pointer from an internal node of the tree
   to a node that is on disk. */
struct disk_child {
    __u32 dc_block_number;              /* Disk child's block number. */
    __u16 dc_size;		            /* Disk child's used space.   */
    __u16 dc_reserved;
} __attribute__ ((__packed__));

#define DC_SIZE (sizeof(struct disk_child))
#define dc_block_number(dc)        (le32_to_cpu((dc)->dc_block_number))
#define set_dc_block_number(dc,v)  ((dc)->dc_block_number = cpu_to_le32((v)))
#define dc_size(dc)                (le16_to_cpu((dc)->dc_size))
#define set_dc_size(dc,v)          ((dc)->dc_size = cpu_to_le16((v)))

/* Get disk child by buffer header and position in the tree node. */
#define B_N_CHILD(p_s_bh,n_pos)  ((struct disk_child *)\
            ((p_s_bh)->b_data + BLKH_SIZE + B_NR_ITEMS(p_s_bh) \
            * KEY_SIZE + DC_SIZE * (n_pos)))

/* Get disk child number by buffer header and position in the tree node. */
#define B_N_CHILD_NUM(p_s_bh,n_pos) (dc_block_number(B_N_CHILD(p_s_bh,n_pos)))
#define child_block_number(bh,pos)  (B_N_CHILD_NUM(bh,pos))
#define set_child_block_number(bh,pos,block) (set_dc_block_number(B_N_CHILD(bh,pos), block))
#define child_block_size(bh,pos) dc_size(B_N_CHILD(bh,pos))


 /* maximal value of field child_size in structure disk_child */ 
 /* child size is the combined size of all items and their headers */
#define MAX_CHILD_SIZE(bh) ((int)( (bh)->b_size - BLKH_SIZE ))

/* amount of used space in buffer (not including block head) */
#define B_CHILD_SIZE(cur) (MAX_CHILD_SIZE(cur)-(B_FREE_SPACE(cur)))

/* max and min number of keys in internal node */
#define MAX_NR_KEY(bh) ( (MAX_CHILD_SIZE(bh)-DC_SIZE)/(KEY_SIZE+DC_SIZE) )
#define MIN_NR_KEY(bh)    (MAX_NR_KEY(bh)/2)


/***************************************************************************/
/*                      PATH STRUCTURES AND DEFINES                        */
/***************************************************************************/

/* Search_by_key fills up the path from the root to the leaf as it
   descends the tree looking for the key.  It uses reiserfs_bread to
   try to find buffers in the cache given their block number.  If it
   does not find them in the cache it reads them from disk.  For each
   node search_by_key finds using reiserfs_bread it then uses
   bin_search to look through that node.  bin_search will find the
   position of the block_number of the next node if it is looking
   through an internal node.  If it is looking through a leaf node
   bin_search will find the position of the item which has key either
   equal to given key, or which is the maximal key less than the given
   key. */

struct path_element  {
    struct buffer_head * pe_buffer; /* Pointer to the buffer at the path in
				       the tree. */
    int pe_position;  /* Position in the tree node which is placed in the
			 buffer above. */
};


#define MAX_HEIGHT 5 /* maximal height of a tree. don't change this without changing JOURNAL_PER_BALANCE_CNT */
#define EXTENDED_MAX_HEIGHT         7 /* Must be equals MAX_HEIGHT + FIRST_PATH_ELEMENT_OFFSET */
#define FIRST_PATH_ELEMENT_OFFSET   2 /* Must be equal to at least 2. */

#define ILLEGAL_PATH_ELEMENT_OFFSET 1 /* Must be equal to FIRST_PATH_ELEMENT_OFFSET - 1 */
#define MAX_FEB_SIZE 6   /* this MUST be MAX_HEIGHT + 1. See about FEB below */



/* We need to keep track of who the ancestors of nodes are.  When we
   perform a search we record which nodes were visited while
   descending the tree looking for the node we searched for. This list
   of nodes is called the path.  This information is used while
   performing balancing.  Note that this path information may become
   invalid, and this means we must check it when using it to see if it
   is still valid. You'll need to read search_by_key and the comments
   in it, especially about decrement_counters_in_path(), to understand
   this structure. */
struct path {
  int                   path_length;                      	/* Length of the array above.   */
  struct  path_element  path_elements[EXTENDED_MAX_HEIGHT];	/* Array of the path elements.  */
  int			pos_in_item;
};

#define INITIALIZE_PATH(var) \
struct path var = {ILLEGAL_PATH_ELEMENT_OFFSET, }

/* Get path element by path and path position. */
#define PATH_OFFSET_PELEMENT(p_s_path,n_offset)  ((p_s_path)->path_elements +(n_offset))

/* Get buffer header at the path by path and path position. */
#define PATH_OFFSET_PBUFFER(p_s_path,n_offset)   (PATH_OFFSET_PELEMENT(p_s_path,n_offset)->pe_buffer)

/* Get position in the element at the path by path and path position. */
#define PATH_OFFSET_POSITION(p_s_path,n_offset) (PATH_OFFSET_PELEMENT(p_s_path,n_offset)->pe_position)


#define PATH_PLAST_BUFFER(p_s_path) (PATH_OFFSET_PBUFFER((p_s_path), (p_s_path)->path_length))
#define PATH_LAST_POSITION(p_s_path) (PATH_OFFSET_POSITION((p_s_path), (p_s_path)->path_length))


#define PATH_PITEM_HEAD(p_s_path)    B_N_PITEM_HEAD(PATH_PLAST_BUFFER(p_s_path),PATH_LAST_POSITION(p_s_path))

/* in do_balance leaf has h == 0 in contrast with path structure,
   where root has level == 0. That is why we need these defines */
#define PATH_H_PBUFFER(p_s_path, h) PATH_OFFSET_PBUFFER (p_s_path, p_s_path->path_length - (h))	/* tb->S[h] */
#define PATH_H_PPARENT(path, h) PATH_H_PBUFFER (path, (h) + 1)			/* tb->F[h] or tb->S[0]->b_parent */
#define PATH_H_POSITION(path, h) PATH_OFFSET_POSITION (path, path->path_length - (h))	
#define PATH_H_B_ITEM_ORDER(path, h) PATH_H_POSITION(path, h + 1)		/* tb->S[h]->b_item_order */

#define PATH_H_PATH_OFFSET(p_s_path, n_h) ((p_s_path)->path_length - (n_h))

#define get_bh(path) PATH_PLAST_BUFFER(path)
#define get_ih(path) PATH_PITEM_HEAD(path)
#define get_item_pos(path) PATH_LAST_POSITION(path)
#define get_item(path) ((void *)B_N_PITEM(PATH_PLAST_BUFFER(path), PATH_LAST_POSITION (path)))
#define item_moved(ih,path) comp_items(ih, path)
#define path_changed(ih,path) comp_items (ih, path)


/***************************************************************************/
/*                       MISC                                              */
/***************************************************************************/


// search_by_key (and clones) and fix_nodes error code
#define CARRY_ON          	0
#define SCHEDULE_OCCURRED  	1
#define PATH_INCORRECT    	2
#define IO_ERROR		3

#define NO_DISK_SPACE           4
#define NO_BALANCING_NEEDED     5
#define ITEM_FOUND              6
#define ITEM_NOT_FOUND          7
#define POSITION_FOUND          8
#define POSITION_NOT_FOUND      9
#define GOTO_PREVIOUS_ITEM      10
#define POSITION_FOUND_INVISIBLE 11
#define FILE_NOT_FOUND          12

// used by fsck
#define DIRECTORY_NOT_FOUND     13 
#define REGULAR_FILE_FOUND     14
#define DIRECTORY_FOUND        15



typedef unsigned long b_blocknr_t;
typedef __u32 unp_t;

struct unfm_nodeinfo {
  __u32	 unfm_nodenum;
  unsigned short unfm_freespace;
};

/* when reiserfs_file_write is called with a byte count >= MIN_PACK_ON_CLOSE,
** it sets the inode to pack on close, and when extending the file, will only
** use unformatted nodes.
**
** This is a big speed up for the journal, which is badly hurt by direct->indirect
** conversions (they must be logged).
*/
#define MIN_PACK_ON_CLOSE		512


  /* This is an aggressive tail suppression policy, I am hoping it
     improves our benchmarks. The principle behind it is that
     percentage space saving is what matters, not absolute space
     saving.  This is non-intuitive, but it helps to understand it if
     you consider that the cost to access 4 blocks is not much more
     than the cost to access 1 block, if you have to do a seek and
     rotate.  A tail risks a non-linear disk access that is
     significant as a percentage of total time cost for a 4 block file
     and saves an amount of space that is less significant as a
     percentage of space, or so goes the hypothesis.  -Hans */
#define STORE_TAIL_IN_UNFM(n_file_size,n_tail_size,n_block_size) \
\
( ((n_tail_size) > MAX_DIRECT_ITEM_LEN(n_block_size)) || \
  ( (n_file_size) >= (n_block_size) * 4 ) || \
   ( ( (n_file_size) >= (n_block_size) * 3 ) && \
   ( (n_tail_size) >=   (MAX_DIRECT_ITEM_LEN(n_block_size))/4) ) || \
   ( ( (n_file_size) >= (n_block_size) * 2 ) && \
   ( (n_tail_size) >=   (MAX_DIRECT_ITEM_LEN(n_block_size))/2) ) || \
   ( ( (n_file_size) >= (n_block_size) ) && \
   ( (n_tail_size) >=   (MAX_DIRECT_ITEM_LEN(n_block_size) * 3)/4) ) )


#define first_direct_byte(inode) ((inode)->u.reiserfs_i.i_first_direct_byte)

#define has_tail(inode) (first_direct_byte(inode) != NO_BYTES_IN_DIRECT_ITEM)

#define tail_offset(inode) (first_direct_byte(inode) - 1)

// mark file as not having tail stored in direct item
#define file_has_no_tail(inode) (first_direct_byte (inode) = NO_BYTES_IN_DIRECT_ITEM)

#define block_size(inode) ((inode)->i_sb->s_blocksize)
#define file_size(inode) ((inode)->i_size)
#define tail_size(inode) (file_size (inode) & (block_size (inode) - 1))

#define tail_has_to_be_packed(inode) (!dont_have_tails ((inode)->i_sb) &&\
!STORE_TAIL_IN_UNFM(file_size (inode), tail_size(inode), block_size (inode)))


/* Size of pointer to the unformatted node. */
#define UNFM_P_SIZE (sizeof(__u32))

#define INODE_PKEY(inode) ((struct key *)((inode)->u.reiserfs_i.i_key))
#define inode_key_format(inode) ((inode)->u.reiserfs_i.i_key_format) 

//#define MAX_UL_INT ULONG_MAX
//#define MAX_INT    INT_MAX
//#define MAX_US_INT  USHRT_MAX

#define MAX_KEY1_OFFSET	 INT_MAX
#define MAX_KEY2_OFFSET  0xfffffffffffffffLL



#define MAX_KEY_UNIQUENESS	UINT_MAX
#define MAX_KEY_OBJECTID	UINT_MAX

#define MAX_B_NUM  UINT_MAX
#define MAX_FC_NUM USHRT_MAX


/* the purpose is to detect overflow of an unsigned short */
#define REISERFS_LINK_MAX (USHRT_MAX - 1000)


/* The following defines are used in reiserfs_insert_item and reiserfs_append_item  */
#define REISERFS_KERNEL_MEM		0	/* reiserfs kernel memory mode	*/
#define REISERFS_USER_MEM		1	/* reiserfs user memory mode		*/


/***************************************************************************/
/*                  FIXATE NODES                                           */
/***************************************************************************/

#define VI_TYPE_STAT_DATA 1
#define VI_TYPE_DIRECT 2
#define VI_TYPE_INDIRECT 4
#define VI_TYPE_DIRECTORY 8
#define VI_TYPE_FIRST_DIRECTORY_ITEM 16
#define VI_TYPE_INSERTED_DIRECTORY_ITEM 32

#define VI_TYPE_LEFT_MERGEABLE 64
#define VI_TYPE_RIGHT_MERGEABLE 128

/* To make any changes in the tree we always first find node, that contains
   item to be changed/deleted or place to insert a new item. We call this node
   S. To do balancing we need to decide what we will shift to left/right
   neighbor, or to a new node, where new item will be etc. To make this
   analysis simpler we build virtual node. Virtual node is an array of items,
   that will replace items of node S. (For instance if we are going to delete
   an item, virtual node does not contain it). Virtual node keeps information
   about item sizes and types, mergeability of first and last items, sizes of
   all entries in directory item. We use this array of items when calculating
   what we can shift to neighbors and how many nodes we have to have if we do
   not any shiftings, if we shift to left/right neighbor or to both. */
struct virtual_item
{
    unsigned short vi_type;	/* item type, mergeability */
    unsigned short vi_item_len; /* length of item that it will have after balancing */
  
    short vi_entry_count;	/* number of entries in directory item
				   (including the new one if any, or excluding
				   entry if it must be cut) */
    unsigned short * vi_entry_sizes; /* array of entry lengths for directory item */
};

struct virtual_node
{
    char * vn_free_ptr;		/* this is a pointer to the free space in the buffer */
    unsigned short vn_nr_item;	/* number of items in virtual node */
    short vn_size;        	/* size of node , that node would have if it has unlimited size and no balancing is performed */
    short vn_mode;		/* mode of balancing (paste, insert, delete, cut) */
    short vn_affected_item_num; 
    short vn_pos_in_item;
    struct item_head * vn_ins_ih;	/* item header of inserted item, 0 for other modes */
    struct virtual_item * vn_vi;	/* array of items (including a new one, excluding item to be deleted) */
};


/***************************************************************************/
/*                  TREE BALANCE                                           */
/***************************************************************************/

/* This temporary structure is used in tree balance algorithms, and
   constructed as we go to the extent that its various parts are needed.  It
   contains arrays of nodes that can potentially be involved in the balancing
   of node S, and parameters that define how each of the nodes must be
   balanced.  Note that in these algorithms for balancing the worst case is to
   need to balance the current node S and the left and right neighbors and all
   of their parents plus create a new node.  We implement S1 balancing for the
   leaf nodes and S0 balancing for the internal nodes (S1 and S0 are defined
   in our papers.)*/

#define MAX_FREE_BLOCK 7	/* size of the array of buffers to free at end of do_balance */

/* maximum number of FEB blocknrs on a single level */
#define MAX_AMOUNT_NEEDED 2

/* someday somebody will prefix every field in this struct with tb_ */
struct tree_balance
{
    struct reiserfs_transaction_handle *transaction_handle ;
    struct super_block * tb_sb;
    struct path * tb_path;
    struct buffer_head * L[MAX_HEIGHT];        /* array of left neighbors of nodes in the path */
    struct buffer_head * R[MAX_HEIGHT];        /* array of right neighbors of nodes in the path*/
    struct buffer_head * FL[MAX_HEIGHT];       /* array of fathers of the left  neighbors      */
    struct buffer_head * FR[MAX_HEIGHT];       /* array of fathers of the right neighbors      */
    struct buffer_head * CFL[MAX_HEIGHT];      /* array of common parents of center node and its left neighbor  */
    struct buffer_head * CFR[MAX_HEIGHT];      /* array of common parents of center node and its right neighbor */
    
    /* array of blocknr's that are free and are the nearest to the left node that are usable
       for writing dirty formatted leaves, using the write_next_to algorithm. */
    /*unsigned long free_and_near[MAX_DIRTIABLE];*/
    
    struct buffer_head * FEB[MAX_FEB_SIZE]; /* array of empty buffers. Number of buffers in array equals
					       cur_blknum. */
    struct buffer_head * used[MAX_FEB_SIZE];
    short int lnum[MAX_HEIGHT];	/* array of number of items which must be shifted to the left in
				   order to balance the current node; for leaves includes item
				   that will be partially shifted; for internal nodes, it is
				   the number of child pointers rather than items. It includes
				   the new item being created.  For preserve_shifted() purposes
				   the code sometimes subtracts one from this number to get the
				   number of currently existing items being shifted, and even
				   more often for leaves it subtracts one to get the number of
				   wholly shifted items for other purposes. */
    short int rnum[MAX_HEIGHT];	/* substitute right for left in comment above */
    short int lkey[MAX_HEIGHT];               /* array indexed by height h mapping the key delimiting L[h] and
					       S[h] to its item number within the node CFL[h] */
    short int rkey[MAX_HEIGHT];               /* substitute r for l in comment above */
    short int insert_size[MAX_HEIGHT];        /* the number of bytes by we are trying to add or remove from
						 S[h]. A negative value means removing.  */
    short int blknum[MAX_HEIGHT];             /* number of nodes that will replace node S[h] after
						 balancing on the level h of the tree.  If 0 then S is
						 being deleted, if 1 then S is remaining and no new nodes
						 are being created, if 2 or 3 then 1 or 2 new nodes is
						 being created */
    
    /* fields that are used only for balancing leaves of the tree */
    short int cur_blknum;	/* number of empty blocks having been already allocated			*/
    short int s0num;             /* number of items that fall into left most  node when S[0] splits	*/
    short int s1num;             /* number of items that fall into first  new node when S[0] splits	*/
    short int s2num;             /* number of items that fall into second new node when S[0] splits	*/
    short int lbytes;            /* number of bytes which can flow to the left neighbor from the	left	*/
    /* most liquid item that cannot be shifted from S[0] entirely		*/
    /* if -1 then nothing will be partially shifted */
    short int rbytes;            /* number of bytes which will flow to the right neighbor from the right	*/
    /* most liquid item that cannot be shifted from S[0] entirely		*/
    /* if -1 then nothing will be partially shifted                           */
    short int s1bytes;		/* number of bytes which flow to the first  new node when S[0] splits	*/
            			/* note: if S[0] splits into 3 nodes, then items do not need to be cut	*/
    short int s2bytes;
    struct buffer_head * buf_to_free[MAX_FREE_BLOCK]; /* buffers which are to be freed after do_balance finishes by unfix_nodes */
    char * vn_buf;		/* kmalloced memory. Used to create
				   virtual node and keep map of
				   dirtied bitmap blocks */
    int vn_buf_size;		/* size of the vn_buf */
    struct virtual_node * tb_vn;	/* VN starts after bitmap of bitmap blocks */
} ;



/* These are modes of balancing */

/* When inserting an item. */
#define M_INSERT	'i'
/* When inserting into (directories only) or appending onto an already
   existant item. */
#define M_PASTE		'p'
/* When deleting an item. */
#define M_DELETE	'd'
/* When truncating an item or removing an entry from a (directory) item. */
#define M_CUT 		'c'

/* used when balancing on leaf level skipped (in reiserfsck) */
#define M_INTERNAL	'n'

/* When further balancing is not needed, then do_balance does not need
   to be called. */
#define M_SKIP_BALANCING 		's'
#define M_CONVERT	'v'

/* modes of leaf_move_items */
#define LEAF_FROM_S_TO_L 0
#define LEAF_FROM_S_TO_R 1
#define LEAF_FROM_R_TO_L 2
#define LEAF_FROM_L_TO_R 3
#define LEAF_FROM_S_TO_SNEW 4

#define FIRST_TO_LAST 0
#define LAST_TO_FIRST 1

/* used in do_balance for passing parent of node information that has been
   gotten from tb struct */
struct buffer_info {
    struct buffer_head * bi_bh;
    struct buffer_head * bi_parent;
    int bi_position;
};


/* there are 4 types of items: stat data, directory item, indirect, direct.
   FIXME: This table does not describe new key format
+-------------------+------------+--------------+------------+
|	            |  k_offset  | k_uniqueness | mergeable? |
+-------------------+------------+--------------+------------+
|     stat data     |	0        |      0       |   no       |
+-------------------+------------+--------------+------------+
| 1st directory item| DOT_OFFSET |DIRENTRY_UNIQUENESS|   no       | 
| non 1st directory | hash value |              |   yes      |
|     item          |            |              |            |
+-------------------+------------+--------------+------------+
| indirect item     | offset + 1 |TYPE_INDIRECT |   if this is not the first indirect item of the object
+-------------------+------------+--------------+------------+
| direct item       | offset + 1 |TYPE_DIRECT   | if not this is not the first direct item of the object
+-------------------+------------+--------------+------------+
*/



#define KEY_IS_STAT_DATA_KEY(p_s_key) 	( get_type (p_s_key) == TYPE_STAT_DATA )
#define KEY_IS_DIRECTORY_KEY(p_s_key)	( get_type (p_s_key) == TYPE_DIRENTRY )
#define KEY_IS_DIRECT_KEY(p_s_key) 	( get_type (p_s_key) == TYPE_DIRECT )
#define KEY_IS_INDIRECT_KEY(p_s_key)	( get_type (p_s_key) == TYPE_INDIRECT )

#define I_IS_STAT_DATA_ITEM(p_s_ih) 	KEY_IS_STAT_DATA_KEY(&((p_s_ih)->ih_key))
#define I_IS_DIRECTORY_ITEM(p_s_ih) 	KEY_IS_DIRECTORY_KEY(&((p_s_ih)->ih_key))
#define I_IS_DIRECT_ITEM(p_s_ih) 	KEY_IS_DIRECT_KEY(&((p_s_ih)->ih_key))
#define I_IS_INDIRECT_ITEM(p_s_ih) 	KEY_IS_INDIRECT_KEY(&((p_s_ih)->ih_key))

#define is_indirect_ih(ih) I_IS_INDIRECT_ITEM(ih)
#define is_direct_ih(ih) I_IS_DIRECT_ITEM(ih)
#define is_direntry_ih(ih) I_IS_DIRECTORY_ITEM(ih)
#define is_stat_data_ih(ih) I_IS_STAT_DATA_ITEM(ih)

#define is_indirect_key(key) KEY_IS_INDIRECT_KEY(key)
#define is_direct_key(key) KEY_IS_DIRECT_KEY(key)
#define is_direntry_key(key) KEY_IS_DIRECTORY_KEY(key)
#define is_stat_data_key(key) KEY_IS_STAT_DATA_KEY(key)

#define COMP_KEYS comp_keys

//#define COMP_SHORT_KEYS comp_short_keys
#define not_of_one_file comp_short_keys

/* number of blocks pointed to by the indirect item */
#define I_UNFM_NUM(p_s_ih)	( ih_item_len(p_s_ih) / UNFM_P_SIZE )

/* the used space within the unformatted node corresponding to pos within the item pointed to by ih */
#define I_POS_UNFM_SIZE(ih,pos,size) (((pos) == I_UNFM_NUM(ih) - 1 ) ? (size) - ih_free_space (ih) : (size))

/* check whether byte number 'offset' is in this item */
#define I_OFF_BYTE_IN_ITEM(p_s_ih, n_offset, n_blocksize) \
                  ( get_offset(&(p_s_ih)->ih_key) <= (n_offset) && \
                    get_offset(&(p_s_ih)->ih_key) + get_bytes_number(p_s_ih,n_blocksize) > (n_offset) )

/* get the item header */ 
#define B_N_PITEM_HEAD(bh,item_num) ( (struct item_head * )((bh)->b_data + BLKH_SIZE) + (item_num) )

/* get key */
#define B_N_PDELIM_KEY(bh,item_num) ( (struct key * )((bh)->b_data + BLKH_SIZE) + (item_num) )

/* get the key */
#define B_N_PKEY(bh,item_num) ( &(B_N_PITEM_HEAD(bh,item_num)->ih_key) )

/* get item body */
#define B_N_PITEM(bh,item_num) ( (bh)->b_data + ih_location(B_N_PITEM_HEAD((bh),(item_num))))

/* get the stat data by the buffer header and the item order */
#define B_N_STAT_DATA(bh,nr) \
( (struct stat_data *)((bh)->b_data+ih_location(B_N_PITEM_HEAD((bh),(nr))) ) )

 /* following defines use reiserfs buffer header and item header */
 /* get item body */
#define B_I_PITEM(bh,ih) ( (bh)->b_data + ih_location(ih))

/* get stat-data */
#define B_I_STAT_DATA(bh, ih) ( (struct stat_data * )B_I_PITEM(bh,ih) )

#define MAX_DIRECT_ITEM_LEN(size) ((size) - BLKH_SIZE - 2*IH_SIZE - SD_SIZE - UNFM_P_SIZE)

/* indirect items consist of entries which contain blocknrs, pos
   indicates which entry, and B_I_POS_UNFM_POINTER resolves to the
   blocknr contained by the entry pos points to */
#define B_I_POS_UNFM_POINTER(bh,ih,pos) (*(((__u32 *)B_I_PITEM(bh,ih)) + (pos)))



/***************************************************************************/
/*                    FUNCTION DECLARATIONS                                */
/***************************************************************************/




/* objectid.c */
__u32 reiserfs_get_unused_objectid (struct reiserfs_transaction_handle *th);
void reiserfs_release_objectid (struct reiserfs_transaction_handle *th, __u32 objectid_to_release);
int reiserfs_convert_objectid_map_v1(struct super_block *s);


/* stree.c */
void padd_item (char * item, int total_length, int length);
int B_IS_IN_TREE(struct buffer_head *);
struct key * get_rkey (struct path * p_s_chk_path, struct super_block  * p_s_sb);
int bin_search (void * p_v_key, void * p_v_base, int p_n_num, int p_n_width, int * p_n_pos);
int search_by_key (struct super_block *, struct key *, struct path *, int * , int);
int search_by_entry_key (struct super_block * sb, struct key * key, struct path * path);
int search_for_position_by_key (struct super_block * p_s_sb, struct key * p_s_key, 
				struct path * p_s_search_path);
int search_by_objectid (struct super_block *, struct key *, struct path *, int *);
void decrement_counters_in_path (struct path * p_s_search_path);
void pathrelse (struct path * p_s_search_path);


int is_left_mergeable (struct super_block * s, struct path * path);
int is_right_mergeable (struct super_block * s, struct path * path);
int are_items_mergeable (struct item_head * left, struct item_head * right, int bsize);


/* fix_nodes.c */
void * reiserfs_kmalloc (size_t size, int flags, struct super_block * s);
void reiserfs_kfree (/*const*/ void * vp, size_t size, struct super_block * s);
int fix_nodes (/*struct reiserfs_transaction_handle *th,*/ int n_op_mode, struct tree_balance * p_s_tb, 
               /*int n_pos_in_item,*/ struct item_head * p_s_ins_ih);
void unfix_nodes (/*struct reiserfs_transaction_handle *th,*/ struct tree_balance *);
void free_buffers_in_tb (struct tree_balance * p_s_tb);
void init_path (struct path *);

/* prints.c */
#define PRINT_LEAF_ITEMS 1   /* print all items */
#define PRINT_ITEM_DETAILS 2 /* print contents of directory items and stat
                                data items and indirect items */
#define PRINT_DIRECT_ITEMS 4 /* print contents of direct items */
void print_tb (int mode, int item_pos, int pos_in_item, struct tree_balance * tb, char * mes);


void print_bmap (FILE * fp, reiserfs_filsys_t fs, int silent);
void print_objectid_map (FILE * fp, reiserfs_filsys_t fs);



/* lbalance.c */
int leaf_move_items (int shift_mode, struct tree_balance * tb, 
                     int mov_num, int mov_bytes, struct buffer_head * Snew);
int leaf_shift_left (struct tree_balance * tb, int shift_num, int shift_bytes);
int leaf_shift_right (struct tree_balance * tb, int shift_num, int shift_bytes);
void leaf_delete_items (reiserfs_filsys_t, struct buffer_info * cur_bi, 
                        int last_first, int first, int del_num, int del_bytes);
void leaf_insert_into_buf (reiserfs_filsys_t, struct buffer_info * bi, 
			   int before, struct item_head * inserted_item_ih, const char * inserted_item_body, 
			   int zeros_number);
void leaf_paste_in_buffer (reiserfs_filsys_t, struct buffer_info * bi, int pasted_item_num, 
			   int pos_in_item, int paste_size, const char * body, int zeros_number);
void leaf_cut_from_buffer (reiserfs_filsys_t, struct buffer_info * bi, int cut_item_num, 
                           int pos_in_item, int cut_size);
void leaf_paste_entries (struct buffer_head * bh, int item_num, int before, int new_entry_count,
			 struct reiserfs_de_head * new_dehs, const char * records,
			 int paste_size);
void delete_item (reiserfs_filsys_t fs, struct buffer_head * bh, int item_num);
void cut_entry (reiserfs_filsys_t fs, struct buffer_head * bh,
		int item_num, int entry_num, int del_count);


/* ibalance.c */
int balance_internal (struct tree_balance * , int, int, struct item_head * , 
                      struct buffer_head **);

/* do_balance.c */
void do_balance (struct tree_balance * tb,
                 struct item_head * ih, const char * body, int flag, int zeros_num);
void reiserfs_invalidate_buffer (struct tree_balance * tb, struct buffer_head * bh, int);
int get_left_neighbor_position (struct tree_balance * tb, int h);
int get_right_neighbor_position (struct tree_balance * tb, int h);
void replace_key (reiserfs_filsys_t, struct buffer_head *, int, struct buffer_head *, int);
void replace_lkey (struct tree_balance *, int, struct item_head *);
void replace_rkey (struct tree_balance *, int, struct item_head *);
void make_empty_node (struct buffer_info *);
struct buffer_head * get_FEB (struct tree_balance *);


__u64 get_bytes_number (struct item_head * ih, int blocksize);




/* hashes.c */
__u32 keyed_hash (const char *msg, int len);
__u32 yura_hash (const char *msg, int len);
__u32 r5_hash (const char *msg, int len);



/* node_format.c */
int get_journal_old_start_must (struct reiserfs_super_block * rs);
int get_journal_start_must (int blocksize);
/*extern hashf_t hashes [];*/


