/*
 * $Id: filelist.h,v 1.2 2003/02/07 17:21:13 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Prototypes of the functions located in FILELIST.C are declared here.
 *
 */

#ifndef FILELIST_INCLUDED
#define FILELIST_INCLUDED

/* The filelist models in ARJ and ARJSFX are completely different, however,
   the naming, purpose, and sometimes the parameters of routines are the same,
   hence we insist on keeping the code parts together.

   The SIMPLE_FLIST constant controls the way of compile. */

#if SFX_LEVEL<=ARJSFXV
 #define SIMPLE_FLIST
#endif

#ifndef SIMPLE_FLIST

/* Block defines */

#define FLIST_BLOCK_SIZE        2048    /* Minimum granularity of blocks */
#define ENTRIES_PER_BLOCK         85    /* May be increased */

#endif

/* File list types */

#define FL_STANDARD                0    /* For smaller lists */
#define FL_HASH                    1    /* Hash table with CRC matching */

/* Special return codes */

#define FLS_END  (FLIST_SPEC_BASE+0)    /* Indicates end of enumerator list */
#define FLS_NONE (FLIST_SPEC_BASE+1)    /* Link search failure */

/* Advanced filelist structures */

#ifndef SIMPLE_FLIST

/* ID block in hash tables. This structure is never used as a variable, its
   members are referenced with pointers. */

struct idblock
{
 unsigned int total_entries;            /* # of entries */
 unsigned int size;
 unsigned int crc[64];                  /* 2-byte CRCs (v 2.72+) */
 /* Don't know/care about the padding that must go here. It may be
    intended to compensate the (ENTRIES_PER_BLOCK-64) number of CRC units,
    e.g. it must be unsigned int pad[21] but we omit it for memory
    conservation reasons. -- ASR fix for v 2.72.03 */
 int sub_offset[ENTRIES_PER_BLOCK];     /* Subpointers */
 char filler[1];                        /* Beginning of raw data */
};

/* Filelist data table (pointed to by a root entry) */

struct flist_table
{
 int xlist_blocks;                      /* Initialized with 8 */
 unsigned long FAR *enumerators;        /* Entry enumerators */
 int hiblock;                           /* Highest # of block */
 unsigned int block;                    /* ID of block that was recently fetched */
 unsigned int block_to_flush;           /* ID of block to be flushed */
 int low_block;                         /* Lowest block number */
 char not_flushed;                      /* 0 if cache is saved */
 char not_allocated;                    /* 0 if cache is initialized */
 struct idblock FAR *cache;             /* Caching area */
 struct idblock FAR *sec_cache;         /* Secondary caching area */
 char FAR *hcrc;                        /* Internal CRC? */
 short xms_handle;                      /* One per table */
 int xms_mem_blocks;                    /* Blocks in XMS */
 char FAR * FAR *far_ptrs;              /* Pointers to FAR blocks */
 FILE *sf_stream;                       /* Temporary file */
 char *sf_name;                         /* Temporary file name */
};

#endif

#if TARGET==UNIX

/* Hardlink candidates */

struct l_entries
{
 struct l_search FAR *list;
 FILE_COUNT total;
 FILE_COUNT alloc;
};

#endif

/* Filelist root */

#ifndef SIMPLE_FLIST

struct flist_root
{
 char storage;
 /* char unk_01; */ /* It was here in original ARJ but we omitted it to lower
                       the memory requirements -- ASR fix for v 2.72.03 */
 char type;
 char no_dupl;
 FILE_COUNT maxfiles;
 FILE_COUNT files;
 char *fsptr;
 struct flist_table *table;
};

#else

struct flist_root
{
 FILE_COUNT maxfiles;                   /* Initialized */
 FILE_COUNT boundary;                   /* Next unsafe value */
 FILE_COUNT files;                      /* Count of file entries */
 int no_dupl;
 #ifdef REARJ
  int check_excl;
 #endif
 char FAR *checksums;                   /* Simplified hash table */
 char FAR * FAR *names;                 /* Filename array */
 #ifdef REARJ
  FILE_COUNT FAR *instances;
  FILE_COUNT d_files;
  FILE_COUNT d_boundary;
  char FAR * FAR *d_names;
 #endif
};

#endif

/* Prototypes */

void flist_cleanup_proc(struct flist_root *root);
#ifndef SIMPLE_FLIST
 void retrieve_entry(char *dest, struct file_properties *properties, struct flist_root *root, FILE_COUNT entry);
 int add_entry(struct flist_root *root, char *name, FILE_COUNT *count, struct file_properties *properties);
 void flist_init_proc(struct flist_root *root, FILE_COUNT maxfiles, char type);
#else
 void retrieve_entry(char *dest, struct flist_root *root, FILE_COUNT num);
 #ifdef REARJ
  int add_entry(struct flist_root *root, char *name, FILE_COUNT *count);
 #else
  int add_entry(struct flist_root *root, struct flist_root *search_flist, char *name, FILE_COUNT *count);
 #endif
 #ifdef REARJ
  void flist_init(struct flist_root *root, FILE_COUNT maxfiles, int no_dupl, int check_excl);
 #else
  void flist_init(struct flist_root *root, FILE_COUNT maxfiles, char no_dupl);
 #endif
#endif

#if SFX_LEVEL>=ARJ&&TARGET==UNIX
FILE_COUNT link_search(struct l_entries *entries, struct l_search *l_search, struct file_properties *properties, FILE_COUNT ref);
#endif

#endif
