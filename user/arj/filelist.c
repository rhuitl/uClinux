/*
 * $Id: filelist.c,v 1.4 2004/04/14 20:54:21 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * XMS routines and functions  for dealing  with file lists are located  here.
 * Note: the  current  caching algorithm  implies that  the filelist is  first
 * sequentially composed, then sequentially read. No random access.
 *
 */

#include "arj.h"
#ifndef SIMPLE_FLIST
 #include "arj_xms.h"
#endif

DEBUGHDR(__FILE__)                      /* Debug information block */

/* This file actually consists of two completely different code groups, one
   for ARJ full-featured filelists, and another one for simplified filelists
   created by ARJSFX. */

#ifndef SIMPLE_FLIST

#define FLIST_BLOCK_INCREMENT     16    /* Number of blocks to preallocate
                                           when a new block is allocated */
#define L_ENTRIES_INCREMENT      512    /* # of entries to reserve at once */

#if TARGET==DOS
 #define XMS_BLOCK_PREALLOC        2    /* Number of preallocated XMS blocks */
 #define XMS_MULTIPLIER (FLIST_BLOCK_SIZE/1024)
#endif

/* Local far heap constants */

#define FAR_PROBE             32000L    /* Amount of memory allocated to check
                                           if we're still alive */
#define FAR_HEAP_LOWBOUND     150000    /* If the amount of free memory goes
                                           below this, the heap needs to be
                                           relocated to XMS */

#else                                   /* ARJSFX constants */

#define FILES_PER_BLOCK            8
#ifdef REARJ
 #define BLOCKS_LIMIT            512
#else
 #define BLOCKS_LIMIT           1024
#endif

#endif

/* Private CRC union - used for hash table calculation in ARJ. In SFX, we'll
   use simple checksums instead. */

#ifndef SIMPLE_FLIST

struct crc_words
{
 unsigned short lo;
 unsigned short hi;
};

union crc32
{
 unsigned long crc32;
 struct crc_words x;
 char low;
};

#endif

#ifndef SIMPLE_FLIST

/* Private data. Again, it has effect in ARJ only. */

static FILE_COUNT flist_capacity;    	/* Filelist capacity (=const) */
static unsigned long crc_matches, hash_matches;

#endif

/* From this point onward, #define REARJ means #define SIMPLE_FLIST
   (although REARJ filelist model is far from SIMPLE) */

#ifdef REARJ

/* REARJ service routine - checks if a file is present in the exclusion list */

static int is_excluded(char *name)
{
 char tmp_name[CCHMAXPATH];
 int tmp_entry, e_entry;
 FILE_COUNT i;

 tmp_entry=split_name(name, NULL, NULL);
 for(i=0; i<flist_exclusion.files; i++)
 {
  retrieve_entry(tmp_name, &flist_exclusion, i);
  e_entry=split_name(tmp_name, NULL, NULL);
  if(e_entry!=0&&strlen(tmp_name)==e_entry&&!strncmp(tmp_name, name, e_entry))
   return(1);
  if(e_entry==0||(e_entry==tmp_entry&&!strncmp(tmp_name, name, e_entry)))
  {
   if(match_wildcard(name+tmp_entry, tmp_name+e_entry))
    return(1);
  }
 }
 return(0);
}

#endif

/* Since SFX won't permit neither XMS nor disk storage, a big part of code is
   skipped for it till find_match(). */

#ifndef SIMPLE_FLIST

/* A macro too free a block of XMS */

#define xms_free(root) free_xms(root->table->xms_handle)

/* Allocates a block of extended memory and stores its handle in the hash
   table entry given. */

#if TARGET==DOS
static int xms_malloc(unsigned long size, struct flist_root *root)
{
 unsigned short xmsize;                 /* Size of allocated XMS in blocks */
 short handle;

 xmsize=(unsigned short)(size/(unsigned long)FLIST_BLOCK_SIZE);
 if(size%(unsigned long)FLIST_BLOCK_SIZE!=0L)
  xmsize++;
 if(!allocate_xms(xmsize*XMS_MULTIPLIER, &handle))
  return(0);
 root->table->xms_handle=handle;
 return(1);
}
#endif

/* Reallocates a block of extended memory that belongs to the current hash
   structure */

#if TARGET==DOS
static int xms_realloc(unsigned long size, struct flist_root *root)
{
 struct xms_move xms_move;
 unsigned short xmsize;                 /* Size of allocated RAM in blocks */
 short handle, old_handle;

 xmsize=(unsigned short)(size/(unsigned long)FLIST_BLOCK_SIZE);
 if(size%(unsigned long)FLIST_BLOCK_SIZE!=0L)
  xmsize++;
 if(!allocate_xms(xmsize*XMS_MULTIPLIER, &handle))
  return(0);
 xms_move.src_handle=old_handle=root->table->xms_handle;
 xms_move.src_offset=0L;
 xms_move.dest_handle=handle;
 xms_move.dest_offset=0L;
 xms_move.length=(unsigned long)root->table->xms_mem_blocks*(unsigned long)FLIST_BLOCK_SIZE;
 if(!move_xms(&xms_move))
  return(0);                            /* Potential extended memory leak! */
 free_xms(old_handle);
 root->table->xms_handle=handle;
 return(1);
}
#endif

/* Creates a temporary swap file for holding file lists */

static void create_swapfile(struct flist_root *root)
{
 char *sf_name;

 sf_name=(char *)malloc_msg(CCHMAXPATH);
 sf_name[0]='\0';
 if(swptr_hm[0]!='\0')
  add_pathsep(strcpy(sf_name, swptr_hm));
 strcat(sf_name, arjtemp_spec);
 find_tmp_filename(sf_name);
 root->table->sf_name=(char *)malloc_msg(strlen(sf_name)+2);
 strcpy(root->table->sf_name, sf_name);
 if((root->table->sf_stream=file_open(root->table->sf_name, m_wbp))==NULL)
  error(M_CANTOPEN, root->table->sf_name);
 free(sf_name);
}

/* Reads the block given, moving it into the cache area */

static void get_heap_block(unsigned int block, struct flist_root *root)
{
 #if TARGET==DOS
  struct xms_move xms_move;
 #endif
 char *tmp_block;                       /* For transfers from far RAM */

 if(root->table->block!=block)
 {
  if(root->storage==BST_FAR)
   far_memmove((char FAR *)root->table->cache, (char FAR *)root->table->far_ptrs[block], FLIST_BLOCK_SIZE);
  else if(root->storage==BST_DISK)
  {
   fseek(root->table->sf_stream, (unsigned long)block*FLIST_BLOCK_SIZE, SEEK_SET);
   tmp_block=(char *)malloc_msg(FLIST_BLOCK_SIZE);
   if(fread(tmp_block, 1, FLIST_BLOCK_SIZE, root->table->sf_stream)!=FLIST_BLOCK_SIZE)
    error(M_CANTREAD);
   far_memmove((char FAR *)root->table->cache, (char FAR *)tmp_block, FLIST_BLOCK_SIZE);
   free(tmp_block);
  }
 #if TARGET==DOS
  else if(root->storage==BST_XMS)
  {
   xms_move.src_handle=root->table->xms_handle;
   xms_move.src_offset=(unsigned long)block*FLIST_BLOCK_SIZE;
   xms_move.dest_handle=0;
   xms_move.dest_offset=(unsigned long)(char FAR *)root->table->cache;
   xms_move.length=FLIST_BLOCK_SIZE;
   if(!move_xms(&xms_move))
    error(M_LISTING_XMS_ERROR, M_XMS_READ);
  }
 #endif
  root->table->block=block;
 }
}

/* Saves a cached block in the heap if it's necessary */

static void save_heap_block(struct flist_root *root, char FAR *data)
{
 #if TARGET==DOS
  struct xms_move xms_move;
 #endif
 unsigned int block;                    /* Block number */
 char *tmp_block;                       /* Temporary transfer area */

 if(root->table->not_flushed)
 {
  block=root->table->block_to_flush;
  if(root->storage==BST_FAR)
  {
   if(root->table->far_ptrs[block]==NULL)
    root->table->far_ptrs[block]=farmalloc_msg(FLIST_BLOCK_SIZE);
   far_memmove(root->table->far_ptrs[block], data, FLIST_BLOCK_SIZE);
  }
  else if(root->storage==BST_DISK)
  {
   if(root->table->sf_stream==NULL)
    create_swapfile(root);
   fseek(root->table->sf_stream, (unsigned long)block*FLIST_BLOCK_SIZE, SEEK_SET);
   tmp_block=malloc_msg(FLIST_BLOCK_SIZE);
   far_memmove((char FAR *)tmp_block, data, FLIST_BLOCK_SIZE);
   file_write(tmp_block, 1, FLIST_BLOCK_SIZE, root->table->sf_stream);
   free(tmp_block);
  }
 #if TARGET==DOS
  else if(root->storage==BST_XMS)
  {
   /* If the block number exceeds the quantity of allocated XMS blocks, resize
      XMS buffer */
   if(block>=root->table->xms_mem_blocks)
   {
    if(!xms_realloc((unsigned long)(block+FLIST_BLOCK_INCREMENT)*FLIST_BLOCK_SIZE, root))
     error(M_LISTING_XMS_ERROR, M_XMS_WRITE);
    root->table->xms_mem_blocks=block+FLIST_BLOCK_INCREMENT;
   }
   xms_move.src_handle=0;
   xms_move.src_offset=(unsigned long)data;
   xms_move.dest_handle=root->table->xms_handle;
   xms_move.dest_offset=(unsigned long)block*FLIST_BLOCK_SIZE;
   xms_move.length=(unsigned long)FLIST_BLOCK_SIZE;
   if(!move_xms(&xms_move))
    error(M_LISTING_XMS_ERROR, M_XMS_WRITE);
  }
 #endif
  root->table->not_flushed=0;
 }
}

/* Swaps all members of the given heap to disk */

static void relocate_heap(struct flist_root *root)
{
 unsigned int hiblock, curblock;

 hiblock=root->table->hiblock;
 root->table->sf_stream=NULL;
 for(curblock=0; curblock<=hiblock; curblock++)
 {
  root->storage=BST_FAR;
  get_heap_block(curblock, root);
  root->storage=BST_DISK;
  root->table->block_to_flush=curblock;
  root->table->not_flushed=1;
  save_heap_block(root, (char FAR *)root->table->cache);
  farfree(root->table->far_ptrs[curblock]);
 }
 farfree(root->table->far_ptrs);
 root->storage=BST_DISK;
}

/* Updates header CRCs */

static void update_hcrc(struct flist_root *root, unsigned long crc)
{
 unsigned short hr;
 union crc32 crc32;
 char h;

 crc32.crc32=crc;
 hr=65535-flist_capacity+1;
 hr=(hr<=crc32.x.lo)?crc32.x.lo-hr:crc32.x.lo;
 h=crc32.crc32>>29;
 root->table->hcrc[hr]|=(1<<h);
}

/* Reverts CRC, should return 0 if a hash match occured */

static unsigned int revert_hcrc(struct flist_root *root, unsigned long crc)
{
 unsigned short hr;
 union crc32 crc32;
 char h;

 crc32.crc32=crc;
 hr=65535-flist_capacity+1;
 hr=(hr<=crc32.x.lo)?crc32.x.lo-hr:crc32.x.lo;
 h=crc32.crc32>>29;
 return((unsigned int)root->table->hcrc[hr]&((unsigned char)1<<h));
}

#else

/* Returns a checksum for the given string -- "simple" implementation uses
   checksums rather than CRCs. */

static char checksum(char *str)
{
 char rc;

 rc=str[0];
 while(*++str!='\0')
  rc+=*str;
 return(rc);
}

#endif

#ifdef REARJ

/* (REARJ) looks for a name in backup filelist */

static FILE_COUNT find_d_match(struct flist_root *root, char *name)
{
 FILE_COUNT cur_file;

 if((cur_file=root->d_files)>0L)
 {
  do
  {
   cur_file--;
   if(!far_strccmp((char FAR *)name, root->d_names[cur_file]))
    return(cur_file+1);
  } while(cur_file!=0);
 }
 return(0);
}

#endif

/* Finds if a filename is present in the given filelist */

#ifndef REARJ
static int find_match(struct flist_root *root, char *name)
#else
static int find_match(struct flist_root *root, char *name, FILE_COUNT instance)
#endif
{
 #ifndef SIMPLE_FLIST
  int cur_entry;
  struct idblock FAR *idblock_ptr;
  char FAR *fnm_ptr;                    /* Pointer to filename in ID block */
  struct disk_file_info FAR *dptr;
  union crc32 crc_term;
  unsigned int crc_seed;
  int curblock;
  char *tmp_name;
 #else
  FILE_COUNT cur_entry;
  char c;
 #endif

 #ifndef SIMPLE_FLIST
  crc32term=CRC_MASK;
  tmp_name=malloc_str(name);
  crc32_for_block(tmp_name, strlen(tmp_name));
  free(tmp_name);
  if(!revert_hcrc(root, crc_term.crc32=crc32term))
   return(0);
  hash_matches++;
  crc_seed=crc_term.x.lo;
  idblock_ptr=root->table->cache;
  for(curblock=root->table->low_block; curblock<=root->table->hiblock; curblock++)
  {
   if(curblock!=root->table->block_to_flush)
   {
    get_heap_block(curblock, root);
    for(cur_entry=0; cur_entry<idblock_ptr->total_entries; cur_entry++)
    {
     if(idblock_ptr->crc[cur_entry]==crc_seed)
     {
      crc_matches++;
      dptr=(struct disk_file_info FAR *)&idblock_ptr->filler[idblock_ptr->sub_offset[cur_entry]];
      fnm_ptr=dptr->name;
      if(!far_strccmp(fnm_ptr, (char FAR *)name))
      {
       root->table->low_block=curblock;
       return(1);                       /* Matched */
      }
     }
    }
   }
  }
  for(curblock=0; curblock<root->table->low_block; curblock++)
  {
   if(curblock!=root->table->block_to_flush)
   {
    get_heap_block(curblock, root);
    for(cur_entry=0; cur_entry<idblock_ptr->total_entries; cur_entry++)
    {
     if(idblock_ptr->crc[cur_entry]==crc_seed)
     {
      crc_matches++;
      dptr=(struct disk_file_info FAR *)&idblock_ptr->filler[idblock_ptr->sub_offset[cur_entry]];
      fnm_ptr=dptr->name;
      if(!far_strccmp(fnm_ptr, (char FAR *)name))
      {
       root->table->low_block=curblock;
       return(1);                       /* Matched */
      }
     }
    }
   }
  }
  idblock_ptr=(struct idblock FAR *)root->table->sec_cache;
  for(cur_entry=0; cur_entry<idblock_ptr->total_entries; cur_entry++)
  {
   if(idblock_ptr->crc[cur_entry]==crc_seed)
   {
    dptr=(struct disk_file_info FAR *)&idblock_ptr->filler[idblock_ptr->sub_offset[cur_entry]];
    fnm_ptr=dptr->name;
    if(!far_strccmp(fnm_ptr, (char FAR *)name))
    {
     root->table->low_block=curblock;
     return(1);                         /* Matched */
    }
   }
  }
 #else
  c=checksum(name);
  for(cur_entry=0; cur_entry<root->files; cur_entry++)
  {
   /* Return # of file + 1 if everything matched */
   #ifndef REARJ
    if(root->checksums[cur_entry]==c&&!far_strccmp(root->names[cur_entry], (char FAR *)name))
     return(cur_entry+1);
   #else
    if(root->checksums[cur_entry]==c&&root->instances[cur_entry]==instance&&!far_strccmp(root->names[cur_entry], (char FAR *)name))
     return(cur_entry+1);
   #endif
  }
 #endif
 return(0);
}

#ifndef SIMPLE_FLIST

/* Frees memory structures associated with filelist search */

static void cache_cleanup(struct flist_root *root)
{
 if(!root->table->not_allocated)
 {
  if(root->table->hiblock>0||root->table->block_to_flush>0)
  {
   save_heap_block(root, (char FAR *)root->table->sec_cache);
   if(root->table->sec_cache!=NULL&&root->table->sec_cache!=root->table->cache)
    farfree(root->table->sec_cache);
   root->table->sec_cache=NULL;
  }
  if(root->table->hcrc!=NULL)
   farfree(root->table->hcrc);
  root->table->hcrc=NULL;
  root->table->not_allocated=1;
 }
}

/* Invalidates and releases the filelist root */

void flist_cleanup_proc(struct flist_root *root)
{
 int block;

 if(root->table==NULL)
  return;
 if(debug_enabled&&strchr(debug_opt, 'v')!=NULL)
 {
  msg_cprintf(0, M_XLIST_BLOCKS, root->table->xlist_blocks);
  if(root==&flist_main)
   msg_cprintf(0, M_HASH_MATCHES, hash_matches, crc_matches);
 }
 if(root->storage==BST_FAR)
 {
  for(block=0; block<root->table->xlist_blocks; block++)
  {
   if(root->table->far_ptrs[block]!=NULL)
    farfree(root->table->far_ptrs[block]);
  }
  farfree(root->table->far_ptrs);
 }
 else if(root->storage==BST_DISK&&root->table->sf_stream!=NULL)
 {
  fclose(root->table->sf_stream);
  file_unlink(root->table->sf_name);
  free(root->table->sf_name);
 }
#if TARGET==DOS
 else if(root->storage==BST_XMS)
  xms_free(root);
#endif
 if(root->storage!=BST_NONE)
 {
  if(root->table->enumerators!=NULL)
   farfree(root->table->enumerators);
  if(root->table->hcrc!=NULL)
   farfree(root->table->hcrc);
  if(root->table->sec_cache!=NULL&&root->table->sec_cache!=root->table->cache)
   farfree(root->table->sec_cache);
  if(root->table->cache!=NULL)
   farfree(root->table->cache);
  free(root->table);
  if(root->fsptr!=NULL)
   free(root->fsptr);
 }
 root->storage=BST_NONE;
}

#elif defined(REARJ)                    /* REARJ-only version of cleanup proc. */

void flist_cleanup_proc(struct flist_root *root)
{
 FILE_COUNT i;

 if(root->files>0)
 {
  for(i=0; i<root->files; i++)
   farfree(root->names[i]);
  for(i=0; i<root->d_files; i++)
   farfree(root->d_names[i]);
  farfree(root->names);
  farfree(root->instances);
  if(root->d_names!=NULL)
   farfree(root->d_names);
  if(root->checksums!=NULL)
   farfree(root->checksums);
  root->files=0;
 }
}

#endif

/* Retrieves a filename with given entry code from the list. Two implemenations
   follow... */

#ifndef SIMPLE_FLIST

void retrieve_entry(char *dest, struct file_properties *properties, struct flist_root *root, FILE_COUNT entry)
{
 struct idblock FAR *idblock_ptr;       /* Temporary cache pointer */
 struct disk_file_info FAR *dptr;
 int idx;                               /* Temporary idblock index */
 int curblock;

 idblock_ptr=root->table->cache;
 /* If there are unfreed locations, do neccessary cleanup */
 if(!root->table->not_allocated)
   cache_cleanup(root);
 if(root->table->hiblock<=0)
 {
  curblock=0;
  idblock_ptr=root->table->sec_cache;
 }
 else
 {
  for(curblock=0; curblock<=root->table->hiblock; curblock++)
  {
   if(root->table->enumerators[curblock]>entry)
    break;
  }
  if(curblock>0)
   curblock--;
  get_heap_block(curblock, root);
 }
 idx=idblock_ptr->sub_offset[entry-root->table->enumerators[curblock]];
 dptr=(struct disk_file_info FAR *)&idblock_ptr->filler[idx];
 /* Allow NULL destinations for hardlink search -- ASR fix 24/08/2001 */
 if(dest!=NULL)
  far_strcpy((char FAR *)dest, (char FAR *)dptr->name);
 if(properties!=NULL)
  far_memmove((char FAR *)properties, (char FAR *)&dptr->file_properties, sizeof(struct file_properties));
}

#else

/* Retrieves a filelist entry */

void retrieve_entry(char *dest, struct flist_root *root, FILE_COUNT num)
{
 #ifdef REARJ
  FILE_COUNT instance;
 #endif

 #ifdef REARJ
  instance=root->instances[num];
  far_strcpy((char FAR *)dest, root->d_names[instance-1]);
  far_strcat((char FAR *)dest, root->names[num]);
 #else
  far_strcpy((char FAR *)dest, root->names[num]);
 #endif
}

#endif

/* Adds an entry to the hash. Returns -1 if there was an error. There are two
   implementations of it. */

#ifndef SIMPLE_FLIST

int add_entry(struct flist_root *root, char *name, FILE_COUNT *count, struct file_properties *properties)
{
 struct idblock FAR *idblock_ptr;
 struct disk_file_info FAR *dptr;
 #ifdef TILED
  void FAR *tmp_ptr;                    /* Used for heap allocation test */
 #endif
 unsigned long tmp_crc;
 long tmp_offset;                       /* Offset to fileinfo in blocks */
 int new_blocks;                        /* New qty of XList blocks */
 int old_blocks;                        /* Old qty of XList blocks */
 int curblock;                          /* Cleanup loop variable */
 int index;                             /* Index in ID block */
 FILE_COUNT tmp_files;
 int tmp_hiblock;
 int extend_len;                        /* Number of bytes to reserve */

 if(root->files>=root->maxfiles)
 {
  #if SFX_LEVEL>=ARJSFXV
   msg_cprintf(0, M_NAMES_LIMIT, root->maxfiles, name);
  #else
   msg_cprintf(0, M_NAMES_LIMIT, root->maxfiles, name);
  #endif
  return(-1);
 }
 if((idblock_ptr=root->table->sec_cache)==NULL)
 {
  if(root->type!=FL_STANDARD)
   root->table->sec_cache=farmalloc_msg(FLIST_BLOCK_SIZE);
  else
   root->table->sec_cache=root->table->cache;
  idblock_ptr=root->table->sec_cache;
  idblock_ptr->total_entries=0;
  idblock_ptr->size=0;
 }
 /* ASR fix -- debug enhancement 03/10/2001 */
 if(debug_enabled&&strchr(debug_opt, '.')!=NULL)
  msg_cprintf(0, M_TOKEN, name);
 if(root->type!=FL_STANDARD&&root->no_dupl)
 {
  if(find_match(root, name))
  {
   if(count!=NULL)
    (*count)++;
   return(0);
  }
 }
 tmp_hiblock=root->table->hiblock;
 extend_len=strlen(name)+sizeof(struct file_properties);
 tmp_files=root->files;
 tmp_offset=(long)idblock_ptr->size;
 /* Check against limits */
 if(idblock_ptr->total_entries+1>ENTRIES_PER_BLOCK||(tmp_offset+(long)extend_len+1>(long)(FLIST_BLOCK_SIZE-sizeof(struct idblock)-2)))
 {
  save_heap_block(root, (char FAR *)root->table->sec_cache);
  /* WARNING: compiler-dependent... */
  #ifdef TILED
   if((tmp_ptr=farmalloc(FAR_PROBE))==NULL)
   {
    msg_cprintf(0, M_HASH_MEM_LACK, name);
    return(-1);
   }
   farfree(tmp_ptr);
  #endif
  /* If the far heap has overgrown its limits, relocate it to XMS ASAP */
  if(root->storage==BST_FAR&&filelist_storage!=BST_NONE)
  {
   if(root->files>max_filenames||farcoreleft()<FAR_HEAP_LOWBOUND)
    relocate_heap(root);
  }
  root->table->block_to_flush++;
  tmp_hiblock++;
  /* Reallocate the block if it's needed */
  if(tmp_hiblock+1>=root->table->xlist_blocks)
  {
   old_blocks=root->table->xlist_blocks;
   root->table->xlist_blocks=new_blocks=old_blocks+FLIST_BLOCK_INCREMENT;
   root->table->enumerators=farrealloc_msg(root->table->enumerators, (unsigned long)new_blocks*sizeof(unsigned long));
   if(root->storage==BST_FAR)
   {
    root->table->far_ptrs=farrealloc_msg(root->table->far_ptrs, (unsigned long)new_blocks*sizeof(char FAR *));
    /* Reset the newly created pointers to NULL */
    for(curblock=old_blocks; curblock<new_blocks; curblock++)
     root->table->far_ptrs[curblock]=NULL;
   }
  }
  /* New block starts, with no file entries yet */
  idblock_ptr->total_entries=0;
  idblock_ptr->size=0;
  tmp_offset=0L;
  root->table->hiblock=tmp_hiblock;
  root->table->enumerators[tmp_hiblock]=tmp_files;
  root->table->enumerators[tmp_hiblock+1]=FLS_END;
 }
 root->table->not_flushed=1;
 dptr=(struct disk_file_info FAR *)&idblock_ptr->filler[tmp_offset];
 far_strcpy(dptr->name, (char FAR *)name);
 if(properties!=NULL)
  far_memmove((char FAR *)&dptr->file_properties, (char FAR *)properties, sizeof(struct file_properties));
 index=tmp_files-root->table->enumerators[tmp_hiblock];
 idblock_ptr->sub_offset[index]=(int)tmp_offset;
 idblock_ptr->size=tmp_offset+extend_len+1;
 idblock_ptr->total_entries++;
 root->files++;
 if(root->type!=FL_STANDARD)
 {
  crc32term=CRC_MASK;
  crc32_for_block(name, strlen(name));
  tmp_crc=crc32term;
  update_hcrc(root, tmp_crc);
  idblock_ptr->crc[index]=(char)tmp_crc;
 }
 if(count!=NULL)
  (*count)++;
 return(0);
}

#else

#ifdef REARJ
int add_entry(struct flist_root *root, char *name, FILE_COUNT *count)
#else
int add_entry(struct flist_root *root, struct flist_root *search_flist, char *name, FILE_COUNT *count)
#endif
{
 long diff;
 char FAR * FAR *names_ptr;
 int nl;
 char FAR *nptr;
 unsigned int nblocks;
 char FAR *checksums_ptr;
 FILE_COUNT nfiles;
 #ifdef REARJ
  char tmp_name[CCHMAXPATH];
  char pathname[CCHMAXPATH];
  int tmp_entry;
  FILE_COUNT dir_num;
  FILE_COUNT FAR *instances_ptr;
 #endif

 if(root->files>=root->maxfiles)
 {
  #if SFX_LEVEL>=ARJSFXV
   msg_cprintf(0, M_NAMES_LIMIT, root->maxfiles, name);
  #else
   msg_cprintf(0, M_NAMES_LIMIT, root->maxfiles, name);
  #endif
  return(-1);
 }
 #ifdef REARJ
  if(root->check_excl&&is_excluded(name))
   return(0);
  tmp_entry=split_name(name, NULL, tmp_name);
  if(tmp_entry>0)
   strncpy(pathname, name, tmp_entry);
  pathname[tmp_entry]='\0';
  dir_num=find_d_match(root, pathname);
  if(root->no_dupl&&dir_num!=0&&find_match(root, tmp_name, dir_num))
   return(0);
 #else
  if(root->no_dupl&&find_match(root, name))
  {
   if(count!=NULL)
    (*count)++;
   return(0);
  }
 #endif
 /* Separate directory storage is available in (and required by) REARJ only */
 #ifdef REARJ
  if(dir_num==0)
  {
   if(root->d_files>=root->d_boundary)
   {
    diff=(long)root->maxfiles-root->d_files;
    diff=max(diff, 64L);
    diff+=(long)root->d_files;
    if((names_ptr=(char FAR * FAR *)farrealloc(root->d_names, diff*sizeof(char FAR *)))==NULL)
    {
     #if SFX_LEVEL>=ARJSFXV
      msg_cprintf(0, M_HASH_MEM_LACK, name);
     #else
      msg_cprintf(0, M_HASH_MEM_LACK, name);
     #endif
     return(-1);
    }
    root->d_names=names_ptr;
    root->d_boundary=(FILE_COUNT)diff;
   }
   nl=strlen(pathname);
   if((nptr=(char FAR *)farmalloc(nl+1))==NULL)
   {
    #if SFX_LEVEL>=ARJSFXV
     msg_cprintf(0, M_HASH_MEM_LACK, name);
    #else
     msg_cprintf(0, M_HASH_MEM_LACK, name);
    #endif
    return(-1);
   }
   root->d_names[root->d_files]=nptr;
   far_strcpy(nptr, (char FAR *)pathname);
   dir_num=++root->d_files;
  }
 #endif
 if(root->files>=root->boundary)
 {
  nblocks=root->maxfiles/FILES_PER_BLOCK;
  if(nblocks>BLOCKS_LIMIT)
   nblocks=BLOCKS_LIMIT;
  diff=(long)root->maxfiles-root->files;
  if((long)nblocks<diff)
   diff=(long)nblocks;
  diff+=(long)root->files;
  if((names_ptr=(char FAR * FAR *)farrealloc(root->names, diff*sizeof(char FAR *)))==NULL)
  {
   #if SFX_LEVEL>=ARJSFXV
    msg_cprintf(0, M_HASH_MEM_LACK, name);
   #else
    msg_cprintf(0, M_HASH_MEM_LACK, name);
   #endif
   return(-1);
  }
  checksums_ptr=NULL;
  if(root->no_dupl)
  {
   if((checksums_ptr=(char FAR *)farrealloc(root->checksums, diff*sizeof(FILE_COUNT)))==NULL)
   {
    #if SFX_LEVEL>=ARJSFXV
     msg_cprintf(0, M_HASH_MEM_LACK, name);
    #else
     msg_cprintf(0, M_HASH_MEM_LACK, name);
    #endif
    return(-1);
   }
  }
  #ifdef REARJ
   if((instances_ptr=(FILE_COUNT FAR *)farrealloc(root->instances, diff*sizeof(FILE_COUNT)))==NULL)
   {
    #if SFX_LEVEL>=ARJSFXV
     msg_cprintf(0, M_HASH_MEM_LACK, name);
    #else
     msg_cprintf(0, M_HASH_MEM_LACK, name);
    #endif
    return(-1);
   }
  #endif
  root->names=names_ptr;
  root->checksums=checksums_ptr;
  #ifdef REARJ
   root->instances=instances_ptr;
  #endif
  root->boundary=(FILE_COUNT)diff;
 }
 #ifdef REARJ
  nl=strlen(tmp_name);
 #else
  nl=strlen(name);
 #endif
 if((nptr=(char FAR *)farmalloc(nl+1))==NULL)
 {
  #if SFX_LEVEL>=ARJSFXV
   msg_cprintf(0, M_HASH_MEM_LACK, name);
  #else
   msg_cprintf(0, M_HASH_MEM_LACK, name);
  #endif
  return(-1);
 }
 nfiles=root->files;
 root->names[nfiles]=nptr;
 #ifdef REARJ
  far_strcpy(nptr, (char FAR *)tmp_name);
 #else
  far_strcpy(nptr, (char FAR *)name);
 #endif
 #ifdef REARJ
  root->instances[nfiles]=dir_num;
  if(root->no_dupl)
   root->checksums[nfiles]=checksum(tmp_name);
 #else
  if(root->no_dupl)
   root->checksums[nfiles]=checksum(name);
 #endif
 root->files++;
 if(count!=NULL)
  (*count)++;
 return(0);
}

#endif

/* Initializes the filelist storage */

#if SFX_LEVEL>=ARJ
void flist_init_proc(struct flist_root *root, FILE_COUNT maxfiles, char type)
#elif defined(REARJ)
void flist_init(struct flist_root *root, FILE_COUNT maxfiles, int no_dupl, int check_excl)
#else
void flist_init(struct flist_root *root, FILE_COUNT maxfiles, char no_dupl)
#endif
{
 #ifndef SIMPLE_FLIST
  int curblock, cur_entry;
  char *cptr;

  root->storage=BST_NONE;
  root->maxfiles=maxfiles;
  root->type=type;
  root->files=0L;
  root->no_dupl=0;
  root->fsptr=NULL;
  root->table=NULL;
  if(maxfiles==0L)
   return;
  if(root==&flist_main)
   hash_matches=crc_matches=0;
  if(debug_enabled&&strchr(debug_opt, 'v')!=NULL)
   msg_cprintf(0, M_SEARCH_FLAG, type);
  root->table=malloc_msg(sizeof(struct flist_table));
 #if TARGET==DOS
  if(detect_xms()&&filelist_storage==BST_XMS)
  {
   root->storage=BST_XMS;
   get_xms_entry();
   if(!xms_malloc(XMS_BLOCK_PREALLOC*FLIST_BLOCK_SIZE, root))
    error(M_LISTING_XMS_ERROR, M_XMS_INIT);
   root->table->xms_mem_blocks=XMS_BLOCK_PREALLOC;
  }
  else
 #endif
  if(filelist_storage!=BST_NONE&&max_filenames<50)
  {
   root->storage=BST_DISK;
   root->table->sf_stream=NULL;
  }
  else
  {
   root->storage=BST_FAR;
   root->table->far_ptrs=farmalloc_msg((unsigned long)FLIST_BLOCK_INCREMENT*sizeof(void FAR *));
   for(curblock=0; curblock<FLIST_BLOCK_INCREMENT; curblock++)
    root->table->far_ptrs[curblock]=NULL;
  }
  root->table->cache=farmalloc_msg(FLIST_BLOCK_SIZE);
  root->table->sec_cache=NULL;
  root->table->block=-1;
  root->table->block_to_flush=0;
  root->table->low_block=0;
  root->table->not_flushed=0;
  root->table->not_allocated=0;
  root->table->xlist_blocks=FLIST_BLOCK_INCREMENT;
  root->table->enumerators=farmalloc_msg((unsigned long)FLIST_BLOCK_INCREMENT*sizeof(FILE_COUNT));
  root->table->enumerators[0]=0;
  root->table->enumerators[1]=FLS_END;
  root->table->hiblock=0;
  root->table->hcrc=NULL;
  flist_capacity=FILELIST_CAPACITY;
  if(debug_enabled&&(cptr=strchr(debug_opt, 'z'))!=NULL)
   flist_capacity=(FILE_COUNT)strtol(cptr, &cptr, 10);
  if(root->type!=FL_STANDARD)
  {
   root->table->hcrc=farmalloc_msg((FILE_COUNT)flist_capacity);
   for(cur_entry=0; cur_entry<flist_capacity; cur_entry++)
    root->table->hcrc[cur_entry]=0;
  }
 #else
  root->maxfiles=maxfiles;
  root->no_dupl=(int)no_dupl;
  root->files=0;
  root->boundary=0;
  root->checksums=NULL;
  root->names=NULL;
  #ifdef REARJ
   root->check_excl=check_excl;
   root->d_files=0;
   root->d_boundary=0;
   root->d_names=NULL;
   root->instances=NULL;
  #endif
 #endif
}

#if SFX_LEVEL>=ARJ&&TARGET==UNIX

/* [Hard]link search routine. Either returns a pointer to an existing
   entry in l_search structure, or creates a new entry. May operate
   with symlinks too (e.g. elimination of circular links) */

FILE_COUNT link_search(struct l_entries *entries, struct l_search *l_search, struct file_properties *properties, FILE_COUNT ref)
{
 FILE_COUNT i;

 for(i=0; i<entries->total; i++)
 {
  /* The refcount values are not compared, since these may vary */
  if(!far_memcmp(&l_search->dev, (void FAR *)&entries->list[i].dev, sizeof(dev_t))&&
     l_search->inode==entries->list[i].inode)
  {
   if(properties!=NULL)
   {
    properties->islink=1;
    properties->l_search.ref=entries->list[i].ref;
    properties->type=ARJT_UXSPECIAL;
    properties->fsize=0L;
   }
   return(i);
  }
 }
 if(entries->total>=entries->alloc)
 {
  entries->alloc+=L_ENTRIES_INCREMENT;
  entries->list=(struct l_search FAR *)farrealloc_msg(entries->list, entries->alloc*sizeof(struct l_search));
 }
 entries->list[i]=*l_search;
 entries->list[i].ref=ref;
 entries->total++;
 return(FLS_NONE);
}

#endif
