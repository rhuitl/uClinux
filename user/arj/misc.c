/*
 * $Id: misc.c,v 1.5 2004/05/31 16:08:41 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Various system-independent routines are kept here. This module is needed if
 * the ENVIRON.C is linked, since both of them cross-reference each other.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Compact filelist array */

#if SFX_LEVEL>=ARJSFXV
 static unsigned char FAR * FAR *flist_array=NULL;
 static FILE_COUNT cfa_allocated;	/* # of allocated blocks */
#endif

/* Extended wildcard specifiers */

static char xwild_symbols[]="?*[]^";

/* Forward references */

static int xwild_propagate(char *wcstr, char *str);

#if SFX_LEVEL>=ARJ

/* Dumb extended wildcard lookup routine */

static int xwild_lookup(char *str)
{
 char *p;
 char c;

 for(p=str; *p!='\0'; p++)
 {
  c=*p;
  if(c=='*'||c=='?'||c=='['||c=='^')
   return(XW_OK);
 }
 return(XW_NONE);
}

/* An extended wildcard parser */

static int xwild_parser(char *wcstr, int *rc)
{
 char *p;
 char c;

 *rc=XWP_NONE;
 for(p=wcstr; *p!='\0'; p++)
 {
  c=*p;
  if(c=='^')
  {
   p++;
   if(*p=='\0')
   {
    *rc=XWP_TERM;
    return(XW_NONE);
   }
  }
  else if(c=='[')
  {
   p++;
   if((c=*p)==']')
   {
    *rc=XWP_NBRACKET;
    return(XW_NONE);
   }
   if(c=='\0')
   {
    *rc=XWP_OBRACKET;
    return(XW_NONE);
   }
   while(*p!=']')
   {
    if(*p=='^')
    {
     p++;
     if((c=*p)=='\0')
     {
      *rc=XWP_TERM;
      return(XW_NONE);
     }
    }
    else
     p++;
    if((c=*p)=='\0')
    {
     *rc=XWP_OBRACKET;
     return(XW_NONE);
    }
    if(*p=='-')
    {
     c=*++p;
     if(c=='\0'||c==']')
     {
      *rc=XWP_MDASH;
      return(XW_NONE);
     }
     if(*p=='^')
      p++;
     if((c=*p++)=='\0')
     {
      *rc=XWP_TERM;
      return(XW_NONE);
     }
    }
   }
  }
  else
   p++;
 }
 return(XW_OK);
}

/* Extended wildcard expansion and matching routine */

static int xwild_match(char *wcstr, char *str)
{
 char *wptr;
 char *sptr;
 char c, sc;
 char fchar;
 int xchar;
 int pflag;
 int unproc;
 char xc, xpc;                          /* Wildcard processed characters */

 wptr=wcstr;
 sptr=str;
 while(*wptr!='\0')
 {
  if((c=*sptr)=='\0')
   return((*wptr=='*'&&*++wptr=='\0')?XW_OK:XW_OWC);
  fchar=*wptr;
  switch(fchar)
  {
   case '*':
    return(xwild_propagate(wptr, sptr));
   case '[':
    xchar=0;
    wptr++;
    if(*wptr=='!')
    {
     xchar=1;
     wptr++;
    }
    unproc=0;
    pflag=1;
    while(pflag!=0)
    {
     if(*wptr!=']')
     {
      c=(*wptr=='^')?*++wptr:*wptr;     /* Escape character */
      xpc=xc=toupper(c);
      if(c=='\0')
       return(XW_TERM);
      wptr++;
      if(*wptr=='-')
      {
       c=*++wptr;
       if(c=='\0'&&c!=']')
        return(XW_TERM);
       xc=toupper(c);
       if(xc=='^')
       {
        c=*++wptr;
        xc=toupper(c);
        if(xc=='\0')
         return(XW_TERM);
       }
       wptr++;
      }
      sc=toupper(*sptr);
      if((xpc>=xc&&sc>=xc&&sc<=xpc)||(sc>=xpc&&sc<=xc))
      {
       unproc=1;
       pflag=0;
      }
     }
     else
      pflag=0;
    }
    if((xchar!=0&&unproc)||(xchar==0&&!unproc))
     return(XW_UNPROC);
    if(!unproc)
     break;
    /* Skip the rest, applying usual check-ups */
    while(*wptr!=']')
    {
     if(*wptr=='\0')
      return(XW_TERM);
     if(*wptr=='^')
     {
      if(*++wptr=='\0')
       return(XW_TERM);
     }
     wptr++;
    }
    break;
   case '?':
    break;                              /* Skip the comparison */
   case '^':
    wptr++;
    if(*wptr=='\0')
     return(XW_TERM);
   default:                             /* fallthru */
    if(toupper(*wptr)!=toupper(*sptr))
     return(XW_MISMATCH);
    break;
  }
  wptr++;
  sptr++;
 }
 return((*sptr=='\0')?XW_OK:XW_PREM_END);
}

/* Propagates (expands) wildcard markers */

static int xwild_propagate(char *wcstr, char *str)
{
 int rc=0;
 char c;

 while(*wcstr=='?'||*wcstr=='*')
 {
  if(*wcstr=='?')
  {
   if(*++str=='\0')
    return(XW_OWC);
  }
  wcstr++;
 }
 if(*wcstr=='\0')
  return(XW_OK);
 if((c=*wcstr)=='^')
 {
  if((c=*++wcstr)=='\0')
   return(XW_TERM);
 }
 do
 {
  if(toupper(c)==toupper(*str)||c=='[')
   rc=xwild_match(wcstr, str);
  if(*str++=='\0')
   rc=XW_OWC;
 } while(rc!=XW_OK&&rc!=XW_OWC&&rc!=XW_TERM);
 return(rc);
}

/* Wildcard matching routine wrapper (provides boolean RCs) */

static int xwild_compare(char *wcstr, char *str)
{
 int xrc;

 xrc=xwild_match(wcstr, str);
 return((xrc==XW_OK)?XW_OK:XW_NONE);
}

/* Change all UNIX-style path specifiers to DOS-style ones in a given string */

void unix_path_to_dos(char *path)
{
 int i=0;
 if(translate_unix_paths)
 {
  while(path[i]!='\0')
  {
   if(path[i]==PATHSEP_UNIX)
    path[i]=PATHSEP_DEFAULT;
   i++;
  }
 }
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Allocate a block of memory that will exactly fit the length of string,
   and copy the string into this newly-created block. */

void *malloc_str(char *str)
{
 return(strcpy((char *)malloc_msg(strlen(str)+1), str));
}

#endif

#if SFX_LEVEL>=ARJ

/* The same as malloc_str, but it allocates near memory for far strings */

void *malloc_far_str(char FAR *str)
{
 char *k;

 k=malloc_msg(far_strlen(str)+1);
 far_strcpy((char FAR *)k, str);
 return(k);
}

#endif

#if SFX_LEVEL>=ARJ

/* Converts current time to a standard timestamp */

void cur_time_stamp(struct timestamp *dest)
{
 time_t cur_unixtime;

 cur_unixtime=time(NULL);
 ts_store(dest, OS_UNIX, cur_unixtime);
}

/* A strchr() function for far strings */

#if COMPILER!=MSC&&defined(TILED)
char FAR *far_strchr(char FAR *str, char chr)
{
 while(str[0]!=chr)
 {
  if(str[0]=='\0') return(NULL);
  str++;
 }
 return(str);
}
#endif

#endif

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)

/* A strcmp() function for far strings */

#if COMPILER!=MSC&&defined(TILED)
int far_strcmp(char FAR *str1, char FAR *str2)
{
 unsigned int k;

 for(k=0; str1[k]!='\0'&&str2[k]!='\0'; k++);
 return((int)(str1[k]-str2[k]));
}
#endif

/* A stricmp() function for far strings */

#if COMPILER!=MSC&&defined(TILED)
int far_stricmp(char FAR *str1, char FAR *str2)
{
 unsigned int k;

 for(k=0; toupper(str1[k]!='\0')&&toupper(str2[k]!='\0'); k++);
 return(toupper(str1[k])-toupper(str2[k]));
}
#endif

#endif

#if SFX_LEVEL>=ARJ||defined(REARJ)

/* A strcat() function for far strings */

#if COMPILER!=MSC&&defined(TILED)
char FAR *far_strcat(char FAR *dest, char FAR *src)
{
 char FAR *tmp_dest;

 tmp_dest=dest;
 while(tmp_dest[0]!='\0')
  tmp_dest++;
 do
  (tmp_dest++)[0]=src[0];
 while((src++)[0]!='\0');
 return(dest);
}
#endif

#endif

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)

/* A strcpy() function for far strings */

#if COMPILER!=MSC&&defined(TILED)
char FAR *far_strcpy(char FAR *dest, char FAR *src)
{
 int k;

 for(k=0; src[k]!='\0'; k++)
  dest[k]=src[k];
 dest[k]='\0';
 return(dest);
}
#endif

#endif

#if SFX_LEVEL>=ARJ

/* A strlen() function for far strings */

#if COMPILER!=MSC&&defined(TILED)
unsigned int far_strlen(char FAR *str)
{
 unsigned int k=0;

 while(str[k]!='\0')
  k++;
 return(k);
}
#endif

#endif

#if SFX_LEVEL>=ARJSFXV

/* Fills a buffer with the specified value */

#if COMPILER!=MSC&&defined(TILED)
void FAR *far_memset(void FAR *buf, int filler, unsigned int size)
{
 char FAR *p;
 unsigned int l;

 p=(char FAR *)buf;
 for(l=0; l<size; l++)
  *p++=(char)filler;
 return(buf);
}
#endif

#endif

#if SFX_LEVEL>=ARJSFXV

/* Copies at most n characters */

char FAR *far_strcpyn(char FAR *dest, char FAR *src, int limit)
{
 int k;

 for(k=1; k<limit&&src[0]!='\0'; k++)
 {
  (dest++)[0]=(src++)[0];
 }
 if(limit>0)
  dest[0]='\0';
 return(dest);
}

#endif

#if SFX_LEVEL>=ARJSFX

/* Converts the given string to 7-bit */

void to_7bit(char *str)
{
 while(*str!='\0')
  *str++&=0x7F;
}

#endif

#if SFX_LEVEL>=ARJSFX||defined(REARJ)

/* Convert a string to uppercase, depending on locale */

void strupper(char *s)
{
 #if SFX_LEVEL>=ARJSFXV||defined(REARJ)
  toupper_loc(s, strlen(s));
 #else
  while(*s!='\0')
  {
   *s=toupper(*s);
   s++;
  }
 #endif
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Convert a string to lowercase (note: no locale hack here - the one in
   strupper() was made exclusively for filename matching under DOS) */

void strlower(char *s)
{
 while(*s!='\0')
 {
  *s=tolower(*s);
  s++;
 }
}

#endif

#if SFX_LEVEL>=ARJ

/* Finds an entry in the filelist, returns 1 if matched. Wildcards allowed. */

int flist_find(struct flist_root *root, char *name)
{
 char tmp_name[FILENAME_MAX];           /* Hash filename storage */
 char n_path[FILENAME_MAX], f_path[FILENAME_MAX];
 FILE_COUNT entry;
 int pathname_length;
 int tmp_pathname_length;

 if(root==NULL)
  return(0);
 pathname_length=split_name(name, n_path, NULL);
 for(entry=0; entry<root->files; entry++)
 {
  flist_retrieve(tmp_name, NULL, root, entry);
  tmp_pathname_length=split_name(tmp_name, f_path, NULL);
  if(marksym_expansion)
  {
   if(tmp_pathname_length!=0&&strlen(tmp_name)==tmp_pathname_length&&xwild_compare(f_path, n_path)==XW_OK)
     return(1);
   if(tmp_pathname_length==0||xwild_compare(f_path, n_path)==XW_OK)
   {
    if(xwild_compare(tmp_name+tmp_pathname_length, name+pathname_length)==XW_OK)
     return(1);
   }
  }
  else
  {
   /* If it was a directory specification, return OK */
   if(tmp_pathname_length!=0&&strlen(tmp_name)==tmp_pathname_length&&!strncmp_os(tmp_name, name, tmp_pathname_length))
    return(1);
   /* For filename specifications, proceed with compare */
   if(tmp_pathname_length==0||(tmp_pathname_length==pathname_length&&!strncmp_os(tmp_name, name, tmp_pathname_length)))
    if(match_wildcard(&name[pathname_length], &tmp_name[tmp_pathname_length]))
     return(1);
  }
 }
 return(0);
}

/* Checks if a file already exists in the archive */

int flist_is_in_archive(struct flist_root *root, char *name)
{
 char tmp_name[CCHMAXPATHCOMP];         /* For names retrieved from the hash */
 char case_name[CCHMAXPATHCOMP];        /* and for converting them to u-case */
 FILE_COUNT entry;

 for(entry=0; entry<root->files; entry++)
 {
  if(cfa_get(entry)==FLFLAG_PROCESSED)
  {
   flist_retrieve(tmp_name, NULL, root, entry);
   default_case_path(case_name, tmp_name);
   if(!stricmp(name, case_name))
    return(1);
  }
 }
 return(0);
}

/* Returns 1 if the file properties given match the current search narrowing
   criteria (such as "same or newer", and so on) */

int match_attrib(struct file_properties *properties)
{
 int matched;

 /* First, check if the attributes match */
 if(filter_attrs)
 {
  matched=0;
  if(file_attr_mask&TAG_DIREC&&properties->type==ARJT_DIR)
   matched=1;
  if(file_attr_mask&TAG_UXSPECIAL&&properties->type==ARJT_UXSPECIAL)
   matched=1;
  if(file_attr_mask&TAG_NORMAL&&
   !(properties->attrib&FATTR_DIREC)&&
   !(properties->attrib&FATTR_RDONLY)&&
   !(properties->attrib&FATTR_SYSTEM)&&
   !(properties->attrib&FATTR_HIDDEN)&&
     properties->type!=ARJT_UXSPECIAL)
   matched=1;
  if(file_attr_mask&TAG_RDONLY&&properties->attrib&FATTR_RDONLY)
   matched=1;
  if(file_attr_mask&TAG_HIDDEN&&properties->attrib&FATTR_HIDDEN)
   matched=1;
  if(file_attr_mask&TAG_SYSTEM&&properties->attrib&FATTR_SYSTEM)
   matched=1;
  if(file_attr_mask&TAG_ARCH&&!(properties->attrib&FATTR_ARCH))
   return(0);
  if(file_attr_mask&TAG_NOT_ARCH&&properties->attrib&FATTR_ARCH)
   return(0);
  if(!matched)
   return(0);
 }
 if(filter_fa_arch==FAA_BACKUP||filter_fa_arch==FAA_BACKUP_CLEAR)
 {
  if(!properties->isarchive)
   return(0);
 }
 /* Now, check the file against the time limits for it */
 /* ftime */
 if(ts_valid(tested_ftime_newer)&&(filter_same_or_newer==TCHECK_NDAYS||filter_same_or_newer==TCHECK_FTIME))
 {
  if(properties->ftime<ts_native(&tested_ftime_newer, OS))
   return(0);
 }
 if(ts_valid(tested_ftime_older)&&(filter_older==TCHECK_NDAYS||filter_older==TCHECK_FTIME))
 {
  if(properties->ftime>=ts_native(&tested_ftime_older, OS))
   return(0);
 }
 /* ctime */
 if(ts_valid(tested_ftime_newer)&&filter_same_or_newer==TCHECK_CTIME)
 {
  if(properties->ctime<ts_native(&tested_ftime_newer, OS))
   return(0);
 }
 if(ts_valid(tested_ftime_older)&&filter_older==TCHECK_CTIME)
 {
  if(properties->ctime>=ts_native(&tested_ftime_older, OS))
   return(0);
 }
 /* atime */
 if(ts_valid(tested_ftime_newer)&&filter_same_or_newer==TCHECK_ATIME)
 {
  if(properties->atime<ts_native(&tested_ftime_newer, OS))
   return(0);
 }
 if(ts_valid(tested_ftime_older)&&filter_older==TCHECK_ATIME)
 {
  if(properties->atime>=ts_native(&tested_ftime_older, OS))
   return(0);
 }
 return(1);
}

/* Frees memory allocated for the hash table */

void flist_cleanup(struct flist_root *root)
{
 flist_cleanup_proc(root);
}

/* Adds an entry to the filelist if it does not already exist. Returns -1 if
   an error occured. */

int flist_add(struct flist_root *root, struct flist_root *search_flist, char *name, FILE_COUNT *count, struct file_properties *properties)
{
 FILE_COUNT i;
 
 if(search_flist!=NULL)
 {
  /* If an existing entry has been found, don't add anything */
  if(flist_find(search_flist, name))
  {
   if(count!=NULL)
    (*count)++;
   return(0);
  }
 }
 if(root!=NULL&&root->fsptr!=NULL&&!xwild_compare(root->fsptr, name))
 {
  if(count!=NULL)
   (*count)++;
  return(0);
 }
 if(properties!=NULL&&root==&flist_main&&!match_attrib(properties))
 {
  if(count!=NULL)
   (*count)++;
  return(0);
 }
 #if TARGET==UNIX
  /* Resolve hard links if there are any */
  if(properties!=NULL&&
     properties->l_search.refcount>1&&
     !suppress_hardlinks)
   link_search(&l_entries, &properties->l_search, properties, root->files);
 #endif
 return(add_entry(root, name, count, properties));
}

/* Initializes the filelist storage structures */

void flist_init(struct flist_root *root, FILE_COUNT maxfiles, char type)
{
 flist_init_proc(root, maxfiles, type);
}

/* Retrieves an entry from the filelist */

void flist_retrieve(char *dest, struct file_properties *properties, struct flist_root *root, FILE_COUNT entry)
{
 retrieve_entry(dest, properties, root, entry);
}

/* Converts an extended wildcard to canonical wildcard */

static void xwild_to_canonical(char *name)
{
 char *tmp_name;
 char *xwptr;
 int entry;

 tmp_name=malloc_str(name);
 xwptr=strpbrk(tmp_name, xwild_symbols);
 if(xwptr!=NULL)
 {
  *(xwptr+1)='\0';
  entry=split_name(tmp_name, NULL, NULL);
  if(entry>0)
  {
   tmp_name[entry-1]='\0';
   sprintf(name, "%s%c%s", tmp_name, PATHSEP_DEFAULT, all_wildcard);
  }
  else
   strcpy(name, all_wildcard);
 }
 free(tmp_name);
}

#endif

#if SFX_LEVEL>=ARJSFXV

/* Expands wildcards and prepares a file list */

int flist_add_files(struct flist_root *root, struct flist_root *search_flist, char *name, int expand_wildcards, int recurse_subdirs, int file_type, FILE_COUNT *count)
{
 int result;
 char *tmp_name;
 #if SFX_LEVEL>=ARJ
  int parse_rc;
 #endif

 #if SFX_LEVEL>=ARJ
  if(expand_wildcards&&marksym_expansion&&xwild_lookup(name)==XW_OK&&
     xwild_parser(name, &parse_rc)==XW_OK)
  {
   /* ASR fix for variable all_wildcard length follows: */
   tmp_name=(char *)malloc_msg(strlen(name)+strlen(all_wildcard)+1);
   strcpy(tmp_name, name);
   root->fsptr=malloc_str(tmp_name);
   xwild_to_canonical(tmp_name);
   result=wild_list(root, search_flist, tmp_name, expand_wildcards, recurse_subdirs, file_type, count);
   root->no_dupl=1;
   free(tmp_name);
  }
  else
  {
   result=wild_list(root, search_flist, name, expand_wildcards, recurse_subdirs, file_type, count);
   root->no_dupl=1;
  }
 #else
  if((tmp_name=(char *)malloc(strlen(name)+1))==NULL)
  {
   msg_cprintf(0, M_HASH_MEM_LACK, name);
   result=-1;
  }
  else
  {
   result=0;
   strcpy(tmp_name, name);
   case_path(tmp_name);
   if(add_entry(root, search_flist, tmp_name, count))
    result=-1;
   free(tmp_name);
  }
 #endif
 return(result);
}

#if SFX_LEVEL>=ARJSFXV

/* Returns pointer to the idx-th element, enlarging the CFA if required */

static unsigned char FAR *cfa_get_index(FILE_COUNT idx)
{
 FILE_COUNT fblock;

 if(flist_array==NULL)
  cfa_allocated=0L;
 fblock=idx/CFA_BLOCK_SIZE;
 /* Enlarge the CFA */
 if(fblock>=cfa_allocated)
 {
  flist_array=(unsigned char FAR * FAR *)
	      farrealloc_msg(
               flist_array,
               (fblock+1)*sizeof(char FAR *)
              );
  while(cfa_allocated<=fblock)
   flist_array[cfa_allocated++]=NULL;
 }
 /* Allocate a new block if it has been empty before */
 if(flist_array[fblock]==NULL)
  flist_array[fblock]=(char FAR *)farmalloc_msg((CFA_BLOCK_SIZE+3)>>2);
 return(flist_array[fblock]+((idx%CFA_BLOCK_SIZE)>>2));
}

/* Releases the CFA structure */

void cfa_shutdown()
{
 unsigned long i;

 if(flist_array!=NULL)
 {
  for(i=0; i<cfa_allocated; i++)
  {
   if(flist_array[i]!=NULL)
   {
    farfree(flist_array[i]);
    flist_array[i]=NULL;
   }
  }
  farfree(flist_array);
  flist_array=NULL;
 }
}

/* Retrieves a CFA element */

int cfa_get(FILE_COUNT num)
{
 int pos_num;
 unsigned char bit_mask, value_bits;

 pos_num=(int)(num%4)<<1;
 bit_mask=(unsigned char)3<<pos_num;
 value_bits=*cfa_get_index(num)&bit_mask;
 return(value_bits>>pos_num);
}

/* Stores an element in the CFA */

void cfa_store(FILE_COUNT num, int value)
{
 int pos_num;
 unsigned char bit_mask, value_bits;
 unsigned char FAR *p;

 pos_num=(int)(num%4)<<1;
 bit_mask=(unsigned char)3<<pos_num;
 value_bits=(unsigned char)value<<pos_num;
 p=cfa_get_index(num);
 *p=(*p&=~bit_mask)|value_bits;
}

/* Initializes the CFA structures */

int cfa_init(FILE_COUNT capacity)
{
 unsigned long bytes;
 FILE_COUNT i;

 bytes=(unsigned long)capacity>>2;
 flist_array=farmalloc_msg(bytes+1);
 for(i=0; i<capacity; i++)
  cfa_store(i, FLFLAG_TO_PROCESS);
 return(0);                             /* ASR fix for High C -- 01/04/2001 */
}

#endif

/* Allocates a block of memory, executes error stub if failed */

void *malloc_msg(unsigned int size)
{
 void *tmp;

 #ifdef DEBUG
  if(debug_enabled&&strchr(debug_opt, 'm')!=NULL)
   printf("(Nm%u", size);
 #endif
 if((tmp=malloc(size))==NULL)
  error(M_OUT_OF_NEAR_MEMORY);
 #ifdef DEBUG
  if(debug_enabled&&strchr(debug_opt, 'm')!=NULL)
   printf(")");
 #endif
 return(tmp);
}

#endif

#if SFX_LEVEL>=ARJSFXV||defined(ARJUTIL)

/* Allocates a block of far memory, executes error stub if failed.
   Implementation-dependent (farmalloc for Borland, _fmalloc for MS C) */

void FAR *farmalloc_msg(unsigned long size)
{
 void FAR *tmp;

 #if defined(DEBUG)&&!defined(ARJUTIL)
  if(debug_enabled&&strchr(debug_opt, 'm')!=NULL)
   printf("(Fm%u", size);
 #endif
 if((tmp=farmalloc(size))==NULL)
  #ifdef ARJUTIL
   {
    printf("Failed to farmalloc(%lu)\n", size);
    exit(1);
   }
  #else
   error(M_OUT_OF_MEMORY);
  #endif
 #if defined(DEBUG)&&!defined(ARJUTIL)
  if(debug_enabled&&strchr(debug_opt, 'm')!=NULL)
   printf(")");
 #endif
 return(tmp);
}

#endif

#if SFX_LEVEL>=ARJSFX

/* Reallocates a block of far memory, executes error stub if failed.
   Implementation-dependent (farrealloc for Borland, _frealloc for MS C) */

void FAR *farrealloc_msg(void FAR *memblock, unsigned long size)
{
 void FAR *tmp;

 if((tmp=farrealloc(memblock, size))==NULL)
  error(M_OUT_OF_MEMORY);
 return(tmp);
}

#endif

#ifdef REARJ

/* Replaces all LF characters with 0's, returning the end of string */

char *tokenize_lf(char *str)
{
 while(*str!='\0')
 {
  if(*str=='\n')
   *str='\0';
  str++;
 }
 return(str);
}

#endif
