/*
 * $Id: ea_mgr.c,v 1.4 2004/04/17 11:39:43 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This file provides basic routines for handling extended attributes.
 *
 */

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* OS/2 v 1.2 structure declarations for Win32 */

#if TARGET==WIN32

typedef struct _FEA {
	BYTE	fEA;		/* flags				*/
	BYTE	cbName; 	/* name length not including NULL	*/
	WORD	cbValue;	/* value length 			*/
} FEA;
typedef FEA FAR *PFEA;

/* flags for _FEA.fEA */

#define FEA_NEEDEA 0x80 	/* need EA bit */

typedef struct _FEALIST {
	DWORD  cbList;		/* total bytes of structure inc full list */
	FEA    list[1]; 	/* variable length FEA structures	  */
} FEALIST;
typedef FEALIST FAR * PFEALIST;

#endif

/* Local variables */

#if defined(HAVE_EAS)
static char longname_ea[]=".LONGNAME";
static char forbidden_chars[]="\\/:?*<>|";
#endif

/* Aligns any address to DWORD */

#if (TARGET==OS2&&defined(__32BIT__))||TARGET==WIN32
static char FAR *align_dword(char FAR *p)
{
 unsigned int p_l;

 p_l=(unsigned int)p;
 if(p_l%4==0)
  return(p);
 else
  return(p+4-(p_l%4));
}
#endif

/* Returns 1 if the EA is to be included/processed */

#if SFX_LEVEL>=ARJ&&defined(HAVE_EAS)
static int ea_filter(char FAR *name, int skip_ln)
{
 char tmp_name[CCHMAXPATH];

 far_strcpy((char FAR *)tmp_name, name);
 if(skip_ln&&!stricmp(tmp_name, longname_ea))
  return(0);
 if(include_eas&&!flist_find(&flist_ea, tmp_name))
  return(0);
 if(exclude_eas&&flist_find(&flist_xea, tmp_name))
  return(0);
 return(1);
}
#endif

/* Returns size of extended attributes attached to file */

unsigned int get_ea_size(char *name)
{
 #if TARGET==OS2
  #ifdef __32BIT__
   FILESTATUS4 fs;
  #else
   FILESTATUS2 fs;
  #endif
  unsigned int rc;

  #ifdef __32BIT__
   DosQueryPathInfo(name, FIL_QUERYEASIZE, (PVOID)&fs, sizeof(fs));
  #else
   DosQPathInfo(name, FIL_QUERYEASIZE, (PVOID)&fs, sizeof(fs), 0L);
  #endif
  rc=(fs.cbList>=4)?fs.cbList-4:fs.cbList;
  #ifdef __32BIT__
   rc>>=1;                             /* BUGBUG? */
  #endif
  return(rc);
 #elif TARGET==WIN32
  struct nt_sid *sid;
  unsigned long rc;

  if(!ea_supported||(sid=open_streams(name, 0))==NULL)
   return(0);
  rc=seek_stream_id(BACKUP_EA_DATA, sid);
  close_streams(sid);
  return((rc>0xFFFF)?0:rc);
 #else
  return(0);
 #endif
}

/* Returns EA block size */

unsigned int get_eablk_size(char FAR *blk)
{
 unsigned int rc;
 unsigned int i, total, data_len;
 char FAR *blk_ptr;

 total=mget_word(blk);
 rc=2;
 blk_ptr=blk+2;
 for(i=0; i<total; i++)
 {
  blk_ptr++;
  data_len=mget_byte(blk_ptr++);
  data_len+=mget_word(blk_ptr);
  blk_ptr+=2;
  rc+=data_len+4;
  blk_ptr+=data_len;
 }
 return(rc);
}

/* Returns # of EAs in the block to external caller */

unsigned int get_num_eas(char FAR *blk)
{
 return(mget_word(blk));
}

/* EA deletion routine */

int discard_ea(char *name)
{
 #if TARGET==OS2
  ULONG count;
  #ifdef __32BIT__
   APIRET rc;
   char FAR *real_pfeal;
   PFEA2LIST pfeal;
   EAOP2 eaop;
   PDENA2 pdena;
  #else
   USHORT rc;
   PFEALIST pfeal;
   EAOP eaop;
   PDENA1 pdena;
  #endif
  int rcode=0;

  #ifdef __32BIT__
   pdena=(PDENA2)farmalloc_msg(sizeof(*pdena)+CCHMAXPATHCOMP);
   real_pfeal=(char FAR *)farmalloc_msg(sizeof(*pdena)+CCHMAXPATHCOMP);
   pfeal=(PFEA2LIST)align_dword(real_pfeal);
  #else
   pdena=(PDENA1)farmalloc_msg(sizeof(*pdena)+CCHMAXPATHCOMP);
   pfeal=(PFEALIST)farmalloc_msg(sizeof(*pdena)+CCHMAXPATHCOMP);
  #endif
  while(1)
  {
   count=1L;
   #ifdef __32BIT__
    if(DosEnumAttribute(ENUMEA_REFTYPE_PATH, (PVOID)name, 1L, (PVOID)pdena,
                        sizeof(*pdena)+CCHMAXPATHCOMP, &count,
                        ENUMEA_LEVEL_NO_VALUE))
   #else
    if(DosEnumAttribute(ENUMEA_REFTYPE_PATH, (PVOID)name, 1L, (PVOID)pdena,
                        sizeof(*pdena)+CCHMAXPATHCOMP, &count,
                        ENUMEA_LEVEL_NO_VALUE, 0L))
   #endif
    break;
   if(count==0L)
    break;
   /* EA (pdena->szName) consumes (pdena->cbValue) bytes */
   #ifdef __32BIT__
    eaop.fpFEA2List=pfeal;
    pfeal->list[0].oNextEntryOffset=0;
   #else
    eaop.fpFEAList=pfeal;
   #endif
   pfeal->list[0].fEA=0;
   pfeal->list[0].cbName=far_strlen(pdena->szName);
   pfeal->list[0].cbValue=0;
   #ifdef __32BIT__
    far_strcpy((char FAR *)&(pfeal->list[0])+sizeof(FEA2)-1, pdena->szName);
    pfeal->cbList=(unsigned long)sizeof(FEA2LIST)+pfeal->list[0].cbName;
    if((rc=DosSetPathInfo(name, FIL_QUERYEASIZE, (PBYTE)&eaop, sizeof(eaop), 0))!=0)
    {
     rcode=-1;
     break;
    }
   #else
    far_strcpy((char FAR *)&(pfeal->list[0])+sizeof(FEA), pdena->szName);
    pfeal->cbList=(unsigned long)sizeof(FEALIST)+pfeal->list[0].cbName+1;
    if((rc=DosSetPathInfo(name, FIL_QUERYEASIZE, (PBYTE)&eaop, sizeof(eaop), 0, 0L))!=0)
    {
     rcode=-1;
     break;
    }
   #endif
  }
  farfree(pdena);
  #ifndef TILED
   farfree(real_pfeal);
  #endif
  return(rcode);
 #elif TARGET==WIN32
  /* There seems to be no easy way to not purge EAs using the backup APIs! */
  return(0);
 #else
  return(-1);
 #endif
}

/* Allocates memory for and stores extended attributes */

#if SFX_LEVEL>=ARJ
int query_ea(char FAR **dest, char *name, int skip_ln)
{
 #ifdef HAVE_EAS
  ULONG count, j;
  #if TARGET==OS2
   #ifdef __32BIT__
    EAOP2 eaop;
    PGEA2LIST pgeal;
    PFEA2LIST pfeal;
    APIRET rc;
    PDENA2 pdena;
    FILESTATUS4 fs;
   #else
    EAOP eaop;
    PGEALIST pgeal;
    PFEALIST pfeal;
    USHORT rc;
    PDENA1 pdena;
    FILESTATUS2 fs;
   #endif
  #elif TARGET==WIN32
   struct nt_sid *sid;
   unsigned char *streambuf;
   unsigned long stream_len;
   PFEALIST pfeal;
  #endif
  int rcode=0;
  char FAR *dptr, FAR *nptr;

  #if TARGET==OS2
   pdena=farmalloc_msg(sizeof(*pdena)+CCHMAXPATHCOMP);
   #ifdef __32BIT__
    pgeal=(PGEA2LIST)farmalloc_msg(sizeof(GEA2LIST)+CCHMAXPATHCOMP);
    if(DosQueryPathInfo(name, FIL_QUERYEASIZE, (PVOID)&fs, sizeof(fs)))
     return(-1);
   #else
    pgeal=(PGEALIST)farmalloc_msg(sizeof(GEALIST)+CCHMAXPATHCOMP);
    if(DosQPathInfo(name, FIL_QUERYEASIZE, (PVOID)&fs, sizeof(fs), 0L))
     return(-1);
   #endif
   if(fs.cbList<4)
    fs.cbList=4;                         /* Fix for Ext2FS */
   /* Allocate enough space to hold EA block */
   #ifdef __32BIT__
    *dest=(char FAR *)farmalloc_msg((int)fs.cbList*2); /* SDK does recommend it */
   #else
    *dest=(char FAR *)farmalloc_msg((int)fs.cbList-2);
   #endif
  #elif TARGET==WIN32
   if((sid=open_streams(name, 0))==NULL)
    return(-1);
   stream_len=seek_stream_id(BACKUP_EA_DATA, sid);
   if(stream_len==0||stream_len>65535)
   {
    close_streams(sid);
    *dest=(char FAR *)farmalloc_msg(2);
    dptr=*dest;
    mput_word(0, dptr);
    return(0);
   }
   /* It's a plain FEALIST, so doesn't require much caution */
   streambuf=(char FAR *)farmalloc_msg((int)stream_len);
   *dest=(char FAR *)farmalloc_msg((int)stream_len);
   if((stream_len=read_stream(streambuf, stream_len, sid))==0)
   {
    close_streams(sid);
    dptr=*dest;
    mput_word(0, dptr);
    free(streambuf);
    return(0);
   }
  #endif
  /* Initialize storage */
  dptr=*dest;
  mput_word(0, dptr);
  dptr+=2;
  j=0L;
  while(1)
  {
   #if TARGET==OS2
    count=1L;
    #ifdef __32BIT__
     if(DosEnumAttribute(ENUMEA_REFTYPE_PATH, (PVOID)name, ++j, (PVOID)pdena,
                         sizeof(*pdena)+CCHMAXPATHCOMP, &count,
                         ENUMEA_LEVEL_NO_VALUE))
      break;
    #else
     if(DosEnumAttribute(ENUMEA_REFTYPE_PATH, (PVOID)name, ++j, (PVOID)pdena,
                         sizeof(*pdena)+CCHMAXPATHCOMP, &count,
                         ENUMEA_LEVEL_NO_VALUE, 0L))
      break;
    #endif
    if(count==0L)
     break;
    /* EA (pdena->szName) consumes (pdena->cbValue) bytes */
    #ifdef __32BIT__
     eaop.fpGEA2List=pgeal;
    #else
     eaop.fpGEAList=pgeal;
    #endif
    far_strcpy(pgeal->list[0].szName, pdena->szName);
    pgeal->list[0].cbName=pdena->cbName;
    #ifdef __32BIT__
     pgeal->list[0].oNextEntryOffset=0;
     pgeal->cbList=sizeof(GEA2LIST)+pdena->cbName;
     eaop.fpGEA2List=pgeal;
     pfeal=(PFEA2LIST)farmalloc_msg(sizeof(FEA2LIST)+pdena->cbName+pdena->cbValue+1);
     pfeal->cbList=sizeof(FEA2LIST)+pdena->cbName+pdena->cbValue+1;
     eaop.fpFEA2List=pfeal;
     if((rc=DosQueryPathInfo(name, FIL_QUERYEASFROMLIST, (PBYTE)&eaop, sizeof(eaop)))!=0)
     {
      farfree(pfeal);
      rcode=-1;
      break;
     }
     nptr=(char FAR *)&(pfeal->list[0])+sizeof(FEA2)-1;
    #else
     pgeal->cbList=sizeof(GEALIST)+pdena->cbName;
     eaop.fpGEAList=pgeal;
     pfeal=(PFEALIST)farmalloc_msg(sizeof(FEALIST)+pdena->cbName+pdena->cbValue+1);
     pfeal->cbList=sizeof(FEALIST)+pdena->cbName+pdena->cbValue+1;
     eaop.fpFEAList=pfeal;
     if((rc=DosQPathInfo(name, FIL_QUERYEASFROMLIST, (PBYTE)&eaop, sizeof(eaop), 0L))!=0)
     {
      farfree(pfeal);
      rcode=-1;
      break;
     }
     nptr=(char FAR *)&(pfeal->list[0])+sizeof(FEA);
    #endif
   #elif TARGET==WIN32
    /* Win32 provides us with a FEALIST at our disposal. */
    pfeal=(PFEALIST)streambuf;
    nptr=(char FAR *)&(pfeal->list[0])+sizeof(FEA);
   #endif
  #if SFX_LEVEL>=ARJ
   if(ea_filter(nptr, skip_ln)&&((pfeal->list[0].fEA&FEA_NEEDEA)||!crit_eas))
  #endif
   {
    mput_word(mget_word(*dest)+1, *dest);
    mput_byte(pfeal->list[0].fEA, dptr++);
    mput_byte(pfeal->list[0].cbName, dptr++);
    mput_word(pfeal->list[0].cbValue, dptr);
    dptr+=2;
    far_memmove(dptr, nptr, (int)pfeal->list[0].cbName);
    dptr+=pfeal->list[0].cbName;
    far_memmove(dptr, nptr+pfeal->list[0].cbName+1, pfeal->list[0].cbValue);
    dptr+=pfeal->list[0].cbValue;
   }
   #if TARGET==OS2
    farfree(pfeal);
   #elif TARGET==WIN32
    if(pfeal->cbList==0)                /* Indicates the last EA */
     break;
    streambuf+=pfeal->cbList;
   #endif
  }
  #if TARGET==OS2
   farfree(pdena);
   farfree(pgeal);
  #endif
  #if TARGET==WIN32
   close_streams(sid);
  #endif
  return(rcode);
 #else
  return(-1);
 #endif
}
#endif

/* setea() routine */

int set_ea(char FAR *i_eas, char *name)
{
 #ifdef HAVE_EAS
  int rc=0;
  char FAR *eas;
  unsigned int i, total;
  #if TARGET==OS2
   #ifdef __32BIT__
    FILESTATUS4 fs;
    EAOP2 eaop;
    char FAR *real_pfeal;
    PFEA2LIST pfeal;
    PFEA2 pf, opf;
   #else
    EAOP eaop;
    PFEALIST pfeal;
    PFEA pf;
    FILESTATUS2 fs;
    SEL selector;
   #endif
  #elif TARGET==WIN32
   PFEALIST pfeal0, pfeal;
   PFEA pf;
   struct nt_sid *sid;
   unsigned char *pstreambuf, *streambuf;
   WIN32_STREAM_ID w32sid;
   unsigned long stream_len;
  #endif

  eas=i_eas;
  if(discard_ea(name))
   return(-1);
  if((total=mget_word(eas))==0)
   return(0);
  #if TARGET==OS2
   #ifdef __32BIT__
    /* This takes the 4-byte prefixes into account (are the V1.2 EAs still
       valid if they flow beyond 64K when the oNextEntryOffset is applied?).
       Also, we ensure that it is aligned properly. In theory, there may be
       a way to crash this (72K doesn't consider the multitude of EAs) but we
       don't know/care about it -- ASR 17/10/2000 */
    real_pfeal=(char FAR *)farmalloc_msg(73728);
    pfeal=(PFEA2LIST)align_dword(real_pfeal);
    eaop.fpFEA2List=pfeal;
   #else
    if(DosAllocSeg(65535U, &selector, SEG_NONSHARED))
     return(-1);
    pfeal=(PFEALIST)MAKEP(selector, 0);
    eaop.fpFEAList=pfeal;
   #endif
  #elif TARGET==WIN32
   pstreambuf=(char *)farmalloc_msg(65536+260*total);
   pfeal=pfeal0=(PFEALIST)(streambuf=align_dword(pstreambuf));
  #endif
  eas+=2;
  pf=&pfeal->list[0];
  for(i=0; i<total; i++)
  {
   #if TARGET==OS2&&defined(__32BIT__)
    opf=pf;
   #endif
   #if TARGET==WIN32
    pf=&pfeal->list[0];
   #endif
   pf->fEA=mget_byte(eas++);
   pf->cbName=mget_byte(eas++);
   pf->cbValue=mget_word(eas);
   eas+=2;
   #if TARGET==OS2&&defined(__32BIT__)
     far_memmove((char FAR *)pf+sizeof(FEA2)-1, eas, pf->cbName);
     *((char FAR *)pf+sizeof(FEA2)-1+pf->cbName)='\0';
   #else /* Win32 or OS/2-16 */
     far_memmove((char FAR *)pf+sizeof(FEA), eas, pf->cbName);
     *((char FAR *)pf+sizeof(FEA)+pf->cbName)='\0';
   #endif
   eas+=pf->cbName;
   #if TARGET==OS2&&defined(__32BIT__)
    far_memmove((char FAR *)pf+sizeof(FEA2)+pf->cbName, eas, pf->cbValue);
   #else /* Win32 or OS/2-16 */
    far_memmove((char FAR *)pf+sizeof(FEA)+pf->cbName+1, eas, pf->cbValue);
   #endif
   eas+=pf->cbValue;
   #if SFX_LEVEL>=ARJ
    #if TARGET==OS2&&defined(__32BIT__)
     if(ea_filter((char FAR *)pf+sizeof(FEA2), 0)&&((pf->fEA&FEA_NEEDEA)||!crit_eas))
    #else /* Win32 or OS/2-16 */
     if(ea_filter((char FAR *)pf+sizeof(FEA), 0)&&((pf->fEA&FEA_NEEDEA)||!crit_eas))
    #endif
   #endif
   /* Update the offsets */
   #if TARGET==OS2
    #ifdef __32BIT__
     pf=(PFEA2)((char FAR *)pf+sizeof(FEA2)+pf->cbName+pf->cbValue);
    #else
     pf=(PFEA)((char FAR *)pf+sizeof(FEA)+pf->cbName+1+pf->cbValue);
    #endif
    /* Align at DWORD boundary and issue the list fixups */
    #ifdef __32BIT__
     pf=(PFEA2)align_dword((char FAR *)pf);
     opf->oNextEntryOffset=(i+1==total)?0:(char FAR *)pf-(char FAR *)opf;
    #endif
   #elif TARGET==WIN32
    pfeal=(PFEALIST)((char FAR *)pfeal+sizeof(FEALIST)+pf->cbName+1+pf->cbValue);
    if(i<total-1)
     pfeal=(PFEALIST)align_dword((char FAR*)pfeal);
    pfeal0->cbList=(i==total-1)?
                   0:
                   (((char FAR *)pfeal)-((char FAR *)pfeal0));
    pfeal0=pfeal;
   #endif
  }
  #if TARGET==OS2
   pfeal->cbList=(char FAR *)pf-(char FAR *)pfeal;
   #ifdef __32BIT__
    rc=DosSetPathInfo((PSZ)name, FIL_QUERYEASIZE, (PBYTE)&eaop, sizeof(eaop), 0);
    farfree(real_pfeal);
   #else
    rc=DosSetPathInfo((PSZ)name, FIL_QUERYEASIZE, (PBYTE)&eaop, sizeof(eaop), 0, 0L);
    DosFreeSeg(selector);
   #endif
   if(!rc)
   {
    #ifdef __32BIT__
     if(DosQueryPathInfo(name, FIL_QUERYEASIZE, (PVOID)&fs, sizeof(fs)))
    #else
     if(DosQPathInfo(name, FIL_QUERYEASIZE, (PVOID)&fs, sizeof(fs), 0L))
    #endif
     rc=-1;
    else
     if(fs.cbList<=4)
      rc=-1;
   }
  #elif TARGET==WIN32
   if((sid=open_streams(name, 1))==NULL)
    rc=-1;
   else
   {
    memset(&w32sid, 0, sizeof(w32sid));
    w32sid.dwStreamId=BACKUP_EA_DATA;
    w32sid.Size.LowPart=stream_len=(((char FAR *)pfeal)-streambuf);
    if(create_stream(&w32sid, sid)||write_stream(streambuf, stream_len, sid)<stream_len)
     rc=-1;
    close_streams(sid);
   }
   free(pstreambuf);
  #endif
  return(rc);
 #else
  return(-1);
 #endif
}

/* Returns 1 if the target file system supports extended attributes */

int detect_ea(char *name)
{
 #if TARGET==DOS
  return(0);
 #elif TARGET==OS2||TARGET==WIN32
  return(1);                            /* ...but not always */
 #else
  return(0);				/* Assume "no" if we don't know */
 #endif
}

/* Resolves .LONGNAME EAs. Returns 0 if not resolved. */

#if SFX_LEVEL>=ARJ
int resolve_longname(char *dest, char *name)
{
 #ifdef HAVE_EAS
  unsigned char *tmp_name;
  int entry, l_sel, rc;
  #if TARGET==OS2
   #ifdef __32BIT__
    EAOP2 eaop;
    PGEA2LIST pgeal;
    PFEA2LIST pfeal;
   #else
    EAOP eaop;
    PGEALIST pgeal;
    PFEALIST pfeal;
   #endif
  #elif TARGET==WIN32
   struct nt_sid *sid=NULL;
   unsigned char *streambuf=NULL;
   unsigned long stream_len, rem_len, fetch;
   FEALIST feal;
   PFEALIST pfeal;
  #endif
  char FAR *valptr;
  unsigned int st_len;

  if(name[0]=='\0'||name[0]==PATHSEP_DEFAULT&&name[1]=='\0'||name[1]==':'&&name[2]=='\0')
  {
   strcpy(dest, name);
   return(0);
  }
  tmp_name=(char *)malloc_msg(FILENAME_MAX);
  l_sel=entry=split_name(name, tmp_name, NULL);
  if(entry>0)
  {
   tmp_name[entry-1]='\0';
   resolve_longname(dest, tmp_name);
   entry=strlen(dest);
   dest[entry]=PATHSEP_DEFAULT;
   dest[entry+1]='\0';
  }
  else
   dest[0]='\0';
  #if TARGET==OS2
   #ifdef __32BIT__
    pgeal=(PGEA2LIST)farmalloc_msg(sizeof(GEA2LIST)+sizeof(longname_ea));
    pfeal=(PFEA2LIST)farmalloc_msg(sizeof(FEA2LIST)+sizeof(longname_ea)+FILENAME_MAX);
   #else
    pgeal=(PGEALIST)farmalloc_msg(sizeof(GEALIST)+sizeof(longname_ea));
    pfeal=(PFEALIST)farmalloc_msg(sizeof(FEALIST)+sizeof(longname_ea)+FILENAME_MAX);
   #endif
   far_strcpy(pgeal->list[0].szName, (char FAR *)longname_ea);
  #elif TARGET==WIN32
   pfeal=(PFEALIST)farmalloc_msg(sizeof(FEALIST)+sizeof(longname_ea)+FILENAME_MAX);
  #endif
  #if TARGET==OS2
   #ifdef __32BIT__
    pgeal->list[0].oNextEntryOffset=0;
   #endif
   pgeal->list[0].cbName=sizeof(longname_ea)-1;
   #ifdef __32BIT__
    pgeal->cbList=sizeof(GEA2LIST)+sizeof(longname_ea)-1;
    pfeal->cbList=sizeof(FEA2LIST)+sizeof(longname_ea)+FILENAME_MAX-1-entry;
    eaop.fpGEA2List=pgeal;
    eaop.fpFEA2List=pfeal;
   #else
    pgeal->cbList=sizeof(GEALIST)+sizeof(longname_ea)-1;
    pfeal->cbList=sizeof(FEALIST)+sizeof(longname_ea)+FILENAME_MAX-1-entry;
    eaop.fpGEAList=pgeal;
    eaop.fpFEAList=pfeal;
   #endif
   #ifdef __32BIT__
    if(DosQueryPathInfo(name, FIL_QUERYEASFROMLIST, (PBYTE)&eaop, sizeof(eaop)))
   #else
    if(DosQPathInfo(name, FIL_QUERYEASFROMLIST, (PBYTE)&eaop, sizeof(eaop), 0L))
   #endif
     rc=0;
   else
   {
    rc=1;
    #ifdef __32BIT__
     valptr=(char FAR *)pfeal+sizeof(FEA2LIST)+pfeal->list[0].cbName;
    #else
     valptr=(char FAR *)pfeal+sizeof(FEALIST)+pfeal->list[0].cbName+1;
    #endif
   }
  #elif TARGET==WIN32
   rc=0;
   if((sid=open_streams(name, 0))!=NULL&&
      (stream_len=seek_stream_id(BACKUP_EA_DATA, sid))>0)
   {
    valptr=streambuf=(char *)farmalloc_msg(256);
    pfeal=(PFEALIST)&feal;
    while(read_stream((char *)pfeal, sizeof(FEALIST), sid)==sizeof(FEALIST)&&
          read_stream(streambuf, pfeal->list[0].cbName+1, sid)==pfeal->list[0].cbName+1)
    {
     rem_len=pfeal->cbList-sizeof(FEALIST)-pfeal->list[0].cbName-1;
     if(!stricmp(streambuf, longname_ea))
     {
      if(pfeal->list[0].cbValue<256)
      {
       read_stream(streambuf, pfeal->list[0].cbValue, sid);
       rc=1;
       break;
      }
     }
     else
     {
      if(pfeal->cbList==0)
       break;
      /* Advance to the next EA entry */
      while(rem_len>0)
      {
       fetch=min(256, rem_len);
       read_stream(streambuf, fetch, sid);
       rem_len-=fetch;
      }
     }
    }
   }
  #endif
  if(rc)
  {
   if((st_len=pfeal->list[0].cbValue)==0)
    rc=0;
   else
   {
    far_memmove((char FAR *)tmp_name, valptr, st_len);
    tmp_name[st_len]='\0';
    if(tmp_name[0]==0xFD&&tmp_name[1]==0xFF)
    {
     strcpy(tmp_name, (char *)tmp_name+4);
     st_len-=4;
    }
    if(st_len==0||st_len+entry>=FILENAME_MAX)
     rc=0;
    else
    {
     while(st_len-->0)
     {
      if(tmp_name[st_len]<' '||strchr(forbidden_chars, tmp_name[st_len])!=NULL)
      {
       rc=0;
       break;
      }
     }
    }
   }
  }
  if(!rc)
  {
   if(strlen(name)+entry+l_sel>=FILENAME_MAX)
    error(M_MAXPATH_EXCEEDED, FILENAME_MAX, name);
   strcat(dest, name+l_sel);
  }
  else
   strcat(dest, (char *)tmp_name);
  #if TARGET==OS2
   farfree(pgeal);
   farfree(pfeal);
  #elif TARGET==WIN32
   if(streambuf!=NULL)
    farfree(streambuf);
   if(sid!=NULL)
    close_streams(sid);
  #endif
  free(tmp_name);
  return(rc);
 #else
  return(0);
 #endif
}
#endif
