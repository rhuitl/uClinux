/*
 * $Id: uxspec.c,v 1.6 2004/04/17 11:39:43 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This module handles the UNIX special files and the owner IDs.
 *
 */

#include "arj.h"

#if TARGET==UNIX
 #include <pwd.h>
 #include <grp.h>
 #include <unistd.h>
#endif

DEBUGHDR(__FILE__)                      /* Debug information block */

/* UXSPECIAL block types */

#define UXSB_FIFO               0x00
#define UXSB_HLNK               0x01
#define UXSB_LNK                0x02
#define UXSB_BLK                0x03
#define UXSB_CHR                0x04
#define UXSB_ID_BITS               3    /* Bits for block ID */
#define UXSB_SIZE_BITS (8-UXSB_ID_BITS) /* Bits for block size */
#define UXSB_SIZE_THRESHOLD ((1<<UXSB_SIZE_BITS)-1)  /* When to switch to 2-byte fmt. */
#define MK_UXSB(id, size) (((unsigned char)(id)<<UXSB_SIZE_BITS)|(unsigned char)(size))
#define UXSB_GET_ID(c) ((unsigned char)(c)>>UXSB_SIZE_BITS)
#define UXSB_GET_SIZE(c) ((unsigned char)(c)&((1<<UXSB_SIZE_BITS)-1))
#define UXSB_CALC_SIZE(s) (s+((s<UXSB_SIZE_THRESHOLD)?1:3))
/* Reference partition support */
#if SFX_LEVEL>=ARJ&&TARGET==UNIX
#define MAX_DEVS                 256    /* # of devs specified by the user */
static dev_t user_devs[MAX_DEVS];
static unsigned int total_devs=0;
static int excl_mode=1;
#endif

/*
 * UNIX special file handling
 */

/* Given a raw UXSPECIAL block, reports its size */

unsigned int get_uxspecial_size(char FAR *blk)
{
 int l;

 l=UXSB_GET_SIZE(blk[0]);
 if(l==UXSB_SIZE_THRESHOLD)
  return(mget_word(blk+1)+3);
 else
  return(l+1);
}

/* Fills in the header size fields, returning a pointer to the data area */

static char FAR *fill_hdr_size(char FAR *dest, int type, int size)
{
 if(size<UXSB_SIZE_THRESHOLD)
 {
  mput_byte(MK_UXSB(type, size), dest);
  return(dest+1);
 }
 else
 {
  mput_byte(MK_UXSB(type, UXSB_SIZE_THRESHOLD), dest);
  mput_word(size, dest+1);
  return(dest+3);
 }
}

/* Stores the UNIX special file data in archive fields */

#if SFX_LEVEL>=ARJ
int query_uxspecial(char FAR **dest, char *name, struct file_properties *props)
{
 #if TARGET==UNIX
  struct stat st;
  char tmp_name[FILENAME_MAX-1];
  int l;
  char FAR *dptr;
  int hardlink=0;

  if(lstat(name, &st)==-1)
   return(-1);
  if(!S_ISDIR(st.st_mode)&&st.st_nlink>1&&props->islink)
   hardlink=1;
  if(S_ISFIFO(st.st_mode))
   mput_byte(MK_UXSB(UXSB_FIFO, 0), (*dest=(char FAR *)farmalloc_msg(1)));
  else if(S_ISLNK(st.st_mode)||hardlink)
  {
   if(hardlink)
   {
    retrieve_entry(tmp_name, NULL, &flist_main, props->l_search.ref);
    l=strlen(tmp_name);
   }
   else
   {
    if((l=readlink(name, tmp_name, sizeof(tmp_name)))<=0)
     return(-1);
   }
   *dest=(char FAR *)farmalloc_msg(UXSB_CALC_SIZE(l));
   dptr=fill_hdr_size(*dest, hardlink?UXSB_HLNK:UXSB_LNK, l);
   far_memmove(dptr, (char FAR *)tmp_name, l);
  }
  else if(S_ISCHR(st.st_mode)||S_ISBLK(st.st_mode))
  {
   *dest=(char FAR *)farmalloc_msg(UXSB_CALC_SIZE(sizeof(st.st_rdev)));
   dptr=fill_hdr_size(*dest, S_ISCHR(st.st_mode)?UXSB_CHR:UXSB_BLK, sizeof(st.st_rdev));
   far_memmove(dptr, (char FAR *)&st.st_rdev, sizeof(st.st_rdev));
  }
  else
   return(-1);                          /* Unusual file type, report warning */
 #else
  return(-1);
 #endif
 return(0);
}
#endif

/* Restores the UNIX special file data */

int set_uxspecial(char FAR *storage, char *name)
{
 #if TARGET==UNIX
  char FAR *dptr;
  int l, id;
  char tmp_name[FILENAME_MAX];
  int rc;

  unlink(name);
  l=UXSB_GET_SIZE(storage[0]);
  if(l==UXSB_SIZE_THRESHOLD)
   l=mget_word(storage+1);
  id=UXSB_GET_ID(storage[0]);
  dptr=storage+((UXSB_GET_SIZE(*storage)==UXSB_SIZE_THRESHOLD)?3:1);
  switch(id)
  {
   case UXSB_FIFO:
    rc=mkfifo(name, 0644);
    return(rc?UXSPEC_RC_ERROR:0);
   case UXSB_HLNK:
   case UXSB_LNK:
    #if SFX_LEVEL>=ARJ    
     if(id==UXSB_HLNK)
     {
      if(suppress_hardlinks==SHL_DROP)
       return(UXSPEC_RC_SUPPRESSED);
      else if(suppress_hardlinks==SHL_SOFT)
       id=UXSB_LNK;
     }
    #endif
    if(l>=sizeof(tmp_name))
     l=sizeof(tmp_name)-1;
    far_memmove((char FAR *)tmp_name, dptr, l);
    tmp_name[l]='\0';
    rc=(id==UXSB_HLNK)?link(tmp_name, name):symlink(tmp_name, name);
    if(!rc)
     return(0);
    return(errno==EPERM?UXSPEC_RC_NOLINK:UXSPEC_RC_ERROR);
   case UXSB_BLK:
   case UXSB_CHR:
    /* Check for platform mismatch */
    if(sizeof(dev_t)!=l)
     return(UXSPEC_RC_FOREIGN_OS);
    rc=mknod(name, 0644|((id==UXSB_BLK)?S_IFBLK:S_IFCHR), *(dev_t FAR *)dptr);
    return(rc?UXSPEC_RC_ERROR:0);
  }
  return(0);
 #else
  return(UXSPEC_RC_ERROR);
 #endif
}

/* Statistics report */

void uxspecial_stats(char FAR *storage, int format)
{
 #if TARGET==UNIX
  FMSGP fm;
 #endif
 #if SFX_LEVEL>=ARJ
  char tmp[FILENAME_MAX-1];
  char FAR *dptr;
  int i, l, m, id;
 #endif

 if(format==UXSTATS_SHORT)
 {
  /* Only relevant under UNIX when extracting the files */
#if TARGET==UNIX  
  switch(UXSB_GET_ID(storage[0]))
  {
   case UXSB_FIFO:
    fm=M_UXSPECIAL_FIFO;
    break;
   case UXSB_HLNK:
    fm=M_UXSPECIAL_HLNK;
    break;
   case UXSB_LNK:
    fm=M_UXSPECIAL_LNK;
    break;
   case UXSB_CHR:
    fm=M_UXSPECIAL_CHR;
    break;
   case UXSB_BLK:
    fm=M_UXSPECIAL_BLK;
    break;
   default:
    return;
  }
  msg_cprintf(0, fm);
  fputc(' ', new_stdout);
#endif
 }
#if SFX_LEVEL>=ARJ
 else
 {
  l=UXSB_GET_SIZE(storage[0]);
  if(l==UXSB_SIZE_THRESHOLD)
   l=mget_word(storage+1);
  id=UXSB_GET_ID(storage[0]);
  dptr=storage+((UXSB_GET_SIZE(*storage)==UXSB_SIZE_THRESHOLD)?3:1);
  switch(id)
  {
   case UXSB_FIFO:
    msg_cprintf(0, M_UXLIST_FIFO);
    break;
   case UXSB_HLNK:
   case UXSB_LNK:
    if(l>=sizeof(tmp))
     l=sizeof(tmp)-1;
    far_memmove((char FAR *)tmp, dptr, l);
    tmp[l]='\0';
    msg_cprintf(0, (id==UXSB_HLNK)?M_UXLIST_HLNK:M_UXLIST_LNK, tmp);
    break;
   case UXSB_BLK:
   case UXSB_CHR:
    m=0;
    tmp[0]='\0';
    for(i=0; i<l&&m<sizeof(tmp)-4; i++)
     m+=sprintf(tmp+m, "%02x ", (unsigned char)dptr[i]);
    if(m>0)
     tmp[m-1]='\0';
    msg_cprintf(0, (id==UXSB_BLK)?M_UXLIST_BLK:M_UXLIST_CHR, tmp);
    break;
  }
 }
#endif
}

/* Given a raw UXSPECIAL block, reports its size */

unsigned int get_owner_size(char FAR *blk)
{
 return(*(unsigned char *)blk+1);
}

/* Queries the file owner */

#if SFX_LEVEL>=ARJ
int query_owner(char FAR **dest, char *name, int how_to_resolve)
{
 #if TARGET==UNIX
  struct passwd *pw;
  struct group *gr;
  struct stat st;
  unsigned int l, lg, lt;
  char FAR *dst;

  if(lstat(name, &st)==-1)
   return(-1);
  if(how_to_resolve==OWNSTG_CHAR||how_to_resolve==OWNSTG_CHAR_GID)
  {
   if((pw=getpwuid(st.st_uid))==NULL)
    return(-1);
   l=strlen(pw->pw_name);
   if(l>=256)
   {
    return(-1);
   }
   dst=(char FAR *)farmalloc_msg(l+1);
    dst[0]=(unsigned char)l;
   far_memmove(dst+1, (char FAR *)pw->pw_name, l);
   /* Now locate the GID entry if we have to, otherwise shut down */
   if(how_to_resolve!=OWNSTG_CHAR_GID)
   {
    *dest=dst;
    return(0);
   }
   if((gr=getgrgid(st.st_gid))==NULL)
    return(-1);
   lg=strlen(gr->gr_name);
   if(lg>=256)
    return(-1);
   lt=lg+l+1;
   dst=(char FAR *)farrealloc_msg(dst, lt+1);
    dst[0]=(unsigned char)lt;
   dst[l+1]='\0';
   far_memmove(dst+l+2, (char FAR *)gr->gr_name, lg);
   *dest=dst;
  }
  else
  {
   *dest=(char FAR *)farmalloc_msg(9);
   *dest[0]=8;
   mput_dword((unsigned long)st.st_uid, *dest+1);
   mput_dword((unsigned long)st.st_gid, *dest+5);
  }
  return(0);
 #else
  return(-1);
 #endif
}
#endif

/* Restores the file properties */

int set_owner(char FAR *storage, char *name, int resolve)
{
 #if TARGET==UNIX
  struct passwd *pw;
  struct group *gr;
  char tmp[513];
  int l, i, rc;
  gid_t gid;

  l=*(unsigned char FAR *)storage;
  if(l>=sizeof(tmp))
   return(-1);                          /* Prevent overruns */
  if(resolve)
  {
   far_memmove((char FAR *)tmp, storage+1, l);
   tmp[l]='\0';
   i=strlen(tmp);
   if((pw=getpwnam(tmp))==NULL)
    return(-1);
   gid=pw->pw_gid;
   /* Is the group information hidden somewhere? The group may be allowed to
      be nonexistent, in this case we'll simply fall back to the "default"
      group received from getpwnam() */
   if(i<l-1&&(gr=getgrnam(tmp+i+1))!=NULL)
    gid=gr->gr_gid;
   rc=lchown(name, pw->pw_uid, gid);
   return(rc);
  }
  else
  {
   if(l!=8)
    return(-1);
   return(lchown(name, mget_dword(storage+1), mget_dword(storage+5)));
  }
 #else
  return(-1);
 #endif
}

/* Report the owner */

#if SFX_LEVEL>=ARJ
void owner_stats(char FAR *storage, int resolve)
{
 char tmp[256];
 int l, i;

 l=*(unsigned char FAR *)storage;
 if(resolve)
 {
  far_memmove((char FAR *)tmp, storage+1, l);
  tmp[l]='\0';
  i=strlen(tmp);
  if(i<l-1)
   tmp[i]='/';                          /* Format as "<user>/<group>" */
 }
 else
 {
  if(l==8)
   msg_sprintf(tmp, M_OWNER_ID, mget_dword(storage+1), mget_dword(storage+5));
  else
   strcpy(tmp, "???");
 }
 msg_cprintf(0, M_OWNER_LIST, tmp);
}
#endif

/*
 * Device-specific archiving
 */

#if SFX_LEVEL>=ARJ&&TARGET==UNIX

/* Sets inclusion/exclusion mode */

void set_dev_mode(int is_excl)
{
 excl_mode=is_excl;
}

/* Add a device specification to the pool */

int add_dev(char *name)
{
 struct stat st;
 unsigned int i;

 if(total_devs>=MAX_DEVS||stat(name, &st))
  return(-1);
 for(i=0; i<total_devs; i++)
  if(user_devs[i]==st.st_dev)
   return(-1);
 user_devs[total_devs++]=st.st_dev;
 return(0);
}

/* Validate a file against the device spec */

int is_dev_allowed(dev_t dev)
{
 int i;

 for(i=0; i<total_devs; i++)
 {
  if(user_devs[i]==dev)
   return(!excl_mode);
 }
 return(excl_mode);
}

#endif
