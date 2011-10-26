/*
 * $Id: environ.c,v 1.23 2004/06/18 16:19:37 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This module contains  platform-specific routines along with a  set of hacks
 * to implement the common functions of Borland compilers and their behavior.
 *
 */

#include "arj.h"

#if TARGET!=UNIX
#include <conio.h>
#include <io.h>
#include <process.h>
#endif

#include <fcntl.h>

#if COMPILER==BCC
 #include <dir.h>
#elif COMPILER==MSC||COMPILER==MSVC||COMPILER==ICC
 #include <direct.h>
#endif

#if TARGET!=UNIX
 #include <share.h>
#endif

#if COMPILER==MSC||COMPILER==MSVC||COMPILER==ICC||COMPILER==HIGHC||defined(__EMX__)||(TARGET==OS2&&defined(LIBC))
 #include <sys/types.h>
 #include <sys/stat.h>
 #if COMPILER==HIGHC&&!defined(LIBC)
  #define SH_DENYRW _SH_DENYRW
  #define SH_DENYWR _SH_DENYWR
  #define SH_DENYNO _SH_DENYNO
 #endif
#elif TARGET!=UNIX
 #include <share.h>
#endif
#if COMPILER==BCC&&TARGET==DOS
 #include <sys/stat.h>                  /* S_* only */
#endif
#if TARGET==UNIX
 #ifdef SUNOS
  #include <sys/statvfs.h>
  #include <termio.h>
 #endif
 #ifdef __sco__
  #include <sys/statvfs.h>
 #endif
 #include <unistd.h>
 #include <fnmatch.h>
 #include <signal.h>                    /* fork()+spawnvp() control */
 #include <utime.h>
 #include <sys/time.h>                  /* LIBC high-resolution timing */
 #include <sys/resource.h>              /* Priority control */
 #if defined(linux)
  #include <sys/ioctl.h>
  #include <sys/statfs.h>
  #include <sys/statvfs.h>
 #elif defined(__FreeBSD__)||defined(__NetBSD__)
  #include <sys/param.h>
  #include <sys/mount.h>
 #elif defined(__QNXNTO__)
  #include <sys/statvfs.h>
 #else
  #include <sys/statfs.h>
 #endif
#endif
#ifdef TILED
 #include <dos.h>
#endif

#if TARGET==DOS
 #include "win95dos.h"
#endif

#if TARGET==WIN32&&!defined(F_OK)
 #define F_OK                      0    /* For MSVCRT */
#endif

/* IBM toolkit -> EMX wrapper */

#ifdef __EMX__
 #define DosCaseMap     DosMapCase
 #define DosQCurDisk    DosQueryCurrentDisk
 #define DosQFileInfo   DosQueryFileInfo
 #define DosQFSInfo     DosQueryFSInfo
 #define DosSelectDisk  DosSetDefaultDisk
 #define DosSetPrty     DosSetPriority
#endif

DEBUGHDR(__FILE__)                      /* Debug information block */

/*
 * DOS legacy
 */

#if TARGET==DOS

/* INT 24h */

#define INT24                   0x24
#define INT24_IGNORE               0
#define INT24_RETRY                1
#define INT24_ABORT                2
#define INT24_FAIL                 3
#define INT24_DPF_WRITING     0x0100    /* Device processing flag in AX */
#define INT24_IO_ERROR        0x8000

/* Character device IOCTL statements */

#define CHDI_STDOUT           0x0001
#define CHDI_STDIN            0x0002
#define CHDI_NUL              0x0004
#define CHDI_CLOCK            0x0008
#define CHDI_SPECIAL          0x0010
#define CHDI_BINARY           0x0020
#define CHDI_EOF_ON_INPUT     0x0040
#define CHDI_SET              0x0080
#define CHDI_OPENCLOSE        0x0800
#define CHDI_OUTPUT_TILL_BUSY 0x2000
#define CHDI_CAN_IOCTL        0x4000

/* File IOCTL statements */

#define CHDF_NOT_WRITTEN      0x0040
#define CHDF_NOT_FILE         0x0080
#define CHDF_EXT_INT24        0x0100    /* DOS 4.x only */
#define CHDF_NOT_REMOVABLE    0x0800
#define CHDF_NO_TIMESTAMPING  0x4000
#define CHDF_IS_REMOTE        0x8000

/* This macro checks if DOS version is less than 3.10 */

#define is_dos_31                  (_osmajor<3||_osmajor==3&&_osminor<10)

/* For MS C, a macro to query the current time */

#if COMPILER==MSC
 #define g_timer(t) t=*(long FAR *)0x0000046CL
#endif

#endif /* TARGET==DOS */

/* An OS/2 & Win32 macro to join timestamps */

#if TARGET==OS2||TARGET==WIN32
 #define make_ftime(fd, ft) ((unsigned long)*(USHORT *)&fd<<16)+(unsigned long)*(USHORT *)&ft
#endif

/* Allowable DOS file attributes (HSRA) */

#if TARGET!=UNIX
 #define STD_FILE_ATTR             (FATTR_ARCH|FATTR_SYSTEM|FATTR_HIDDEN|FATTR_RDONLY)
#endif

/* Attribute comparison for UNIX */

#if TARGET==UNIX
 #define match_unix_attrs(attr, pattern) (((pattern)==0)||(((attr)&(pattern))==(pattern)))
#endif

/* Command-line input limit */

#if TARGET==DOS
 #define INPUT_LIMIT             127
#endif

/* UNIX file time requests */

#if TARGET==UNIX
 #define UFTREQ_FTIME              0
 #define UFTREQ_ATIME              1
 #define UFTREQ_CTIME              2
#endif

/*
 * Exported variables
 */

/* Line feed string */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
 char simple_lf[]="\n";
#endif

/* Carriage return */

#if SFX_LEVEL>=ARJ||TARGET==DOS&&(SFX_LEVEL>=ARJSFX||defined(REARJ))
 char simple_cr[]="\r";
#endif

/* The following systems are considered equal to host OS under which ARJ is
   run. The contents of this list greatly depend upon the host OS itself... */

#if SFX_LEVEL>=ARJSFX
 #if TARGET==DOS
  int friendly_systems[]={OS_DOS, OS_WIN95, OS_WINNT, -1};
 #elif TARGET==OS2
  int friendly_systems[]={OS_DOS, OS_OS2, OS_WIN95, OS_WINNT, -1};
 #elif TARGET==WIN32
  int friendly_systems[]={OS_DOS, OS_WIN95, OS_WINNT, -1};
 #elif TARGET==UNIX
  int friendly_systems[]={OS_UNIX, OS_NEXT, -1};
 #endif
#endif

/* Standard devices */

#if SFX_LEVEL>=ARJSFX
 #if TARGET==UNIX
  char dev_null[]="/dev/null";          /* NULL device */
  char dev_con[]="/dev/tty";            /* Console device */
 #else
  char dev_null[]="NUL";                /* NULL device */
  char dev_con[]="CON";                 /* Console device */
 #endif
#endif

/* Wildcard used to select all files */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
 #if TARGET==DOS
  char all_wildcard[]="*.*";
 #else
  char all_wildcard[]="*";
 #endif
#endif

/* Win32 can't use setftime_on_stream - this is required for ARJSFXJR: */

#if SFX_LEVEL==ARJSFXJR&&TARGET==WIN32
 #define NEED_SETFTIME_HACK
#endif

/*
 * Internal variables
 */

/* Attribute format */

#if SFX_LEVEL>=ARJSFX
 static char attrib_buf[]="---W";       /* ASHR if all set */
#endif

/* Arbitrary disk drive for LFN testing */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
 static char drive_c[]="C:";            /* Although it's incorrect... */
#endif

/* Directory specifiers for file search */

#if SFX_LEVEL>=ARJ||defined(REARJ)
 /* Subdirectory/root search wildcard */
 #if TARGET==DOS
  char root_wildcard[]="\\*.*";
 #elif TARGET==OS2||TARGET==WIN32
  char root_wildcard[]="\\*";
 #elif TARGET==UNIX
  char root_wildcard[]="/*";
 #endif
 char up_dir_spec[]="..";               /* Parent directory specifier */
 char pathsep_str[]={PATHSEP_DEFAULT, '\0'};
#endif
#if SFX_LEVEL>=ARJ||defined(REARJ)||(SFX_LEVEL>=ARJSFXV&&TARGET==UNIX)
 char cur_dir_spec[]=".";               /* Current directory specifier */
#endif

/* FCB mask (used to fill in FCBs) */

#if SFX_LEVEL>=ARJSFXV&&TARGET==DOS
 static char fcb_mask[]="???????????";
#endif

/* Queues for detecting child session shutdown */

#if TARGET==OS2&&defined(REARJ)
 static char rearj_q_fmt[]="\\QUEUES\\REARJ#%u";
#endif

/* Name of file that is currently being opened */

#if COMPILER==MSC&&TARGET==DOS
 static char *f_file_ptr=NULL;
#endif

/* For the case if the environment doesn't allow to query EXE name, we'll store
   our own ones. */

#if TARGET==DOS
 #if SFX_LEVEL>=ARJ
  static char default_exe[]="arj" EXE_EXTENSION;
 #elif SFX_LEVEL>=ARJSFXJR
  static char default_exe[]="arjsfx" EXE_EXTENSION;
 #elif defined(REARJ)
  static char default_exe[]="rearj" EXE_EXTENSION;
 #endif
#endif

/*
 * Frequently used Borland routines
 */

/* Returns 0 for A:, 1 for B:, etc. */

#if defined(HAVE_DRIVES)&&((SFX_LEVEL>=ARJSFX||defined(REARJ))&&COMPILER!=BCC)
int getdisk()
{
 #if TARGET==DOS
  int rc;

  _dos_getdrive((unsigned int *)&rc);
  return(rc-1);
 #elif TARGET==OS2
  #ifndef __32BIT__
   USHORT rc;
   ULONG total;

   DosQCurDisk(&rc, &total);
   return(rc-1);
  #else
   ULONG rc, total;

   DosQCurDisk(&rc, &total);
   return(rc-1);
  #endif
 #elif TARGET==WIN32
  char cur_dir[CCHMAXPATH];

  if(GetCurrentDirectory(sizeof(cur_dir), cur_dir)&&cur_dir[1]==':')
   return(cur_dir[0]-'A');
  else
   return(-1);
 #endif
}
#endif

/* Performs heap checking if required */

#if SFX_LEVEL>=ARJ
int verify_heap()
{
 #if COMPILER==BCC
  return(heapcheck()==_HEAPCORRUPT);
 #elif COMPILER==MSC||COMPILER==MSVC
  int rc;

  rc=_heapchk();
  return(rc!=_HEAPOK&&rc!=_HEAPEMPTY);
 #elif COMPILER==ICC&&defined(DEBUG)
  _heap_check();
  return(0);
 #else
  return(0);                            /* Not implemented otherwise */
 #endif
}
#endif

/* Performs far heap verification (if there is any) */

#if SFX_LEVEL>=ARJ
int verify_far_heap()
{
 #if COMPILER==BCC
  return(farheapcheck());
 #elif COMPILER==MSC
  return(_fheapchk());
 #elif !defined(TILED)
  return(verify_heap());
 #else
  return(0);                            /* Don't even bother of it */
 #endif
}
#endif

/* Returns the available stack space */

#if SFX_LEVEL>=ARJ
static unsigned int get_stack_space()
{
 #if defined(__BORLANDC__)
  return(stackavail());
 #elif defined(__TURBOC__)
  return(_stklen+_SP);
 #elif COMPILER==MSC
  return(stackavail());
 #else
  return(32767);
 #endif
}
#endif

/* Changes the current drive to 0=A:, 1=B:, and so on... */

#if defined(HAVE_DRIVES)&&(defined(REARJ)&&COMPILER!=BCC)
int setdisk(int drive)
{
 #if TARGET==DOS
  int numdrives;

  _dos_setdrive(drive+1, &numdrives);
  return(numdrives);
 #elif TARGET==OS2
  #ifdef __32BIT__
   ULONG rc;
  #else
   USHORT rc;
  #endif
  ULONG total;

  rc=DosSelectDisk(drive+1);
  if(rc)
   return(0);
  DosQCurDisk(&rc, &total);
  return(total);
 #elif TARGET==WIN32
  char t[4];

  t[0]=drive+'A';
  t[1]=':';
  t[2]='\0';
  SetCurrentDirectory(t);
  return(25);                           /* Dummy value */
 #endif
}
#endif

/* Returns the number of bytes available in the far heap (quite slow). This is
   an advisory function for legacy parts of ARJ. Avoid it by all means. */

#if SFX_LEVEL>=ARJSFXV&&COMPILER!=BCC
long farcoreleft()
{
 #if TARGET==DOS
  void _huge *hp;
  static long rc=736L;
  long s_rc;

  s_rc=rc;
  rc+=2L;
  do
   hp=halloc(rc-=2L, 1024);
  while(hp==NULL&&rc>0L);
  if(hp!=NULL)
   hfree(hp);
  if(rc<s_rc)
   return(rc*1024L);
  do
  {
   hp=halloc(rc+=16L, 1024);
   if(hp!=NULL)
    hfree(hp);
  } while(hp!=NULL);
  return((rc-16L)*1024L);
 #elif TARGET==OS2
  #ifdef __32BIT__
   ULONG rc;

   DosQuerySysInfo(QSV_MAXPRMEM, QSV_MAXPRMEM, (PVOID)&rc, sizeof(rc));
   return(rc);
  #else
   ULONG rc;

   DosMemAvail(&rc);
   return(rc);
  #endif
 #elif TARGET==WIN32
  MEMORYSTATUS memstat;

  memstat.dwLength=sizeof(memstat);
  GlobalMemoryStatus(&memstat);
  return(max(0x7FFFFFFFUL, memstat.dwAvailVirtual));
 #else
  return(0x7FFFFFFF);
 #endif
}
#endif

/* Returns the current time of day */

#if (SFX_LEVEL>=ARJSFXV||defined(REARJ)||defined(REGISTER))&&COMPILER!=BCC
void arj_gettime(struct time *ts)
{
 #if TARGET==DOS
  struct dostime_t dts;

  _dos_gettime(&dts);
  ts->ti_hour=dts.hour;
  ts->ti_min=dts.minute;
  ts->ti_sec=dts.second;
  ts->ti_hund=dts.hsecond;
 #elif TARGET==OS2
  DATETIME dts;

  DosGetDateTime(&dts);
  ts->ti_hour=dts.hours;
  ts->ti_min=dts.minutes;
  ts->ti_sec=dts.seconds;
  ts->ti_hund=dts.hundredths;
 #elif TARGET==WIN32
  SYSTEMTIME st;

  GetLocalTime(&st);
  ts->ti_hour=st.wHour;
  ts->ti_min=st.wMinute;
  ts->ti_sec=st.wSecond;
  ts->ti_hund=st.wMilliseconds/10;
 #else
  time_t t;
  struct timeval v;
  struct tm *tms;

  do
  {
   t=time(NULL);
   gettimeofday(&v, NULL);
  } while(time(NULL)!=t);
  tms=localtime(&t);
  ts->ti_hour=tms->tm_hour;
  ts->ti_min=tms->tm_min;
  ts->ti_sec=tms->tm_sec;
  ts->ti_hund=v.tv_usec/10000;
 #endif
}
#endif

/* Returns the current date */

#if defined(REARJ)&&COMPILER!=BCC
void arj_getdate(struct date *ds)
{
 #if TARGET==DOS
  struct dosdate_t dds;

  _dos_getdate(&dds);
  ds->da_year=1980+dds.year;
  ds->da_day=dds.day;
  ds->da_mon=dds.month;
 #elif TARGET==OS2
  DATETIME dts;

  DosGetDateTime(&dts);
  ds->da_year=dts.year;
  ds->da_day=dts.day;
  ds->da_mon=dts.month;
 #elif TARGET==WIN32
  SYSTEMTIME st;

  GetLocalTime(&st);
  ds->da_year=st.wYear;
  ds->da_day=st.wDay;
  ds->da_mon=st.wMonth;
 #else
  time_t t;
  struct tm *tms;

  t=time(NULL);
  tms=localtime(&t);
  ds->da_year=tms->tm_year+1900;
  ds->da_day=tms->tm_mday;
  ds->da_mon=tms->tm_mon+1;
 #endif
}
#endif

/* Gets address of DOS DTA */

#if SFX_LEVEL>=ARJSFXV&&COMPILER!=BCC&&TARGET==DOS
static char FAR *getdta()
{
 union REGS regs;
 struct SREGS sregs;

 regs.h.ah=0x2F;
 intdosx(&regs, &regs, &sregs);
 return(MK_FP(sregs.es, regs.x.bx));
}
#endif

/* Sets address of DOS DTA */

#if SFX_LEVEL>=ARJSFXV&&COMPILER!=BCC&&TARGET==DOS
static void setdta(char FAR *dta)
{
 union REGS regs;
 struct SREGS sregs;

 regs.h.ah=0x1A;
 sregs.ds=FP_SEG(dta); regs.x.dx=FP_OFF(dta);
 intdosx(&regs, &regs, &sregs);
}
#endif

/*
 * OS/2 farcalloc()/farfree() routines
 */

#if TARGET==OS2&&defined(TILED)

/* farcalloc() for 0-based segments */

#if SFX_LEVEL>=ARJ&&defined(ASM8086)
void FAR *farcalloc_based(unsigned long num, unsigned long size)
{
 USHORT total;
 SEL selector;
 void FAR *rc;

 total=(USHORT)num*size;
 if(DosAllocSeg(total, &selector, SEG_NONSHARED))
  return(NULL);
 rc=(void FAR *)MAKEP(selector, 0);
 far_memset(rc, 0, total);
 return(rc);
}
#endif

/* farfree() for 0-based segments */

#if SFX_LEVEL>=ARJ&&defined(ASM8086)
void farfree_based(void FAR *ptr)
{
 DosFreeSeg(SELECTOROF(ptr));
}
#endif

#endif

/* Sets the process priority. */

#if TARGET!=DOS&&SFX_LEVEL>=ARJ
void set_priority(struct priority *priority)
{
 #if TARGET==OS2
  DosSetPrty(PRTYS_THREAD, priority->class, priority->delta, 0);
 #elif TARGET==WIN32
  static HANDLE ph=0, th=0;
  static DWORD w32_classes[4]={IDLE_PRIORITY_CLASS,
                               NORMAL_PRIORITY_CLASS,
                               HIGH_PRIORITY_CLASS,
                               REALTIME_PRIORITY_CLASS};

  if(!ph)
   ph=GetCurrentProcess();
  if(!th)
   th=GetCurrentThread();
  if(priority->class<=4)
  SetPriorityClass(ph, w32_classes[priority->class-1]);
  SetThreadPriority(th, priority->delta);
 #else
  #if defined(HAVE_SETPRIORITY)
   setpriority(PRIO_PROCESS, 0, 21-priority->class);
  #else
   #error Priority functions missing
  #endif
 #endif
}
#endif

/*
 * This section is specific to Windows 95 LFN API.
 */

/* Just a customized interrupt call procedure */

#if (SFX_LEVEL>=ARJSFX||defined(REARJ))&&TARGET==DOS
static int call_dos_int(unsigned int funcnum, union REGS *regs, struct SREGS *sregs)
{
 regs->x.ax=funcnum;
 #ifdef ASM8086
  asm{
   pushf
   pop   ax
   or    ax, 1
   push  ax
   popf
  };
 #else
  /* Provoke the carry flag */
  regs->x.cflag=(regs->x.ax&0x7FFF)+0x8000;
 #endif
 intdosx(regs, regs, sregs);
 _doserrno=(regs->x.cflag!=0)?(regs->x.ax):0;
 return(regs->x.cflag);
}
#endif

/* Test the specified volume for long filename support */

#if (SFX_LEVEL>=ARJSFX||defined(REARJ))&&TARGET==DOS
static int w95_test_for_lfn(char *drive)
{
 union REGS regs;
 struct SREGS sregs;
 char filesystem[40];                   /* Ralf Brown says 32 */
 char FAR *fsptr, FAR *dptr;

 fsptr=(char FAR *)filesystem;
 dptr=(char FAR *)drive;
 memset(&sregs, 0, sizeof(sregs));
 sregs.es=FP_SEG(fsptr); regs.x.di=FP_OFF(fsptr);
 regs.x.cx=sizeof(filesystem);
 sregs.ds=FP_SEG(dptr); regs.x.dx=FP_OFF(dptr);
 return(call_dos_int(W95_GET_VOLUME_INFO, &regs, &sregs)==0&&regs.x.bx&0x4000);
}
#endif

/* Return equivalent canonical short filename for a long filename */

#if (SFX_LEVEL>=ARJSFX||defined(REARJ))&&TARGET==DOS
static int w95_get_shortname(char *longname, char *shortname, int cb_shortname)
{
 union REGS regs;
 struct SREGS sregs;
 char FAR *lnptr, FAR *snptr;

 memset(&sregs, 0, sizeof(sregs));
 if(cb_shortname>=CCHMAXPATH_DOS)
 {
  lnptr=(char FAR *)longname;
  snptr=(char FAR *)shortname;
  shortname[0]='\0';
  sregs.ds=FP_SEG(lnptr); regs.x.si=FP_OFF(lnptr);
  sregs.es=FP_SEG(snptr); regs.x.di=FP_OFF(snptr);
  regs.x.cx=W95_GET_SHORTNAME;          /* No SUBST expansion, subfunc #1 */
  if(!call_dos_int(W95_TRUENAME, &regs, &sregs))
   return(strlen(shortname));
  else
   return(0);
 }
 else
  return(0);
}
#endif

/* Changes directory under Windows 95 */

#if defined(REARJ)&&TARGET==DOS
static int w95_chdir(char *longname)
{
 union REGS regs;
 struct SREGS sregs;
 char FAR *lnptr;

 memset(&sregs, 0, sizeof(sregs));
 lnptr=(char FAR *)longname;
 sregs.ds=FP_SEG(lnptr); regs.x.dx=FP_OFF(lnptr);
 return(call_dos_int(W95_CHDIR, &regs, &sregs)?-1:0);
}
#endif

/* Return equivalent canonical long filename for a short filename */

#if (SFX_LEVEL>=ARJ)&&TARGET==DOS
static int w95_get_longname(char *shortname, char *longname, int cb_longname)
{
 union REGS regs;
 struct SREGS sregs;
 char FAR *lnptr, FAR *snptr;

 memset(&sregs, 0, sizeof(sregs));
 if(cb_longname>=CCHMAXPATH_W95)
 {
  longname[0]='\0';
  lnptr=(char FAR *)longname;
  snptr=(char FAR *)shortname;
  sregs.ds=FP_SEG(snptr); regs.x.si=FP_OFF(snptr);
  sregs.es=FP_SEG(lnptr); regs.x.di=FP_OFF(lnptr);
  regs.x.cx=W95_GET_LONGNAME;           /* No SUBST expansion, subfunc #2 */
  if(!call_dos_int(W95_TRUENAME, &regs, &sregs))
   return(strlen(longname));
  else
   return(0);
 }
 else
  return(0);
}
#endif

/* Returns 1 if the current OS is Windows NT, 0 if Windows 95 */

#if SFX_LEVEL>=ARJ&&TARGET==DOS
int test_for_winnt()
{
 return(0);                     	/* Implemented in ARJ32 */
}
#endif

/* Returns the name of current directory */

#if defined(REARJ)&&TARGET==DOS
static char *w95_cwd(char *dest)
{
 union REGS regs;
 struct SREGS sregs;
 char FAR *dptr;

 dptr=(char FAR *)dest;
 memset(&sregs, 0, sizeof(sregs));
 dest[0]=getdisk()+'A';
 dest[1]=':';
 dest[2]=PATHSEP_DEFAULT;
 regs.h.dl=0;
 sregs.ds=FP_SEG(dptr); regs.x.si=FP_OFF(dptr)+3;
 return(call_dos_int(W95_CWD, &regs, &sregs)?NULL:dest);
}
#endif

/* Create a directory with longname. Return -1 if failed. */

#if (SFX_LEVEL>=ARJSFX||defined(REARJ))&&TARGET==DOS
static int w95_mkdir(char *longname)
{
 union REGS regs;
 struct SREGS sregs;
 char FAR *lnptr;

 lnptr=(char FAR *)longname;
 memset(&sregs, 0, sizeof(sregs));      /* BUG?! No register cleanup in ARJ */
 sregs.ds=FP_SEG(lnptr); regs.x.dx=FP_OFF(lnptr);
 return(call_dos_int(W95_MKDIR, &regs, &sregs)?-1:0);
}
#endif

/* Remove a directory with longname. Return -1 if failed. */

#if (SFX_LEVEL>=ARJ||defined(REARJ))&&TARGET==DOS
static int w95_rmdir(char *longname)
{
 union REGS regs;
 struct SREGS sregs;
 char FAR *lnptr;

 lnptr=(char FAR *)longname;
 memset(&sregs, 0, sizeof(sregs));
 sregs.ds=FP_SEG(lnptr); regs.x.dx=FP_OFF(lnptr);
 return(call_dos_int(W95_RMDIR, &regs, &sregs)?-1:0);
}
#endif

/* Delete a file */

#if (SFX_LEVEL>=ARJSFX||defined(REARJ))&&TARGET==DOS
static int w95_unlink(char *longname)
{
 union REGS regs;
 struct SREGS sregs;
 char FAR *lnptr;

 lnptr=(char FAR *)longname;
 memset(&sregs, 0, sizeof(sregs));
 sregs.ds=FP_SEG(lnptr); regs.x.dx=FP_OFF(lnptr);
 #ifndef REARJ
  regs.x.cx=FATTR_ARCH|FATTR_SYSTEM|FATTR_RDONLY;
 #else
  regs.x.cx=0;
 #endif
 regs.x.si=W95_WILDCARDS_DISABLED;      /* Forbid wildcard usage */
 return(call_dos_int(W95_UNLINK, &regs, &sregs)?-1:0);
}
#endif

/* Rename a file */

#if (SFX_LEVEL>=ARJ||defined(REARJ))&&TARGET==DOS
static int w95_rename(char *longname1, char *longname2)
{
 union REGS regs;
 struct SREGS sregs;
 char FAR *lnptr1, FAR *lnptr2;

 lnptr1=(char FAR *)longname1;
 lnptr2=(char FAR *)longname2;
 memset(&sregs, 0, sizeof(sregs));
 sregs.ds=FP_SEG(lnptr1); regs.x.dx=FP_OFF(lnptr1);
 sregs.es=FP_SEG(lnptr2); regs.x.di=FP_OFF(lnptr2);
 return(call_dos_int(W95_RENAME, &regs, &sregs)?-1:0);
}
#endif

/* Query or change attributes */

#if (SFX_LEVEL>=ARJSFX||defined(REARJ))&&TARGET==DOS
static int w95_chmod(char *longname, int action, int pmode)
{
 union REGS regs;
 struct SREGS sregs;
 char FAR *lnptr;

 lnptr=(char FAR *)longname;
 memset(&sregs, 0, sizeof(sregs));
 regs.x.bx=action;
 regs.x.cx=pmode;
 sregs.ds=FP_SEG(lnptr); regs.x.dx=FP_OFF(lnptr);
 return(call_dos_int(W95_CHMOD, &regs, &sregs)?-1:regs.x.cx);
}
#endif

/* access() function for LFNs - test if the file has the given access mode */

#if (SFX_LEVEL>=ARJSFX||defined(REARJ))&&TARGET==DOS
static int w95_access(char *longname, int mode)
{
 if((w95_chmod(longname, W95_GETATTR, 0))==-1)
  return(-1);
 else
 {
  if((!(mode&2))||!(mode&FATTR_RDONLY))
   return(0);
  else
  {
   errno=EACCES;
   return(-1);
  }
 }
}
#endif

/* findfirst() function as implemented in Borland Turbo C++ */

#if (SFX_LEVEL>=ARJSFXV||defined(REARJ))&&TARGET==DOS
static int w95_findfirst(char *path, struct new_ffblk *new_ffblk, int attrib)
{
 union REGS regs;
 struct SREGS sregs;
 struct W95_FFBLK w95_ffblk, FAR *fb_ptr;
 char FAR *p_ptr;

 memset(&sregs, 0, sizeof(sregs));
 fb_ptr=(struct W95_FFBLK FAR *)&w95_ffblk;
 p_ptr=(char FAR *)path;
 sregs.ds=FP_SEG(p_ptr); regs.x.dx=FP_OFF(p_ptr);
 sregs.es=FP_SEG(fb_ptr); regs.x.di=FP_OFF(fb_ptr);
 regs.x.cx=attrib;
 regs.x.si=W95_DT_DOS;                  /* Use DOS date/time format */
 if(!call_dos_int(W95_FINDFIRST, &regs, &sregs))
 {
  #if SFX_LEVEL>=ARJ||defined(REARJ)
   new_ffblk->ff_handle=regs.x.ax;      /* Preserve handle for findclose */
   strcpy(new_ffblk->ff_name, w95_ffblk.ff_longname);
   new_ffblk->ff_atime=w95_ffblk.ff_atime;
   new_ffblk->ff_ctime=w95_ffblk.ff_ctime;
  #endif
  new_ffblk->ff_attrib=(char)w95_ffblk.ff_attrib;
  new_ffblk->ff_ftime=w95_ffblk.ff_ftime;
  new_ffblk->ff_fsize=w95_ffblk.ff_fsize;
  #if SFX_LEVEL==ARJSFXV
   memset(&sregs, 0, sizeof(sregs));
   regs.x.bx=regs.x.ax;                 /* Transfer FF handle */
   call_dos_int(W95_FINDCLOSE, &regs, &sregs);
  #endif
  return(0);
 }
 else
  return(-1);
}
#endif

/* findnext() function as implemented in Borland Turbo C++ */

#if (SFX_LEVEL>=ARJ||defined(REARJ))&&TARGET==DOS
static int w95_findnext(struct new_ffblk *new_ffblk)
{
 union REGS regs;
 struct SREGS sregs;
 struct W95_FFBLK w95_ffblk, FAR *fb_ptr;

 memset(&sregs, 0, sizeof(sregs));
 fb_ptr=(struct W95_FFBLK FAR *)&w95_ffblk;
 sregs.es=FP_SEG(fb_ptr);
 regs.x.di=FP_OFF(fb_ptr);
 regs.x.bx=new_ffblk->ff_handle;
 regs.x.si=W95_DT_DOS;                  /* Not present in original ARJ! */
 if(!call_dos_int(W95_FINDNEXT, &regs, &sregs))
 {
  new_ffblk->ff_attrib=(char)w95_ffblk.ff_attrib;
  strcpy(new_ffblk->ff_name, w95_ffblk.ff_longname);
  new_ffblk->ff_ftime=w95_ffblk.ff_ftime;
  new_ffblk->ff_atime=w95_ffblk.ff_atime;
  new_ffblk->ff_ctime=w95_ffblk.ff_ctime;
  new_ffblk->ff_fsize=w95_ffblk.ff_fsize;
  return(0);
 }
 else
  return(-1);
}
#endif

/* Close search (specific to Windows 95) */

#if (SFX_LEVEL>=ARJSFXV||defined(REARJ))&&TARGET==DOS
static void w95_findclose(struct new_ffblk *new_ffblk)
{
 union REGS regs;
 struct SREGS sregs;

 memset(&sregs, 0, sizeof(sregs));
 regs.x.bx=new_ffblk->ff_handle;
 call_dos_int(W95_FINDCLOSE, &regs, &sregs);
}
#endif

/* Create a file with the same options as given for _open, return handle */

#if (SFX_LEVEL>=ARJSFX||defined(REARJ))&&TARGET==DOS
static int w95_creat(char *longname, int access)
{
 union REGS regs;
 struct SREGS sregs;
 char FAR *lnptr;

 lnptr=(char FAR *)longname;
 memset(&sregs, 0, sizeof(sregs));
 sregs.ds=FP_SEG(lnptr); regs.x.si=FP_OFF(lnptr);
 regs.x.bx=access&(O_RDONLY|O_WRONLY);
 regs.x.cx=32;
 regs.x.dx=0;
 regs.x.di=1;
 /* Translate FCNTL actions into Win95 actions */
 if(access&O_CREAT) regs.x.dx|=W95_A_CREAT;
 if(access&O_TRUNC) regs.x.dx|=W95_A_TRUNC;
 if(access&O_EXCL) regs.x.dx|=W95_A_EXCL;
 return(call_dos_int(W95_OPEN, &regs, &sregs)?-1:regs.x.ax);
}
#endif

/* Stamp date/time of last access on handle. Note that Win95 does not support
   time of last access. */

#if (SFX_LEVEL>=ARJSFXV)&&TARGET==DOS
static int w95_set_dta(int handle, unsigned long ftime)
{
 union REGS regs;
 struct SREGS sregs;

 memset(&sregs, 0, sizeof(sregs));
 regs.x.bx=handle;
 regs.x.cx=0;
 regs.x.dx=(unsigned short)ftime>>16;
 return(call_dos_int(W95_SET_DTA, &regs, &sregs)?-1:0);
}
#endif

/* Stamp date/time of last access on handle. Note that Win95 does not support
   time of last access. */

#if (SFX_LEVEL>=ARJSFXV)&&TARGET==DOS
static int w95_set_dtc(int handle, unsigned long ftime)
{
 union REGS regs;
 struct SREGS sregs;

 memset(&sregs, 0, sizeof(sregs));
 regs.x.bx=handle;
 regs.x.cx=(unsigned short)(ftime%65536L);
 regs.x.dx=(unsigned short)ftime>>16;
 regs.x.si=0;                           /* Number of 1/100ths */
 return(call_dos_int(W95_SET_DTC, &regs, &sregs)?-1:0);
}
#endif

/*
 * Now, some less OS-dependent routines.
 */

/* Return pointer to first character following a drivespec/relative pathspec
   so names like "\VIRUS.COM" will be transformed to safe "VIRUS.COM" */

#if SFX_LEVEL>=ARJSFX
#if SFX_LEVEL>=ARJSFXV
static char *validate_path(char *name, int action)
#else
static char *validate_path(char *name)
#endif
{
#if SFX_LEVEL>=ARJSFXV
 if(action!=VALIDATE_NOTHING)
 {
#endif
#ifdef HAVE_DRIVES
  if(name[0]!='\0'&&name[1]==':')
   name+=2;                             /* Skip over drivespecs */
#endif
#if SFX_LEVEL>=ARJSFXV
  if(action!=VALIDATE_DRIVESPEC)
  {
#endif
   if(name[0]=='.')
   {
    if(name[1]=='.'&&(name[2]==PATHSEP_DEFAULT||name[2]==PATHSEP_UNIX))
     name++;                            /* "..\\" relative path */
    if(name[1]==PATHSEP_DEFAULT||name[1]==PATHSEP_UNIX)
     name++;                            /* ".\\" relative path */
   }
   if(name[0]==PATHSEP_DEFAULT||name[0]==PATHSEP_UNIX)
    name++;                             /* "\\" - revert to root */
#if SFX_LEVEL>=ARJSFXV
  }
 }
#endif
 return(name);
}
#endif

/* Convert the extended finddata record to OS-independent internal storage
   format */

#if SFX_LEVEL>=ARJ
static void finddata_to_properties(struct file_properties *properties, struct new_ffblk *new_ffblk)
{
 #if TARGET==UNIX
  int u;
 #endif

 properties->ftime=new_ffblk->ff_ftime;
 properties->atime=new_ffblk->ff_atime;
 properties->ctime=new_ffblk->ff_ctime;
 properties->fsize=new_ffblk->ff_fsize;
 properties->attrib=(ATTRIB)new_ffblk->ff_attrib;
 #if TARGET!=UNIX
  properties->type=(new_ffblk->ff_attrib&FATTR_DIREC)?ARJT_DIR:ARJT_BINARY;
  properties->isarchive=(new_ffblk->ff_attrib&FATTR_ARCH)?1:0;
 #else
  u=uftype(new_ffblk->ff_attrib);
  if(u&FATTR_DT_DIR)
   properties->type=ARJT_DIR;
  else if(u&FATTR_DT_UXSPECIAL)
   properties->type=ARJT_UXSPECIAL;
  else
   properties->type=ARJT_BINARY;
  /* Can't check fot non-DT_REG since these may be requested by find_file() */
  properties->isarchive=1;
  /* Hardlink data */
  properties->l_search=new_ffblk->l_search;
  properties->l_search.ref=0;
  properties->islink=0;
 #endif
}
#endif

/* Return pointer to the first path delimiter in given string, or NULL if
   nothing found */

#if SFX_LEVEL>=ARJSFX
static char *find_delimiter(char *path, int datatype)
{
 if(path[0]=='\0')
  return(NULL);
 while(path[0]!='\0')
 {
  if(path[0]==PATHSEP_DEFAULT||path[0]==PATHSEP_UNIX)
   return(path);
  path++;
 }
 if(datatype==ARJT_DIR)
  return(path);
 else
  return(NULL);
}
#endif

/*
 * Secondary-level file management routines. Usually they must either be
 * redirected to Win95 LFN API, or serviced with the C RTL functions.
 */

/* chmod() - Borland's implementation */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
int file_chmod(char *name, int action, int attrs)
{
 #if TARGET==DOS
  if(lfn_supported!=LFN_NOT_SUPPORTED)
   return(w95_chmod(name, action, attrs));
  else
  #if COMPILER==BCC
   return(_chmod(name, action, attrs));
  #elif COMPILER==MSC
   {
    int rc;

    if(action)
     return(_dos_setfileattr(name, attrs));
    else
    {
     rc=-1;
     _dos_getfileattr(name, &rc);
     return(rc);
    }
   }
  #endif
 #elif TARGET==OS2
  #ifdef __32BIT__
   FILESTATUS3 fstatus;
   int rc;

   rc=DosQueryPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus));
   if(action)
   {
    fstatus.attrFile=attrs;
    return(DosSetPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus), 0)?-1:0);
   }
   else
    return(rc?-1:fstatus.attrFile);
  #else
   USHORT rc;

   if(action)
    return(DosSetFileMode(name, attrs, 0L)?-1:0);
   else
    return(DosQFileMode(name, &rc, 0L)?-1:rc);
  #endif
 #elif TARGET==WIN32
  DWORD rc;
 
  if(!action)
  {
   rc=GetFileAttributes(name);
   if(rc==0xFFFFFFFF)
    return(-1);
   else
    return((int)rc);
  }
  else
   return(!SetFileAttributes(name, attrs));
 #else
  struct stat st;

  if(action)
  {
   if(!lstat(name, &st)&&S_ISLNK(st.st_mode))
    return(0);                          /* ASR fix 15/06/2003: don't touch symlinks anymore */
   else
    return(chmod(name, attrs));
  }
  else
   return(lstat(name, &st)?-1:st.st_mode);
 #endif
}
#endif

/* Manages the access rights for a stream - required to handle the
   SFX archives properly */

#if SFX_LEVEL>=ARJ&&TARGET==UNIX
int file_acc(FILE *stream)
{
 struct stat st;

 return(fstat(fileno(stream), &st)?-1:st.st_mode);
}

/* Duplicates the "R" access bits into "X" for creating a SFX */

void make_executable(FILE *stream)
{
 int stm;

 stm=file_acc(stream);
 fchmod(fileno(stream), stm|((stm>>2)&0111));
}

#endif

/* access() */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)||defined(REGISTER)
static int file_access(char *name, int mode)
{
 #if TARGET==DOS
  #ifndef REGISTER
   if(lfn_supported!=LFN_NOT_SUPPORTED)
    return(w95_access(name, mode));
   else
  #endif
   return(access(name, mode));
 #elif TARGET==OS2||TARGET==WIN32||TARGET==UNIX
  return(access(name, mode));
 #else
  #error No access() defined
 #endif
}
#endif

#if TARGET==UNIX&&(SFX_LEVEL>=ARJSFXV||defined(REARJ))

/* Locates the first matching dirent, like findnext() but for the first dirent
   as well (the UNIX-way). May trash the new_ffblk structures without returning
   success, but who cares? */

static int roll_dirent(struct new_ffblk *new_ffblk)
{
 struct dirent *ent;
 int a, l, m;
 struct stat st, resolved_st;
 int attrs;
 dev_t real_dev;
 ino_t real_inode;

 a=ufattr(attrs=new_ffblk->attrs);
 strcpy(new_ffblk->ff_name, new_ffblk->dir);
 if(!strcmp(new_ffblk->ff_name, cur_dir_spec))
  new_ffblk->ff_name[l=0]='\0';
 else
 {
  l=strlen(new_ffblk->ff_name);
  if(l==0||new_ffblk->ff_name[l-1]!=PATHSEP_DEFAULT)
   new_ffblk->ff_name[l++]=PATHSEP_DEFAULT;
 }
 /* Now, check all files until we find the matching one */
 while((ent=readdir(new_ffblk->ff_handle))!=NULL)
 {
  strcpy(new_ffblk->ff_name+l, ent->d_name);
  if(a!=0)
   m=match_unix_attrs(file_chmod(new_ffblk->ff_name, 0, 0), a);
  else
   m=1;
  /* Wildcard matching and attribute check */
  if(m&&match_wildcard(ent->d_name, new_ffblk->wildcard))
  {
   if(lstat(new_ffblk->ff_name, &st))
    return(-1);
   real_dev=st.st_dev;
   real_inode=st.st_ino;
#if SFX_LEVEL>=ARJ    
   /* Search in the device pool to see if the user forbids archiving for
      this device */
   if(!is_dev_allowed(real_dev))
    continue;
#endif    
   /* Redo stat if it's a link and we do not handle links (so need it to be
      resolved) */
   if(!(attrs&FATTR_DT_UXSPECIAL)&&stat(new_ffblk->ff_name, &st))
    continue;
   /* Sockets aren't supported, check for other types as well */
#if !defined(S_ISSOCK)
#define S_ISSOCK(m)  0
#endif
   if(!S_ISSOCK(st.st_mode)&&
      (((uftype(attrs)==FATTR_DT_ANY||(uftype(attrs)&FATTR_DT_REG))&&S_ISREG(st.st_mode))||
       ((attrs&FATTR_DT_DIR)&&S_ISDIR(st.st_mode))||
       (attrs&FATTR_DT_UXSPECIAL)))
   {
    /* Reestablish the "unqualified" filename */
    strcpy(new_ffblk->ff_name, ent->d_name);
    /* If it was a link, try to retrieve the mode of file which it points to.
       Otherwise, chmod() will trash the mode of original file upon restore */
    if(S_ISLNK(st.st_mode)&&stat(new_ffblk->ff_name, &resolved_st)!=-1)
    {
     new_ffblk->ff_attrib=resolved_st.st_mode&FATTR_UFMASK;
     real_dev=resolved_st.st_dev;
     real_inode=resolved_st.st_ino;
    }
    else
     new_ffblk->ff_attrib=st.st_mode&FATTR_UFMASK;
    /* Convert the remaining structures to new_ffblk and leave the search */
    new_ffblk->ff_ftype=st.st_mode;
    if(S_ISREG(st.st_mode))
     new_ffblk->ff_attrib|=FATTR_DT_REG;
    else if(S_ISDIR(st.st_mode))
     new_ffblk->ff_attrib|=FATTR_DT_DIR;
    else
     new_ffblk->ff_attrib|=FATTR_DT_UXSPECIAL;
    new_ffblk->ff_ftime=st.st_mtime;
    /* Prevent REARJ from complaining about directory size mismatch */
    new_ffblk->ff_fsize=(S_ISREG(st.st_mode))?st.st_size:0;
    new_ffblk->ff_atime=st.st_atime;
    new_ffblk->ff_ctime=st.st_ctime;
    /* Special structures for hard links */
    new_ffblk->l_search.dev=real_dev;
    new_ffblk->l_search.inode=real_inode;
    new_ffblk->l_search.refcount=S_ISDIR(st.st_mode)?1:st.st_nlink;
    break;
   }
  }
 }
 return(ent==NULL?-1:0);
}

#endif

#if TARGET==WIN32

/* Strip NT timestamps -> DOS timestamps */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
static unsigned long dosify_time(FILETIME *pft)
{
 FILETIME lft;
 WORD dd=0x1111, dt=0x1111;

 FileTimeToLocalFileTime(pft, &lft);
 FileTimeToDosDateTime(&lft, &dd, &dt);
 return(make_ftime(dd, dt));
}
#endif

/* Expand DOS timestamps into NT UTC timestamps */

#if SFX_LEVEL>=ARJSFXJR||defined(REARJ)
static void ntify_time(FILETIME *pft, unsigned long dft)
{
 FILETIME lft;

 DosDateTimeToFileTime((WORD)(dft>>16), (WORD)(dft&0xFFFF), &lft);
 LocalFileTimeToFileTime(&lft, pft);
}
#endif

#endif

/* findfirst() - Borland's implementation */

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)
int lfn_findfirst(char *path, struct new_ffblk *new_ffblk, int attrib)
{
 #if TARGET==DOS
  /* ASR fix 04/09/2001 for the R11 timestamp format */
  new_ffblk->ff_atime=new_ffblk->ff_ctime=0;
  if(lfn_supported==LFN_SUPPORTED)
   return(w95_findfirst(path, new_ffblk, attrib));
  else
   #if COMPILER==BCC
    return(findfirst(path, (struct ffblk *)new_ffblk, attrib));
   #elif COMPILER==MSC
    return(_dos_findfirst(path, attrib, (struct find_t *)new_ffblk));
   #endif
 #elif TARGET==OS2
  HDIR handle=HDIR_CREATE;
  #ifdef __32BIT__
   FILEFINDBUF3 findbuf;
   ULONG fcount=1L;
  #else
   FILEFINDBUF findbuf;
   USHORT fcount=1;
  #endif

  #ifdef __32BIT__
   if(DosFindFirst(path, &handle, attrib, &findbuf, sizeof(findbuf), &fcount, FIL_STANDARD))
    return(-1);
  #else
   if(DosFindFirst(path, &handle, attrib, &findbuf, sizeof(findbuf), &fcount, 0L))
    return(-1);
  #endif
  /* Do the conversion */
  new_ffblk->ff_attrib=findbuf.attrFile;
  new_ffblk->ff_ftime=make_ftime(findbuf.fdateLastWrite, findbuf.ftimeLastWrite);
  new_ffblk->ff_fsize=findbuf.cbFile;
  strcpy(new_ffblk->ff_name, findbuf.achName);
  new_ffblk->ff_atime=make_ftime(findbuf.fdateLastAccess, findbuf.ftimeLastAccess);
  new_ffblk->ff_ctime=make_ftime(findbuf.fdateCreation, findbuf.ftimeCreation);
  #if SFX_LEVEL<=ARJSFXV&&!defined(REARJ)
   DosFindClose(handle);
  #else
   new_ffblk->ff_handle=handle;
  #endif
  return(0);
 #elif TARGET==WIN32
  WIN32_FIND_DATA wfd;
  HANDLE hf;

  if((hf=FindFirstFile(path, &wfd))==INVALID_HANDLE_VALUE)
   return(-1);
  if(wfd.nFileSizeHigh>0||(long)wfd.nFileSizeLow<0)
   return(-1);
  new_ffblk->ff_attrib=wfd.dwFileAttributes;
  new_ffblk->ff_ftime=dosify_time(&wfd.ftLastWriteTime);
  new_ffblk->ff_atime=dosify_time(&wfd.ftLastAccessTime);
  new_ffblk->ff_ctime=dosify_time(&wfd.ftCreationTime);
  new_ffblk->ff_fsize=wfd.nFileSizeLow;
  strcpy(new_ffblk->ff_name, wfd.cFileName);
  #if SFX_LEVEL<=ARJSFXV&&!defined(REARJ)
   FindClose(hf);
  #else
   new_ffblk->ff_handle=hf;
  #endif
  return(0);
 #elif TARGET==UNIX
  split_name(path, new_ffblk->dir, new_ffblk->wildcard);
  if(new_ffblk->wildcard[0]=='\0')
   strcpy(new_ffblk->wildcard, all_wildcard);
  if(new_ffblk->dir[0]=='\0')
   strcpy(new_ffblk->dir, cur_dir_spec);
  if((new_ffblk->ff_handle=opendir(new_ffblk->dir))==NULL)
   return(-1);
  new_ffblk->attrs=attrib;
  if(roll_dirent(new_ffblk)==-1)
  {
   closedir(new_ffblk->ff_handle);
   new_ffblk->ff_handle=NULL;           /* Invalidate the new_ffblk */
   return(-1);
  }
  #if SFX_LEVEL<=ARJSFXV&&!defined(REARJ)
   closedir(new_ffblk->ff_handle);
  #endif
  return(0);
 #endif
}
#endif

/* findnext() - Borland's implementation */

#if SFX_LEVEL>=ARJ||defined(REARJ)
int lfn_findnext(struct new_ffblk *new_ffblk)
{
 #if TARGET==DOS
  if(lfn_supported==LFN_SUPPORTED)
   return(w95_findnext(new_ffblk));
  else
   #if COMPILER==BCC
    return(findnext((struct ffblk *)new_ffblk));
   #elif COMPILER==MSC
    return(_dos_findnext((struct find_t *)new_ffblk));
   #endif
 #elif TARGET==OS2
  HDIR handle;
  #ifdef __32BIT__
   FILEFINDBUF3 findbuf;
   ULONG fcount=1L;
  #else
   FILEFINDBUF findbuf;
   USHORT fcount=1;
  #endif

  handle=new_ffblk->ff_handle;
  if(DosFindNext(handle, &findbuf, sizeof(findbuf), &fcount))
   return(-1);
  /* Do the conversion */
  new_ffblk->ff_attrib=findbuf.attrFile;
  new_ffblk->ff_ftime=make_ftime(findbuf.fdateLastWrite, findbuf.ftimeLastWrite);
  new_ffblk->ff_fsize=findbuf.cbFile;
  strcpy(new_ffblk->ff_name, findbuf.achName);
  new_ffblk->ff_atime=make_ftime(findbuf.fdateLastAccess, findbuf.ftimeLastAccess);
  new_ffblk->ff_ctime=make_ftime(findbuf.fdateCreation, findbuf.ftimeCreation);
  return(0);
 #elif TARGET==WIN32
  WIN32_FIND_DATA wfd;

  if(!FindNextFile(new_ffblk->ff_handle, &wfd))
   return(-1);
  if(wfd.nFileSizeHigh>0||(long)wfd.nFileSizeLow<0)
   return(-1);
  new_ffblk->ff_attrib=wfd.dwFileAttributes;
  new_ffblk->ff_ftime=dosify_time(&wfd.ftLastWriteTime);
  new_ffblk->ff_atime=dosify_time(&wfd.ftLastAccessTime);
  new_ffblk->ff_ctime=dosify_time(&wfd.ftCreationTime);
  new_ffblk->ff_fsize=wfd.nFileSizeLow;
  strcpy(new_ffblk->ff_name, wfd.cFileName);
  return(0);
 #elif TARGET==UNIX
  if(roll_dirent(new_ffblk)==-1)
   return(-1);
  return(0);
 #endif
}
#endif

/* findclose() */

#if SFX_LEVEL>=ARJ||defined(REARJ)
void lfn_findclose(struct new_ffblk *new_ffblk)
{
 #if TARGET==DOS
  if(lfn_supported==LFN_SUPPORTED)
   w95_findclose(new_ffblk);
 #elif TARGET==OS2
  DosFindClose(new_ffblk->ff_handle);
 #elif TARGET==WIN32
  FindClose(new_ffblk->ff_handle);
 #elif TARGET==UNIX
  if(new_ffblk->ff_handle!=NULL)
   closedir(new_ffblk->ff_handle);
  new_ffblk->ff_handle=NULL;    /* Invalidate it! */
 #endif
}
#endif

/* Convert the given symbols to upper case, depending on locale */

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)
void toupper_loc(unsigned char *ptr, int length)
{
 #if TARGET==DOS&&defined(ASM8086)
  struct
  {
   int co_date;
   char co_curr[5];
   char co_thsep[2];
   char co_desep[2];
   char co_dtsep[2];
   char co_tmsep[2];
   char co_currstyle;
   char co_digits;
   char co_time;
   long co_case;
   char co_dasep[2];
   char co_fill[10];
  } cty;
  static int cty_state=0;                /* 0 if not queried yet */
  static char((FAR *ctycnv)());          /* Case map routine */
  union REGS regs;
  char c;

  if(cty_state==0)
  {
   cty_state=-1;
   if(_osmajor>=3)
   {
    regs.x.dx=(unsigned int)&cty;
    regs.x.ax=0x3800;
    intdos(&regs, &regs);
    if(!regs.x.cflag)
    {
     cty_state=1;                        /* Accept any further calls */
     ctycnv=(char (FAR *)())cty.co_case;
    }
   }
  }
  if(cty_state>0)
  {
   while(length>0)
   {
    if(ptr[0]>='a'&&ptr[0]<='z')
     ptr[0]-=0x20;                       /* Convert to upper case */
    else
     if(ptr[0]>=0x80)
     {
      c=ptr[0];
      asm mov al, c;
      ctycnv();
      asm mov c, al;
      ptr[0]=c;
     }
    ptr++;
    length--;
   }
  }
  else
  {
   while(length>0)
   {
    if(ptr[0]>='a'&&ptr[0]<='z')
     ptr[0]-=('a'-'A');                  /* Convert to upper case */
    ptr++;
    length--;
   }
  }
 #elif TARGET==OS2
  COUNTRYCODE cc;

  cc.country=cc.codepage=0;
  DosCaseMap(length, &cc, ptr);
 #else
  unsigned char x;

  /* ASR fix 10/04/2002: this fixes a GCC v 3.0 optimization bug */
  while(length-->0)
  {
   x=*ptr;
   *ptr++=toupper(x);
  }
 #endif
}
#endif

/* Sums two unixtime values (for systems with different implementation of
   time_t and for Year 2106 compliance) */

#if SFX_LEVEL>=ARJ
time_t sum_time(time_t t1, time_t t2)
{
 return(t1+t2);
}
#endif

/* Subtracts two unixtime values (for systems with different implementation of
   time_t and for Year 2106 compliance) */

#ifdef REARJ
time_t sub_time(time_t t1, time_t t2)
{
 return(t1-t2);
}
#endif

/* Depending of LFN support, converts the path specification to UPPERCASE */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
void case_path(char *s)
{
 #if TARGET==DOS
  if(lfn_supported==LFN_NOT_SUPPORTED)
   strupper(s);
 #else
  /* Case-preserving or case-sensitive systems have nothing to do here */
 #endif
}
#endif

/* Looks for duplicate drive specifications in the arguments, returns 1 if
   found one, or 0 if none were found. */

#if SFX_LEVEL>=ARJ&&TARGET!=UNIX
int find_dupl_drivespecs(char **argtable, int args)
{
 int cur_arg, cx_arg;

 if(args<=1)
 {
  if(listchars_allowed==0||argtable[0][0]!=listchar)
   return(0);
  else
   return(1);
 }
 else
 {
  for(cur_arg=0; cur_arg<args; cur_arg++)
  {
   if(argtable[cur_arg][1]!=':'&&strcmp(argtable[cur_arg], nonexist_name))
    return(1);
  }
  for(cur_arg=0; cur_arg<args; cur_arg++)
   for(cx_arg=0; cx_arg<args; cx_arg++)
   {
    if(cx_arg!=cur_arg)
    {
     if(argtable[cx_arg][0]==argtable[cur_arg][0])
      return(1);
    }
   }
  return(0);
 }
}
#endif

/* Returns 0 if monopolized R/O access to the file can be granted, -1 if not */

#if SFX_LEVEL>=ARJSFXV
int file_test_access(char *name)
{
 #if TARGET==DOS
  char tmp_name[CCHMAXPATH];
 #endif
 int handle;

 #if TARGET==DOS
  if(_osmajor>=3&&!disable_sharing)
  {
   strcpy(tmp_name, name);
   if(lfn_supported!=LFN_NOT_SUPPORTED)
    w95_get_shortname(name, tmp_name, sizeof(tmp_name));
   #if COMPILER==BCC
    if((handle=_open(tmp_name, O_BINARY|O_DENYALL|O_RDONLY))==-1)
     return(-1);
   #elif COMPILER==MSC
    if((handle=sopen(tmp_name, O_BINARY|O_RDONLY, SH_DENYRW))==-1)
     return(-1);
   #endif
   close(handle);
  }
  return(0);
 #elif TARGET==OS2||TARGET==WIN32
  if((handle=sopen(name, O_BINARY|O_RDONLY, SH_DENYRW))==-1)
   return(-1);
  close(handle);
  return(0);
 #elif TARGET==UNIX
  struct flock flk;
  int rc;

  if((handle=open(name, O_RDONLY))==-1)
   return(-1);
  memset(&flk, 0, sizeof(flk));
  rc=fcntl(handle, F_GETLK, &flk);
  close(handle);
  return(((rc==-1&&errno!=EINVAL)||(rc!=1&&flk.l_type==F_RDLCK))?-1:0);
 #endif
}
#endif

/* Detect long filename support */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
int detect_lfns()
{
 #if TARGET==DOS
  if(_osmajor<7)
   return(lfn_supported=0);
  else
   return(lfn_supported=w95_test_for_lfn(drive_c));
 #else
  return(lfn_supported=1);              /* Setting to 0 will disable DTA/DTC
                                           handling! */
 #endif
}
#endif

/* Detect extended attribute support */

#if SFX_LEVEL>=ARJSFXV
int detect_eas()
{
 #if TARGET==OS2
  ea_supported=1;
 #elif TARGET==WIN32
  OSVERSIONINFO osvi;

  osvi.dwOSVersionInfoSize=sizeof(osvi);
  GetVersionEx(&osvi);
  return(ea_supported=(osvi.dwPlatformId==VER_PLATFORM_WIN32_NT));
 #else
  ea_supported=0;
 #endif
 return(ea_supported);
}
#endif

/* Null subroutine for compiler bugs */

void nullsub(int arg, ...)
{
}

/* Delay */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)||defined(REGISTER)||defined(ARJDISP)
void arj_delay(unsigned int seconds)
{
 #if TARGET==DOS
  #if COMPILER==MSC
   long c_time, e_time, t_time;

   /* This is inappropriate for some rare machines with non-standard timer
      arrangement, e.g. Tandy 2000 but at least it doesn't involve
      reprogramming the timer ports. */
   e_time=(long)seconds*182L/10L;
   while(e_time--)
   {
    g_timer(t_time);
    c_time=t_time;
    do
    {
     g_timer(c_time);
    } while(c_time==t_time);
   }
  #else
   sleep(seconds);
  #endif
 #elif TARGET==OS2
  DosSleep(seconds*1000L);
 #elif TARGET==WIN32
  Sleep(seconds*1000L);
 #else
  sleep(seconds);
 #endif
}
#endif

/* Collect memory statistics (for debugging purposes) */

#if SFX_LEVEL>=ARJSFXV
void mem_stats()
{
 if(debug_enabled&&strchr(debug_opt, 'v')!=NULL)
 {
  #if SFX_LEVEL>=ARJ
   msg_cprintf(0, M_MEMSTATS, coreleft(), verify_heap(), farcoreleft(), verify_far_heap(), get_stack_space());
  #else
   msg_cprintf(0, M_MEMSTATS, coreleft(), farcoreleft());
  #endif
 }
}
#endif

/* Interrupt 24h handler */

#if SFX_LEVEL>=ARJSFXV&&TARGET==DOS
#if COMPILER==BCC
void interrupt int24_fatal_handler(unsigned int bp, unsigned int di,
                                   unsigned int si, unsigned int ds,
                                   unsigned int es, unsigned int dx,
                                   unsigned int cx, unsigned int bx,
                                   unsigned int ax)
#elif COMPILER==MSC
void _interrupt _far int24_fatal_handler( unsigned int es, unsigned int ds,
                                            unsigned int di, unsigned int si,
                                            unsigned int bp, unsigned int sp,
                                            unsigned int bx, unsigned int dx,
                                            unsigned int cx, unsigned int ax,
                                            unsigned int ip, unsigned int cs,
                                            unsigned int flags)
#endif
{
 ax=INT24_FAIL;
}
#endif

/* Check for the existence of file given; INT 24h handler is reset to ensure
   that the FAIL action is automatically generated instead of prompting the
   user for action. */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)||defined(REGISTER)
int file_exists(char *name)
{
 int rc;

 #if TARGET==DOS
  #if COMPILER==BCC
   void interrupt (*oldhdl)();
  #elif COMPILER==MSC
   void (_interrupt _far *oldhdl)();
  #endif

  #if SFX_LEVEL>=ARJSFXV
   if(is_dos_31)
    rc=file_access(name, 0);
   else
   {
    oldhdl=getvect(INT24);
    setvect(INT24, int24_fatal_handler);
    rc=file_access(name, 0);
    setvect(INT24, oldhdl);
   }
  #else
   rc=file_access(name, 0);
  #endif
 #elif TARGET==OS2
  rc=file_access(name, 0);
 #else
  rc=file_access(name, F_OK);
 #endif
 return(!rc);
}
#endif

/* An extended fopen that supports long filenames and uses sharing. */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
FILE *file_open(char *name, char *mode)
{
 #if TARGET==DOS
  char tmp_name[CCHMAXPATH];
 #endif
 #if SFX_LEVEL>=ARJSFXV
  char tmp_mode[10];
 #endif
 #if COMPILER!=BCC&&SFX_LEVEL>=ARJSFXV
  int shflag;
 #endif
 #if SFX_LEVEL>=ARJSFXV||TARGET==DOS
  int handle;
 #endif
 #if SFX_LEVEL>=ARJSFXV
  int oflag;
 #endif

 #if TARGET==DOS
  strcpy(tmp_name, name);
  if(lfn_supported!=LFN_NOT_SUPPORTED)
  {
   if(strchr(mode, 'a')!=NULL||strchr(mode, 'w')!=NULL)
   {
    if(w95_access(name, 0))
    {
     /* If the file does not exist, continue here, otherwise get its short
        name and process with fopen. */
     if((handle=w95_creat(name, O_CREAT|O_TRUNC|O_WRONLY))==-1)
      return(NULL);
     else
      close(handle);
     /* At this point, the file has been created but has a zero length. Now
        we can query its short name and use DOS functions to access it. */
    }
   }
   w95_get_shortname(name, tmp_name, sizeof(tmp_name));
  }
 #endif
 #if SFX_LEVEL>=ARJSFXV
  if(disable_sharing)
   return(fopen(name, mode));
  else
  {
   strcpyn(tmp_mode, mode, 9);
   switch(tmp_mode[0])
   {
    case 'r': oflag=0; break;
    case 'w': oflag=O_CREAT|O_TRUNC; break;
    case 'a': oflag=O_CREAT|O_APPEND; break;
    default: return(NULL);
   }
   if(tmp_mode[1]=='+'||(tmp_mode[1]!='\0'&&tmp_mode[2]=='+'))
    oflag|=O_RDWR;
   else
    oflag|=(tmp_mode[0]=='r')?O_RDONLY:O_WRONLY;
   #if TARGET!=UNIX
    if(tmp_mode[1]=='b'||tmp_mode[2]=='b')
     oflag|=O_BINARY;
   #endif
   #if TARGET==DOS
    if(_osmajor>=3)                     /* Sharing modes for DOS v 3.0+ */
    {
     #if COMPILER==BCC
      if(tmp_mode[1]=='+'||tmp_mode[1]!='\0'&&tmp_mode[2]=='+')
       oflag|=O_DENYWRITE;
      else
       oflag|=O_DENYNONE;
     #else
      shflag=(tmp_mode[1]=='+'||tmp_mode[1]!='\0'&&tmp_mode[2]=='+')?SH_DENYWR:SH_DENYNO;
     #endif
    }
    #if COMPILER==BCC
     handle=open(tmp_name, oflag, S_IREAD|S_IWRITE);
    #elif COMPILER==MSC                 /* Advanced mode - designed for OS/2 */
     if((handle=sopen(tmp_name, oflag, shflag, S_IREAD|S_IWRITE))==-1)
     {
      if(errno!=EACCES)
       return(NULL);
      /* Provoke INT 24h call */
      f_file_ptr=name;
      handle=open(tmp_name, oflag, S_IREAD|S_IWRITE);
      f_file_ptr=NULL;
      if(handle==-1)                    /* User abort */
       return(NULL);
      close(handle);
      /* Try to reopen the file in shared mode */
      if((handle=sopen(tmp_name, oflag, shflag, S_IREAD|S_IWRITE))==-1)
       if((handle=open(tmp_name, oflag, S_IREAD|S_IWRITE))==-1)
        return(NULL);
     }
    #endif
    if(handle!=-1)
     return(fdopen(handle, tmp_mode));
    else
     return(NULL);
   #elif TARGET==OS2||TARGET==WIN32
    {
     shflag=(mode[1]=='+'||mode[1]!='\0'&&mode[2]=='+')?SH_DENYWR:SH_DENYNO;
     handle=sopen(name, oflag, shflag, S_IREAD|S_IWRITE);
     if(handle!=-1)
      return((FILE *)fdopen(handle, mode));
     else
      return(NULL);
    }
   #elif TARGET==UNIX
    {
     struct flock flk;

     /* Disengage any links so we don't follow them */
     if(mode[0]=='w')
      unlink(name);
     /* Deny write activities if mixed-mode access */
     if(mode[1]=='+'||(mode[1]!='\0'&&mode[2]=='+'))
     {
      memset(&flk, 0, sizeof(flk));
      flk.l_type=F_WRLCK;
      /* ASR fix 01/10/2003 -- re-fix to handle umask 022 correctly */
      if((handle=open(name, oflag, 0644))==-1)
       return(NULL);
      if(fcntl(handle, F_SETLK, &flk)==-1&&errno!=EINVAL)
      {
       close(handle);
       return(NULL);
      }
      return(fdopen(handle, mode));
     }
     else
      return(fopen(name, mode));
    }
   #endif
  }
 #else
  #if TARGET==DOS
   return(fopen(tmp_name, mode));
  #else
   return(fopen(name, mode));
  #endif
 #endif
}
#endif

/* Convert the given path to uppercase and validate it */

#if SFX_LEVEL>=ARJSFXV
void default_case_path(char *dest, char *src)
{
 case_path(strcpy(dest, validate_path(src, validate_style)));
}
#endif

/* Checks stdin against EOF (for raw input mode) */

#if (SFX_LEVEL>=ARJSFXV||defined(ARJDISP))&&TARGET==DOS
static void check_stdin()
{
 int rc;
 union REGS regs;

 regs.x.ax=0x4400;                      /* IOCTL - query device */
 regs.x.bx=0;                           /* STDIN */
 intdos(&regs, &regs);
 rc=regs.x.dx;
 #ifndef ARJDISP
  if(!(rc&CHDI_NUL))
  {
   if(rc&CHDI_SET)
    return;
   if(!eof(0))
    return;
  }
  error(M_CANTREAD);
 #endif
}
#endif

/* Reads character from console */

#if SFX_LEVEL>=ARJSFXV||defined(ARJDISP)
int uni_getch()
{
 #if TARGET==DOS
  union REGS regs;

  check_stdin();
  regs.h.ah=0x08;                       /* Read character without echo */
  intdos(&regs, &regs);
  return((int)(regs.h.al==0x0D?0x0A:regs.h.al));
 #elif TARGET==OS2
  KBDKEYINFO keyinfo;
  KbdCharIn(&keyinfo, IO_WAIT, 0);

  return(keyinfo.chChar);
 #elif TARGET==WIN32
  return(getch());
 #elif defined(SUNOS)
  static struct termio cookedmode,rawmode;
  static int cookedok;
  int key;

  if (!cookedok)
  {
   ioctl(0,TCGETA,&cookedmode);
   ioctl(0,TCGETA,&rawmode);
   rawmode.c_iflag=IXON|IXOFF;
   rawmode.c_oflag&=~OPOST;
   rawmode.c_lflag=0;
   rawmode.c_cc[VEOF]=1;
   cookedok=1;
  }
  ioctl(0,TCSETAW,&rawmode);
  key=getchar();
  ioctl(0,TCSETAW,&cookedmode);
  return key;
 #else
  return(getchar());
 #endif
}
#endif

/* Returns current system time, in # of ticks since midnight */

#if SFX_LEVEL>=ARJSFXV||defined(REGISTER)
unsigned long get_ticks()
{
 struct time sttime;

 arj_gettime(&sttime);
 return(((unsigned long)sttime.ti_hour*3600L+(unsigned long)sttime.ti_min*60L+
        (unsigned long)sttime.ti_sec)*100L+(unsigned long)sttime.ti_hund);
}
#endif

/* Retrieves current directory */

#if SFX_LEVEL>=ARJSFX&&SFX_LEVEL<=ARJSFXV
void file_getcwd(char *buf, int len)
{
 getcwd(buf, len);
}
#elif defined(REARJ)
char *file_getcwd(char *buf)
{
 #if TARGET==DOS
  if(lfn_supported!=LFN_NOT_SUPPORTED)
   return(w95_cwd(buf));
  else
   return(getcwd(buf, CCHMAXPATH_W95));
 #else
  #if COMPILER==ICC
   return(_getcwd(buf, CCHMAXPATH));
  #else
   return(getcwd(buf, CCHMAXPATH));
  #endif
 #endif
}
#endif

/* Returns switch character used by OS */

#ifdef REARJ
char get_sw_char()
{
 #if TARGET==DOS
  union REGS regs;

  regs.x.ax=0x3700;
  intdos(&regs, &regs);
  return(regs.h.dl);
 #elif TARGET==OS2
  return('/');
 #else
  return('-');
 #endif
}
#endif

/* Returns the amount of free space for disk on which the given file is
   located. */

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)
unsigned long file_getfree(char *name)
{
 #if TARGET==DOS
  #if COMPILER==BCC
   struct dfree dtable;
  #elif COMPILER==MSC
   struct diskfree_t dtable;
  #endif
  char drive=0;

  while(name[0]==' ')                   /* Skip over leading spaces, if any */
   name++;
  if(name[1]==':')
   drive=toupper(name[0])-0x40;
  #if COMPILER==BCC
   getdfree(drive, &dtable);
   if(dtable.df_sclus==65535)
    return(MAXLONG);
   else
   {
    return((LONG_MAX/((long)dtable.df_bsec*dtable.df_sclus)<dtable.df_avail)?
           LONG_MAX:
           (long)dtable.df_bsec*dtable.df_sclus*dtable.df_avail);
   }
  #elif COMPILER==MSC
   if(_dos_getdiskfree((unsigned int)drive, &dtable))
    return(ULONG_MAX);
   else
   {
    return((LONG_MAX/((long)dtable.bytes_per_sector*dtable.sectors_per_cluster)<dtable.avail_clusters)?
           LONG_MAX:
           (long)dtable.bytes_per_sector*dtable.sectors_per_cluster*dtable.avail_clusters);
   }
  #endif
 #elif TARGET==OS2
  USHORT drive=0;
  FSALLOCATE fsinfo;

  while(name[0]==' ')
   name++;
  if(name[1]==':')
   drive=toupper(name[0])-0x40;
  if(DosQFSInfo(drive, FSIL_ALLOC, (PBYTE)&fsinfo, sizeof(fsinfo)))
   return(LONG_MAX);
  else
   return((LONG_MAX/(fsinfo.cSectorUnit*fsinfo.cbSector)<fsinfo.cUnitAvail)?
          LONG_MAX:
          fsinfo.cSectorUnit*fsinfo.cbSector*fsinfo.cUnitAvail);
 #elif TARGET==WIN32
  char tmp[4], *ptmp=NULL;
  DWORD bps, spclu, fclu, clu;

  while(name[0]==' ')
   name++;
  if(name[1]==':')
  {
   ptmp=tmp;
   tmp[0]=toupper(name[0]);
   tmp[1]=':';
   tmp[2]='\\';
   tmp[3]='\0';
  }
  if(!GetDiskFreeSpace(ptmp, &spclu, &bps, &fclu, &clu))
   return(LONG_MAX);
  else
   return((LONG_MAX/(spclu*bps)<fclu)?LONG_MAX:spclu*bps*fclu);
 #elif TARGET==UNIX
  #if defined(__QNXNTO__)||defined(__sco__)||defined(SUNOS)
   struct statvfs vfs;

   if(statvfs(name, &vfs)==-1)
    return(LONG_MAX);
   return((LONG_MAX/512<vfs.f_bavail)?LONG_MAX:vfs.f_bavail*512);
  #else
   struct statfs sfs;

   if(statfs(name, &sfs)==-1)
    return(LONG_MAX);
   return((LONG_MAX/512<sfs.f_bavail)?LONG_MAX:sfs.f_bavail*512);
  #endif
 #endif
}
#endif

/* findfirst() for external use */

#if SFX_LEVEL>=ARJSFXV
int file_find(char *name, struct file_properties *properties)
{
 struct new_ffblk new_ffblk;
 int attrib=STD_FI_ATTRS;
 #if TARGET==UNIX
  int u;
 #endif

 if(lfn_findfirst(name, &new_ffblk, attrib)!=0)
  return(-1);
 else
 {
  #if SFX_LEVEL>=ARJ
   lfn_findclose(&new_ffblk);
   finddata_to_properties(properties, &new_ffblk);
  #else
   properties->ftime=new_ffblk.ff_ftime;
   properties->fsize=new_ffblk.ff_fsize;
   properties->attrib=(ATTRIB)new_ffblk.ff_attrib;
   #if TARGET!=UNIX
    properties->type=(new_ffblk.ff_attrib&FATTR_DIREC)?ARJT_DIR:ARJT_BINARY;
    properties->isarchive=(new_ffblk.ff_attrib&FATTR_ARCH)?1:0;
   #else
    u=uftype(new_ffblk.ff_attrib);
    if(u&FATTR_DT_DIR)
     properties->type=ARJT_DIR;
    else if(u&FATTR_DT_UXSPECIAL)
     properties->type=ARJT_UXSPECIAL;
    else
     properties->type=ARJT_BINARY;
    properties->isarchive=1;
    properties->l_search=new_ffblk.l_search;
    properties->l_search.ref=0;
    properties->islink=0;
   #endif
  #endif
  return(0);
 }
}
#endif

/* Returns the size of the given file */

#if SFX_LEVEL>=ARJ||defined(REARJ)
long file_getfsize(char *name)
{
 #if SFX_LEVEL>=ARJ
  struct new_ffblk new_ffblk;
  int attrib=STD_FI_ATTRS;

  if(lfn_findfirst(name, &new_ffblk, attrib)!=0)
   return(0L);
  else
  {
   lfn_findclose(&new_ffblk);
    return(new_ffblk.ff_fsize);
  }
 #else
  FILE *stream;
  long rc;

  if((stream=file_open(name, m_rb))==NULL)
   return(0);
  #if TARGET!=UNIX
   rc=filelength(fileno(stream));
  #else
   fseek(stream, 0L, SEEK_END);
   rc=ftell(stream);
  #endif
  fclose(stream);
  return(rc);
 #endif
}
#endif

/* Returns last modification time for the given file */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
unsigned long file_getftime(char *name)
{
 #if TARGET==DOS
  #if SFX_LEVEL>=ARJSFXV
   struct new_ffblk new_ffblk;
   int attrib=STD_FI_ATTRS;

   if(lfn_findfirst(name, &new_ffblk, attrib)!=0)
    return(0L);
   else
   {
    #if SFX_LEVEL>=ARJ
     lfn_findclose(&new_ffblk);         /* Done automatically by ARJSFXV */
    #endif
    return(new_ffblk.ff_ftime);
   }
  #else
   FILE *stream;
   unsigned long rc;

   if((stream=file_open(name, m_rb))==NULL)
    return(0L);
   #if COMPILER==BCC
    getftime(fileno(stream), (struct ftime *)&rc);
   #else
    _dos_getftime(fileno(stream), (unsigned int *)&rc+1, (unsigned int *)&rc);
   #endif
   fclose(stream);
   return(rc);
  #endif
 #elif TARGET==OS2
  HFILE hf;
  #ifdef __32BIT__
   ULONG action;
  #else
   USHORT action;
  #endif
  FILESTATUS fstatus;

  if(DosOpen(name, &hf, &action, 0L, 0, FILE_OPEN, OPEN_ACCESS_READONLY|OPEN_SHARE_DENYNONE, 0L))
   return(0L);
  DosQFileInfo(hf, FIL_STANDARD, &fstatus, sizeof(fstatus));
  DosClose(hf);
  return(make_ftime(fstatus.fdateLastWrite, fstatus.ftimeLastWrite));
 #elif TARGET==WIN32
  FILETIME ftime, atime, ctime;
  HANDLE hf;

  if((hf=CreateFile(name, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0))==INVALID_HANDLE_VALUE)
   return(0L);
  if(!GetFileTime(hf, &ctime, &atime, &ftime))
   return(0L);
  CloseHandle(hf);
  return(dosify_time(&ftime));
 #elif TARGET==UNIX
  struct stat st;

  if(lstat(name, &st)==-1)
   return(0L);
  return(st.st_mtime);
 #endif
}
#endif

/* Queries the volume label for the specified drive. The destination buffer
   will contain "" if the volume label is missing. */

#if SFX_LEVEL>=ARJ&&defined(HAVE_VOL_LABELS)
int file_getlabel(char *label, char drive, ATTRIB *attrib, unsigned long *ftime)
{
 #if TARGET==DOS
  struct new_ffblk new_ffblk;
  char wildcard[10];

  if(drive=='\0')
   wildcard[0]='\0';
  else
  {
   wildcard[0]=drive;
   wildcard[1]=':';
   wildcard[2]='\0';
  }
  strcat(wildcard, root_wildcard);
  if(lfn_findfirst(wildcard, &new_ffblk, FATTR_LABEL))
   return(0);                            /* Pretty incorrect but, if no files
                                            are present, it won't be called */
  if(_osmajor>2)
  {
   while(!(new_ffblk.ff_attrib&FATTR_LABEL))
   {
    if(!lfn_findnext(&new_ffblk))
     return(0);
   }
   lfn_findclose(&new_ffblk);
  }
  strcpy(label, new_ffblk.ff_name);
  *attrib=(ATTRIB)new_ffblk.ff_attrib;
  *ftime=new_ffblk.ff_ftime;
  return(0);
 #elif TARGET==OS2
  FSINFO fsinfo;
  USHORT rc;

  rc=DosQFSInfo(drive=='\0'?0:drive-0x40, FSIL_VOLSER, (PBYTE)&fsinfo, sizeof(fsinfo));
  if(rc)
   return((rc==ERROR_NO_VOLUME_LABEL)?0:-1);
  strcpy(label, fsinfo.vol.szVolLabel);
  return(0);
 #elif TARGET==WIN32
  DWORD dummy;

  return(!GetVolumeInformation(NULL, label, CCHMAXPATH, NULL, &dummy, &dummy, NULL, 0));
 #endif
}
#endif

/* Read a line from the stdin w/echo, returning the number of bytes read. */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
int read_line(char *buf, int size)
{
 #if TARGET==DOS
  union REGS regs;
  #if SFX_LEVEL>=ARJSFX||defined(REARJ)
   char tmp_buf[160];                    /* Actually, DOS limit is 128 */
  #endif
  unsigned int ioctl_set, ioctl_isbinary, ioctl_response;
  int chars_read;
  int cchar;

  regs.x.ax=0x4400;                      /* IOCTL - query device */
  regs.x.bx=0;                           /* STDIN */
  intdos(&regs, &regs);
  ioctl_response=regs.x.dx;
  ioctl_set=(ioctl_response&CHDI_SET)?1:0;
  ioctl_isbinary=(ioctl_response&CHDI_BINARY)?1:0;
  #ifdef REARJ
   ioctl_isbinary=ioctl_set&ioctl_isbinary;
  #endif
  if(ioctl_set&&ioctl_isbinary||_osmajor<3)
  {
   #if SFX_LEVEL>=ARJSFXV
    tmp_buf[0]=min(size, INPUT_LIMIT);   /* Number of input positions */
    tmp_buf[1]=tmp_buf[0]-1;             /* Number of recallable positions */
    regs.h.ah=0x0A;
    regs.x.dx=(unsigned int)tmp_buf;
    intdos(&regs, &regs);
    chars_read=(int)tmp_buf[1];
    if(tmp_buf[chars_read+2]=='\x0D')
     tmp_buf[chars_read+2]='\0';         /* Convert to ASCIIZ */
    strcpy(buf, tmp_buf+2);
    nputlf();                            /* v 2.72+ fixup to live happily
                                            under Unices */
   #elif defined(REARJ)
    tmp_buf[0]=min(size, INPUT_LIMIT);   /* Number of input positions */
    cgets(tmp_buf);
    chars_read=(int)tmp_buf[1];
    strcpy(buf, tmp_buf+2);
   #else
    error(M_RAW_INPUT_REJECTED);
   #endif
  }
  else
  {
   for(chars_read=0; (cchar=fgetc(stdin))!=EOF&&cchar!=LF; chars_read++)
   {
    if(chars_read<size-1)
     buf[chars_read]=(char)cchar;
   }
   if(cchar==-1)
    error(M_CANTREAD);
   buf[chars_read]='\0';
  }
  msg_cprintf(0, cr);                   /* ASR fix 03/02/2003 for COLOR_OUTPUT */
  return(chars_read);
 #elif (TARGET==OS2&&(COMPILER==MSC||defined(LIBC)))||TARGET==WIN32||TARGET==UNIX
  int chars_read;
  int cchar;

  for(chars_read=0; (cchar=fgetc(stdin))!=EOF&&cchar!=LF; chars_read++)
  {
   if(chars_read<size-1)
    buf[chars_read]=(char)cchar;
  }
  if(cchar==-1)
   error(M_CANTREAD);
  buf[chars_read]='\0';
  return(chars_read);
 #else                          	/* A platform-neutral solution */
  char *p;

  #ifdef DEBUG
   debug_report(dbg_cur_file, __LINE__, 'W');
  #endif
  fgets(buf, size, stdin);              /* DIRTY HACK */
  if((p=strchr(buf, '\n'))!=NULL)
   *p='\0';
  if((p=strchr(buf, '\r'))!=NULL)
   *p='\0';
  return(strlen(buf));
 #endif
}
#endif

/* Returns file access mode in character format */

#if SFX_LEVEL>=ARJSFX
void get_mode_str(char *str, unsigned int mode)
{
 #if TARGET==UNIX
  int i;

  str[0]='-';
  for(i=0; i<3; i++)
  {
   str[(2-i)*3+1]=(mode&4)?'r':'-';
   str[(2-i)*3+2]=(mode&2)?'w':'-';
   str[(2-i)*3+3]=(mode&1)?'x':'-';
   mode>>=3;
  }
  str[10]=' ';
  str[11]=(mode&FATTR_SGID)?'G':'-';
  str[12]=(mode&FATTR_SUID)?'U':'-';
  str[13]=(mode&FATTR_SVTX)?'A':'-';
  str[14]='\0';
 #else
  strcpy(str, attrib_buf);
  if(mode&FATTR_ARCH)
   str[0]='A';
  if(mode&FATTR_SYSTEM)
   str[1]='S';
  if(mode&FATTR_HIDDEN)
   str[2]='H';
  if(mode&FATTR_RDONLY)
   str[3]='R';
 #endif
}
#endif

/* Retrieves an environment string */

#if TARGET==OS2&&SFX_LEVEL>=ARJSFX
static char FAR *get_env_str(char *t)
{
 #ifdef __32BIT__
  PSZ rc;

  if(DosScanEnv(t, &rc))
   return(NULL);
  return((char FAR *)rc);
 #else
  USHORT selector;
  USHORT cmd_offset;
  char FAR *env_ptr;
  int i;

  DosGetEnv(&selector, &cmd_offset);
  env_ptr=MAKEP(selector, 0);
  while(*env_ptr!='\0')
  {
   for(i=0; t[i]!='\0'; i++)
    if(env_ptr[i]=='\0'||env_ptr[i]!=t[i])
     break;
   if(t[i]=='\0'&&env_ptr[i]=='=')
    return(env_ptr+i+1);
   env_ptr+=i;
   while(*env_ptr++!='\0');
  }
  return(NULL);
 #endif
}
#endif

/* Reserves memory and gets an environment string */

#if TARGET==OS2&&SFX_LEVEL>=ARJSFX
char *malloc_env_str(char *t)
{
 char FAR *str, FAR *sptr;
 char *rc, *rptr;
 int i;

 if((str=get_env_str(t))==NULL)
  return(NULL);
 i=1;
 for(sptr=str; *sptr!='\0'; sptr++)
  i++;
 if((rc=(char *)malloc(i))==NULL)
  return(NULL);                         /* Env. string was too long */
 rptr=rc;
 for(sptr=str; *sptr!='\0'; sptr++)
  *rptr++=*sptr;
 *rptr='\0';
 return(rc);
}
#endif

/* A small exported stub for C RTL to be happy */

#if TARGET==OS2&&COMPILER==MSC&&SFX_LEVEL>=ARJ
char *getenv(const char *str)
{
 return(NULL);                          /* No such a string */
}
#endif

/* Executes the given program directly, returning its RC */

#if defined(REARJ)||(SFX_LEVEL>=ARJSFX&&TARGET==OS2)
int exec_pgm(char *cmdline)
{
 char tmp_cmd[CMDLINE_LENGTH+CCHMAXPATH];
 #if TARGET==OS2                	/* && SFX_LEVEL>=ARJSFX */
  char *params;
  int p_pos;
  #ifdef REARJ
   #ifdef __32BIT__
    PPIB ppib=NULL;
    PTIB ptib=NULL;
    ULONG child_pid, session_pid;
    REQUESTDATA qr;
    ULONG qrc;
    ULONG cb_res;
   #else
    PID child_pid, session_pid;
    PIDINFO pidi;
    QUEUERESULT qr;
    USHORT qrc;
    USHORT cb_res;
   #endif
   STARTDATA sd;
   char qname[CCHMAXPATH];
   HQUEUE queue;
   USHORT errcode;
   PUSHORT res;
   BYTE elem_priority;
   char *argv[PARAMS_MAX];
   int arg;
   static char param_sep[]=" ";
  #else
   RESULTCODES rc;
  #endif

  #ifndef REARJ
   memset(tmp_cmd, 0, sizeof(tmp_cmd));
   if((params=strchr(cmdline, ' '))!=NULL)
   {
    p_pos=params-cmdline;
    if(p_pos>0)
     memcpy(tmp_cmd, cmdline, p_pos);
    strcpy(tmp_cmd+p_pos+1, params);
   }
   else
    strcpy(tmp_cmd, cmdline);
   if(!DosExecPgm(NULL, 0, EXEC_SYNC, tmp_cmd, NULL, &rc, tmp_cmd))
    return(rc.codeResult);
   else
    return(-1);
  #else
   strncpy(tmp_cmd, cmdline, sizeof(tmp_cmd)-1);
   tmp_cmd[sizeof(tmp_cmd)-1]='\0';
   argv[0]=strtok(tmp_cmd, param_sep);
   if(argv[0]==NULL)
    return(-1);
   for(arg=1; arg<PARAMS_MAX; arg++)
    if((argv[arg]=strtok(NULL, param_sep))==NULL)
     break;
   if(arg>=PARAMS_MAX)
    return(-1);
   if((errcode=spawnvp(P_WAIT, argv[0], argv))!=0xFFFF)
    return(errcode);
   else
   {
    /* Try running the program asynchronously using the SESMGR */
    memset(tmp_cmd, 0, sizeof(tmp_cmd));
    if((params=strchr(cmdline, ' '))!=NULL)
    {
     p_pos=params-cmdline;
     if(p_pos>0)
      memcpy(tmp_cmd, cmdline, p_pos);
     strcpy(tmp_cmd+p_pos+1, params);
    }
    else
     strcpy(tmp_cmd, cmdline);
    #ifdef __32BIT__
     DosGetInfoBlocks(&ptib, &ppib);    /* Fixed for PJ24109 */
     sprintf(qname, rearj_q_fmt, ppib->pib_ulpid);
    #else
     DosGetPID(&pidi);
     sprintf(qname, rearj_q_fmt, pidi.pid);
    #endif
    if(DosCreateQueue(&queue, QUE_FIFO, qname))
     return(-1);
    memset(&sd, 0, sizeof(sd));
    sd.Length=sizeof(sd);
    sd.Related=TRUE;
    sd.FgBg=TRUE;                       /* Start in background */
    sd.PgmName=tmp_cmd;
    sd.PgmInputs=params;
    sd.TermQ=qname;
    sd.InheritOpt=1;
    if(DosStartSession(&sd, &session_pid, &child_pid))
     return(-1);
    while((qrc=DosReadQueue(queue, &qr, &cb_res, (PVOID FAR *)&res, 0, DCWW_WAIT,
                             &elem_priority, 0))==0)
    {
     errcode=res[1];
     #ifdef __32BIT__
      DosFreeMem(res);
      if(qr.ulData==0)
       break;
     #else
      DosFreeSeg(SELECTOROF(res));
      if(qr.usEventCode==0)
       break;
     #endif
    }
    DosCloseQueue(queue);
    return(errcode);
   }
  #endif
 #else
  char *argv[PARAMS_MAX];
  int arg;
  static char param_sep[]=" ";
  #if TARGET==UNIX
   int pid, rc, status;
   struct sigaction ign_set, intr, quit;
  #endif

  strncpy(tmp_cmd, cmdline, sizeof(tmp_cmd)-1);
  tmp_cmd[sizeof(tmp_cmd)-1]='\0';
  argv[0]=strtok(tmp_cmd, param_sep);
  if(argv[0]==NULL)
   return(-1);
  for(arg=1; arg<PARAMS_MAX; arg++)
  {
   if((argv[arg]=strtok(NULL, param_sep))==NULL)
    break;
   #if TARGET==UNIX
    if(argv[arg][0]=='"'&&argv[arg][strlen(argv[arg])-1]=='"')
    {
     argv[arg]++;
     argv[arg][strlen(argv[arg])-1]='\0';
    }
   #endif
  }
  if(arg>=PARAMS_MAX)
   return(-1);
  #if TARGET!=UNIX
   return(spawnvp(P_WAIT, argv[0], argv));
  #else
   if((pid=fork())==-1)
    return(-1);
   if(pid==0)
   {
    exit(execvp(argv[0], argv));
   }
   else
   {
    /* Prevent signals from appearing */
    ign_set.sa_handler=SIG_IGN;
    ign_set.sa_flags=0;
    sigemptyset(&ign_set.sa_mask);
    sigaction(SIGINT, &ign_set, &intr);
    sigaction(SIGQUIT, &ign_set, &quit);
    /* Wait for the child */
    do
     rc=waitpid(pid, &status, 0);
    while(rc==-1&&errno==EINTR);
    /* Restore signals */
    sigaction(SIGINT, &intr, NULL);
    sigaction(SIGQUIT, &quit, NULL);
    return(status);
   }
  #endif
 #endif
}
#endif

/* Executes a program or a shell command */

#if SFX_LEVEL>=ARJSFX&&TARGET==OS2
int system_cmd(char *cmd)
{
 char tmp_cmd[CMDLINE_LENGTH+CCHMAXPATH];
 char *comspec;

 comspec=malloc_env_str("COMSPEC");
 strcpy(tmp_cmd, (comspec==NULL)?"cmd" EXE_EXTENSION:comspec);
 free_env_str(comspec);
 strcat(tmp_cmd, " /C");
 strcat(tmp_cmd, cmd);
 return((exec_pgm(tmp_cmd)==-1)?-1:0);
}
#endif

/* Retrieves the name of executable */

#if (SFX_LEVEL>=ARJSFXJR||defined(REARJ))
#ifndef SKIP_GET_EXE_NAME
void get_exe_name(char *dest)
{
 #if TARGET==DOS
  char FAR *env_ptr;
  unsigned short s_seg;
  unsigned int i;
  unsigned short psp_seg;

  if(_osmajor<3)
  {
   if(_osmajor!=2||_osminor!=11)
    strcpy(dest, default_exe);
   else
   {
    #if COMPILER==BCC
     s_seg=*(unsigned short FAR *)MK_FP(_psp, 2)-56;
    #else                               /* Microsoft C changes the MCB order */
     s_seg=(*(unsigned short FAR *)0x00400013<<6)-56;
    #endif
    env_ptr=MK_FP(s_seg, 9);            /* Not actually ENV but it works! */
    i=0;
    while(*env_ptr!='\0'&&i<FILENAME_MAX)
     dest[i++]=*(env_ptr++);
    dest[i]='\0';
    if(dest[i-4]!='.'||dest[i-3]!='E'||dest[i-2]!='X'||dest[i-1]!='E')
     strcpy(dest, default_exe);
   }
  }
  else
  {
   #ifdef ASM8086
    asm{
     push ax
     push bx
     mov ah, 62h
     int 21h
     mov psp_seg, bx
     pop bx
     pop ax
    }
   #else
    {
     union REGS regs;

     regs.x.ax=0x6200;
     intdos(&regs, &regs);
     psp_seg=regs.x.bx;
    }
   #endif
   env_ptr=MK_FP(*(unsigned short FAR *)MK_FP(psp_seg, 0x2C), 0);
   while(*(short FAR *)(env_ptr++)!=0);
   env_ptr+=3;
   i=0;
   while(*env_ptr!='\0'&&i<FILENAME_MAX)
    dest[i++]=*(env_ptr++);
   dest[i]='\0';
  }
 #elif TARGET==OS2
  #ifdef __32BIT__
   PTIB ptib;
   PIB *ppib;

   DosGetInfoBlocks(&ptib, &ppib);
   DosQueryModuleName(ppib->pib_hmte, CCHMAXPATH, dest);
  #else
   USHORT selector;
   USHORT cmd_offset;
   char FAR *sptr;

   DosGetEnv(&selector, &cmd_offset);
   sptr=MAKEP(selector, 0);
   while(*(SHORT FAR *)sptr!=0)
    sptr++;
   sptr+=2;
   while(*sptr!='\0')
    *dest++=*sptr++;
   *dest='\0';
  #endif
 #elif TARGET==WIN32
  GetModuleFileName(NULL, dest, CCHMAXPATH);
 #endif
}
#else /* SKIP_GET_EXE_NAME */
void get_exe_name(char *dest, char *arg)
{
 char *ps, *pe;
 int l;
 int len;

 if(strchr(arg, PATHSEP_DEFAULT)!=NULL)
 {
  strcpy(dest, arg);
  return;
 }
 len=FILENAME_MAX-2-strlen(arg);
 ps=getenv("PATH");
 do
 {
  pe=strchr(ps, ':');
  if(pe==NULL)
   pe=ps+(l=strlen(ps));
  else
   l=pe-ps;
  if(l>=len)
   l=len-1;
  memcpy(dest, ps, l);
  if(dest[l-1]!=PATHSEP_DEFAULT)
   dest[l++]=PATHSEP_DEFAULT;
  strcpy(dest+l, arg);
  if(!access(dest, F_OK)||errno==EINVAL)
   return;
  ps=pe+1;
 } while(*pe!='\0');
 /* Notes to porters: below are the totally unlikely "last-chance" values.
    The DOS legacy parts of ARJ open its executable when looking for SFX
    modules and help screens. In most cases we are happy with argv[0] and
    PATH lookup. When that fails, we assume the locations below, and if
    they are missing altogether, the corresponding code will gracefully
    terminate. */
 #if SFX_LEVEL==ARJ
  strcpy(dest, "/usr/local/bin/arj");
 #elif SFX_LEVEL==ARJSFXV
  strcpy(dest, "./arjsfxv");
 #elif SFX_LEVEL==ARJSFX
  strcpy(dest, "./arjsfx");
 #elif SFX_LEVEL==ARJSFXJR
  strcpy(dest, "./arjsfxjr");
 #elif defined(REARJ)
  strcpy(dest, "/usr/local/bin/rearj");
 #else
  dest[0]='\0';
 #endif
}
#endif
#endif

/* Read a line from console without echoing it (used only when prompting for
   passwords) */

#if SFX_LEVEL>=ARJSFXV
int read_line_noecho(char *buf, int size)
{
 int chars_read;
 int cchar;

 chars_read=0;
 cchar=uni_getch();
 while(cchar!=LF&&cchar!=CR)
 {
  if(cchar=='\b')
  {
   if(chars_read!=0)
    chars_read--;
  }
  else if(chars_read<size-1)
   buf[chars_read++]=cchar;
  cchar=uni_getch();
 }
 buf[chars_read]='\0';
 nputlf();
 return(chars_read);
}
#endif

/* Returns the number of bytes per allocation unit for the drive that contains
   the given file. NOTE: this is an advisory value to align multivolume
   archives tightly when the free space is a constraint. Not to be used in
   converting allocation units to bytes. */

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)
unsigned int get_bytes_per_cluster(char *name)
{
 #if TARGET==DOS
  #if COMPILER==BCC
   struct dfree dtable;
  #elif COMPILER==MSC
   struct diskfree_t dtable;
  #endif
  char drive=0;

  while(name[0]==' ')                   /* Skip over leading spaces, if any */
   name++;
  if(name[1]==':')
   drive=toupper(name[0])-0x40;
  #if COMPILER==BCC
   getdfree(drive, &dtable);
   if(dtable.df_sclus==65535)
    return(1024);
   else
    return(dtable.df_bsec*dtable.df_sclus);
  #elif COMPILER==MSC
   if(_dos_getdiskfree((unsigned int)drive, &dtable))
    return(1024);
   else
    return(dtable.bytes_per_sector*dtable.sectors_per_cluster);
  #endif
 #elif TARGET==OS2
  USHORT drive=0;
  FSALLOCATE fsinfo;
  unsigned long rc;

  while(name[0]==' ')
   name++;
  if(name[1]==':')
   drive=toupper(name[0])-0x40;
  if(DosQFSInfo(drive, FSIL_ALLOC, (PBYTE)&fsinfo, sizeof(fsinfo)))
   return(ULONG_MAX);
  rc=(unsigned long)fsinfo.cbSector*fsinfo.cSectorUnit;
  return(rc>UINT_MAX?UINT_MAX:rc);
 #elif TARGET==WIN32
  char fpn[CCHMAXPATH];
  LPTSTR fnc;
  DWORD bps, spclu, fclu, clu;

  if(!GetFullPathName(name, CCHMAXPATH, fpn, &fnc)||fpn[1]!=':')
   return(ULONG_MAX);
  fpn[3]='\0';
  if(!GetDiskFreeSpace(fpn, &spclu, &bps, &fclu, &clu))
   return(ULONG_MAX);
  else
   return(bps*spclu);
 #elif TARGET==UNIX
  #ifdef linux
   struct statvfs vfs;

   if(statvfs(name, &vfs)==-1)
    return(512);
   else
    return(vfs.f_bsize);
  #else
   return(512);
  #endif
 #endif
}
#endif

/* Returns canonical Windows 95 longname for a given file */

#if SFX_LEVEL>=ARJ&&TARGET==DOS
void get_canonical_longname(char *cname, char *name)
{
 int name_ofs;                          /* Offset of LFN within name[] */
 char *cname_ptr, *name_ptr;

 if(name[1]==':'||name[0]==PATHSEP_DEFAULT||name[0]==PATHSEP_UNIX||name[0]=='.')
  name_ofs=0;
 else
 {
  w95_get_longname(cur_dir_spec, cname, CCHMAXPATH);
  name_ofs=strlen(cname);
 }
 w95_get_longname(name, cname, CCHMAXPATH);
 if(name_ofs==0)
  return;
 cname_ptr=cname;
 name_ptr=name+name_ofs;
 if(name_ptr[0]==PATHSEP_DEFAULT||name_ptr[0]==PATHSEP_UNIX)
  name_ptr++;
 while(name_ptr[0]!='\0')
 {
  (cname_ptr++)[0]=(name_ptr++)[0];
 }
 cname_ptr[0]='\0';
}
#endif

/* Returns canonical short name for a given Windows 95 long filename */

#if SFX_LEVEL>=ARJ&&TARGET==DOS
void get_canonical_shortname(char *cname, char *name)
{
 int name_ofs;                          /* Offset of LFN within name[] */
 char *cname_ptr, *name_ptr;

 if(name[1]==':'||name[0]==PATHSEP_DEFAULT||name[0]==PATHSEP_UNIX||name[0]=='.')
  name_ofs=0;
 else
 {
  w95_get_shortname(cur_dir_spec, cname, CCHMAXPATH);
  name_ofs=strlen(cname);
 }
 w95_get_shortname(name, cname, CCHMAXPATH);
 if(name_ofs==0)
  return;
 cname_ptr=cname;
 name_ptr=name+name_ofs;
 if(name_ptr[0]==PATHSEP_DEFAULT||name_ptr[0]==PATHSEP_UNIX)
  name_ptr++;
 while(name_ptr[0]!='\0')
 {
  (cname_ptr++)[0]=(name_ptr++)[0];
 }
 cname_ptr[0]='\0';
}
#endif

/* Displays a string pointed to by a FAR pointer on the stdout. Used only by
   internal functions of ENVIRON.C. */

#if SFX_LEVEL>=ARJSFXV&&TARGET==DOS
static void far_ttyout(char FAR *str)
{
 union REGS regs;
 char FAR *str_ptr;

 str_ptr=str;
 regs.h.ah=2;                           /* Jung does it in the loop but we
                                           don't. */
 while(str_ptr[0]!='\0')
 {
  regs.h.dl=(str_ptr++)[0];
  intdos(&regs, &regs);
 }
}
#endif

/* Reads one character from keyboard without echo. Used only by internal
   functions of ENVIRON.C */

#if SFX_LEVEL>=ARJSFXV&&TARGET==DOS
static int flush_and_getch()
{
 union REGS regs;

 regs.x.ax=0xC08;                          /* Clear buffer and then getch */
 intdos(&regs, &regs);
 return((int)regs.h.al);
}
#endif

/* "Intelligent" interrupt 24h handler */

#if SFX_LEVEL>=ARJSFXV&&TARGET==DOS
#if COMPILER==BCC
static void interrupt int24_smart_handler(unsigned int bp, unsigned int di,
                                          unsigned int si, unsigned int ds,
                                          unsigned int es, unsigned int dx,
                                          unsigned int cx, unsigned int bx,
                                          unsigned int ax)
#elif COMPILER==MSC
void _interrupt _far int24_smart_handler( unsigned int es, unsigned int ds,
                                            unsigned int di, unsigned int si,
                                            unsigned int bp, unsigned int sp,
                                            unsigned int bx, unsigned int dx,
                                            unsigned int cx, unsigned int ax,
                                            unsigned int ip, unsigned int cs,
                                            unsigned int flags)
#endif
{
 char msg[40];
 char query[64];
 #if COMPILER==BCC
  struct DOSERROR exterr;
 #elif COMPILER==MSC
  union REGS regs;
 #endif
 char dev[12];
 char *action;
 FMSG *final_response;
 int user_action;
 char response;
 char drive;
 int errcode;
 #if COMPILER==MSC
  int dos_errcode;
 #endif
 int dev_ctr;

 #if COMPILER==MSC
  _enable();
  dos_errcode=errcode=di&0xFF;
 #endif
 action=malloc_fmsg(ax&INT24_DPF_WRITING?M_WRITING:M_READING);
 #if SFX_LEVEL>=ARJ
  if(errcode>0x12)
   errcode=0x12;                        /* Ignore DOS 4.x error codes */
  if(_osmajor>=3)
  {
   #if COMPILER==BCC
    errcode=dosexterr(&exterr);
   #elif COMPILER==MSC
    regs.h.ah=0x59;
    regs.x.bx=0;
    intdos(&regs, &regs);
    errcode=regs.x.ax;
   #endif
   if(errcode<0x13||errcode>0x25)
    errcode=0x25;                       /* Ignore DOS 2.x/4.x error codes */
   errcode-=0x13;
  }
  msg_strcpyn((FMSG *)msg, DOS_MSGS[errcode], sizeof(msg)-1);
 #else
  if(errcode>0x0D)
   errcode=0x0D;
 #endif
 if(ax&INT24_IO_ERROR)
 {
  if(((char *)MK_FP(bp, si))[5]&0x80)
   far_ttyout((char FAR *)M_CRIT_ERROR);
  else
  {
   for(dev_ctr=0; dev_ctr<8; dev_ctr++)
    dev[dev_ctr]=((char *)MK_FP(bp, si))[10+dev_ctr];
   dev[dev_ctr]='\0';
   msg_sprintf(query, M_DEVICE, msg, action, dev);
   far_ttyout((char FAR *)query);
  }
 }
 else
 {
  #if COMPILER==MSC
   if(f_file_ptr!=NULL&&dos_errcode==0x0D||dos_errcode==0x0E)
    msg_sprintf(query, M_FOPEN, msg, f_file_ptr);
   else
  #endif
  {
   drive=(char)ax+'A';
   msg_sprintf(query, M_DRIVE, msg, action, drive);
  }
  far_ttyout((char FAR *)query);
 }
 user_action=1;
 if(ignore_errors)
 {
  free_fmsg(action);
  ax=INT24_FAIL;
 }
 else
 {
  query[1]=CR;
  query[2]=LF;
  query[3]='\0';
  do
  {
   far_ttyout((char FAR *)M_OK_TO_RETRY);
   query[0]=response=(char)flush_and_getch();
   far_ttyout((char FAR *)query);
  }
  while((final_response=msg_strchr(M_REPLIES, (char)toupper(response)))==NULL||
        (user_action=final_response-M_REPLIES)>2);
  free_fmsg(action);
  if(user_action==0)
   ax=INT24_RETRY;
  else if(user_action==2||is_dos_31)    /* DOS 2.x/3.0 do not support FAIL */
   ax=INT24_ABORT;
  else
  {
   ax=INT24_FAIL;
   user_wants_fail=-1;
  }
 }
}
#endif

/* Installs the "smart" handler */

#if SFX_LEVEL>=ARJSFXV
void install_smart_handler()
{
 #if TARGET==DOS
  setvect(INT24, int24_smart_handler);
 #elif TARGET==OS2
  if(ignore_errors)
  {
   #ifdef __32BIT__
    DosError(FERR_DISABLEHARDERR|FERR_DISABLEEXCEPTION);
   #else
    DosError(HARDERROR_DISABLE);
    DosError(EXCEPTION_DISABLE);
   #endif
  }
 #elif TARGET==UNIX
  /* No hard error daemon here */
 #endif
}
#endif

/* Checks if the given file handle actually represents a file */

#if SFX_LEVEL>=ARJSFXV
int is_file(FILE *stream)
{
 #if TARGET==DOS
  #if COMPILER==BCC
   return(ioctl(fileno(stream), 0)&CHDF_NOT_FILE?1:0);
  #elif COMPILER==MSC
   union REGS regs;

   regs.x.ax=0x4400;
   regs.x.bx=fileno(stream);
   intdos(&regs, &regs);
   return(regs.x.dx&CHDF_NOT_FILE?1:0);
  #endif
 #elif TARGET==OS2||TARGET==WIN32
  return(fileno(stream)<2?1:0);         /* Another dirty hack... */
 #else
  struct stat st;

  fstat(fileno(stream), &st);
  /* ASR fix 02/05/2003: ineed, we shouldn't check for FATTR_DT_REG here! */
  return(st.st_mode==S_IFREG);
 #endif
}
#endif

/* Returns 1 if the given file is stored on removable media */

#if SFX_LEVEL>=ARJSFXV
int file_is_removable(char *name)
{
 #if TARGET!=UNIX
  char drive=0;

  while(name[0]==' ')
   name++;
  if(name[1]==':')
   drive=toupper(name[0])-0x40;
  else
   drive=getdisk()+1;
  #if TARGET==DOS
   if(_osmajor<3)                        /* DOS 2.x - A: and B: are removable */
    return(drive==1||drive==2);
   else
   #if COMPILER==BCC
    return(ioctl(drive, 8)==0);
   #elif COMPILER==MSC
   {
    union REGS regs;

    regs.x.ax=0x4408;
    regs.x.bx=(unsigned int)drive;
    intdos(&regs, &regs);
    return(regs.x.ax==0);
   }
  #endif
  #elif TARGET==OS2||TARGET==WIN32
   return(drive==1||drive==2);
  #endif
 #else
  return(0);                            /* BUGBUG: fix for floppies! */
 #endif
}
#endif

/* Checks if the given file handle represends a terminal or console */

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)
int is_tty(FILE *stream)
{
 return(isatty(fileno(stream))==0?0:1);
}
#endif

/* mkdir() - Borland's implementation */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
int file_mkdir(char *name)
{
 #if TARGET==DOS
  if(lfn_supported!=LFN_NOT_SUPPORTED)
   return(w95_mkdir(name));
  else
   return(mkdir(name));
 #elif TARGET==OS2||TARGET==WIN32
  #ifdef __EMX__
   return(mkdir(name, 0));
  #else
   return(mkdir(name));
  #endif
 #else
  return(mkdir(name, 0755));
 #endif
}
#endif

#if (TARGET==OS2||TARGET==WIN32)&&!defined(TILED)

/* The "workhorse" routine for wildcard matching */

static int wild_proc(char *wild, char *name, UINT32 *trail, unsigned int first, unsigned int nesting)
{
 #define set_trail(w,r) trail[((w)*MAXWILDAST+(r))>>5]|=(1<<(((w)*MAXWILDAST+(r))&31))
 #define check_trail(w,r) (trail[((w)*MAXWILDAST+(r))>>5]&(1<<(((w)*MAXWILDAST+(r))&31)))
 int rc=1;

 if(nesting>=MAXWILDAST)
  return(1);
 while(*wild)
 {
  switch(*wild)
  {
   case '?':
    if(*name=='\0')
     return(1);
    wild++;
    break;
   case '*':
    if(!check_trail(first, nesting)&&!wild_proc(wild+1, name, trail, first, nesting+1))
     return(0);
    if(*name=='\0')
     return(1);
    set_trail(first, nesting);
    break;
   default:
    if(toupper(*name)!=toupper(*wild))
     return(1);
    wild++;
  }
  name++;
  first++;
 }
 return(*name!=*wild);
 #undef set_trail
 #undef check_trail
}
#endif

/* Returns non-zero if the given filename matches the given wildcard */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
int match_wildcard(char *name, char *wcard)
{
 #if TARGET==DOS
  if(!stricmp(wcard, all_wildcard))
   return(1);
  while(wcard[0]!='\0')
  {
   switch(wcard[0])
   {
    case '*':
     while(name[0]!='\0'&&name[0]!='.')
      name++;
     while(wcard[0]!='\0'&&wcard[0]!='.')
      wcard++;
     break;
    case '.':
     if(name[0]!='\0')
     {
      if(name[0]!=wcard[0])
       return(0);
      name++;
     }
     wcard++;
     break;
    case '?':
     if(name[0]!='\0'&&name[0]!='.')
      name++;
     wcard++;
     break;
    default:
     if(toupper(name[0])!=toupper(wcard[0]))
      return(0);
    name++;
    wcard++;
   }
  }
  return(name[0]=='\0'?1:0);
 #elif TARGET==OS2&&defined(TILED)
  char dest[CCHMAXPATH];

  /* This is a speedy and compact hack for 16-bit mode */
  DosEditName(0x0001, name, wcard, dest, CCHMAXPATH);
  return(!stricmp(dest, name));  
 #elif TARGET==OS2||TARGET==WIN32
  char tmp_wild[CCHMAXPATH];
  /* Bit map: (maximum # of wildcards) x (maximum pattern length) */
  UINT32 trail[(MAXWILDAST*CCHMAXPATHCOMP+31)>>5];
  int l;

  memcpy(tmp_wild, wcard, (l=strlen(wcard))+1);
  memset(trail, 0, sizeof(trail));
  if(tmp_wild[l-1]=='.')
  {
   if(strchr(name, '.')!=NULL)
    return(1);
   tmp_wild[l-1]='\0';
  }
  return(!wild_proc(tmp_wild, name, trail, 0, 0));
 #else
  int rc;

  rc=fnmatch(wcard, name, 0);
  #ifndef TOLERANT_FNMATCH
   if(rc)
    rc=strcmp_os(wcard, name);
  #endif
  return(!rc);
 #endif
}
#endif

/* rmdir() */

#if SFX_LEVEL>=ARJ||defined(REARJ)
int file_rmdir(char *name)
{
 #if TARGET!=UNIX
  if(clear_archive_bit)
   dos_chmod(name, FATTR_NOARCH);
 #endif
 #if TARGET==DOS
  if(lfn_supported!=LFN_NOT_SUPPORTED)
   return(w95_rmdir(name));
  else
   return(rmdir(name));
 #else
  return(rmdir(name));
 #endif
}
#endif

/* unlink() */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
int file_unlink(char *name)
{
 #if SFX_LEVEL>=ARJSFXV&&TARGET!=UNIX
  if(file_test_access(name))
   return(-1);
  #if SFX_LEVEL>=ARJ
   if(clear_archive_bit)
    dos_chmod(name, 0);
  #else
   if(overwrite_ro)
    dos_chmod(name, 0);
  #endif
 #endif
 #if TARGET==DOS
  if(lfn_supported!=LFN_NOT_SUPPORTED)
   return(w95_unlink(name));
  else
   return(unlink(name));
 #else
  return(unlink(name));
 #endif
}
#endif

/* rename() */

#if SFX_LEVEL>=ARJ||defined(REARJ)
int file_rename(char *oldname, char *newname)
{
 #if TARGET==DOS
  if(lfn_supported!=LFN_NOT_SUPPORTED)
   return(w95_rename(oldname, newname));
  else
   return(rename(oldname, newname));
 #else
  return(rename(oldname, newname));
 #endif
}
#endif

/* This INT 24h handler always forces the operation that causes it to fail */

#if SFX_LEVEL>=ARJ&&TARGET==DOS
#if COMPILER==BCC
static void interrupt int24_autofail_handler(unsigned int bp, unsigned int di,
                                             unsigned int si, unsigned int ds,
                                             unsigned int es, unsigned int dx,
                                             unsigned int cx, unsigned int bx,
                                             unsigned int ax)
#elif COMPILER==MSC
void _interrupt _far int24_autofail_handler(unsigned int es, unsigned int ds,
                                           unsigned int di, unsigned int si,
                                           unsigned int bp, unsigned int sp,
                                           unsigned int bx, unsigned int dx,
                                           unsigned int cx, unsigned int ax,
                                           unsigned int ip, unsigned int cs,
                                           unsigned int flags)
#endif
{
 char msg[40];
 char query[64];
 #if COMPILER==BCC
  struct DOSERROR exterr;
 #elif COMPILER==MSC
  union REGS regs;
 #endif
 char *action;
 char drive;
 int errcode;

 #if COMPILER==MSC
  _enable();
 #endif
 action=malloc_fmsg(ax&INT24_DPF_WRITING?M_WRITING:M_READING);
 errcode=di&0xFF;
 if(errcode>0x12)
  errcode=0x12;                         /* Ignore DOS 4.x error codes */
 if(_osmajor>=3)
 {
   #if COMPILER==BCC
    errcode=dosexterr(&exterr);
   #elif COMPILER==MSC
    regs.h.ah=0x59;
    regs.x.bx=0;
    intdos(&regs, &regs);
    errcode=regs.x.ax;
   #endif
  if(errcode<0x13||errcode>0x25)
   errcode=0x25;                        /* Ignore DOS 2.x/4.x error codes */
  errcode-=0x13;
 }
 msg_strcpyn((FMSG *)msg, DOS_MSGS[errcode], sizeof(msg)-1);
 drive=(char)(ax&0xFF)+'A';
 msg_sprintf(query, M_DRIVE, msg, action, drive);
 far_ttyout(query);
 free_fmsg(action);
 ax=INT24_FAIL;
}
#endif

/* Clears the archive attribute */

#if SFX_LEVEL>=ARJ
int dos_clear_arch_attr(char *name)
{
 #if TARGET!=UNIX
  int cur_attr, result;
  #if TARGET==DOS
   #if COMPILER==BCC
    void interrupt (*oldhdl)();
   #elif COMPILER==MSC
    void (_interrupt _far *oldhdl)();
   #endif
  #endif

  cur_attr=file_chmod(name, 0, 0)&STD_FILE_ATTR;
  if((cur_attr&~FATTR_ARCH)==cur_attr)
   return(0);
  cur_attr&=~FATTR_ARCH;
  #if TARGET==DOS
   if(is_dos_31)
    result=file_chmod(name, 1, cur_attr);
   else
   {
    oldhdl=getvect(INT24);
    setvect(INT24, int24_autofail_handler);
     result=file_chmod(name, 1, cur_attr);
    setvect(INT24, oldhdl);
   }
  #elif TARGET==OS2||TARGET==WIN32
   result=file_chmod(name, 1, cur_attr);
  #endif
  return(result==-1?-1:0);
 #else
  return(0);
 #endif
}
#endif

/* Flushes the disk cache and resets the drive (W95) */

#if SFX_LEVEL>=ARJ&&TARGET==DOS
static int w95_resetdrive(int drive)
{
 union REGS regs;
 struct SREGS sregs;

 memset(&sregs, 0, sizeof(sregs));
 regs.x.cx=W95_FLUSH_CACHE;
 regs.x.dx=drive;
 return(call_dos_int(W95_RESETDRIVE, &regs, &sregs)?-1:0);
}
#endif

/* Flushes the disk cache and resets the drive (W95) */

#if SFX_LEVEL>=ARJ
int reset_drive(char *name)
{
 #if TARGET==DOS
  int drive;

  while(name[0]==' ')
   name++;
  if(name[1]==':')
   drive=(int)(toupper(name[0]))-0x40;
  else
   drive=getdisk()+1;
  if(_osmajor<7)                        /* DOS 2.x - A: and B: are removable */
  {
   bdos(0x0D, 0, 0);
   return(1);
  }
  else
  {
   if(w95_test_for_lfn(drive_c))
   {
    w95_resetdrive(drive);
    return(1);
   }
   else
    return(0);
  }
 #elif TARGET==OS2
  HFILE hf;
  #ifdef __32BIT__
   ULONG action;
  #else
   USHORT action;
  #endif

  if(DosOpen(name, &hf, &action, 0L, 0, FILE_OPEN, OPEN_ACCESS_READONLY|OPEN_SHARE_DENYNONE, 0L))
   return(0);
  #ifdef TILED
   DosBufReset(hf);
  #else
   DosResetBuffer(hf);
  #endif
  DosClose(hf);
  return(0);
 #elif TARGET==WIN32
  return(0);
 #elif TARGET==UNIX
  sync();
  return(0);
 #endif
}
#endif

/* Checks for pending keystrokes and clears the keyboard buffer. */

#if SFX_LEVEL>=ARJSFXV||defined(REARJ)
int fetch_keystrokes()
{
 #if TARGET==DOS
  union REGS regs;
  int rc=0;

  while(kbhit())
  {
   regs.h.ah=7;
   intdos(&regs, &regs);
   rc=1;
  }
  return(rc);
 #elif TARGET==OS2
  #if COMPILER==MSC
   int rc=0;
   KBDKEYINFO keyinfo;

   while(kbhit())
   {
    rc=1;
    KbdCharIn(&keyinfo, IO_WAIT, 0);
   }
   return(rc);
  #else
   KBDKEYINFO keyinfo;
   int rc, pressed;
   int frc=0;

   do
   {
    rc=KbdPeek(&keyinfo, 0);
    pressed=rc?0:(keyinfo.fbStatus&KBDTRF_FINAL_CHAR_IN);
    if(pressed)
    {
     frc=1;
     KbdCharIn(&keyinfo, IO_WAIT, 0);
    }
   } while(pressed);
   return(frc);
  #endif
 #else
  return(0);                            /* Not implemented */
 #endif
}
#endif

/* Changes the current directory and/or drive */

#if SFX_LEVEL>=ARJSFX&&SFX_LEVEL<=ARJSFXV
void file_chdir(char *dir)
{
 #ifdef HAVE_DRIVES
  int l;
  char *tmp_dir;

  if((l=strlen(dir))>2)
  {
   if(dir[1]==':')

   if((dir[l-1]==PATHSEP_DOS||dir[l-1]==PATHSEP_UNIX)&&(dir[1]!=':'||l!=3))
   {
    tmp_dir=malloc(l);
    if(tmp_dir==NULL)                   /* ASR fix 29/10/2000 */
     return;
    strcpy(tmp_dir, dir);
    tmp_dir[l-1]='\0';
    chdir(tmp_dir);
    free(tmp_dir);
   }
  }
 #else
  chdir(dir);
 #endif
}
#elif defined(REARJ)                    /* REARJ modification (LFN-capable) */
int file_chdir(char *dir)
{
 #ifdef HAVE_DRIVES
  char dest_disk;

  if(dir[1]==':')
  {
   dest_disk=toupper(dir[0])-'A';
   if(setdisk(dest_disk)<dest_disk)
    return(1);
   if(dir[2]=='\0')
    return(1);
  }
  #if TARGET==DOS
   if(lfn_supported)
    return(w95_chdir(dir)?1:0);
   else
    return(chdir(dir)?1:0);
  #elif TARGET==OS2||TARGET==WIN32
   return(chdir(dir)?1:0);
  #endif
 #else
  return(chdir(dir));
 #endif
}
#endif

/* This routine needs to be moved on top of file_unlink. */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)
int dos_chmod(char *name, int attrib)
{
 #if TARGET!=UNIX
  return(file_chmod(name, 1, attrib&STD_FILE_ATTR)==-1?-1:0);
 #else
  return(file_chmod(name, 1, attrib)==-1?-1:0);
 #endif
}
#endif

/* Changes the size of the file (Borland-specific implementation) */

#if SFX_LEVEL>=ARJ
int file_chsize(FILE *stream, unsigned long size)
{
 #if TARGET!=UNIX
  return(chsize(fileno(stream), size));
 #else
  return(ftruncate(fileno(stream), size));
 #endif
}
#endif

/* Sets last modification date/time for a file specified by handle */

#if (SFX_LEVEL==ARJSFXJR||SFX_LEVEL>=ARJ)&&TARGET!=UNIX
int file_setftime_on_hf(int hf, unsigned long ftime)
{
 #if TARGET==DOS
  #if COMPILER==BCC
   return(setftime(hf, (struct ftime *)&ftime));
  #elif COMPILER==MSC
   return(_dos_setftime(hf, *((unsigned int *)&ftime+1), *(unsigned int *)&ftime));
  #endif
 #elif TARGET==OS2
  HFILE hfc;
  FILESTATUS fstatus;

  hfc=(HFILE)hf;                        /* Dirty hack but it works */
  DosQFileInfo(hfc, FIL_STANDARD, &fstatus, sizeof(fstatus));
  *(USHORT *)&fstatus.fdateLastWrite=ftime>>16;
  *(USHORT *)&fstatus.ftimeLastWrite=ftime&0xFFFF;
  return(DosSetFileInfo(hfc, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus)));
 #elif TARGET==WIN32
  return(-1);                           /* Nobody wants to play it under
                                           Win32 (fileno is NOT a HANDLE) */
 #endif
}
#endif

/* Updates the modification date/time field in the file's directory entry for
   a file that has been already open. */

#if SFX_LEVEL>=ARJ&&TARGET!=UNIX
int file_setftime_on_stream(FILE *stream, unsigned long ftime)
{
 return(file_setftime_on_hf(fileno(stream), ftime));
}
#endif

/* UNIX file time request router */

#if TARGET==UNIX&&(SFX_LEVEL>=ARJSFX||defined(REARJ))
static int ftime_router(char *name, int idx, unsigned long ftime)
{
 struct stat st;
 struct utimbuf ut;
 int rc;
 #if SFX_LEVEL>=ARJ
  struct stat resolved_st;
  int res_cnt, protect_resolved=0;
  char resolved_name[CCHMAXPATH];
 #endif

 if(lstat(name, &st)==-1)
  return(-1);
 /* If it is a symlink, protect the original file */
 if(S_ISLNK(st.st_mode))
 {
  #if SFX_LEVEL>=ARJ
   if(!symlink_accuracy)
    return(-1);
   res_cnt=readlink(name, resolved_name, sizeof(resolved_name)-1);
   if(res_cnt>0)
   {
    resolved_name[res_cnt]='\0';
    if(stat(name, &resolved_st)!=-1)
     protect_resolved=1;
   }
  #else
   return(-1);
  #endif
 }
 ut.actime=(idx==UFTREQ_ATIME)?ftime:st.st_atime;
 ut.modtime=(idx==UFTREQ_FTIME)?ftime:st.st_mtime;
 rc=utime(name, &ut);
 #if SFX_LEVEL>=ARJ
  if(protect_resolved)
  {
   ut.actime=resolved_st.st_atime;
   ut.modtime=resolved_st.st_mtime;
   rc=utime(resolved_name, &ut);
  }
 #endif
 return(rc);
}
#endif

/* Updates the last access date field in the file's directory entry (unlike
   file_setftime, standard parameters are passed). */

#if SFX_LEVEL>=ARJSFXV
int file_setatime(char *name, unsigned long ftime)
{
 #if TARGET==DOS
  FILE *stream;
  int result;

  if(lfn_supported!=LFN_NOT_SUPPORTED)
  {
   if((stream=fopen(name, m_rbp))==NULL)
    if((stream=fopen(name, m_rb))==NULL)
     return(-1);
   result=w95_set_dta(fileno(stream), ftime);
   fclose(stream);
   return(result);
  }
  else
   return(0);
 #elif TARGET==OS2
  #ifdef __32BIT__
   FILESTATUS3 fstatus;
  #else
   FILESTATUS fstatus;
  #endif

  #ifdef __32BIT__
   DosQueryPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus));
  #else
   DosQPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus), 0L);
  #endif
  *(USHORT *)&fstatus.fdateLastAccess=ftime>>16;
  *(USHORT *)&fstatus.ftimeLastAccess=ftime&0xFFFF;
  #ifdef __32BIT__
   return(DosSetPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus), 0));
  #else
   return(DosSetPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus), 0, 0L));
  #endif
 #elif TARGET==WIN32
  HANDLE hf;
  FILETIME satime, sftime, sctime;

  if((hf=CreateFile(name, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0))==INVALID_HANDLE_VALUE)
   return(-1);
  GetFileTime(hf, &sctime, &satime, &sftime);
  ntify_time(&satime, ftime);
  SetFileTime(hf, &sctime, &satime, &sftime);
  CloseHandle(hf);
  return(0);
 #elif TARGET==UNIX
  return(ftime_router(name, UFTREQ_ATIME, ftime));
 #endif
}
#endif

/* Updates the creation date/time field in the file's directory entry (unlike
   file_setftime, standard parameters are passed). */

#if SFX_LEVEL>=ARJSFXV
int file_setctime(char *name, unsigned long ftime)
{
 #if TARGET==DOS
  FILE *stream;
  int result;
 #endif

 #if TARGET==DOS
  if(lfn_supported!=LFN_NOT_SUPPORTED)
  {
   if((stream=fopen(name, m_rbp))==NULL)
    if((stream=fopen(name, m_rb))==NULL)
     return(-1);
   result=w95_set_dtc(fileno(stream), ftime);
   fclose(stream);
   return(result);
  }
  else
   return(0);
 #elif TARGET==OS2
  #ifdef __32BIT__
   FILESTATUS3 fstatus;
  #else
   FILESTATUS fstatus;
  #endif

  #ifdef __32BIT__
   DosQueryPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus));
  #else
   DosQPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus), 0L);
  #endif
  *(USHORT *)&fstatus.fdateCreation=ftime>>16;
  *(USHORT *)&fstatus.ftimeCreation=ftime&0xFFFF;
  #ifdef __32BIT__
   return(DosSetPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus), 0));
  #else
   return(DosSetPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus), 0, 0L));
  #endif
 #elif TARGET==WIN32
  HANDLE hf;
  FILETIME satime, sftime, sctime;

  if((hf=CreateFile(name, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0))==INVALID_HANDLE_VALUE)
   return(-1);
  GetFileTime(hf, &sctime, &satime, &sftime);
  ntify_time(&sctime, ftime);
  SetFileTime(hf, &sctime, &satime, &sftime);
  CloseHandle(hf);
  return(0);
 #elif TARGET==UNIX
  return(ftime_router(name, UFTREQ_CTIME, ftime));
 #endif
}
#endif

/* Updates the modification date/time field in the file's directory entry */

#if SFX_LEVEL>=ARJSFX||defined(REARJ)||defined(NEED_SETFTIME_HACK)
int file_setftime(char *name, unsigned long ftime)
{
 #if TARGET==DOS
  FILE *stream;
  int result;

  if((stream=fopen(name, m_rbp))==NULL)
  #if SFX_LEVEL>=ARJSFXV
   if((stream=fopen(name, m_rb))==NULL)
  #endif
    return(-1);
  #if COMPILER==BCC
   result=setftime(fileno(stream), (struct ftime *)&ftime);
  #elif COMPILER==MSC
  result=_dos_setftime(fileno(stream), *((unsigned int *)&ftime+1), *(unsigned int *)&ftime);
  #endif
  fclose(stream);
  return(result);
 #elif TARGET==OS2
  #ifdef __32BIT__
   FILESTATUS3 fstatus;
  #else
   FILESTATUS fstatus;
  #endif

  #ifdef __32BIT__
   DosQueryPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus));
  #else
   DosQPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus), 0L);
  #endif
  *(USHORT *)&fstatus.fdateLastWrite=ftime>>16;
  *(USHORT *)&fstatus.ftimeLastWrite=ftime&0xFFFF;
  #ifdef __32BIT__
   return(DosSetPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus), 0));
  #else
   return(DosSetPathInfo(name, FIL_STANDARD, (PBYTE)&fstatus, sizeof(fstatus), 0, 0L));
  #endif
 #elif TARGET==WIN32
  HANDLE hf;
  FILETIME satime, sftime, sctime;

  if((hf=CreateFile(name, GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0))==INVALID_HANDLE_VALUE)
   return(-1);
  GetFileTime(hf, &sctime, &satime, &sftime);
  ntify_time(&sftime, ftime);
  SetFileTime(hf, &sctime, &satime, &sftime);
  CloseHandle(hf);
  return(0);
 #elif TARGET==UNIX
  return(ftime_router(name, UFTREQ_FTIME, ftime));
 #endif
}
#endif

/* Sets the volume label */

#if SFX_LEVEL>=ARJSFXV&&defined(HAVE_DRIVES)
int file_setlabel(char *label, char drive, ATTRIB attrib, unsigned long ftime)
{
 #if TARGET==DOS
  union REGS regs;
  char fnm[64];
  struct xfcb xfcb;
  char dta[64];
  char FAR *saved_dta;
  int handle;

  if(_osmajor<2)
   return(-1);
  /* Set DTA so it'll point to an internal structure */
  saved_dta=getdta();
  setdta((char FAR *)dta);
  /* Fill the extended FCB structure */
  xfcb.xfcb_flag=0xFF;
  xfcb.xfcb_attr=FATTR_LABEL;
  if(drive!='\0')
   xfcb.xfcb_fcb.fcb_drive=toupper(drive)-0x40;
  strcpy(xfcb.xfcb_fcb.fcb_name, fcb_mask);
  /* Find first matching file (i.e., volume label) using this FCB. Note that
     the current directory does not need to be root. */
  regs.h.ah=0x11;                        /* findfirst() for FCB */
  regs.x.dx=(unsigned int)&xfcb;
  intdos(&regs, &regs);
  setdta(saved_dta);                     /* Temporarily restore the DTA */
  if(_osmajor==2)
  {
   /* If there's a label, just rename it */
   if(regs.h.al==0)
   {
    #if COMPILER==BCC
     parsfnm(label, (struct fcb *)(dta+0x17), 3);
    #elif COMPILER==MSC
     regs.x.ax=0x2903;
     regs.x.si=(unsigned int)label;
     regs.x.di=(unsigned int)(dta+0x17);
     intdos(&regs, &regs);
    #endif
    regs.h.ah=0x17;                       /* rename() for FCB */
    regs.x.dx=(unsigned int)dta;
    intdos(&regs, &regs);
   }
   /* Otherwise, create a new file */
   else
   {
    #if COMPILER==BCC
     parsfnm(label, &xfcb.xfcb_fcb, 3);
    #elif COMPILER==MSC
     regs.x.ax=0x2903;
     regs.x.si=(unsigned int)label;
     regs.x.di=(unsigned int)&xfcb.xfcb_fcb;
     intdos(&regs, &regs);
    #endif
    regs.h.ah=0x16;                       /* create file using FCB */
    regs.x.dx=(unsigned int)&xfcb;
    intdos(&regs, &regs);
    /* Close file if it has been created successfully */
    if(regs.h.al==0)
    {
     regs.h.ah=0x10;                      /* fclose() for FCB */
     regs.x.dx=(unsigned int)&xfcb;
     intdos(&regs, &regs);
    }
   }
   return((int)regs.h.al);
  }
  /* DOS 3.x */
  else
  {
   if(regs.h.al==0)                      /* Check RC from findfirst() */
   {
    regs.h.ah=0x13;                      /* unlink() for FCB */
    regs.x.dx=(unsigned int)dta;
    intdos(&regs, &regs);
   }
   if(drive!='\0')
   {
    fnm[0]=drive;
    fnm[1]=':';
    fnm[2]='\0';
   }
   else
    fnm[0]='\0';
   strcat(fnm, label);
   if((handle=_creat(fnm, FATTR_LABEL))==EOF)
    return(-1);
   #if COMPILER==BCC
    setftime(handle, (struct ftime *)&ftime);
   #elif COMPILER==MSC
    return(_dos_setftime(handle, *((unsigned int *)&ftime+1), *(unsigned int *)&ftime));
   #endif
   _close(handle);
   return(0);
  }
 #elif TARGET==OS2
  VOLUMELABEL vl;

  strcpyn(vl.szVolLabel, label, 11);
  vl.cch=strlen(vl.szVolLabel);
  return(DosSetFSInfo(drive=='\0'?0:drive-0x40, FSIL_VOLSER, (PBYTE)&vl, sizeof(vl)));
 #elif TARGET==WIN32
  char vn[4];

  vn[0]=drive;
  vn[1]=':';
  vn[2]='\\';
  vn[3]='\0';
  return(!SetVolumeLabel(vn, label));
 #endif
}
#endif

/* Sets the file type */

#if SFX_LEVEL>=ARJ
int file_settype(FILE *stream, int istext)
{
 #if TARGET!=UNIX
  fflush(stream);
  #if COMPILER==HIGHC&&!defined(LIBC)
   setmode(stream, istext?_O_TEXT:_O_BINARY);
  #else
   setmode(fileno(stream), istext?O_TEXT:O_BINARY);
  #endif
 #endif
 return(1);
}
#endif

/* Sets the file API mode */

#if SFX_LEVEL>=ARJ
void set_file_apis(int is_ansi)
{
 #if TARGET==WIN32
  if(is_ansi)
   SetFileApisToANSI();
  else
   SetFileApisToOEM();
 #endif
}
#endif

/* Creates a subdirectory tree (qmode specifies if the user is to be asked).
   Returns 1 if an error occured */

#if SFX_LEVEL>=ARJSFX
#if SFX_LEVEL>=ARJSFXV
int create_subdir_tree(char *path, int qmode, int datatype)
#else
int create_subdir_tree(char *path, int datatype)
#endif
{
 char tmp_path[CCHMAXPATH];             /* Jung uses 256 but it's incorrect */
 char *tmp_ptr;
 int access_status;
 int no_queries;                        /* 1 automatically forces "yes" */

 #if SFX_LEVEL>=ARJSFXV
  tmp_ptr=validate_path(path, VALIDATE_ALL);
  no_queries=qmode||prompt_for_mkdir;
 #else
  tmp_ptr=validate_path(path);
  no_queries=yes_on_all_queries||make_directories;
 #endif
 while((tmp_ptr=find_delimiter(tmp_ptr, datatype))!=NULL)
 {
  strcpyn(tmp_path, path, tmp_ptr-path+1);
  if((access_status=file_chmod(tmp_path, 0, 0))==-1)
  {
   if(!no_queries)
   {
    #if SFX_LEVEL>=ARJSFXV
     msg_sprintf(misc_buf, M_QUERY_CREATE_DIR, path);
     /* If the user forbids creation, return 1 */
     if((no_queries=query_action(0, QUERY_CREATE_DIR, misc_buf))==0)
      return(1);
    #else
     msg_cprintf(0, M_QUERY_CREATE_DIR, path);
     if((no_queries=query_action())==0)
      return(1);
    #endif
   }
   if(file_mkdir(tmp_path)&&errno!=ENOENT)
   {
    /* Creation failed, inform the user about it */
    #if SFX_LEVEL>=ARJSFXV
     msg_cprintf(H_ERR, M_CANT_MKDIR, tmp_path);
    #else
     msg_cprintf(H_ERR, M_CANT_MKDIR, tmp_path);
    #endif
    #if SFX_LEVEL>=ARJ
     error_report();
    #endif
    return(1);
   }
  }
  else
  {
   /* If a file with the same name exists, jerk off... */
  #if TARGET!=UNIX
   if(!(access_status&FATTR_DIREC))
  #else
   struct stat st;

   if((stat(tmp_path, &st)==-1)||!S_ISDIR(st.st_mode))
  #endif
   {
    #if SFX_LEVEL>=ARJSFXV
     msg_cprintf(H_ERR, M_CANT_MKDIR, tmp_path);
    #else
     msg_cprintf(H_ERR, M_CANT_MKDIR, tmp_path);
    #endif
    return(1);
   }
  }
  if(*tmp_ptr!='\0')
   tmp_ptr++;
 }
 return(0);
}
#endif

/* Returns 1 if the given filename is valid, 0 otherwise */

#if SFX_LEVEL>=ARJSFXV
int is_filename_valid(char *name)
{
 return(name[0]=='\0'?0:1);
}
#endif

/* Returns 1 if the given file is a directory, 0 otherwise */

#if SFX_LEVEL>=ARJSFXV
int is_directory(char *name)
{
 int attrib;

 attrib=file_chmod(name, 0, 0);
 if(attrib==-1)
  return(0);
 else
 #if TARGET!=UNIX
  return(attrib&FATTR_DIREC?1:0);
 #else
  return(S_ISDIR(attrib));
 #endif
}
#endif

/* Allocate memory and create a wildcard that expands to all files of the
   subdirectory given. */

#if SFX_LEVEL>=ARJ
char *malloc_subdir_wc(char *name)
{
 char tmp_wc[WC_RESERVE];
 char *wc_ptr;

 tmp_wc[0]=PATHSEP_DEFAULT;
 strcpy(tmp_wc+1, all_wildcard);
 wc_ptr=malloc_msg(strlen(tmp_wc)+strlen(name)+2);
 strcpy(wc_ptr, name);
 strcat(wc_ptr, tmp_wc);
 return(wc_ptr);
}
#endif

/* Copies one file to another, performing a check if needed. Issues a native
   API if the target platform supports it (note: Win32 does not provide a
   way to verify the file so we avoid the CopyFile function under Win32) */

#if SFX_LEVEL>=ARJ
int file_copy(char *dest, char *src, int chk)
{
 #if TARGET==OS2
  #ifdef __32BIT__
   BOOL32 vf;
   APIRET rc;
  #else
   BOOL vf;
   USHORT rc;
  #endif

  if(chk)
  {
   #ifdef __32BIT__
    DosQueryVerify(&vf);
   #else
    DosQVerify(&vf);
   #endif
   DosSetVerify(1);
  }
  #ifdef __32BIT__
   rc=DosCopy(src, dest, DCPY_EXISTING);
  #else
   rc=DosCopy(src, dest, DCPY_EXISTING, 0);
  #endif
  if(chk)
  {
   msg_cprintf(0, M_TESTING, dest);
   DosSetVerify(vf);
  }
  switch(rc)
  {
   case NO_ERROR:
    break;
   case ERROR_FILE_NOT_FOUND:
   case ERROR_PATH_NOT_FOUND:
   case ERROR_ACCESS_DENIED:
   case ERROR_SHARING_VIOLATION:
    msg_cprintf(H_ERR, M_CANTOPEN, src);
    break;
   case ERROR_DISK_FULL:
    msg_cprintf(0, M_DISK_FULL);
    break;
   default:
    msg_cprintf(0, M_CRC_ERROR);
    break;
  }
  if(rc)
  {
   nputlf();
   return(-1);
  }
  return(0);
 #else
  FILE *istream, *ostream;
  char *buf, *dbuf;
  unsigned int bytes_read;
  
  istream=file_open(src, m_rb);
  if(istream==NULL)
  {
   error_report();
   msg_cprintf(H_ERR, M_CANTOPEN, src);
   nputlf();
   return(-1);
  }
  ostream=file_open(dest, m_wb);
  if(ostream==NULL)
  {
   fclose(istream);
   error_report();
   msg_cprintf(H_ERR, M_CANTOPEN, dest);
   nputlf();
   return(-1);
  }
  buf=malloc_msg(PROC_BLOCK_SIZE);
  mem_stats();
  while((bytes_read=fread(buf, 1, PROC_BLOCK_SIZE, istream))>0)
  {
   if(fwrite(buf, 1, bytes_read, ostream)!=bytes_read)
   {
    msg_cprintf(0, M_DISK_FULL);
    nputlf();
    break;
   }
  }
  free(buf);
  if(fclose(ostream))
  {
   fclose(istream);
   return(-1);
  }
  if(fclose(istream))
   return(-1);
  if(file_is_removable(dest))
   reset_drive(dest);
  if(bytes_read==0&&chk)
  {
   msg_cprintf(0, M_TESTING, dest);
   istream=file_open(src, m_rb);
   if(istream==NULL)
   {
    error_report();
    msg_cprintf(H_ERR, M_CANTOPEN, src);
    nputlf();
    return(-1);
   }
   ostream=file_open(dest, m_rb);
   if(ostream==NULL)
   {
    fclose(istream);
    error_report();
    msg_cprintf(H_ERR, M_CANTOPEN, dest);
    nputlf();
    return(-1);
   }
   buf=malloc_msg(PROC_BLOCK_SIZE/2);
   dbuf=malloc_msg(PROC_BLOCK_SIZE/2);
   while((bytes_read=fread(buf, 1, PROC_BLOCK_SIZE/2, istream))>0)
   {
    if(fread(dbuf, 1, PROC_BLOCK_SIZE/2, ostream)!=bytes_read)
     break;
    if(memcmp(buf, dbuf, bytes_read))
     break;
   }
   free(buf);
   free(dbuf);
   fclose(ostream);
   fclose(istream);
   msg_cprintf(0, (FMSG *)vd_space);
   msg_cprintf(0, bytes_read==0?M_OK:M_CRC_ERROR);
  }
  return((bytes_read>0)?-1:0);
 #endif
}
#endif

#if SFX_LEVEL>=ARJ||defined(REARJ)

/* ASR fix 02/04/2003: Reduce memory consumption on 16-bit systems. */

#ifdef TILED
static char *pack_fname(char *f)
{
 char *rc;

 if((rc=(char *)realloc(f, strlen(f)+1))==NULL)
  return(f);
 return(rc);
}
#else
 #define pack_fname(f) (f)
#endif

/* Recursive subdirectory search helper */

#ifndef REARJ
int wild_subdir(struct flist_root *root, struct flist_root *search_flist, char *name, int expand_wildcards, int recurse_subdirs, int file_type, FILE_COUNT *count)
#else
int wild_subdir(struct flist_root *root, char *name, int file_type, int expand_wildcards, int recurse_subdirs, FILE_COUNT *count)
#endif
{
 int attr_mask;                         /* Narrowing criteria */
 struct new_ffblk *pnew_ffblk=NULL;     /* OS-dependent data block */
 char *subdir_spec=NULL;                /* Subdirectory name */
 char *tmp_name=NULL;
 int result=0, rc;
 char *subdir_wildcard=NULL;            /* Subdirectory entries */

 if(recurse_subdirs)
 {
  attr_mask=STD_DIR_ATTR;
  if(file_type!=FETCH_DEFAULT)
 #if TARGET!=UNIX
   attr_mask|=FATTR_HIDDEN|FATTR_SYSTEM|FATTR_RDONLY;
 #else
   attr_mask|=FATTR_DT_REG|FATTR_DT_UXSPECIAL;
 #endif
  #ifndef REARJ
   #if TARGET==UNIX
    if(filter_attrs)
    {
     if(file_attr_mask&TAG_SYSTEM)
      attr_mask|=FATTR_SYSTEM;
     if(file_attr_mask&TAG_HIDDEN)
      attr_mask|=FATTR_HIDDEN;
     if(file_attr_mask&TAG_RDONLY)
      attr_mask|=FATTR_RDONLY;
     #if TARGET==UNIX
      if(file_attr_mask&TAG_UXSPECIAL)
       attr_mask|=FATTR_DT_UXSPECIAL;
      if(file_attr_mask&TAG_DIREC)
       attr_mask|=FATTR_DT_DIR;
     #endif
    }
   #endif
  #endif
  if((subdir_spec=(char *)malloc(strlen(name)+WC_RESERVE))==NULL)
  {
   result=-1;
   goto l_error;
  }
  split_name(name, subdir_spec, NULL);
  strcat(subdir_spec, all_wildcard);
  case_path(subdir_spec);
  subdir_spec=pack_fname(subdir_spec);
  if((pnew_ffblk=(struct new_ffblk *)malloc(sizeof(struct new_ffblk)))==NULL)
  {
   result=-1;
   goto l_error;
  }
  rc=lfn_findfirst(subdir_spec, pnew_ffblk, attr_mask);
  while(rc==0)
  {
   if(
      /* Entries like "." and ".." are skipped */
      pnew_ffblk->ff_attrib&STD_DIR_ATTR&&strcmp(pnew_ffblk->ff_name, cur_dir_spec)&&strcmp(pnew_ffblk->ff_name, up_dir_spec)
#if TARGET==UNIX&&SFX_LEVEL>=ARJ
      /* Disallow circular symlinks - the symlink will be stored but will
         not be recursed into */
      &&link_search(&sl_entries, &pnew_ffblk->l_search, NULL, 0)==FLS_NONE
#endif
     )
   {
    /* Reallocate these */
    if((subdir_wildcard=(char *)realloc(subdir_wildcard, CCHMAXPATHCOMP))==NULL||
       (tmp_name=(char *)realloc(tmp_name, CCHMAXPATH+20))==NULL)
    {
     result=-1;
     goto l_error;
    }
    split_name(name, tmp_name, subdir_wildcard);
    subdir_wildcard=pack_fname(subdir_wildcard);
    if(strlen(tmp_name)+strlen(pnew_ffblk->ff_name)+strlen(subdir_wildcard)+2>=CCHMAXPATHCOMP)
     msg_cprintf(H_ERR, M_MAXPATH_EXCEEDED, CCHMAXPATH, tmp_name);
    else
    {
     strcat(tmp_name, pnew_ffblk->ff_name);
     strcat(tmp_name, pathsep_str);
     strcat(tmp_name, subdir_wildcard);
     case_path(tmp_name);
     tmp_name=pack_fname(tmp_name);
     #ifdef REARJ
      if(wild_list(root, tmp_name, file_type, expand_wildcards, recurse_subdirs, count))
      {
       result=-1;
       goto l_error;
      }
     #else
      if(wild_list(root, search_flist, tmp_name, expand_wildcards, recurse_subdirs, file_type, count))
      {
       result=-1;
       goto l_error;
      }
     #endif
    }
   }
   rc=lfn_findnext(pnew_ffblk);
  }
  lfn_findclose(pnew_ffblk);
 }
l_error:
 if(pnew_ffblk!=NULL)
  free(pnew_ffblk);
 if(subdir_spec!=NULL)
  free(subdir_spec);
 if(tmp_name!=NULL)
  free(tmp_name);
 if(subdir_wildcard!=NULL)
  free(subdir_wildcard);
 return(result);
}

/* Findfirst/findnext, wildcard expansion and so on... */

#ifndef REARJ
int wild_list(struct flist_root *root, struct flist_root *search_flist, char *name, int expand_wildcards, int recurse_subdirs, int file_type, FILE_COUNT *count)
#else
int wild_list(struct flist_root *root, char *name, int file_type, int expand_wildcards, int recurse_subdirs, FILE_COUNT *count)
#endif
{
 int attr_mask;                         /* Narrowing criteria */
 struct new_ffblk *pnew_ffblk=NULL;     /* OS-dependent data block */
 int result=0, rc;                      /* findfirst/findnext() result */
 char *tmp_name=NULL;
 int pathspec_len;                      /* Maximum path length */
 #ifndef REARJ
  struct file_properties properties;    /* Universal block */
 #endif

 pathspec_len=strlen(name);
 if(pathspec_len<CCHMAXPATH)
  pathspec_len=CCHMAXPATH;
 flush_kbd();
 if(!expand_wildcards)
 {
  if((tmp_name=(char *)strdup(name))==NULL)
  {
   result=-1;
   goto l_error;
  }
  case_path(tmp_name);
  #ifdef REARJ
   if(add_entry(root, tmp_name, count))
   {
    result=-1;
    goto l_error;
   }
  #else
   if(flist_add(root, search_flist, tmp_name, count, NULL))
   {
    result=-1;
    goto l_error;
   }
  #endif
 }
 else
 {
#ifndef REARJ
  /* First, perform recursive subdirectory search if needed */
  if(recursion_order==RO_LAST)
   result=wild_subdir(root, search_flist, name, expand_wildcards, recurse_subdirs, file_type, count);
#endif   
  if((tmp_name=(char *)malloc(pathspec_len+50))==NULL)
  {
   result=-1;
   goto l_error;
  }
  /* Search for the ordinary files */
  attr_mask=0;
  if(file_type!=FETCH_DEFAULT)
  #if TARGET!=UNIX
   attr_mask|=FATTR_HIDDEN|FATTR_SYSTEM|FATTR_RDONLY;
  #else
   attr_mask|=FATTR_DT_REG|FATTR_DT_UXSPECIAL;
  #endif
  if(file_type==FETCH_DIRS)
   attr_mask|=STD_DIR_ATTR;
  #if !defined(REARJ)&&TARGET!=UNIX
   if(filter_attrs)
   {
    if(file_attr_mask&TAG_DIREC)
     attr_mask|=FATTR_DIREC;
    if(file_attr_mask&TAG_SYSTEM)
     attr_mask|=FATTR_SYSTEM;
    if(file_attr_mask&TAG_HIDDEN)
     attr_mask|=FATTR_HIDDEN;
    if(file_attr_mask&TAG_RDONLY)
     attr_mask|=FATTR_RDONLY;
   }
  #endif
  #if TARGET==UNIX
   if(file_attr_mask&TAG_UXSPECIAL)
    attr_mask|=FATTR_DT_UXSPECIAL;
   if(file_attr_mask&TAG_DIREC)
    attr_mask|=FATTR_DT_DIR;
  #endif
  if((pnew_ffblk=(struct new_ffblk *)malloc(sizeof(struct new_ffblk)))==NULL)
  {
   result=-1;
   goto l_error;
  }
  rc=lfn_findfirst(name, pnew_ffblk, attr_mask);
  while(rc==0)
  {
   /* Entries like "." and ".." are skipped but symlinks AREN'T */
   if((!(pnew_ffblk->ff_attrib&STD_DIR_ATTR)||(strcmp(pnew_ffblk->ff_name, cur_dir_spec)&&strcmp(pnew_ffblk->ff_name, up_dir_spec))))
   {
    split_name(name, tmp_name, NULL);
    /* ASR fix for 2.76.04 */
    if(strlen(tmp_name)+strlen(pnew_ffblk->ff_name)>=CCHMAXPATH)
     msg_cprintf(H_ERR, M_MAXPATH_EXCEEDED, CCHMAXPATH, pnew_ffblk->ff_name);
    else
    {
     strcat(tmp_name, pnew_ffblk->ff_name);
     case_path(tmp_name);
     #ifdef REARJ
      if(add_entry(root, tmp_name, count))
      {
       result=-1;
       goto l_error;
      }
     #else
      finddata_to_properties(&properties, pnew_ffblk);
      if(flist_add(root, search_flist, tmp_name, count, &properties))
      {
       result=-1;
       goto l_error;
      }
     #endif
    }
   }
   rc=lfn_findnext(pnew_ffblk);
  }
  lfn_findclose(pnew_ffblk);            /* BUG: Original REARJ v 2.28 didn't
                                           close the search -- fixed in 2.42 */
  if(tmp_name!=NULL)
  {
   free(tmp_name);
   tmp_name=NULL;
  }
  if(pnew_ffblk!=NULL)
  {
   free(pnew_ffblk);
   pnew_ffblk=NULL;
  }
  /* Last, perform recursive subdirectory search if needed */
#ifndef REARJ
  if(recursion_order==RO_FIRST)
   result=wild_subdir(root, search_flist, name, expand_wildcards, recurse_subdirs, file_type, count);
#else
   result=wild_subdir(root, name, file_type, expand_wildcards, recurse_subdirs, count);
#endif
 }
 /* Return 0 if no errors occured */
l_error:
 if(tmp_name!=NULL)
  free(tmp_name);
 if(pnew_ffblk!=NULL)
  free(pnew_ffblk);
 return(result);
}
#endif
