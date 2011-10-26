/*
 * $Id: environ.h,v 1.14 2004/05/31 16:08:41 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * All environment-specific declarations are held here.
 *
 */

#ifndef ENVIRON_INCLUDED
#define ENVIRON_INCLUDED

/* First of all, let's try to guess what kind of compiler we're using. The
   COMPILER macro will lead us all the way */

#ifndef C_DEFS_INCLUDED                 /* All-time definitions */
 #include "c_defs.h"
#endif

#define GENERIC                    0

#define BCC                        1
#define MSC                        2
#define ICC                        3
#define GCC                        4
#define HIGHC                      5
#define WCC                        6
#define MSVC                       7

#if defined(__TURBOC__)||defined(__BORLANDC__)
 #define COMPILER BCC
#elif defined(_MSC_VER)||defined(_QC)
  #ifdef _WIN32
   #define COMPILER MSVC
  #else
   #define COMPILER MSC
   #ifdef MSC_VER
    #error BUG
   #endif
   #if (defined(_MSC_VER)&&_MSC_VER<600)||(!defined(_MSC_VER)&&defined(_QC))
    #define MSC_ANCIENT                   /* Old-style Microsoft compiler */
   #endif
 #endif
#elif defined(__IBMC__)||defined(__IBMCPP__)
 #define COMPILER ICC
#elif defined(__GNUC__)
 #define COMPILER GCC
#elif defined(__WATCOMC__)
 #define COMPILER WCC
 #ifdef M_I386
  #define __32BIT__
 #endif
#elif defined(__HIGHC__)||defined(__HIGHC_ANSI__)||defined(_OS2)
 #define COMPILER HIGHC
 #define __32BIT__
#else
 #define COMPILER GENERIC
#endif

/* Now, make it clear about target OS */

#define DOS                        1
#define OS2                        2    /* OS/2-32 is OS2+__32BIT__ */
#ifdef UNIX
 #undef UNIX
#endif
#define UNIX                       3
#define WIN32                      4

#if defined(_OS2)||defined(__OS2__)||defined(__EMX__)
 #define TARGET                  OS2
#elif defined(_WIN32)
 #define TARGET                WIN32
#elif defined(_UNIX)
 #define TARGET                 UNIX
#else
 #define TARGET                  DOS
#endif

#if TARGET==DOS||TARGET==OS2&&!defined(__32BIT__)
 #define TILED
#endif

#if TARGET!=UNIX
 #define HAVE_DRIVES
 #define HAVE_VOL_LABELS
#endif

#if TARGET==OS2||TARGET==WIN32
 #define HAVE_EAS
#endif

#include <ctype.h>

#if COMPILER==BCC
 #include <alloc.h>
#elif COMPILER==MSC||COMPILER==MSVC
 #include <malloc.h>
#endif
 #include <errno.h>
 #include <string.h>
 #include <stdarg.h>
 #include <stdio.h>
 #if COMPILER==ICC&&defined(DEBUG)
  #define __DEBUG_ALLOC__               /* For heap checking */
 #endif
 #include <stdlib.h>
 #include <time.h>
#if COMPILER==BCC
 #include <values.h>
#else
 #include <limits.h>
#endif
#if TARGET!=UNIX
 #include <io.h>
#endif
#if COMPILER==BCC
 #include <dir.h>
#elif COMPILER!=GCC && !defined(SUNOS)
 #include <direct.h>
#endif

/* OS-dependent headers */

#if TARGET==DOS
 #include <dos.h>
#elif TARGET==OS2
 #define INCL_BASE
 #include <os2.h>
#elif TARGET==WIN32
 #include <windows.h>
#elif TARGET==UNIX
 #include <dirent.h>
 #include <sys/types.h>
 #include <sys/stat.h>                  /* For dev_t, chmod(), etc. */
#endif

/* Keywords remapping */

#if !defined(TILED)
 #ifndef _WIN32
  #define FAR
  #define NEAR
 #endif
 #define S_NEAR
#elif COMPILER==BCC
 #define FAR                     far
 #define NEAR                   near
 #define S_NEAR                 NEAR
#elif COMPILER==MSC
 #if TARGET==DOS
  #ifdef MSC_ANCIENT
   #define FAR                   far
   #define NEAR                 near
  #else
   #define FAR                  _far
   #define NEAR                _near
  #endif
 #endif
 #ifndef MSC_ANCIENT
  #define asm                   _asm
 #endif
 #define S_NEAR                 NEAR
#else
 #error *** A FAR/NEAR translation must be defined for this compiler!
#endif

/* Special functions enablement */

#if COMPILER==MSC
 #define FINETUNE_BUFSIZ                /* Alternate adjustment method */
#endif

#if defined(TILED)&&!defined(MSC_ANCIENT)
 #define ASM8086                        /* Enable assembly routines */
#endif

/* Library functions/equates remapping */

#if !defined(TILED)
 #define farfree                free
 #define farmalloc            malloc
 #define farrealloc          realloc
 #define farcalloc            calloc
 #define coreleft()          1048576    /* Don't know/care about it */
#elif COMPILER==MSC
 #define farfree              _ffree
 #define farmalloc(s) _fmalloc((size_t)s)
 #define farrealloc(p, s)  _frealloc(p, (size_t)s)
 #define farcalloc(n, s) _fcalloc((size_t)(n), (size_t)(s))
 #define coreleft            _memmax    /* Size of largest unallocated block */
#endif

#if COMPILER==MSC
 #define findfirst    _dos_findfirst
 #define findnext      _dos_findnext
 #define getvect        _dos_getvect
 #define setvect        _dos_setvect
 #ifdef MSC_ANCIENT
  #define _far                   far
 #endif
 #if _MSC_VER>=0x0700
  #define diskfree_t     _diskfree_t
  #define dosdate_t       _dosdate_t
  #define dostime_t       _dostime_t
  #define _far                 __far
  #define find_t             _find_t
  #define _interrupt     __interrupt
  #define rccoord          __rccoord
  #define stackavail     _stackavail
  #define strlwr             _strlwr
  #define strupr             _strupr
  #define videoconfig  __videoconfig
 #else
  #define _close               close
  #define _chmod               chmod
  #define _creat               creat
  #define _open                 open
  #define _read                 read
  #define _write               write
 #endif
 #if _MSC_VER<600
  #define _fcalloc           fcalloc
  #define _fmemcmp           fmemcmp
  #define _fmemset           fmemset
  #define _frealloc         frealloc
  #define _fstrcat           fstrcat
  #define _fstrchr           fstrchr
  #define _fstrcmp           fstrcmp
  #define _fstrcpy           fstrcpy
  #define _fstrlen           fstrlen
 #endif
#endif
#if (COMPILER==MSC&&_MSC_VER>=0x0700)||COMPILER==IBMC||COMPILER==HIGHC||TARGET==OS2&&defined(LIBC)
 #define filelength      _filelength
 #define fcloseall        _fcloseall
#endif
#if COMPILER==BCC||COMPILER==MSC
 #define _lseek                lseek
#endif
#if COMPILER==ICC||COMPILER==HIGHC
 #define mkdir                _mkdir
#endif
#if TARGET==UNIX
 #ifndef __QNXNTO__
    #define O_BINARY                  0    /* N/A under UNIX */
 #endif /* __QNXNTO__ */
 #define _lseek                lseek
 #define _open                  open
 #define _write                write
 #define _read                  read
 #define _close                close
#endif
/* BSD 4.3 LIBC forwarders */
#ifdef HAVE_STRCASECMP
 #define stricmp          strcasecmp
 #define strnicmp        strncasecmp
#endif

/* Watcom variables remapping: the "-5r" convention requires this */

#if TARGET==OS2&&COMPILER==WCC&&defined(LIBC)
 #pragma aux stdin "*"
 #pragma aux stdout "*"
 #pragma aux stderr "*"
 #pragma aux stdaux "*"
 #pragma aux stdprn "*"
 #pragma aux _timezone "*"
 #pragma aux _daylight "*"
 #pragma aux errno "*"
#endif

/* MetaWare High C/C++, GCC, etc. add-ons */

#if !defined(HAVE_MIN)&&!defined(min)
 #define min(a, b) ((a)<(b)?(a):(b))
#endif

#if !defined(HAVE_MAX)&&!defined(max)
 #define max(a, b) ((a)>(b)?(a):(b))
#endif

/* Structures that are already present in Borland C but missing from MS C */

#if COMPILER!=BCC

/* DOS FCB */

struct fcb
{
 char fcb_drive;
 char fcb_name[8];
 char fcb_ext[3];
 short fcb_curblk;
 short fcb_recsize;
 long fcb_filsize;
 short fcb_date;
 char fcb_resv[10];
 char fcb_currec;
 long fcb_random;
};

/* DOS Extended FCB */

struct xfcb
{
 char xfcb_flag;
 char xfcb_resv[5];
 char xfcb_attr;
 struct fcb xfcb_fcb;
};

/* Time structure */

struct time
{
 unsigned char ti_min;
 unsigned char ti_hour;
 unsigned char ti_hund;
 unsigned char ti_sec;
};

/* Date structure */

struct date
{
 int da_year;
 char da_day;
 char da_mon;
};


#endif

/* Far pointer creation macro */

#ifndef MK_FP
 #define MK_FP(seg,ofs)  ((void FAR *)(((unsigned long)seg<<16)+(unsigned long)ofs))
#endif

/* Far memory comparison macro/function */

#if !defined(TILED)
 #define far_memcmp           memcmp
#elif COMPILER==BCC
 #include "fmemcmp.h"
#elif COMPILER==MSC
 #define far_memcmp         _fmemcmp
#endif

/* Error message output */

#if COMPILER==BCC
 #define error_report() msg_cprintf(H_ERR, M_ERROR_CODE, errno, strerror(errno))
 #define error_freport() msg_cprintf(H_ERR, M_ERROR_CODE, errno, strerror(errno))
#else
 /* LIBCS.DLL complains about missing message resources */
 #if defined(LIBC)&&TARGET==OS2
  #define error_report()
 #else
  #define error_report() \
          { \
           msg_cprintf(H_ERR, M_ERROR_CODE, errno, strerror(errno)); \
           msg_cprintf(H_ERR, (FMSG *)lf); \
          }
 #endif
#endif

/* Signal handler parameter set */

#if COMPILER==BCC
 #define SIGHDLPARAMS
#else
 #define SIGHDLPARAMS        int sig
#endif

/* Host operating system. Note that OS codes are defined separately in
   DEFINES.H, so this macro has no effect until DEFINES.H is included. */

#if TARGET==DOS
 #define OS                   OS_DOS
#elif TARGET==OS2
 #define OS                   OS_OS2
#elif TARGET==UNIX
 #define OS                  OS_UNIX
#elif TARGET==WIN32
 #define OS                 OS_WIN32
#endif

/* Fixed-bit quantities. Atomic integer types comprising no less than the
   designated number of bits */

#define UINT32         unsigned long
#define INT32          unsigned long

/* Case sensitivity (under OS/2, this actually depends on the IFS used!) */

#if TARGET!=UNIX
 #define CASE_INSENSITIVE
#endif

/* Maximum size of path/path component */

#if TARGET==OS2||defined(__TILED__)
 #define CCHMAXPATH              260
 #define CCHMAXPATHCOMP          256
#else
 #define CCHMAXPATH              512
 #define CCHMAXPATHCOMP   CCHMAXPATH
#endif
#define MAXWILDAST               128    /* Maximum # of asterisks in wildcards */

/* Our own archive filename storage */

#ifdef FILENAME_MAX
 #undef FILENAME_MAX                    /* Already defined in some compilers */
#endif
#if TARGET==DOS
 #define FILENAME_MAX            500
#else
 #define FILENAME_MAX            512
#endif

/* Wildcard equates */

#define WC_RESERVE                10    /* Number of bytes to reserve for w/c */

/* Length of screen-wide strings */

#define INPUT_LENGTH              80    /* Used in various queries */
#define TXTD_LENGTH               78    /* Used when displaying found text */

/* Length of command lines */

#if TARGET==DOS
 #define CMDLINE_LENGTH          160
#elif TARGET==OS2
 #define CMDLINE_LENGTH          264
#else
 #define CMDLINE_LENGTH          512    /* ASR fix: applies to Unices too!
                                           15/01/2003 -- Win32 preparations */
#endif

/* Number of command-line parameters. It must NOT be too high since some arrays
   are based on its value */

#if TARGET==DOS
 #define PARAMS_MAX               64    /* parameters+spaces: 64*2=128 */
 #define SFLIST_MAX               64    /* ARJSFX filelist array limit */
#elif TARGET==OS2
 #define PARAMS_MAX              131    /* ~262 */
 #define SFLIST_MAX              131
#else
 #define PARAMS_MAX             1024    /* May be less on some platforms */
 #define SFLIST_MAX             1024
#endif

/* FAR memory block size limit */

#ifdef TILED
 #if COMPILER==BCC
  #define FAR_BLK_MAX           65535
 #elif COMPILER==MSC
  #define FAR_BLK_MAX           65512
 #else
  #define FAR_BLK_MAX           65535
 #endif
 #define FLIST_ALLOC_MAX  FAR_BLK_MAX
#elif TARGET==OS2
 #define FAR_BLK_MAX        469762048   /* Unless it's Aurora */
 #define FLIST_ALLOC_MAX        65535
#else
 #define FAR_BLK_MAX        524288000   /* ASR fix 27/10/2002: larger
                                           values overflow the 2G limit in
                                           FILELIST.C, leading to
                                           ARJSFXV/Linux failure */
 #define FLIST_ALLOC_MAX        65535
#endif

/* CFA block increments. It will be wise to keep them proportional to the
   page size under OS/2, and memory-conserving under DOS. As a sidenote, this
   significantly reduces the memory requirements for ARJ under DOS. */

#if TARGET==OS2
 #define CFA_BLOCK_SIZE        16384
#elif defined(TILED)
 #define CFA_BLOCK_SIZE         4096
#else
 #define CFA_BLOCK_SIZE        16384    /* Presume i386 paged RAM */
#endif

/* Maximum # of files in the filelist. No longer an environment limit but
   a marketing logic! */

#define FILELIST_INCREMENT       256    /* Increment count for order blocks */
/* In original ARJ, there was a "commercial" filelist capacity (EXT LIC). The
   shareware/ordinary license limit was FLIST_ALLOC_MAX-1. */
#define EXT_FILELIST_CAPACITY ((unsigned long)FAR_BLK_MAX*4-5)
#define FILELIST_CAPACITY (FLIST_ALLOC_MAX-1)
#define FLIST_SPEC_BASE FILELIST_CAPACITY /* Special entries start here */

/* Implicit filelist limits */

#define FCLIM_DELETION  FILELIST_CAPACITY /* Limit for deletion */
#define FCLIM_ARCHIVE   EXT_FILELIST_CAPACITY /* Archive filelist size */
#define FCLIM_EXCLUSION FILELIST_CAPACITY /* Limit for exclusion */
#define FCLIM_EA        FILELIST_CAPACITY /* Limit for EA [in/ex]clusion */

/* Console settings */

#ifdef CR
 #undef CR
#endif
#define CR                      0x0D    /* CR */

#ifdef LF
 #undef LF
#endif
#define LF                      0x0A    /* LF */

#ifdef BEL
 #undef BEL
#endif
#define BEL                     0x07    /* Bell */

#ifdef TAB
 #undef TAB
#endif
#define TAB                     0x09    /* Tab */
#define TAB_POS                    8    /* Tab stops spacing */

#define CON_LBOUND                32    /* Lowest displayable character */
#define CON_UBOUND               126    /* Highest displayable character */

#if TARGET==UNIX||COMPILER==ICC||COMPILER==HIGHC||TARGET==OS2&&defined(LIBC)
 #define STDOUT_SETBUF_FIX              /* XPG.4 libraries (namely, IBM LIBC
                                           and GLIBC) do excessive stdout
                                           buffering */
#endif

#if TARGET==UNIX||TARGET==OS2
 #define DIRECT_TO_ANSI                 /* Means to reimplement screen commands
                                           via ANSI */
#endif

/* UNIX and DOS-style path separators */

#if TARGET==UNIX
 #define PATH_SEPARATORS         "/"
#else
 #define PATH_SEPARATORS      "\\:/"    /* Path separators allowed by target
                                           OS */
#endif
#if TARGET==UNIX
 #define PATHSEP_DEFAULT          '/'
 #define PATHSEP_DEFSTR           "/"
#else
 #define PATHSEP_DEFAULT         '\\'
 #define PATHSEP_DEFSTR          "\\"
#endif

/* File buffering equates (defining NO_CACHING will disable buffering) */

#define CACHE_SIZE              4096    /* Allocate this amount for buffer */
#define CACHE_SIZE_SFXJR        8192    /* ARJSFXJR incoming data cache size */
#define PROC_BLOCK_SIZE        27648    /* Size of sequential processing block */
#if TARGET==DOS
 #define VBUF_ADD               4096    /* Old archive stream */
 #define VBUF_EXTRACT           8192    /* Input archive stream */
 #define TBUF_ARJ               4096    /* Output archive stream */
 #if COMPILER==BCC
  #define VBUF_SFX              4096
 #else
  #define VBUF_SFX              2048
 #endif
#elif TARGET==OS2||TARGET==WIN32
 /* Microsoft C constraints (fragmented heap, and so on...) */
 #ifdef TILED
  #define VBUF_ADD              1024
  #define VBUF_EXTRACT          1024
  #define TBUF_ARJ              1024
  #define VBUF_SFX              1024
 #else
  #define VBUF_ADD              8192
  #define VBUF_EXTRACT         16384
  #define TBUF_ARJ              8192
  #define VBUF_SFX              8192
 #endif
#elif TARGET==UNIX
 #define VBUF_ADD               8192
 #define VBUF_EXTRACT           8192
 #define VBUF_ARJ               8192
 #define TBUF_ARJ               8192
 #define VBUF_SFX               8192
#else
 #error *** Buffering limits must be defined for the target platform!
#endif
#define TBUF_MINFREE          42000U    /* If less memory left, tbuf>>=1 */
#define VBUF_MINFREE          40000U    /* If less memory left, vbuf>>=1 */

/*
 * Error handling capabilities:
 *
 *   NO_TERM_HDL        disables termination handler
 *   NO_FATAL_ERROR_HDL disables fatal error handler
 *
 */

#if TARGET==DOS
 #define NO_TERM_HDL                    /* Disable termination handler */
#endif
#if TARGET==WIN32
 #define HAVE_BREAK_HANDLER
#endif

/* File attribute mapping */

/* DOS-way */
#define FATTR_HIDDEN          0x0002
#define FATTR_SYSTEM          0x0004
#define FATTR_RDONLY          0x0001
#define FATTR_ARCH            0x0020
#define FATTR_NOARCH          0x0000
#define FATTR_DIREC           0x0010
#define FATTR_LABEL           0x0008
/* UNIX-way */
#define FATTR_IROTH           0x0004
#define FATTR_IWOTH           0x0002
#define FATTR_IXOTH           0x0001
#define FATTR_IRGRP (FATTR_IROTH<<3)
#define FATTR_IWGRP (FATTR_IWOTH<<3)
#define FATTR_IXGRP (FATTR_IXOTH<<3)
#define FATTR_IRUSR (FATTR_IRGRP<<3)
#define FATTR_IWUSR (FATTR_IWGRP<<3)
#define FATTR_IXUSR (FATTR_IXGRP<<3)
#define FATTR_SVTX            0x0200    /* Sticky bit */
#define FATTR_SGID            0x0400    /* Set GID on exec */
#define FATTR_SUID            0x0800    /* Set UID on exec */
#define FATTR_UFMASK          0x0FFF    /* UID/GID/VTX + rwxrwxrwx */
#define ufattr(a) ((a)&FATTR_UFMASK)
/* Internal mapping for wild_list(), etc. */
#define FATTR_DT_ANY          0x0000    /* Default */
#define FATTR_DT_REG          0x1000    /* Regular files */
#define FATTR_DT_DIR          0x2000    /* Directories */
#define FATTR_DT_UXSPECIAL    0x4000    /* Links, pipes, etc. */
#define uftype(a)  ((a)&~FATTR_UFMASK)

/* Certain capabilities of non-UNIX operating systems aren't supported at all
   or are heavily modified */

#if TARGET==UNIX
 #define MAP_UNIX_ATTRS                 /* Convert to DOS representation */
#endif

#if TARGET!=UNIX
 #define STD_ATTRS              0x27    /* Borland compatibility mask */
 /* The following is for fileinfo searches */
 #define STD_FI_ATTRS (FATTR_DIREC|FATTR_HIDDEN|FATTR_SYSTEM|FATTR_RDONLY)
 #define STD_DIR_ATTR    FATTR_DIREC
 #define STD_FATTR_NOARCH FATTR_NOARCH
#else
 #define STD_FI_ATTRS (FATTR_DT_REG|FATTR_DT_DIR|FATTR_DT_UXSPECIAL)
 #define STD_DIR_ATTR   FATTR_DT_DIR
 #define STD_FATTR_NOARCH       0644
#endif

/* Priority classes */

#if TARGET==OS2||TARGET==WIN32
 #define PRIORITY_CLASSES               4       /* 1...4 */
#elif TARGET==UNIX
 #define PRIORITY_CLASSES              41       /* -20...20 -> 1...41 */
#else
 #define PRIORITY_CLASSES             100       /* For compatibility */
#endif

/* OS-specific options */

#if TARGET==DOS||TARGET==OS2||TARGET==WIN32
 #if TARGET==DOS
  #define EXE_EXTENSION            ".EXE"
  #define MOD_EXTENSION            ".COM"
 #else
  #define EXE_EXTENSION            ".exe"
  #define MOD_EXTENSION            ".dll"
 #endif
#else
 #define EXE_EXTENSION                 ""
 #define NULL_EXE_EXTENSION             /* For ARJ_USER to construct SFX names */
 #define MOD_EXTENSION              ".so"
#endif

/* OS-dependent types */

typedef unsigned short ATTRIB;          /* Attributes in internal structures */

/* File count type */

#define FILE_COUNT     unsigned long


/* Hard link search structure in ffblks and properties */

#if TARGET==UNIX
struct l_search
{
 dev_t dev;
 ino_t inode;
 nlink_t refcount;
 FILE_COUNT ref;
};
#endif

/* lfn_findfirst/findnext customized structure */

struct new_ffblk
{
 /* To stay compatible with findfirst/findnext functions that rely on DOS
    block format: */
 #if TARGET==DOS
  char ff_reserved[21];
 #endif
 #if TARGET!=UNIX
  char ff_attrib;
 #else
  int ff_attrib;
  int ff_ftype;                         /* Wild UNIX representation - for
                                           circular symlink treatment */
 #endif
 unsigned long ff_ftime;
 unsigned long ff_fsize;
 char ff_name[CCHMAXPATH];
 #if TARGET==DOS
  short ff_handle;
 #elif TARGET==OS2
  HDIR ff_handle;
 #elif TARGET==WIN32
  HANDLE ff_handle;
 #elif TARGET==UNIX
  DIR *ff_handle;
  char dir[CCHMAXPATH];                 /* dirent doesn't hold it */
  char wildcard[CCHMAXPATH];            /* dirent doesn't hold it */
  int attrs;                            /* dirent doesn't hold it */
  struct l_search l_search;
 #endif
 unsigned long ff_atime;
 unsigned long ff_ctime;
};

/* File information structure (used in file_find and so on) */

struct file_properties
{
 unsigned long fsize;
 unsigned long ftime;
 unsigned long atime;
 unsigned long ctime;
 ATTRIB attrib;
 char type;                             /* One of ARJT_* */
 char isarchive;
 /* For hardlink detection */
 #if TARGET==UNIX
  struct l_search l_search;
  char islink;
 #endif
};

/* Priority structure */

struct priority
{
 int class;
 int delta;
};

/* After defining all OS-dependent types, we may include additional files */

#include "filelist.h"                   /* For flist_root structure */

/* Exported from ENVIRON.C */

extern int friendly_systems[];
extern char dev_null[];
extern char dev_con[];
extern char cur_dir_spec[];
extern char up_dir_spec[];
extern char pathsep_str[];
extern char all_wildcard[];
extern char root_wildcard[];

/*
 * Macro section
 */

/* A substitution of kbhit() */

#if COMPILER==BCC||COMPILER==MSC||COMPILER==MSVC
 #define flush_kbd() kbhit()
#else
 #define flush_kbd() fetch_keystrokes()
#endif

/* OS-dependent strcmp() used for comparing filenames */

#ifdef HAVE_STRCASECMP
 #define stricmp strcasecmp
#endif

#ifdef CASE_INSENSITIVE
 #define strcmp_os(s1, s2) stricmp(s1, s2)
 #define strncmp_os(s1, s2, l) strnicmp(s1, s2, l)
#else
 #define strcmp_os(s1, s2) strcmp(s1, s2)
 #define strncmp_os(s1, s2, l) strncmp(s1, s2, l)
#endif

/* IBM's implementation of XPG4 CRT (LIBCS.DLL in OS/2) can't do localtime() properly.
   So we expose a timezone variable and use a homebrew implementation. May be used as a
   macro, i.e. real timezone converted to seconds. */

#if (defined(LIBC)&&TARGET==OS2)||TARGET==WIN32
 #define TZ_VAR             _timezone
#endif

/* fchmod() to make SFX'es executable and other archives non-executable */

#if TARGET==UNIX
 int file_acc(FILE *stream);
 void make_executable(FILE *stream);
 #define make_nonexecutable(stream) fchmod(fileno(stream), file_acc(stream)&~0111)
#else
 #define make_executable(stream)
 #define make_nonexecutable(stream)
#endif

/* Block optimizers in insane compilers. __LINE__ is for the compiler to be unable
   to optimize the function arguments if called more than once. */

#if COMPILER==HIGHC||COMPILER==ICC
 #define stop_optimizer() nullsub(__LINE__)
#else                                   /* Others are considered sane */
 #define stop_optimizer()
#endif

/*
 * Exported function prototypes - see ENVIRON.C for details
 */

#if TARGET==UNIX
#define SKIP_GET_EXE_NAME
void get_exe_name(char *dest, char *arg);
#else
void get_exe_name(char *dest);
#endif
#if TARGET==OS2&&SFX_LEVEL>=ARJSFX
 char *malloc_env_str(char *t);
 #define free_env_str(str) free(str)
 int system_cmd(char *cmd);
#else
 #define malloc_env_str(t) getenv(t)
 #define free_env_str(str)
 #define system_cmd(cmd) system(cmd)
#endif

#if SFX_LEVEL!=ARJSFXJR

int verify_heap();
int verify_far_heap();
#if SFX_LEVEL>=ARJSFXV&&COMPILER!=BCC
long farcoreleft();
#endif
#if COMPILER!=BCC
 #ifndef SUNOS 
  int getdisk();
  int setdisk(int drive);
 #endif
 void arj_gettime(struct time *ts);
 void arj_getdate(struct date *ds);
#else
 #define arj_gettime(x) gettime(x)
 #define arj_getdate(x) getdate(x)
#endif
#if TARGET==OS2&&defined(TILED)
 void FAR *farcalloc_based(unsigned long num, unsigned long size);
 void farfree_based(void FAR *ptr);
#else
 #define farcalloc_based farcalloc
 #define farfree_based farfree
#endif
void set_priority(struct priority *priority);
int test_for_winnt();
int file_chmod(char *name, int action, int attrs);
int lfn_findfirst(char *path, struct new_ffblk *new_ffblk, int attrib);
int lfn_findnext(struct new_ffblk *new_ffblk);
void lfn_findclose(struct new_ffblk *new_ffblk);
void toupper_loc(unsigned char *ptr, int length);
time_t sum_time(time_t t1, time_t t2);
time_t sub_time(time_t t1, time_t t2);
void case_path(char *s);
int find_dupl_drivespecs(char **argtable, int args);
int file_test_access(char *name);
int detect_lfns();
int detect_eas();
void fix_ansi_name(char *name);
void nullsub(int arg, ...);
/* IN ARJ32, it fixes filename to comply with OEM/ANSI codepage issues */
#define fix_ansi_name(name)
void arj_delay(unsigned int seconds);
void mem_stats();
int file_exists(char *name);
FILE *file_open(char *name, char *mode);
void default_case_path(char *dest, char *src);
int uni_getch();
unsigned long get_ticks();
unsigned long file_getfree(char *name);
int file_find(char *name, struct file_properties *properties);
#if SFX_LEVEL>=ARJ||defined(REARJ)
 long file_getfsize(char *name);
#endif
unsigned long file_getftime(char *name);
int file_getlabel(char *label, char drive, ATTRIB *attrib, unsigned long *ftime);
int read_line(char *buf, int size);
void get_mode_str(char *str, unsigned int mode);
int exec_pgm(char *cmdline);
#if TARGET==OS2&&SFX_LEVEL>=ARJSFX
 char *malloc_env_str(char *t);
 #define free_env_str(str) free(str)
 int system_cmd(char *cmd);
#else
 #define malloc_env_str(t) getenv(t)
 #define free_env_str(str)
 #define system_cmd(cmd) system(cmd)
#endif
int read_line_noecho(char *buf, int size);
unsigned int get_bytes_per_cluster(char *name);
void get_canonical_longname(char *cname, char *name);
void get_canonical_shortname(char *cname, char *name);
void install_smart_handler();
int is_file(FILE *stream);
int file_is_removable(char *name);
int is_tty(FILE *stream);
int file_mkdir(char *name);
int match_wildcard(char *name, char *wcard);
int file_rmdir(char *name);
int file_unlink(char *name);
int file_rename(char *oldname, char *newname);
int dos_clear_arch_attr(char *name);
int reset_drive(char *name);
int fetch_keystrokes();
int dos_chmod(char *name, int attrib);
int file_chsize(FILE *stream, unsigned long size);
int file_setftime_on_stream(FILE *stream, unsigned long ftime);
int file_setatime(char *name, unsigned long ftime);
int file_setctime(char *name, unsigned long ftime);
int file_setftime(char *name, unsigned long ftime);
int file_setlabel(char *label, char drive, ATTRIB attrib, unsigned long ftime);
int file_settype(FILE *stream, int istext);
void set_file_apis(int is_ansi);
#if SFX_LEVEL>=ARJSFXV
 int create_subdir_tree(char *path, int qmode, int datatype);
#else
 int create_subdir_tree(char *path, int datatype);
#endif
int is_filename_valid(char *name);
int is_directory(char *name);
char *malloc_subdir_wc(char *name);
int file_copy(char *dest, char *src, int chk);
#ifndef REARJ
 int wild_list(struct flist_root *root, struct flist_root *search_flist, char *name, int expand_wildcards, int recurse_subdirs, int file_type, FILE_COUNT *count);
#else
 int wild_list(struct flist_root *root, char *name, int file_type, int expand_wildcards, int recurse_subdirs, FILE_COUNT *count);
#endif

#if SFX_LEVEL>=ARJSFX&&SFX_LEVEL<=ARJSFXV
 void file_getcwd(char *buf, int len);
 void file_chdir(char *dir);
#endif

#ifdef REARJ
 char *file_getcwd(char *buf);
 int file_chdir(char *dir);
 char get_sw_char();
#endif

#endif /* !ARJSFXJR */

int file_setftime_on_hf(int hf, unsigned long ftime);

#endif
