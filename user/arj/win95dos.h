/*
 * $Id: win95dos.h,v 1.1.1.2 2002/03/28 00:03:28 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * Windows 95 DOS gateway definitions. They must be included only if the DOS16
 * operating mode is used.
 *
 */

#define CCHMAXPATH_W95           260    /* Maximum long pathname length */
#ifdef MAXPATH
 #define CCHMAXPATH_DOS      MAXPATH    /* Maximum DOS pathname length */
#else
 #define CCHMAXPATH_DOS           80
#endif

/* W95 API functions */

#define W95_RESETDRIVE        0x710D
#define W95_MKDIR             0x7139
#define W95_RMDIR             0x713A
#define W95_CHDIR             0x713B
#define W95_UNLINK            0x7141
#define W95_CHMOD             0x7143
#define W95_CWD               0x7147
#define W95_FINDFIRST         0x714E
#define W95_FINDNEXT          0x714F
#define W95_RENAME            0x7156
#define W95_TRUENAME          0x7160
#define W95_OPEN              0x716C
#define W95_GET_VOLUME_INFO   0x71A0
#define W95_FINDCLOSE         0x71A1

/* New subfunctions to control DTA/DTC */

#define W95_GET_DTA           0x5704
#define W95_SET_DTA           0x5705
#define W95_GET_DTC           0x5706
#define W95_SET_DTC           0x5707

/* W95_RESETDRIVE equates */

#define W95_FLUSH_BUFFERS          0
#define W95_FLUSH_CACHE            1
#define W95_REMOUNT                2

/* W95_CHMOD Subfunction codes */

#define W95_GETATTR                0
#define W95_SETATTR                1

/* W95_TRUENAME Subfunction codes */

#define W95_CANONICALIZE           0
#define W95_GET_SHORTNAME          1
#define W95_GET_LONGNAME           2

/* W95 Wildcard expansion flags */

#define W95_WILDCARDS_DISABLED     0
#define W95_WILDCARDS_ENABLED      1

/* Findfirst/findnext formats */

#define W95_DT_64BIT               0
#define W95_DT_DOS                 1
#define W95_TRANSLATE_SHORT        0    /* Substitute "_"'s for unconvertable
                                           Unicode characters */
#define W95_TRANSLATE_LONG         1

/* Longname open actions */

#define W95_A_EXCL                 1
#define W95_A_TRUNC                2
#define W95_A_CREAT             0x10

/* W95 findfirst/findnext specialized structure (no 64-bit entries) */

struct W95_FFBLK
{
 unsigned long ff_attrib;
 unsigned long ff_ctime;                /* Creation */
 unsigned long reserved1;
 unsigned long ff_atime;                /* Last access */
 unsigned long reserved2;
 unsigned long ff_ftime;                /* Last modification (as in DOS) */
 unsigned long reserved3;
 unsigned long ff_fsize_m;              /* MSDW (not used right now) */
 unsigned long ff_fsize;                /* LSDW */
 char ff_reserved[8];
 char ff_longname[CCHMAXPATH_W95];
 char ff_name[14];
};

