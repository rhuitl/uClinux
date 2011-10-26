/* $Id: tripwire.h,v 1.32 1994/07/25 16:04:34 gkim Exp $ */

/************************************************************************
 *
 *   All files in the distribution of Tripwire are Copyright 1992, 1993 by 
 *   the Purdue Research Foundation of Purdue University.  All rights
 *   reserved.  Some individual files in this distribution may be covered
 *   by other copyrights, as noted in their embedded comments.
 *
 *   Redistribution and use in source and binary forms are permitted
 *   provided that this entire copyright notice is duplicated in all such
 *   copies, and that any documentation, announcements, and other
 *   materials related to such distribution and use acknowledge that the
 *   software was developed at Purdue University, W. Lafayette, IN by
 *   Gene Kim and Eugene Spafford.  No charge, other than an "at-cost"
 *   distribution fee, may be charged for copies, derivations, or
 *   distributions of this material without the express written consent
 *   of the copyright holder.  Neither the name of the University nor the
 *   names of the authors may be used to endorse or promote products
 *   derived from this material without specific prior written
 *   permission.  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY
 *   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE
 *   IMPLIED WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR ANY PARTICULAR
 *   PURPOSE.
 *
 ************************************************************************/

/*
 * tripwire.h
 *
 *	common definitions for Tripwire
 *
 * Gene Kim
 * Purdue University
 */

/* version information */

#define VERSION_NUM 	"1.2"
#define DB_VERSION_NUM	4

/* For signature routines prototypes: */

#include "../sigs/snefru/snefru.h"
#include "../sigs/md5/md5.h"
#include "../sigs/crc32/crc32.h"
#include "../sigs/crc/crc.h"
#include "../sigs/md2/md2.h"
#include "../sigs/md4/md4.h"
#include "../sigs/sha/sha.h"
#include "../sigs/haval/haval.h"

/* essential includes common to all sources files */

#include <errno.h>


/* get any missing inode typedefs */

#include "../include/inode.h"

/* database record format */
/* filename: (entrynumber, ignorevec, st_mode, st_ino, st_nlink,
 *		st_uid, st_gid, st_size,
 *		ltob64(statbuf->st_atime, vec64_a),
 *		ltob64(statbuf->st_mtime, vec64_m),
 *		ltob64(statbuf->st_ctime, vec64_c), sig0, sig1, ..., sig9
 */

# define DB_RECORD_FORMAT "%ld %s %lo %lu %lu %lu %lu %lu %s %s %s %s %s %s %s %s %s %s %s %s %s\n"
#define DB_RECORD_FIELDS 21

/* system defaults */

extern int db_version_num;
extern char *config_file;	
extern char *config_path;	
extern char *database_file;	
extern char *database_path;	
extern char tempdatabase_file[];
extern FILE *fptempdbase;
extern int debuglevel, verbosity, quietmode, printpreprocess;
extern int test_interactive;
extern char *specified_dbasefile, *specified_configfile;
extern int specified_configfd, specified_dbasefd;
extern int specified_configmode, specified_dbasemode;
extern char *progname;
extern char *defaultignore;
extern char *db_record_format;
extern struct list *olddbase_list;
extern struct list *toc_list;
extern char *version_num;
extern char backupfile[];
extern int printhex;
extern int runtimeignore;
extern int loosedir;

/* debugging verbosity */

#define SPDEBUG(x) if (debuglevel >= (x))

#define TRUE 1
#define FALSE 0

#define SIG_MAX_LEN 200

/* ignore vector flags */
/*	note:  as an optimization, IGNORE_0 .. IGNORE_9 are ordered.
 *	do not change the ordering of these vectors!
 */

#define IGNORE_P	0x1
#define IGNORE_I	0x2
#define IGNORE_N	0x4
#define IGNORE_U	0x8
#define IGNORE_G	0x10
#define IGNORE_S	0x20
#define IGNORE_A	0x40
#define IGNORE_M	0x80
#define IGNORE_C	0x100
#define IGNORE_0	0x200
#define IGNORE_1	0x400
#define IGNORE_2	0x800
#define IGNORE_3	0x1000
#define IGNORE_4	0x2000
#define IGNORE_5	0x4000
#define IGNORE_6	0x8000
#define IGNORE_7	0x10000
#define IGNORE_8	0x20000
#define IGNORE_9	0x40000
#define IGNORE_0_9	(IGNORE_0|IGNORE_1|IGNORE_2|IGNORE_3|IGNORE_4|IGNORE_5|IGNORE_6|IGNORE_7|IGNORE_8|IGNORE_9)
#define IGNORE_GROW	0x80000		/* growing log files */

/* filelist flags */
#define FLAG_CHANGED 	1
#define FLAG_NOOPEN	2
#define FLAG_SYMLINK	4
#define FLAG_SEEN	8
#define FLAG_UPDATE	16
#define FLAG_UNCHANGE	32
#define FLAG_DELETE	64

/* prunelist flags */
#define PRUNE_ALL	1
#define PRUNE_ONE	2

/* database_build() modes */

#define DBASE_PERMANENT		0
#define DBASE_TEMPORARY 	1
#define DBASE_UPDATE 		2

/* database update modes */

#define UPDATE_INVALID		0
#define UPDATE_ADDFILE		1
#define UPDATE_DELETEFILE	2
#define UPDATE_UPDATEFILE	3
#define UPDATE_NOTFOUND		4
#define UPDATE_ADDENTRY		5
#define UPDATE_DELETEENTRY	6
#define UPDATE_UPDATEENTRY	7

/* define specified file modes */

#define SPECIFIED_NONE		0
#define SPECIFIED_FILE		1
#define SPECIFIED_FD		2

/* diff lists */
extern struct list *diff_added_list,
		   *diff_deleted_list,
		   *diff_changed_list;
extern int 	diff_added_num,
    		diff_changed_num,
		diff_deleted_num,
		diff_unignored_num;
extern int	files_scanned_num;

/* diff parsing */

struct diff_bucket {
    int 	arg1, arg2, arg3, arg4;
    int		diffmode;
};

/* diff_parsing() types */
#define DIFF_SAME 	0
#define DIFF_CHANGED	1
#define DIFF_ADDED	2
#define DIFF_DELETED	3

/* signature functions */
#define NUM_SIGS	10
extern int (*pf_signatures[NUM_SIGS]) ();
extern char *signames[NUM_SIGS];

/* prototypes */

/*** Do not remove this line.  Protyping depends on it! ***/
#if defined(__STDC__) || defined(__cplusplus)
#define P_(s) s
#else
#define P_(s) ()
#endif

/* config.parse.c */
void configfile_read P_((struct list **pp_list, struct list **pp_entry_list));
/* main.c */
int main P_((int argc, char *argv[]));
/* list.c */
void list_set P_((char *pc_name, char *pc_value, int priority, struct list **pp_list));
char *list_lookup P_((char *pc_name, struct list **pp_list));
int list_isthere P_((char *pc_name, struct list **pp_list));
void list_unset P_((char *pc_name, struct list **pp_list));
int list_setflag P_((char *pc_name, int flag, struct list **pp_list));
int list_getflag P_((char *pc_name, struct list **pp_list));
void list_print P_((struct list **pp_list));
void list_reset P_((struct list **pp_list));
int list_init P_((void));
int list_open P_((struct list **pp_list));
struct list_elem *list_get P_((struct list **pp_list));
int list_close P_((struct list **pp_list));
/* ignorevec.c */
int ignore_vec_to_scalar P_((char *s));
void ignore_configvec_to_dvec P_((char *s));
/* dbase.build.c */
void database_build P_((struct list **pp_list, int mode, struct list **pp_entry_list));
/* utils.c */
void warn_with_err P_((char *format, char *name));
void die_with_err P_((char *format, char *name));
void filename_hostname_expand P_((char **ps));
int slash_count P_((char *pathname));
int string_split_space P_((char *string, char *s, char *t));
int string_split_ch P_((char *string, char *s, char *t, int ch));
void chop P_((char *s));
void filename_escape_expand P_((char *filename));
char *filename_escape P_((char *filename));
char *pltob64 P_((uint32 *pl, char *pcout, int numlongs));
char *btob64 P_((register unsigned char *pcbitvec, register char *pcout, int numbits));
int32 b64tol P_((char *vec));
int32 oldb64tol P_((char *vec));
void direntry_print P_((char *name, struct stat statbuf, int mode));
int fd_tempfilename_generate P_((void));
int fd_copy_to_tmp P_((int fdin));
int file_copy_to_tmp P_((char *filename));
int file_to_fd P_((char *filename));
/* preen.c */
void update_gather P_((int interactive, char ***ppp_updateentries));
void update_mark P_((char **ppentry, int num));
void dbase_entry_howclose P_((char *filename, struct list **ppentrylist, char *pentryname, int *pentrynum));
/* preen.interp.c */
void preen_interp P_((FILE *fpin));
/* preen.report.c */
void preen_report P_((int interactive, char ***ppp_updateentries));
/* nullsig.c */
int sig_null_get P_((int fd_in, char *ps_signature, int siglen));
/* config.prim.c */
void tw_mac_define P_((char *varname, char *varvalue));
char *tw_mac_dereference P_((char *varname));
void tw_mac_undef P_((char *varname));
int tw_mac_ifdef P_((char *varname));
int tw_mac_ifhost P_((char *hostname));
/* dbase.update.c */
void dbase_entry_flag P_((struct list **pp_list, int flagentry, int orflag, char *ignore));
/* config.pre.c */
void tw_macro_parse P_((char *filename, FILE *fpin, FILE *fpout, struct list **pp_entry_list));
/* help.c */
void tw_help_print P_((FILE *fpout));
