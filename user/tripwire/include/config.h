/* $Id: config.h,v 1.5 1994/07/15 11:02:52 gkim Exp $ */

/*
 * config.h
 *
 *	Tripwire configuration file
 *
 * Gene Kim
 * Purdue University
 */


/***
 *** Operating System specifics
 ***	
 ***	Look in the .,/configs directory, and include appropriate header
 ***	file that corresponds with your operating system.
 ***/

#include "../configs/conf-linux.h"

#ifdef TW_TYPE32
typedef TW_TYPE32 int32;
typedef unsigned TW_TYPE32 uint32;
#else
typedef long int32;
typedef unsigned long uint32;
#endif

/***
 *** SYSTEM SPECIFIC Tripwire Configuration
 ***/

/******* signature functions *****************************************
 *
 * Choose among these:
 *
 *	sig_md5_get		: MD5 function
 *				  (the RSA Data Security, Inc. MD5 Message-
 *				   Digesting Algorithm)
 *	sig_snefru_get		: Snefru function
 *				  (the Xerox Secure Hash Function)
 *	sig_null_get		: null function (returns 0 for all)
 *
 *  By default, Tripwire uses
 *		int (pf_signature0)() = sig_null_get;
 *		int (pf_signature1)() = sig_md5_get;
 *		int (pf_signature2)() = sig_snefru_get;
 *
 *  However, since Snefru is comparatively computationally expensive, you
 *  might consider using only MD5.  This can be done in the configuration,
 *  however, and should not be done by defining away the signature here.
 *
 *  You can replace one of the signature algorithms with another of your
 *  own choice by adding it to the build procedure, and putting it in
 *  here in place of one of these standard routines.  See the design
 *  document for hints on this.
 *
 *  To do this, just set one of the signature function pointers to
 *  your own function.
 *
 *********************************************************************/

#define SIG0FUNC	sig_null_get
#define SIG1FUNC	sig_md5_get
#define SIG2FUNC	sig_snefru_get
#define SIG3FUNC	sig_crc32_get
#define SIG4FUNC	sig_crc_get
#define SIG5FUNC	sig_md4_get
#define SIG6FUNC	sig_md2_get
#define SIG7FUNC	sig_sha_get
#define SIG8FUNC	sig_haval_get
#define SIG9FUNC	sig_null_get

#define SIG0NAME	"nullsig"
#define SIG1NAME	"md5"
#define SIG2NAME	"snefru"
#define SIG3NAME	"crc32"
#define SIG4NAME	"crc16"
#define SIG5NAME	"md4"
#define SIG6NAME	"md2"
#define SIG7NAME	"sha"
#define SIG8NAME	"haval"
#define SIG9NAME	"nullsig"

/******* path to Tripwire files **************************************
 *
 *	Ideally, CONFIG_PATH and DATABASE_PATH should be pointing to
 *	some read-only media, or some filesystem mounted remotely
 *	from a "secure-server".  (See design document for details.)
 *
 *	Note:  No trailing '/' in the paths!
 *
 *********************************************************************/

/*
#if !defined(SYSV) || (defined(SYSV) && (SYSV > 2))
# define CONFIG_PATH     "/usr/adm/tcheck"
# define DATABASE_PATH   "/usr/adm/tcheck/databases"
#else
# define CONFIG_PATH     "/usr/local/adm/tcheck"
# define DATABASE_PATH   "/usr/local/adm/tcheck/databases"
#endif
*/

#define CONFIG_PATH     "/etc/config"
/* #define DATABASE_PATH   "/etc/config/databases" */
#define DATABASE_PATH   "/etc/config"

/******* name of Tripwire files **************************************
 *
 *	Static filenames are nice, but we allow run-time binding to
 *	support multiple hosts sharing the same directory (without
 *	having to recompile.
 *
 *	Use the '@' character to represent the hostname of the machine
 *	running Tripwire.
 *
 *	For example "tw.db_@" would expand to:
 *		
 *		tw.db_mentor.cc.purdue.edu
 *
 *********************************************************************/

#define CONFIG_FILE 	"tw.config"
#define DATABASE_FILE	"tw.db_@"

/******* Default ignore mask ****************************************
 *
 *	Usually, the only thing you want to ignore is the access time
 *	stamp.  But there may be applications where you want to know
 *	about any accesses, too.
 *
 *	Similarly, there may be some environments where you can have a much
 * 	more forgiving ignore mask.
 *
 *	By default, Tripwire uses:
 *		"R" --  read-only files, where only the access time
 *			stamp can change.
 *      Alternatively, you might want to make the default be "R-2"
 *      This would be faster than simply "R", at some small loss
 *	(perhaps) of protection.
 *
 *	NOTE:  Users with backup programs that read through the file
 *	system rather than the raw disk (e.g., bru and cpio) should
 *	add a "-c" to the DEFAULTIGNORE string.  Otherwise, every file
 *	will be reported as changed after backups.
 *
 *********************************************************************/

#define DEFAULTIGNORE	"R-3456789"

/******* Temporary file template ************************************
 *
 *	Usually, temporary files are stored in /tmp.  You may want
 *	to use a different directory if your system does not support
 *	the BSD "sticky" bit on directories.  (i.e., only owner or root
 *	can rename or delete files.)
 *
 *	Make sure that there are at least 6 X's in the template.
 *	Each consecutive X signifies a number that mktemp() can
 *	fill in with a random number.
 *
 *********************************************************************/

#define TEMPFILE_TEMPLATE "/tmp/twzXXXXXX"



