/* $Id: conf-hpux.h,v 1.5 1994/07/16 23:39:37 gkim Exp $ */

/*
 * conf-hpux.h
 *
 *      Tripwire configuration file
 *
 * Gene Kim
 * Purdue University
 *
 * HP/UX port by:
 * 	Lance Bailey <lrb@ctrg.rri.uwo.ca>
 */

/* "Cory F. Cohen" <syscory@starbase.spd.louisville.edu> writes:
 * 	My GCC already had _HPUX_SOURCE defined...  so I used
 *   #ifndef __GNUC__      (I added)
 *   #define _HPUX_SOURCE  (My GCC already had this defined)
 *   #endif                (I added)
 */

#define _HPUX_SOURCE

/***
 *** Operating System specifics
 ***    
 ***    If the answer to a question in the comment is "Yes", then
 ***    change the corresponding "#undef" to a "#define"
 ***/

/*
 * is your OS a System V derivitive?  if so, what version?
 *                      (e.g., define SYSV 4)
 */

#undef SYSV

/* 
 * does your system have a <malloc.h> like System V? 
 */

#define MALLOCH         

/* 
 * does your system have a <stdlib.h> like POSIX says you should? 
 */

#define STDLIBH

/*
 * does your system use readdir(3) that returns (struct dirent *)?
 */

#define DIRENT

/*
 * is #include <string.h> ok?  (as opposed to <strings.h>)
 */

#define STRINGH

/* 
 * does your system have gethostname(2) (instead of uname(2))?
 */

#define GETHOSTNAME
