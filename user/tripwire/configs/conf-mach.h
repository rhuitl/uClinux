/* $Id: conf-mach.h,v 1.2 1993/08/19 05:26:58 genek Exp $ */

/*
 * conf-mach.h
 *
 *	Tripwire configuration file
 *
 * Peter Shipley
 * TFS (TRW Financial Systems)
 */

/***
 *** Operating System specifics
 ***	
 ***	If the answer to a question in the comment is "Yes", then
 ***	change the corresponding "#undef" to a "#define"
 ***/

/*
 * is your OS a System V derivitive?  if so, what version?
 *			(e.g., define SYSV 4)
 */

#undef SYSV

/* 
 * does your system have a <malloc.h> like System V? 
 */

#undef MALLOCH 	

/* 
 * does your system have a <stdlib.h> like POSIX says you should? 
 */

#undef STDLIBH

/*
 * does your system use readdir(3) that returns (struct dirent *)?
 */

/* MACH has readdir(3) but no include file <dirent.h> */
#undef DIRENT

/*
 * is #include <string.h> ok?  (as opposed to <strings.h>)
 */

#define STRINGH

/* 
 * does your system have gethostname(2) (instead of uname(2))?
 */

#define GETHOSTNAME


/*
 * miscellaneous stuff
 */

#define MACH 1

/* MACH seems to be missing the define for S_IFIFO [but is had S_ISFIFO() ] */
#ifndef S_IFIFO
#define S_IFIFO 0010000
#endif


