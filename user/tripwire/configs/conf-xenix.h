/* $Id: conf-xenix.h,v 1.3 1993/08/19 05:27:10 genek Exp $ */

/*
 * conf-xenix.h
 *
 *	Tripwire configuration file
 *
 * Gene Kim
 * Purdue University
 *
 * Xenix port by:
 *	Daniel Ray <norstar@tnl.com>
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

#define SYSV 3

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

#undef DIRENT

/*
 * is #include <string.h> ok?  (as opposed to <strings.h>)
 */

#define STRINGH
 
/* 
 * does your system have gethostname(2) (instead of uname(2))?
 */

#undef GETHOSTNAME

/*
 * To work around lack of gettimeofday() in src/dbase.build.c
 */

#define NOGETTIMEOFDAY

/*
 * miscallaneous stuff 
 */

#define XENIX

