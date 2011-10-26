/* $Id: conf-bsdi.h,v 1.2 1994/08/04 03:44:12 gkim Exp $ */

/*
 * conf-bsdi.h
 *
 *	Tripwire configuration file
 *
 * Terry Kennedy
 * St. Peter's College
 * Derived from:
 * Gene Kim
 * Purdue University
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
