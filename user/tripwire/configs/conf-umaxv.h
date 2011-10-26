/* $Id: conf-umaxv.h,v 1.3 1993/11/30 19:29:52 genek Exp $ */

/*
 * conf-umaxv.h
 *
 *	Tripwire configuration file
 *
 * Gene Kim
 * Purdue University
 *
 * Modified by Michael Barnett (mikeb@rmit.edu.au) for UMAX V R2.4.1.
 * Modified by Georges Tomazi (tomazi@kralizec.zeta.org.au) for UMAX V 2.4.1.P3
 *
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

#define SYSV 2

/* 
 * does your system have a <malloc.h> like System V? 
 */

#define MALLOCH 	

/* 
 * does your system have a <stdlib.h> like POSIX says you should? 
 */

#undef STDLIBH

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

/*
 * miscellaneous stuff - mnb
 */

#define MAXPATHLEN PATH_MAX
