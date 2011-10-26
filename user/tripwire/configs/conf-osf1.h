/* $Id: conf-osf1.h,v 1.3 1994/07/15 11:02:47 gkim Exp $ */

/*
 * conf-osf1.h
 *
 *	Tripwire configuration file
 *
 * Gene Kim
 * Purdue University
 *
 * OSF/1 port by:
 *	Rich Salz <rsalz@osf.org>
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
 * does your system have gethostname(2) (instead of uname(2))?
 */

#define GETHOSTNAME

/*
 * does your system use readdir(3) that returns (struct dirent *)?
 */

#define DIRENT

/*
 * is #include <string.h> ok?  (as opposed to <strings.h>)
 */

#define STRINGH
