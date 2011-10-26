/* $Id: conf-irix4.h,v 1.2 1993/08/19 05:26:57 genek Exp $ */

/*
 * conf-irix4.h
 *
 *	Tripwire configuration file
 *
 * Gene Kim
 * Purdue University
 *
 * IRIX4 port by:
 * 	Simon Leinen <simon@lia.di.epfl.ch>
 * 	Ecole Polytechnique Federale de Lausanne
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

#define DIRENT

/*
 * does your system have lstat()
 */
#define HAVE_LSTAT

/*
 * is #include <string.h> ok?  (as opposed to <strings.h>)
 */

#define STRINGH
