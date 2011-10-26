/* $Id: conf-osx-ucb.h,v 1.2 1993/08/19 05:27:02 genek Exp $ */

/*
 * conf-osx-ucb.h
 *
 *	Tripwire configuration file for Pyramid's OSx and ucb universe
 *
 * Ken McDonell
 * Pyramid Technology
 *
 */

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
 * -- yes, but we do not have a <dirent.h> to #include
 */

#undef DIRENT

/*
 * is #include <string.h> ok?  (as opposed to <strings.h>)
 */

#undef STRINGH

/* 
 * does your system have gethostname(2) (instead of uname(2))?
 */

#define GETHOSTNAME
