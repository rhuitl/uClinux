/* $Id: conf-osx-att.h,v 1.2 1993/08/19 05:27:00 genek Exp $ */

/*
 * conf-osx-att.h
 *
 *	Tripwire configuration file for Pyramid's OSx and att universe
 *
 * Ken McDonell
 * Pyramid Technology
 *
 */

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

#undef STDLIBH

/*
 * does your system use readdir(3) that returns (struct dirent *)?
 */

#define DIRENT

/*
 * is #include <string.h> ok?  (as opposed to <strings.h>)
 */

#undef STRINGH

/* 
 * does your system have gethostname(2) (instead of uname(2))?
 */

#undef GETHOSTNAME
