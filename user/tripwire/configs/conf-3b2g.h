/* $Id: conf-3b2g.h,v 1.2 1993/08/19 05:26:48 genek Exp $ */

/*
 * conf-3b2g.h
 *
 *      Tripwire configuration file
 *
 * Gene Kim
 * Purdue University
 *
 * Port by Joe Sirrianni <sirrianni@dockmaster.ncsc.mil>
 *
 */

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

#define STRINGH
 
/* 
 * does your system have gethostname(2) (instead of uname(2))?
 */

#undef GETHOSTNAME

/*
 * missing defines 
 */

#define MAXPATHLEN 256

/*
 * To work around lack of gettimeofday() in src/dbase.build.c
 */
#define NOGETTIMEOFDAY
