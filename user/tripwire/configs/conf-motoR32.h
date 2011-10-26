/*
 * conf-svr3.h
 *
 *	Tripwire configuration file
 *
 * Kevin Johnson
 * Motorola Computer Group
 *
 * Notes:  I used gcc 2.4.5 to compile.  Didn't even try compiling it
 * with the stock C compiler.
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

#undef SYSV
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

#define MAXPATHLEN 255
