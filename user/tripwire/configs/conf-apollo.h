/* $Id: conf-apollo.h,v 1.1 1994/02/22 07:45:25 gkim Exp $ */

/*
 * conf-apollo.h (Apollo Domain/OS SR10.X, m68k or a88k, BSD environment)
 *
 *	Tripwire configuration file
 *
 * Paul Szabo
 * University of Sydney
 */

/***
 *** Operating System specifics
 ***	
 ***	If the answer to a question in the comment is "Yes", then
 ***	change the corresponding "#undef" to a "#define"
 ***/

/*
 * is your OS a System V derivative?  if so, what version?
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

/* Apollos DO NOT have this pre-SR10.4 (or maybe pre-SR10.3 ??),
so you must have NO (#undef) pre-SR10.4 (or pre-SR10.3);
you should have YES (#define) at SR10.4 (or SR10.3). */

#undef STDLIBH

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

#define GETHOSTNAME
