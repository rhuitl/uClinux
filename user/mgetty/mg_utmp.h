#ident "$Id: mg_utmp.h,v 4.1 1997/01/12 14:53:42 gert Exp $ Copyright (c) Gert Doering"

/* definitions for utmp reading / writing routines,
 * highly SysV / BSD dependent
 */

#if !defined(sunos4) && !defined(BSD) && !defined(ultrix) /* SysV style */

#ifdef SVR4			/* on SVR4, use extended utmpx file */
# include <utmpx.h>
# define utmp		utmpx
# define getutent	getutxent
# define getutid	getutxid
# define getutline	getutxline
# define pututline	pututxline
# define setutent	setutxent
# define endutent	endutxent
# define ut_time	ut_xtime
#else				/* !SVR4 */
# include <utmp.h>
#endif

#ifdef _AIX
struct utmp * getutent();		/* AIX 3.2.5 doesn't declare these */
void setutent();
#endif

#define UT_INIT		INIT_PROCESS
#define UT_LOGIN	LOGIN_PROCESS
#define UT_USER		USER_PROCESS

#else						 /* SunOS or generic BSD */

#include <sys/types.h>
#include <utmp.h>

/* BSDish /etc/utmp files do not have the "ut_type" field,
 * but I need it as flag whether to write an utmp entry or not */

#define UT_INIT		0
#define UT_LOGIN	1
#define UT_USER		2

#endif						/* SysV vs. BSD */

/* prototypes */

void make_utmp_wtmp _PROTO(( char * line, short ut_type, 
			     char * ut_user, char * ut_host ));
int  get_current_users _PROTO(( void ));

/* system prototypes - not all supported systems have these */

#if defined(M_UNIX)

struct	utmp	*getutent _PROTO((void));
#ifndef _SCO_DS			/* ODT 5.0 */
struct	utmp	*pututline _PROTO((struct utmp * utmp));
#endif
void		setutent _PROTO((void));
void		endutent _PROTO((void));

#endif /* M_UNIX */
