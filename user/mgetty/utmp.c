#ident "$Id: utmp.c,v 4.4 2001/12/17 22:43:24 gert Exp $ Copyright (c) Gert Doering"

/* some parts of the code (writing of the utmp entry)
 * is based on the "getty kit 2.0" by Paul Sutcliffe, Jr.,
 * paul@devon.lns.pa.us, and are used with permission here.
 */

#include "mgetty.h"

#if defined(sunos4) || defined(BSD)

#include <stdio.h>
#include <string.h>
#include <time.h>

#else		/* !BSD */

#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef ENOENT
#include <errno.h>
#endif

#if defined(_3B1_) || defined(MEIBE) || defined(ISC)
typedef short pid_t;
#endif

#endif

#include "mg_utmp.h"

#ifndef UTMP_FILE
# ifdef _PATH_UTMP
#  define UTMP_FILE _PATH_UTMP		/* FreeBSD and NetBSD */
# else
#  define UTMP_FILE "/etc/utmp"		/* SunOS and NeXT */
# endif
#endif


#if defined(sunos4) || defined(BSD) || defined(ultrix)
/* on SunOS (and other BSD-derived systems), the getty process does *
 * not have to care for the utmp entries, login and init do all the work
 * Anyway, we have to _read_ it to get the number of users logged in.
 */
void make_utmp_wtmp _P4( (line, ut_type, ut_user, ut_host),
			 char * line, short ut_type,
			 char * ut_user, char * ut_host )
{
    /* On BSD systems, everything works a bit differently.
     * UT_INIT and UT_LOGIN entries are ignored (init and login do all
     * the work), UT_USER is set via the login() function (in libutil.a).
     * [NB: If we wanted to set UT_INIT, it would have to be an entry with
     * empty ut_name and ut_host]
     */
#if defined(__FreeBSD__) || defined(__NetBSD__)
    struct utmp utmp;
    extern void login _PROTO(( struct utmp * utmp ));

    bzero( (void*) &utmp, sizeof(utmp) );
    if ( ut_type == UT_USER )
    {
	utmp.ut_time = time(NULL);
	strncpy( utmp.ut_name, ut_user, sizeof(utmp.ut_name) );
	strncpy( utmp.ut_line, line, sizeof(utmp.ut_line) );
	if ( ut_host != NULL )
	    strncpy( utmp.ut_host, ut_host, sizeof(utmp.ut_host) );

	login( &utmp );
    }

    lprintf(L_NOISE, "utmp + wtmp entry made");
#endif	/* __FreeBSD__ */
}

int get_current_users _P0(void)
{
    struct utmp utmp;
    FILE *fp;
    int Nusers = 0;

    fp = fopen( UTMP_FILE, "r");
    if ( fp == NULL )
    {
    	lprintf(L_ERROR, "get_cu: %s", UTMP_FILE );
	return 0;
    }

    while ( fread( &utmp, sizeof(utmp), 1, fp ) == 1 )
    {
	if ( utmp.ut_name[0] != 0 && utmp.ut_line[0] != 0 )
	    Nusers++;
    }
    fclose(fp);
    
    return Nusers;
}

#else			/* System V style utmp handling */

void make_utmp_wtmp _P4( (line, ut_type, ut_user, ut_host),
			 char * line, short ut_type,
			 char * ut_user, char * ut_host )
{
struct utmp *utmp;
pid_t	pid;
struct stat	st;
FILE *	fp;

    pid = getpid();
    lprintf(L_JUNK, "looking for utmp entry... (my PID: %d)", pid);

    while ((utmp = getutent()) != (struct utmp *) NULL)
    {
	if (utmp->ut_pid == pid &&
	    (utmp->ut_type == INIT_PROCESS || utmp->ut_type == LOGIN_PROCESS))
	{
	    strcpy(utmp->ut_line, line );

	    utmp->ut_time = time( NULL );

	    utmp->ut_type = ut_type;	/* {INIT,LOGIN,USER}_PROCESS */
	                                /* "LOGIN", "uugetty", "dialout" */
	    strncpy( utmp->ut_user, ut_user, sizeof( utmp->ut_user ) );

#if defined(SVR4) || defined(linux)
	    if (ut_host != NULL)
	    {
	    	strncpy( utmp->ut_host, ut_host, sizeof( utmp->ut_host ) - 1);
# ifdef solaris2		/* Solaris 2.x */
	    	utmp->ut_syslen = strlen(utmp->ut_host) + 1;
# endif
	    }
#endif		/* SVR4 */

#if defined(M_UNIX) || defined(__GLIBC__)
	    if ( pututline(utmp) == NULL )
	    {
		lprintf( L_ERROR, "cannot create utmp entry" );
	    }
#else
	    /* Oh god, how I hate systems declaring functions as void... */
	    pututline( utmp );
#endif

	    /* write same record to end of wtmp
	     * if wtmp file exists
	     */
#ifdef SVR4
	    updwtmpx(WTMPX_FILE, utmp);
#else
# if defined(__GLIBC__) && __GLIBC__ >= 2
	    updwtmp(WTMP_FILE, utmp);
# else
	    if (stat(WTMP_FILE, &st) && errno == ENOENT)
		    break;
	    if ((fp = fopen(WTMP_FILE, "a")) != (FILE *) NULL)
	    {
		(void) fseek(fp, 0L, SEEK_END);
		(void) fwrite((char *)utmp,sizeof(*utmp),1,fp);
		(void) fclose(fp);
	    }
# endif	/* GNU Libc 2.x */
#endif	/* !SVR4 */

	    lprintf(L_NOISE, "utmp + wtmp entry made");
	    break;
	}
    }
    endutent();
}

int get_current_users _P0(void)
{
    struct utmp * utmp;
    int Nusers = 0;

    setutent();
    while ((utmp = getutent()) != (struct utmp *) NULL)
    {
	if (utmp->ut_type == USER_PROCESS)
	{
	    Nusers++;
	    /*lprintf(L_NOISE, "utmp entry (%s)", utmp->ut_name); */
	}
    }
    endutent();

    return Nusers;
}
#endif		/* !sunos4, !BSD, !ultrix */
