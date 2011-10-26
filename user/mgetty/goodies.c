#ident "$Id: goodies.c,v 4.5 2003/11/17 19:08:49 gert Exp $ Copyright (c) 1993 Gert Doering"

/*
 * goodies.c
 *
 * This module is part of the mgetty kit - see LICENSE for details
 *
 * various nice functions that do not fit elsewhere 
 */

#include <stdio.h>
#include "syslibs.h"
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>

/* NeXTStep/86 has some byte order problems (Christian Starkjohann) */
#if defined(NeXT) && defined(__LITTLE_ENDIAN__) && !defined(NEXTSGTTY)
# define pw_uid pw_short_pad1
# define pw_gid pw_short_pad2
# define gr_gid gr_short_pad
#endif

#include "mgetty.h"
#include "config.h"

#ifdef SVR4
# include <sys/procfs.h>
#endif

/* get the base file name of a file path */

char * get_basename _P1( (s), char * s )
{
char * p;

    if ( s == NULL ) return NULL;

    p = strrchr( s, '/' );

    return ( p == NULL ) ? s: p+1;
}

/* auxiliary function: get a uid/gid pair from two strings
 * specifying user and group
 */

void get_ugid _P4( (user, group, uid, gid),
		  conf_data * user, conf_data * group,
		  uid_t * uid, gid_t * gid )
{
    /* default */
    *uid = *gid = 0;

    if ( user->flags != C_EMPTY )		/* user set */
    {
	struct passwd *pwd;

	if ( isdigit( *(char*)(user->d.p) ))	/* numeric */
	    pwd = getpwuid( atoi( (char*) (user->d.p) ));
	else					/* string */
	    pwd = getpwnam( (char*)(user->d.p) );

	if ( pwd == NULL )
	    lprintf( L_ERROR, "can't get user id for '%s'", user->d.p );
	else
	{
	    *uid = pwd->pw_uid;
	    *gid = pwd->pw_gid;
	}
	endpwent();
    }


    /* if group is set, override group corresponding to user */
    if ( group->flags != C_EMPTY )
    {
	struct group * grp;

	if ( isdigit( *(char*)(group->d.p) ))	/* numeric */
	    grp = getgrgid( atoi( (char*)(group->d.p)) );
	else					/* string */
	    grp = getgrnam( (char*) (group->d.p) );

	if ( grp == NULL )
	    lprintf( L_ERROR, "can't get group '%s'", group->d.p );
	else
	    *gid = grp->gr_gid;

	endgrent();
    }
}
/* return process name + arguments for process "PID"
 *
 * use /proc filesystem on Linux and SVR4
 *
 * if no information is available, return NULL
 */

char * get_ps_args _P1 ((pid), int pid )
{
#ifdef SVR4
    char *pscomm = NULL;
# ifdef PIOCPSINFO
    int procfd;
    char procfname[12];
    static prpsinfo_t psi;

    sprintf (procfname, "/proc/%05d", pid);

    procfd = open (procfname, O_RDONLY);
    if ( procfd < 0 )
    {
	lprintf( L_ERROR, "cannot open %s", procfname );
    }
    else
    {
	if (ioctl (procfd, PIOCPSINFO, &psi) != -1)
	{
	    psi.pr_psargs[PRARGSZ-1] = '\0';
	    pscomm = psi.pr_psargs;
	}
	close(procfd);
    }
# endif /* PIOCPSINFO */
    return pscomm;
#endif /* SVR4 */

#if defined(linux) || \
	( defined(__FreeBSD__ ) && __FreeBSD_version >= 330000 )

# ifdef DIALOUT_SHOW_USERNAMES
    char procfn[30];
    struct stat buf;
    struct passwd *pwe;
    static char u_logname[30];

    sprintf (procfn, "/proc/%d", pid);
    if (stat (procfn, &buf) < 0) {
	lprintf( L_ERROR, "cannot stat %s", procfn );
	return NULL;
    }

    if ((pwe = getpwuid (buf.st_uid)) == 0) {
	lprintf( L_ERROR, "cannot getpwuid %d", buf.st_uid );
	return NULL;
    }
	
    strncpy( u_logname, pwe->pw_name, sizeof(u_logname)-1);
    u_logname[sizeof(u_logname)-1]=0;

    return u_logname;

# else		/* standard behaviour: show command line */
    char procfn[30];
    int procfd;
    int i,l;

    static char psinfo[60];	/* 60 is considered long enough */

    sprintf( procfn, "/proc/%d/cmdline", pid );

    procfd = open( procfn, O_RDONLY );

    if ( procfd < 0 )
    {
	lprintf( L_ERROR, "cannot open %s", procfn );
	return NULL;
    }

    l = read( procfd, psinfo, sizeof( psinfo ) -1 );

    if ( l < 0 )
    {
	lprintf( L_ERROR, "reading %s failed", procfn );
	close( procfd );
	return NULL;
    }

    close( procfd );

    psinfo[l] = 0;

    /* arguments separated by \0, replace with space */
    for ( i=0; i<l; i++ )
	if ( psinfo[i] == 0 ) psinfo[i] = ' ';

    /* remove trailing whitespace */
    while( l>0 && isspace(psinfo[l-1]) ) psinfo[--l]='\0';

    return psinfo;

# endif /* show user name, not process cmd line */
#endif /* linux */

#if !defined(SVR4) && !defined(linux)
    return NULL;
#endif
}

#if defined(NEED_STRDUP)

/* provide strdup() for systems not having it... */
char * strdup _P1( (src), char *src)
{
char * dest;

    if (!src) return(NULL);
    dest = (char *)malloc(strlen(src) + 1);
    if (!dest) return(NULL);
    strcpy(dest,src);
    return(dest);
}

#endif


#if defined(NEED_PUTENV)

/* provide putenv() for NEXTSTEP:
 * original code by Terrence W. Holm (tholm@uvicctr.UUCP),
 * slightly modified by Karl Berry (karl@cs.umb.edu)
 * contributed to mgetty by Gregor Hoffleit (flight@mathi.uni-heidelberg.DE)
 */

#define  PSIZE  sizeof(char *)

extern char **environ;

int putenv _P1( (entry), char *entry)
{
unsigned length, size;
char * temp;
char ** p;
char ** new_environ;

    temp = strchr(entry,'=');
    if ( temp == 0 ) return( -1 );

    length = (unsigned) (temp - entry + 1);

    for ( p=environ; *p != 0 ; p++ )
	if ( strncmp( entry, *p, length ) == 0 ) {
	    *p = entry;
	    return( 0 );
	}

    size = p - environ;
    new_environ = (char **) malloc( (size+2)*PSIZE );

    if ( new_environ == (char **) NULL )
	return( -1 );

    memcpy ((char *) new_environ, (const char *) environ, size*PSIZE );
    new_environ[size]   = entry;
    new_environ[size+1] = NULL;
    environ = new_environ;

    return(0);
}
#endif /* NEED_PUTENV */

#ifdef NeXT
  /* provide function to repair broken tty settings
   * mega-ugly, but it seems to work
   * code provided by Christian Starkjohann <cs@ecs.co.at>
   */
# include <libc.h>
# include <sgtty.h>
void    NeXT_repair_line(int fd)
{
    int             bitset = LPASS8 | LPASS8OUT;
    int             bitclr = LNOHANG;
    
#ifndef NEXTSGTTY		/* needed only for broken POSIX subsystem */
    struct sgttyb   sg;

    ioctl(fd, TIOCGETP, &sg);
    sg.sg_flags |= EVENP | ODDP;
    ioctl(fd, TIOCSETP, &sg);
#endif
    ioctl(fd, TIOCLBIS, &bitset);
    ioctl(fd, TIOCLBIC, &bitclr);
}
#endif
