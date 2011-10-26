#ident "$Id: login.c,v 4.19 2003/12/05 22:28:58 gert Exp $ Copyright (C) 1993 Gert Doering"


/* login.c
 *
 * handle calling of login program(s) for data calls
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <ctype.h>
#ifndef EINVAL
#include <errno.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* NeXTStep/86 has some byte order problems (Christian Starkjohann) */
#if defined(NeXT) && defined(__LITTLE_ENDIAN__) && !defined(NEXTSGTTY)
# define pw_uid pw_short_pad1
# define pw_gid pw_short_pad2
# define gr_gid gr_short_pad
#endif

#include "mgetty.h"
#include "config.h"
#include "policy.h"
#include "mg_utmp.h"

#ifdef SECUREWARE
extern int setluid();
#endif

extern char * Device;			/* mgetty.c */

/* match( user, key )
 *
 * match "user" against "key"
 * key may start or end with "*" (wildcard)
 */
boolean match _P2( (user,key), char * user, char * key )
{
    int lk = strlen( key );
    int lu = strlen( user );
    int i;

    lprintf( L_NOISE, "match: user='%s', key='%s'", user, key );

    /* empty lines do not match */
    if ( lk == 0 ) return FALSE;

#ifdef FIDO
    /* special handling for fido logins */
    if ( user[0] == '\377' && strcmp( key, "/FIDO/" ) == 0 )
    {
	return TRUE;
    }
#endif

    if ( key[0] == '*' )			/* "*bc?" */
    {
	if ( key[lk-1] == '*' )			/* "*bc*" */
	{
	    if ( lk < 2 ) return TRUE;		/* "*" or "**" */
	    for ( i=0; i <= lu - (lk-2); i++ )
	    {
		if ( strncmp( &user[i], &key[1], lk-2 ) == 0 ) return TRUE;
	    }
	    return FALSE;
	}
	else					/* "*bcd" */
	{
	    return ( ( lu >= lk-1 ) &&
		     ( strcmp( &user[ lu-(lk-1) ], &key[1] ) == 0 ) );
	}
    }
    else					/* "abc?" */
    {
	if ( key[lk-1] == '*' )			/* "abc*" */
	{
	    return ( ( lu >= lk-1 ) &&
		     ( strncmp( user, key, lk-1 ) == 0 ) ); 
	}
	else
	{
	    return ( ( lu == lk ) && 
		     ( strcmp( user, key ) == 0 ) );
	}
    }
    return FALSE;	/*NOTREACHED*/
}

/* execute login
 *
 * which login program is executed depends on LOGIN_FILE
 * default is "/bin/login user"
 *
 * does *NOT* return
 */

void login_dispatch _P3( (user, is_callback, cfg_file ),  
			 char * user, boolean is_callback, char * cfg_file )
{
#define MAX_LOGIN_ARGS 9
    char * argv[MAX_LOGIN_ARGS+2];	/* name + args + NULL */
    int	argc = 0;
    char * cmd = NULL;
    int i;

    /* read "mgetty.login" config file (if specified) */
    FILE * fp = NULL;
    int file_version = 1;		/* login.config format changed! */
    char * line, * key, *p;
    struct passwd * pw;
    extern struct passwd * getpwnam();

    struct stat st;

    if ( cfg_file == NULL ) 
    {
	lprintf( L_JUNK, "login: no login cfg file defined" );
	goto fallthrough;
    }

    cfg_file = _makepath( cfg_file, CONFDIR );

    lprintf( L_JUNK, "login: use login config file %s", cfg_file );
    
    /* first of all, some (somewhat paranoid) checks for file ownership,
     * file permissions (0i00), ...
     * If something fails, fall through to default ("/bin/login <user>")
     */       
       
    if ( stat( cfg_file, &st ) < 0 )
    {
	lprintf( L_ERROR, "login: stat('%s') failed", cfg_file );
	goto fallthrough;
    }

    /* permission check */
    if ( st.st_uid != 0 || ( ( st.st_mode & 0077 ) != 0 ) )
    {
	errno=EINVAL;
	lprintf( L_FATAL, "login: '%s' ignored, wrong permissions. Must be owned by 'root' and have mode '0600'", cfg_file );
	goto fallthrough;
    }

    /* go for it! */
    if ( (fp = fopen( cfg_file, "r" )) == NULL )
    {
	lprintf( L_FATAL, "login: cannot open %s", cfg_file );
    }
    else
	while ( ( line = fgetline( fp ) ) != NULL )
    {
	norm_line( &line, &key );

	/* as the format of login.config has changed over time, we have
	 * to have "file versions", set by the '!version <n>' keyword
	 */
	if ( strcmp( key, "!version" ) == 0 )
	{
	    file_version = atoi(line);
	    if ( file_version < 1 || file_version > 2 )
	    {
		errno = EINVAL;
		lprintf( L_ERROR, "login: invalid file version '%s'", line);
		file_version = 1;
	    }
	    lprintf( L_NOISE, "login: version %d", file_version);
	    continue;
	}

	if ( match( user, key ) )
	{
	    char * user_id;
	    char * utmp_entry;
	    
	    lputs( L_NOISE, "*** hit!" );
#ifdef FIDO
	    if ( user[0] == '\377' && strcmp( key, "/FIDO/" ) == 0 )
	    {
		user++;
	    }
#endif
	    /* in version 2 files, the next field is used to qualify
	     * this line for callback only/never/don't care
	     */
	    if ( file_version > 1 )
	    {
		char cbq = toupper( *(line++) );

		if ( ( cbq == 'Y' && ! is_callback ) ||
		     ( cbq == 'N' &&   is_callback ) )
		{
		    lprintf( L_NOISE, "-> skipped: %c/%d", cbq, is_callback );
		    continue;
		}
		/* skip to next field */
		while( *line && !isspace(*line) ) line++;
		while( isspace(*line) ) line++;
	    }

	    /* get (login) user id */
	    user_id = strtok( line, " \t" );

	    /* get utmp entry */
	    utmp_entry = strtok( NULL, " \t" );

	    /* get login program */
	    argv[0] = cmd = strtok( NULL, " \t" );

	    /* sanity checks - *before* setting anything */
	    errno = EINVAL;
	    
	    if ( user_id == NULL )
	    {
		lprintf( L_FATAL, "login: uid field blank, skipping line" );
		continue;
	    }
	    if ( utmp_entry == NULL )
	    {
		lprintf( L_FATAL, "login: utmp field blank, skipping line" );
		continue;
	    }
	    if ( cmd == NULL )
	    {
		lprintf( L_FATAL, "login: no login command, skipping line" );
		continue;
	    }

	    /* OK, all values given. Now write utmp entry */

	    if ( strcmp( utmp_entry, "-" ) != 0 )
	    {
		if ( strcmp( utmp_entry, "@" ) == 0 ) utmp_entry = user;

		lprintf( L_NOISE, "login: utmp entry: %s", utmp_entry );
		make_utmp_wtmp( Device, UT_USER, utmp_entry, Connect );
	    }

	    /* set UID (+login uid) */
	    
	    if ( strcmp( user_id, "-" ) != 0 )
	    {
		pw = getpwnam( user_id );
		if ( pw == NULL )
		{
		    lprintf( L_ERROR, "getpwnam('%s') failed", user_id );
		}
		else
		{
		    lprintf( L_NOISE, "login: user id: %s (uid %d, gid %d)",
				      user_id, pw->pw_uid, pw->pw_gid );
#if SECUREWARE
		    if ( setluid( pw->pw_uid ) == -1 )
		    {
			lprintf( L_ERROR, "cannot set LUID %d", pw->pw_uid);
		    }
#endif
		    if ( setgid( pw->pw_gid ) == -1 )
		    {
			lprintf( L_ERROR, "cannot set gid %d", pw->pw_gid );
		    }
		    if ( setuid( pw->pw_uid ) == -1 )
		    {
			lprintf( L_ERROR, "cannot set uid %d", pw->pw_uid );
		    }
		}
	    }				/* end if (uid given) */

	    /* now build 'login' command line */

	    /* strip path name off to-be-argv[0] */
	    p = strrchr( argv[0], '/' );
	    if ( p != NULL ) argv[0] = p+1;

	    /* break up line into whitespace-separated command line
	       arguments, substituting '@' by the user name
	       */
	    
	    argc = 1;
	    p = strtok( NULL, " \t" );
	    while ( argc <= MAX_LOGIN_ARGS && p != NULL )
	    {
		if ( strcmp( p, "@" ) == 0 )		/* user name */
		{
		    if ( user != NULL && user[0] != 0 )
		    {
			argv[argc++] = user;
		    }
		}
		else if ( strcmp( p, "\\I" ) == 0 )	/* Connect */
		{
		    argv[argc++] = Connect[0]? Connect: "??";
		}
		else if ( strcmp( p, "\\Y" ) == 0 )	/* CallerID */
		{
		    argv[argc++] = CallerId;
		}
		else
		    argv[argc++] = p;
		
		p = strtok( NULL, " \t" );
	    }

	    if ( p != NULL )			/* arguments left? */
		lprintf( L_WARN, "login.config: max. %d command line arguments possible, truncated at: '%s'", MAX_LOGIN_ARGS, p);

	    break;
	}		/* end if (matching line found) */
    }	/* end while( not end of config file ) */

    if ( fp != NULL ) fclose( fp );

fallthrough:

    /* default to "/bin/login <user>" */
    if ( argc == 0 )
    {
	lprintf( L_NOISE, "login: fall back to %s", DEFAULT_LOGIN_PROGRAM );
	
	cmd = DEFAULT_LOGIN_PROGRAM;
	argv[argc++] = "login";

	/* append user name to argument list (if not empty) */
	if ( user[0] != 0 )
	{
	    argv[argc++] = user;
	}
    }

    /* terminate list */
    argv[argc] = NULL;

    /* verbose login message */
    lprintf( L_NOISE, "calling login: cmd='%s', argv[]='", cmd );
    for ( i=0; i<argc; i++) { lputs( L_NOISE, argv[i] ); 
			      lputs( L_NOISE, (i<argc-1)?" ":"'" ); }

    /* set a couple of environment variables (mainly useful for "special"
     * logins, like Fido and AutoPPP, because /bin/login reconstructs its
     * environment from scratch) - not general enough, though.
     */
    setup_environment();

    /* audit record */
    lprintf( L_AUDIT, 
       "data dev=%s, pid=%d, caller='%s', conn='%s', name='%s', cmd='%s', user='%s'",
	Device, getpid(), CallerId, Connect, CallName,
	cmd, user );

    /* make sure close-on-exec bit is unset
     * (BUG in FreeBSD 4.1.1 syslog() - sets c-o-e on FD 0 !!!
     */
    if ( fcntl(0, F_GETFD, 0 ) & 1 ) 
	lprintf( L_WARN, "WARNING: close-on-exec bit set on FD 0 - OS BUG?" );

    /* execute login */
    execv( cmd, argv );

    /* FIXME: try via shell call */

    lprintf( L_FATAL, "cannot execute '%s'", cmd );
    exit(FAIL);
}

void setup_environment _P0(void)
{
    if ( *CallerId )
	set_env_var( "CALLER_ID", CallerId );
    if ( *CallName )
	set_env_var( "CALLER_NAME", CallName );
    if ( *CalledNr )
	set_env_var( "CALLED_ID", CalledNr );
    set_env_var( "CONNECT", Connect );
    set_env_var( "DEVICE", Device );
}
