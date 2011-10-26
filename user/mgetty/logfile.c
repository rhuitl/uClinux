#ident "$Id: logfile.c,v 4.10 2004/11/08 20:07:29 gert Exp $ Copyright (c) Gert Doering"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>

#include "mgetty.h"
#include "policy.h"

/* this must be included after ugly.h (sets USE_VARARGS on non-ANSI cc's) */
#ifdef USE_VARARGS
# if !defined(NeXT) || defined(NEXTSGTTY)
#  include <varargs.h>
# endif
#else
# include <stdarg.h>
#endif

#ifdef SYSLOG
#include <syslog.h>

#if !defined(linux) && !defined(BSD) && !defined(_SCO_DS) && \
    !defined(SVR42) && !defined(solaris2) && !defined(_AIX)
int openlog _PROTO(( char *, int, int ));
int syslog _PROTO(( int, char *, ... ));
#endif

#endif

/* on NeXTstep(POSIX), we have to use this *UGLY* way to cheat varargs/stdarg
 */
#if defined(NeXT) && !defined(NEXTSGTTY)
# define va_alist a1,a2,a3,a4,a5,a6,a7,a8,a9
# define va_dcl long a1,a2,a3,a4,a5,a6,a7,a8,a9;
# define vsprintf(buf,fmt,v) sprintf((buf),(fmt),a1,a2,a3,a4,a5,a6,a7,a8,a9)
# define va_list int
# define va_start(v)
# define va_end(v)
#endif


static int log_level = LOG_LEVEL;  /* set default log level threshold (jcp) */

static FILE * log_fp;
static boolean mail_logfile = FALSE;
static char log_path[ MAXPATH ];

static char log_infix[10];	   /* printed between time stamp and text */
static char * log_program = "mgetty";

extern int atexit _PROTO(( void (*)(void) ));

/* Most systems have these variables but do not declare them. On many
   of those systems that _do_ declare them, it won't hurt */

#if !defined(__NetBSD__) && !defined( __FreeBSD__ ) && !defined(__OpenBSD__) && !defined(__GLIBC__) && !defined(__MACH__)
extern int sys_nerr;
extern char *sys_errlist[];
#endif

/* Interactive Unix is a little bit braindead - does not have atexit(),
 */
#if defined(ISC) || defined(SVR4) || defined(_3B1_) || \
    defined(MEIBE) || defined(_SEQUENT_) || defined(_AIX) || \
    defined(sysV68) || ( defined(M_XENIX) && !defined(M_UNIX) )
# define atexit(dummy) 
#endif

/* on SunOS, we can do it with on_exit()
 */
#ifdef sunos4
# define atexit(func) on_exit(func, NULL)
#endif

void log_init_paths _P3 ( (l_program, l_path, l_infix),
		           char * l_program, char * l_path, char * l_infix )
{
    if ( l_program != NULL )			/* set program name */
    {
	char * p = strrchr( l_program, '/' );
	log_program = ( p == NULL ) ? l_program : p+1;
    }

    if ( l_path != NULL )			/* set log file name+path */
    {
	if ( log_fp != NULL &&			/* logfile already open */
	     strcmp( l_path, log_path ) != 0 )	/* and path changed */
	{
	    lprintf( L_MESG, "logging continues in file %s", l_path );
	    log_close();			/* -> reopen */
	}
	    
	strncpy( log_path, l_path, sizeof(log_path)-1 );
	log_path[sizeof(log_path)-1] = 0;
	if ( strlen(l_path) >= sizeof(log_path) )
	{
	    lprintf( L_FATAL, "internal error: log file path too long!" );
	}
    }

    if ( l_infix != NULL )			/* usually tty id */
    {
	sprintf( log_infix, "%.*s ", (int) sizeof(log_infix)-2, l_infix );
    }
}

void log_set_llevel _P1( (level), int level )
{
    log_level = level;
}
	
/* close log file, to give programs like 'savelog' a chance to move it away
 */
void log_close _P0(void)
{
    if ( log_fp != NULL ) fclose( log_fp );
    log_fp = NULL;
}
	    
void logmail _P0( void )
{
char	ws[MAXPATH+100];
char	buf[512];
int	l;
FILE *	pipe_fp;
int	log_fd;

    if ( mail_logfile )
    {
	lprintf( L_MESG, "mailing logfile to %s...", ADMIN );

	sprintf( ws, "%s %s", MAILER, ADMIN );
	pipe_fp = popen( ws, "w" );
	if ( pipe_fp == NULL )
	{
	    lprintf( L_ERROR, "cannot open pipe to %s", MAILER );
	    /* FIXME: write to console - last resort */
	    fprintf( stderr, "cannot open pipe to %s", MAILER );
	    return;
	}

	fprintf( pipe_fp, "Subject: fatal error in logfile\n" );
	fprintf( pipe_fp, "To: %s\n", ADMIN );
	fprintf( pipe_fp, "From: root (Fax Getty)\n" );
	fprintf( pipe_fp, "\nA fatal error has occured! The logfile follows\n" );
	log_fd = open( log_path, O_RDONLY );
	if ( log_fd == -1 )
	{
	    fprintf( pipe_fp, "The logfile '%s' cannot be opened (errno=%d)\n",
		     log_path, errno );
	}
	else
	{
	    do
	    {
	        l = read( log_fd, buf, sizeof( buf ) );
		fwrite( buf, l, 1, pipe_fp );
	    }
	    while( l == sizeof( buf ) );
	    fprintf( pipe_fp, "\n------ logfile ends here -----\n" );
	}
	close( log_fd );
	pclose( pipe_fp );
    }

    mail_logfile = FALSE;
}

int lputc _P2((level, ch), int level, char ch )
{
    if ( log_fp != NULL && level <= log_level )
    {
	if ( isprint(ch) ) fputc( ch, log_fp );
		      else fprintf( log_fp, "[%02x]", (unsigned char) ch );
	fflush( log_fp );
#ifdef LOG_CR_NEWLINE
	if ( ch == '\n' ) fputc( ch, log_fp );
#endif
    }
    return 0;
}

int lputs _P2((level, s), int level, char * s )
{
int retcode = 0;
    if ( log_fp != NULL && level <= log_level )
    {
	retcode = fputs( s!=NULL? s : "(NULL)", log_fp );
	fflush( log_fp );
    }
    return retcode;
}

#ifdef USE_VARARGS
int lprintf( level, format, va_alist )
int level;
const char * format;
va_dcl
#else
int lprintf(int level, const char *format, ...)
#endif
{
char    ws[2000];
time_t  ti;
struct tm *tm;
va_list pvar;
int     errnr;
char * p;
static int first_open = TRUE;

    if ( level > log_level )	/* log level high enough? */
    {
        return 0;		/* no -> return immediately */
    }

#ifdef USE_VARARGS
    va_start( pvar );
#else
    va_start( pvar, format );
#endif

    errnr = errno;

    if ( log_fp == NULL )		/* open log file, if necessary */
    {
        if ( log_path[0] == 0 )
	    sprintf( log_path, LOG_PATH, "unknown" );
	log_fp = fopen( log_path, "a" );

	if ( log_fp == NULL )		/* opening log file failed */
	{

	    sprintf(ws, "cannot open logfile %s", log_path);
	    perror(ws);
	    
	    /* use /dev/console for logging, if possible */
	    if ( ( log_fp = fopen( CONSOLE, "w" ) ) != NULL )
	    {
		fprintf( log_fp, "\n%s: resorting to logging to %s\n",
			log_program, CONSOLE );
	    }
	    else	/* give up, disable logging */
	    {
		sprintf( ws, "cannot log to %s, disable logging", CONSOLE );
		perror( ws );
		log_level = -1;
		return 0;
	    }
	}
	
	/* make sure that the logfile is not accidently stdin, -out or -err
	 */
	if ( fileno( log_fp ) < 3 )
	{
	int fd;
	    if ( ( fd = fcntl( fileno( log_fp ), F_DUPFD, 3 ) ) > 2 )
	    {
		fclose( log_fp );
		log_fp = fdopen( fd, "a" );
	    }
	}

	/* the first time we open the logfile, write a separator line
	 * and initialize syslog logging (if desired)
	 */
	if ( first_open )
	{
	    first_open = FALSE;
	    fprintf( log_fp, "\n--" );
#ifdef SYSLOG
	    openlog( log_program, LOG_PID, SYSLOG_FC );
#endif
	}

	/* set close-on-exec bit (prevent user programs writing to logfile */
	if ( fcntl( fileno( log_fp ), F_SETFD, 1 ) < 0 )
	{
	    lprintf( L_ERROR, "open_log: can't set close-on-exec bit" );
	}
    }

    /* Marc's hack to get different verbosity levels on different
     * intendation levels
     *!!!! ugly. Rewrite some day.
     */
    ws[0] = ' ';
    ws[1] = ' ';

    if (level == L_NOISE)
     vsprintf( &ws[1], format, pvar );
    else if (level == L_JUNK)
     vsprintf( &ws[2], format, pvar );
    else
     vsprintf( &ws[0], format, pvar );
    
    va_end( pvar );

    /* convert non-printable characters "in-place" to "_" */
    if ( level != L_AUDIT )
	for( p=ws; *p!='\0'; p++ )
	{
	    if ( ! isprint(*p) ) *p='_';
	}

    ti = time(NULL); tm = localtime(&ti);

    if ( level == L_AUDIT )		/* some little auditing */
    {
	fprintf(log_fp, "\n%02d/%02d %02d:%02d:%02d ##### %s\n",
		             tm->tm_mon+1,  tm->tm_mday,
			     tm->tm_hour, tm->tm_min, tm->tm_sec, ws );
#ifdef SYSLOG
	syslog( LOG_NOTICE, "%s", ws );
#endif
    }
    else if ( level != L_ERROR && level != L_FATAL )
    {
	fprintf(log_fp, "\n%02d/%02d %02d:%02d:%02d %s %s",
		             tm->tm_mon+1,  tm->tm_mday,
			     tm->tm_hour, tm->tm_min, tm->tm_sec,
		             log_infix, ws );
    }
    else		/* ERROR or FATAL */
    {
	fprintf(log_fp, "\n%02d/%02d %02d:%02d:%02d %s %s: %s",
		             tm->tm_mon+1,  tm->tm_mday,
			     tm->tm_hour, tm->tm_min, tm->tm_sec,
		             log_infix, ws,
			     ( errnr <= sys_nerr ) ? sys_errlist[errnr]:
			     "<error not in list>" );
#ifdef SYSLOG
	syslog( level == L_FATAL? LOG_ALERT: LOG_ERR, "%s: %m", ws );
#endif

#ifndef SYSLOG
	if ( level == L_FATAL )		/* write to console */
	{
	    FILE * cons_fp;
	    if ( ( cons_fp = fopen( CONSOLE, "w" ) ) != NULL )
	    {
		fprintf( cons_fp, "\n%s FATAL: %s %s\n",
			          log_program, log_infix, ws );
		fclose( cons_fp );
	    }
	    else	/* last resort */
		if ( !mail_logfile )
	    {
		atexit( logmail );
		mail_logfile = TRUE;
	    }
	}
#endif
    }	/* end if ( L_ERROR or L_FATAL ) */
    fflush(log_fp);

    return 0;
}

