#ifndef ___MGETTY_H
#define ___MGETTY_H

#ident "$Id: mgetty.h,v 4.26 2005/02/14 12:41:43 gert Exp $ Copyright (c) Gert Doering"

/* mgetty.h
 *
 * contains most of the constants and prototypes necessary for
 * mgetty+sendfax (except some fax constants, they are in fax_lib.h)
 */

#include "ugly.h"

/* some generic, useful defines */

#ifndef ERROR
#define	ERROR	-1
#define NOERROR	0
#endif

#ifndef TRUE
#define TRUE (1==1)
#define FALSE (1==0)
#endif

#define FAIL	-1
#define SUCCESS	0

/* defines for FIDO mailers */

#define TSYNC	0xae
#define YOOHOO	0xf1

/* defines for auto detection of incoming PPP calls (->PAP/CHAP) */

#define PPP_FRAME	0x7e	/* PPP Framing character */
#define PPP_STATION	0xff	/* "All Station" character */
#define PPP_ESCAPE	0x7d	/* Escape Character */ 
#define PPP_CONTROL	0x03	/* PPP Control Field */
#define PPP_LCP_HI	0xc0	/* LCP protocol - high byte */
#define PPP_LCP_LOW	0x21	/* LCP protocol - low byte */
#define PPP_UNESCAPE(c)	((c) ^ 0x20) /* un-escape character */

/* stuff in logfile.c */

#define L_FATAL 0
#define L_ERROR 1
#define L_AUDIT 2
#define L_WARN 3
#define L_MESG 4
#define L_NOISE 5
#define L_JUNK 6

void log_init_paths _PROTO(( char * program, char * path, char * infix ));
void log_set_llevel _PROTO(( int level ));
void log_close _PROTO((void));
int lputc _PROTO(( int level, char ch ));
int lputs _PROTO(( int level, char * s ));
#ifdef USE_VARARGS
int lprintf _PROTO(());
#else
int lprintf _PROTO((int level, const char *format, ...));
#endif

/* various defines */

/* bsd stuff */
#if defined(__BSD_NET2__) || defined(__386BSD__) || \
    defined(__NetBSD__)   || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__MACH__)
# include <sys/param.h>	/* defines BSD, BSD4_3 and BSD4_4 */
# ifndef BSD
#  define BSD		/* just in case... */
# endif
# if defined(__FreeBSD__) && !defined(__FreeBSD_version)
#  include <osreldate.h>		/* FreeBSD version */
# endif
#endif

/* some versions of BSD have their own variant of fgetline that
 * behaves differently. Just change the name for now...
 * FIXME.
 */
#ifdef BSD
# define fgetline mgetty_fgetline
#endif

/* define here what function to use for polling for characters
 * Chose one of the following: USE_SELECT, USE_POLL, USE_READ
 * I recommend USE_SELECT on all machines that have it, except SCO Unix,
 * since the tv_usec timer is not exact at all on SCO.
 * If your System has the "nap(S)" call, you can use this instead of
 * select(S) or poll(S) for sleeping less than one second.
 * Ditto for usleep(S), for systems having it.
 */
#if defined(linux) || defined(_AIX)
# define USE_USLEEP
#endif

#if !defined(USE_POLL) && !defined(USE_READ)
#define USE_SELECT
#endif

/* SunOS4 does not have memmove, but bcopy handles overlapping copies
 * as well. Watch out for src/dst argument order!
 */

#if defined(sunos4) || defined(NEED_MEMMOVE)
# define memmove(dst, src, len) bcopy(src, dst, len)
#endif

/* these definitions specify the return value type and the arguments
 * for signal handler functions - if your compiler barfs, change them
 */
typedef	void	RETSIGTYPE;

#ifdef _SCO_DS		/* SCO OSR 5.0 */
# define SIG_HDLR_ARGS	int signo
#else
# define SIG_HDLR_ARGS
#endif

typedef	char	boolean;

/* the cpp directive "sun" isn't useful at all, since is defined on
 * SunOS 4, Solaris 2, and even Solaris x86...
 * So, you have to define -Dsunos4, -Dsolaris2, or -Dsolaris86.
 * Otherwise: barf!
 */
#ifdef sun
# if !defined( sunos4 ) && !defined( solaris2 ) && !defined( solaris86 )
#  error "Please define -Dsunos4 or -Dsolaris2 or -Dsolaris86"
# endif
#endif

#ifdef solaris2
# define SVR4
# define SVR42
# ifndef sun
#  define sun
# endif
#endif

/* SGI's are SVR4... (jwz@netscape.com) */
#ifdef __sgi
# define SVR4
# define SVR42
#endif

/* assume that all BSD systems have the siginterrupt() function
 * for GNU libc 2.x, we need it as well (default behaviour is now "restart")
 */
#if defined(BSD) || defined(sunos4) ||\
    ( defined(__GLIBC__) && __GLIBC__ >= 2 ) 
# ifndef NO_SIGINTERRUPT
#  define HAVE_SIGINTERRUPT
# endif
#endif

/* assume that some systems do not have long filenames...
 */
#if ( defined(m88k) && !defined(SVR4) )
# ifndef SHORT_FILENAMES
#  define SHORT_FILENAMES
# endif
#endif

/* On systems we know mmap() works, it will be used for reading G3
 * files in the tools (g3topbm.c, g3cat.c), because it is a lot faster
 */
#if defined(linux) || defined(BSD)
# define HAVE_MMAP
#endif

/* recent systems have mkstemp(), and it's more secure than mktemp()
 * SCO does not have it, though :-(
 */
#if !defined(M_UNIX) && !defined(_3B1_)
# define HAVE_MKSTEMP
#endif

/* On a ALPHA, the config routines won't work, unless we change the
 * union to use "void *" and "long", instead of "int" (see config.h).
 * Same for Sparc Ultra machines [at least with SparcLinux]
 */
#if defined(__alpha__) || defined(__sparc64__) || \
	    defined(__ia64__) || defined(__s390x__) || defined(__x86_64__) || \
	    defined(__powerpc64__)
# define PTR_IS_LONG
#endif

#define MAXLINE 1024		/* max. # chars in a line */
#define MAXPATH MAXLINE
#define STDIN	0

typedef enum {
	A_TIMOUT, A_FAIL, A_FAX, A_VCON, A_CONN,
	A_RING1, A_RING2, A_RING3, A_RING4, A_RING5
} action_t;

typedef struct	chat_actions {
			char * expect;
			action_t action; } chat_action_t ;

/* do_chat.c */
int	do_chat _PROTO(( int filedesc, char * expect_send[],
	     	 chat_action_t actions[], action_t * action,
		 int chat_timeout_time, boolean timeout_first ));
int	do_chat_send _PROTO(( int filedesc, char * send_str_with_esc ));
int	clean_line _PROTO(( int filedesc, int tenths ));

/* ring.c */
int	wait_for_ring _PROTO(( int filedesc, char ** msn_list, int timeout, 
			       chat_action_t actions[], action_t * action,
			       int * dist_ring_number ));

/* do_stat.c */
void	get_statistics _PROTO(( int filedesc, char ** chat, char * file ));

/* goodies.c */
char * get_basename _PROTO(( char * ));
char * mydup _PROTO(( char *s ));
char * get_ps_args _PROTO(( int pid ));

/* io.c */
boolean	check_for_input _PROTO (( int fd ));
boolean wait_for_input  _PROTO (( int fd, int seconds ));
void	delay _PROTO(( int waittime ));

/* locks.c */
#define	NO_LOCK	0	/* returned by checklock() if no lock found */
int		makelock _PROTO((char * device));
int		makelock_file _PROTO(( char * lockname ));
int		checklock _PROTO((char * device));
RETSIGTYPE	rmlocks _PROTO (());
int		steal_lock _PROTO((char * device, int pid ));
  
/* fax stuff */
void	faxrec _PROTO(( char * spool_dir, unsigned int switchbd,
		        int uid, int gid, int mode, char * mail_to ));
char *	fax_strerror _PROTO(( int fax_hangup_code ));
void	faxlib_init _PROTO((void));
extern	int modem_quirks;

/* initialization stuff: mg_m_init.c */
int	mg_init_data  _PROTO(( int fd, char * chat_seq[], 
			       boolean need_dsr, char * force_seq[]));
int	mg_init_fax   _PROTO(( int fd, char * mclass, char * fax_id, 
			       boolean fax_only, int fax_max_speed ));
int 	mg_init_voice _PROTO(( int fd ));
void	faxpoll_server_init _PROTO(( int fd, char * fax_server_file ));
int	mg_open_device _PROTO(( char * devname, boolean blocking ));
int	mg_init_device _PROTO(( int fd, boolean toggle_dtr,
			        int toggle_dtr_waittime,
			        unsigned int portspeed ));
int	mg_get_device _PROTO(( char * devname, boolean blocking,
			       boolean toggle_dtr, int toggle_dtr_waittime,
			       unsigned int portspeed ));
int	mg_get_ctty _PROTO(( int fd, char * devname ));
int	mg_drop_ctty _PROTO(( int fd ));

/* modem.c */
int	mdm_send _PROTO(( char * send, int fd ));
int	mdm_read_byte _PROTO(( int fd, char * c ));
char *	mdm_get_line  _PROTO(( int fd ));
int	mdm_command   _PROTO(( char * send, int fd ));
char *  mdm_get_idstring _PROTO(( char * send, int n, int fd ));

/* logname.c */
char *	ln_escape_prompt _PROTO(( char * prompt ));
void	set_env_var _PROTO(( char * var, char * string ));

/* login stuff */
void login_dispatch _PROTO(( char * user, boolean is_callback, char * cf));
void setup_environment _PROTO(( void ));

/* how long should I wait for a string from modem */
#define FAX_RESPONSE_TIMEOUT	120
/* how much time may pass while receiving a fax without getting data */
#define	FAX_PAGE_TIMEOUT	60

/* cnd.c */

extern char *Connect;
extern char *CallerId;
extern char *CallTime;
extern char *CallName;
extern char *CalledNr;

void cndfind _PROTO((char *str));
int cndlookup _PROTO((void));
int cnd_call _PROTO((char *name, char *tty, int dist_ring ));

/* disk statistics retrieval in getdisk.c */

struct mountinfo {
    long	mi_bsize;	/* fundamental block size */
    long	mi_blocks;	/* number of blocks in file system */
    long	mi_bfree;	/* number of free blocks in file system */
    long	mi_bavail;	/* blocks available to non-super user */
    long	mi_files;	/* number of file nodes in file system */
    long	mi_ffree;	/* number of free nodes in fs */
};

typedef struct mountinfo	mntinf;

extern long minfreespace;

int checkspace _PROTO((char *path));
int getdiskstats _PROTO ((char *path, mntinf *mi));

/********* system prototypes **************/
extern char * mktemp _PROTO(( char * template ));

#if  !defined(linux) && !defined(SVR4) && !defined(__hpux) && \
     !defined(BSD) && !defined(M_UNIX) && !defined(_AIX)
extern int	getopt _PROTO(( int, char **, char * ));
#endif
extern int	optind;
extern char *	optarg;

/* system specific stuff */
#ifdef ISC
#define fileno(p)	(p)->_file
# ifndef O_NDELAY
#  define O_NDELAY O_NONBLOCK
# endif
#endif

#if defined(_3B1_) || defined(MEIBE)
    typedef ushort uid_t;
    typedef ushort gid_t;
#endif

#if defined(NeXT)
# define NEED_PUTENV
# define NEED_STRDUP

 char * strdup _PROTO(( char *src ));
#endif

/* hardware handshake flags for tio.c/tio.h
 * we have to define them here, because otherwise config.c would break
 */
#define FLOW_NONE	0x00
#define FLOW_HARD	0x01		/* rts/cts */
#define FLOW_XON_IN	0x02		/* incoming data, send xon/xoff */
#define FLOW_XON_OUT	0x04		/* send data, honor xon/xoff */
#define FLOW_SOFT	(FLOW_XON_IN | FLOW_XON_OUT)
#define FLOW_BOTH	(FLOW_HARD | FLOW_SOFT )
#define FLOW_XON_IXANY	0x08		/* set IXANY flag together with IXON */

#endif			/* ___MGETTY_H */
