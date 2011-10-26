/* - Ftp Server
 * Copyright (c) 1985, 1988, 1990, 1992, 1993, 1994, 2002
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if 0
static char sccsid[] = "@(#)ftpd.c	8.5 (Berkeley) 4/28/95";
#endif

/*
 * FTP server.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#if !defined (__GNUC__) && defined (_AIX)
#pragma alloca
#endif
#ifndef alloca /* Make alloca work the best possible way.  */
# ifdef __GNUC__
#  define alloca __builtin_alloca
# else /* not __GNUC__ */
#  if HAVE_ALLOCA_H
#   include <alloca.h>
#  else /* not __GNUC__ or HAVE_ALLOCA_H */
#    ifndef _AIX /* Already did AIX, up at the top.  */
       char *alloca ();
#    endif /* not _AIX */
#  endif /* not HAVE_ALLOCA_H */
# endif /* not __GNUC__ */
#endif /* not alloca */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_WAIT_H
#  include <sys/wait.h>
#endif

#include <netinet/in.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
#  include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IP_H
#  include <netinet/ip.h>
#endif

#define	FTP_NAMES
#include <arpa/ftp.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <setjmp.h>
#include <signal.h>
#include <grp.h>
#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
#  include <stdarg.h>
#else
#  include <varargs.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#ifdef TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  ifdef HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif
#include <unistd.h>
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif
/* Include glob.h last, because it may define "const" which breaks
   system headers on some platforms. */
#include <glob.h>

#include "extern.h"

#ifndef LINE_MAX
# define LINE_MAX 2048
#endif

#ifndef LOG_FTP
# define LOG_FTP LOG_DAEMON	/* Use generic facility.  */
#endif

#ifndef MAP_FAILED
# define MAP_FAILED (void*)-1
#endif

#if !HAVE_DECL_FCLOSE
/* Some systems don't declare fclose in <stdio.h>, so do it ourselves.  */
extern int fclose __P ((FILE *));
#endif

#ifdef HAVE___PROGNAME
extern char *__progname;
#else
char *__progname;
#endif

/* Exported to ftpcmd.h.  */
struct	sockaddr_in data_dest; /* Data port.  */
struct	sockaddr_in his_addr;  /* Peer address.  */
int	logging;               /* Enable log to syslog.  */
int	type = TYPE_A;         /* Default TYPE_A.  */
int	form = FORM_N;                  /* Default FORM_N.  */
int	debug;                 /* Enable debug mode if 1.  */
int	timeout = 900;         /* Timeout after 15 minutes of inactivity.  */
int	maxtimeout = 7200;     /* Don't allow idle time to be set
				  beyond 2 hours.  */
int	pdata = -1;            /* For passive mode.  */
char	*hostname;             /* Who we are.  */
int	usedefault = 1;	       /* For data transfers.  */
char	tmpline[7];            /* Temp buffer use in OOB.  */

jmp_buf  errcatch;

/* Requester credentials.  */
struct credentials cred;

static struct  sockaddr_in ctrl_addr;    /* Control address.  */
static struct  sockaddr_in data_source;  /* Port address.  */
static struct  sockaddr_in pasv_addr;    /* Pasv address.  */

static int      data = -1;       /* Port data connection socket.  */
static jmp_buf  urgcatch;
static int      stru = STRU_F;     /* Avoid C keyword.  */
static int      stru_mode = MODE_S;/* Default STRU mode stru_mode = MODE_S.  */
static int      anon_only;       /* Allow only anonymous login.  */
static int      no_version;      /* Don't print version to client.  */
static int      daemon_mode;     /* Start in daemon mode.  */
static off_t    file_size;
static off_t    byte_count;
static sig_atomic_t transflag;   /* Flag where in a middle of transfer.  */
static const char *pid_file = PATH_FTPDPID;
#if !defined(CMASK) || CMASK == 0
#undef CMASK
#define CMASK 027
#endif
static int  defumask = CMASK;    /* Default umask value.  */
static int login_attempts;       /* Number of failed login attempts.  */
static int askpasswd;		 /* Had user command, ask for passwd.  */
static char curname[10];	 /* Current USER name.  */
static char ttyline[20];         /* Line to log in utmp.  */


#define NUM_SIMUL_OFF_TO_STRS 4

/* Returns a string with the decimal representation of the off_t OFF, taking
   into account that off_t might be longer than a long.  The return value is
   a pointer to a static buffer, but a return value will only be reused every
   NUM_SIMUL_OFF_TO_STRS calls, to allow multiple off_t's to be conveniently
   printed with a single printf statement.  */
static char *
off_to_str (off_t off)
{
  static char bufs[NUM_SIMUL_OFF_TO_STRS][80];
  static char (*next_buf)[80] = bufs;

  if (next_buf > (bufs+NUM_SIMUL_OFF_TO_STRS))
    next_buf = bufs;

  if (sizeof (off) > sizeof (long))
    sprintf (*next_buf, "%qd", off);
  else if (sizeof (off) == sizeof (long))
    sprintf (*next_buf, "%ld", off);
  else
    sprintf (*next_buf, "%d", off);

  return *next_buf++;
}

/*
 * Timeout intervals for retrying connections
 * to hosts that don't accept PORT cmds.  This
 * is a kludge, but given the problems with TCP...
 */
#define	SWAITMAX	90	/* wait at most 90 seconds */
#define	SWAITINT	5	/* interval between retries */

static int swaitmax = SWAITMAX;
static int swaitint = SWAITINT;

#ifdef HAVE_SETPROCTITLE
char	proctitle[LINE_MAX];	/* initial part of title */
#endif /* SETPROCTITLE */

#define LOGCMD(cmd, file) \
	if (logging > 1) \
	    syslog(LOG_INFO,"%s %s%s", cmd, \
		*(file) == '/' ? "" : curdir(), file);
#define LOGCMD2(cmd, file1, file2) \
	 if (logging > 1) \
	    syslog(LOG_INFO,"%s %s%s %s%s", cmd, \
		*(file1) == '/' ? "" : curdir(), file1, \
		*(file2) == '/' ? "" : curdir(), file2);
#define LOGBYTES(cmd, file, cnt) \
	if (logging > 1) { \
		if (cnt == (off_t)-1) \
		    syslog(LOG_INFO,"%s %s%s", cmd, \
			*(file) == '/' ? "" : curdir(), file); \
		else \
		    syslog(LOG_INFO, "%s %s%s = %s bytes", \
			cmd, (*(file) == '/') ? "" : curdir(), file, \
			   off_to_str (cnt)); \
	}

static void ack __P ((const char *));
static void authentication_setup __P ((const char *));
#ifdef HAVE_LIBWRAP
static int  check_host __P ((struct sockaddr *sa));
#endif
static void complete_login __P ((struct credentials *));
static char *curdir __P ((void));
static FILE *dataconn __P ((const char *, off_t, const char *));
static void dolog __P ((struct sockaddr_in *, struct credentials *));
static void end_login __P ((struct credentials *));
static FILE *getdatasock __P ((const char *));
static char *gunique __P ((const char *));
static void lostconn __P ((int));
static void myoob __P ((int));
static int  receive_data __P ((FILE *, FILE *));
static void send_data __P ((FILE *, FILE *, off_t));
static void sigquit __P ((int));
static void usage __P ((int));

static const char *short_options = "Aa:Ddlp:qt:T:u:";
static struct option long_options[] =
{
  { "anonymous-only", no_argument, 0, 'A' },
  { "auth", required_argument, 0, 'a' },
  { "daemon", no_argument, 0, 'D' },
  { "debug", no_argument, 0, 'd' },
  { "help", no_argument, 0, '&' },
  { "logging", no_argument, 0, 'l' },
  { "pidfile", required_argument, 0, 'p' },
  { "no-version", no_argument, 0, 'q' },
  { "timeout", required_argument, 0, 't' },
  { "max-timeout", required_argument, 0, 'T' },
  { "umask", required_argument, 0, 'u' },
  { "version", no_argument, 0, 'V' },
  { 0, 0, 0, 0 }
};

static void
usage (int err)
{
  if (err != 0)
    {
      fprintf (stderr, "Usage: %s [OPTION] ...\n", __progname);
      fprintf (stderr, "Try `%s --help' for more information.\n", __progname);
    }
  else
    {
      fprintf (stdout, "Usage: %s [OPTION] ...\n", __progname);
      puts ("Internet File Transfer Protocol server.\n\n\
  -A, --anonymous-only      Server configure for anonymous service only\n\
  -D, --daemon              Start the ftpd standalone\n\
  -d, --debug               Debug mode\n\
  -l, --logging             Increase verbosity of syslog messages\n\
  -p, --pidfile=[PIDFILE]   Change default location of pidfile\n\
  -q, --no-version          Do not display version in banner\n\
  -t, --timeout=[TIMEOUT]   Set default idle timeout\n\
  -T, --max-timeout         Reset maximum value of timeout allowed\n\
  -u, --umask               Set default umask(base 8)\n\
      --help                Print this message\n\
  -V, --version             Print version\n\
  -a, --auth=[AUTH]         Use AUTH for authentication, it can be:\n\
                               default     passwd authentication.");
#ifdef WITH_PAM
      puts ("\
                               pam         using pam 'ftp' module.");
#endif
#ifdef WITH_KERBEROS
      puts ("\
                               kerberos");
#endif
#ifdef WITH_KERBEROS5
      puts ("\
                               kderberos5");
#endif
#ifdef WITH_OPIE
      puts ("\
                               opie");
#endif

      fprintf (stdout, "\nSubmit bug reports to %s.\n", PACKAGE_BUGREPORT);
    }
  exit (err);
}

int
main(int argc, char *argv[], char **envp)
{
  extern char *localhost __P ((void));
  int option;

#ifndef HAVE___PROGNAME
  __progname = argv[0];
#endif

#ifdef HAVE_TZSET
  tzset(); /* In case no timezone database in ~ftp.  */
#endif

#ifdef HAVE_INITSETPROCTITLE
  /* Save start and extent of argv for setproctitle.  */
  initsetproctitle (argc, argv, envp);
#endif /* HAVE_INITSETPROCTITLE */

  while ((option = getopt_long (argc, argv, short_options,
				long_options, NULL)) != EOF)
    {
      switch (option)
	{
	case 'A': /* Anonymous ftp only.  */
	  anon_only = 1;
	  break;

	case 'a': /* Authentification method.  */
	  if (strcasecmp (optarg, "default") == 0)
	    cred.auth_type = AUTH_TYPE_PASSWD;
#ifdef WITH_PAM
	  else if (strcasecmp (optarg, "pam") == 0)
	    cred.auth_type = AUTH_TYPE_PAM;
#endif
#ifdef WITH_KERBEROS
	  else if (stracasecmp (optarg, "kerberos") == 0)
	    cred.auth_type = AUTH_TYPE_KERBEROS;
#endif
#ifdef WITH_KERBEROS5
	  else if (stracasecmp (optarg, "kerberos5") == 0)
	    cred.auth_type = AUTH_TYPE_KERBEROS5;
#endif
#ifdef WITH_OPIE
	  else if (stracasecmp (optarg, "opie") == 0)
	    cred.auth_type = AUTH_TYPE_OPIE;
#endif
	  break;

	case 'D': /* Run ftpd as daemon.  */
	  daemon_mode = 1;
	  break;

	case 'd': /* Enable debug mode.  */
	  debug = 1;
	  break;

	case 'l': /* Increase logging level.  */
	  logging++;	/* > 1 == Extra logging.  */
	  break;

	case 'p': /* Override pid file */
	  pid_file = optarg;
	  break;

	case 'q': /* Don't include version number in banner.  */
	  no_version = 1;
	  break;

	case 't': /* Set default timeout value.  */
	  timeout = atoi (optarg);
	  if (maxtimeout < timeout)
	    maxtimeout = timeout;
	  break;

	case 'T': /* Maximum timeout allowed.  */
	  maxtimeout = atoi (optarg);
	  if (timeout > maxtimeout)
	    timeout = maxtimeout;
	  break;

	case 'u': /* Set umask.  */
	  {
	    long val = 0;

	    val = strtol (optarg, &optarg, 8);
	    if (*optarg != '\0' || val < 0)
	      fprintf (stderr, "%s: bad value for -u", argv[0]);
	    else
	      defumask = val;
	    break;
	  }

	case '&': /* Usage.  */
	  usage (0);
	  /* Not reached.  */

	case 'V': /* Version.  */
	  printf ("ftpd (%s) %s\n", PACKAGE_NAME, PACKAGE_VERSION);
	  exit (0);

	case '?':
	default:
	  usage (1);
	  /* Not reached.  */
	}
    }

  /* Bail out, wrong usage */
  argc -= optind;
  if (argc != 0)
    usage (1);

  /* LOG_NDELAY sets up the logging connection immediately,
     necessary for anonymous ftp's that chroot and can't do it later.  */
  openlog ("ftpd", LOG_PID | LOG_NDELAY, LOG_FTP);
  (void) freopen (PATH_DEVNULL, "w", stderr);

  /* If not running via inetd, we detach and dup(fd, 0), dup(fd, 1) the
     fd = accept(). tcpd is check if compile with the support  */
  if (daemon_mode)
    {
      if (server_mode (pid_file, &his_addr) < 0)
	exit (1);
    }
  else
    {
      int addrlen = sizeof (his_addr);
      if (getpeername (STDIN_FILENO, (struct sockaddr *)&his_addr,
		       &addrlen) < 0)
	{
	  syslog (LOG_ERR, "getpeername (%s): %m", __progname);
	  exit (1);
	}
    }

  (void) signal (SIGHUP, sigquit);
  (void) signal (SIGINT, sigquit);
  (void) signal (SIGQUIT, sigquit);
  (void) signal (SIGTERM, sigquit);
  (void) signal (SIGPIPE, lostconn);
  (void) signal (SIGCHLD, SIG_IGN);
  if (signal (SIGURG, myoob) == SIG_ERR)
    syslog (LOG_ERR, "signal: %m");

  /* Get info on the ctrl connection.  */
  {
    int addrlen = sizeof (ctrl_addr);
    if (getsockname (STDIN_FILENO, (struct sockaddr *)&ctrl_addr,
		     &addrlen) < 0)
      {
	syslog (LOG_ERR, "getsockname (%s): %m", __progname);
	exit (1);
      }
  }

#if defined (IP_TOS) && defined (IPTOS_LOWDELAY) && defined (IPPROTO_IP)
  /* To  minimize delays for interactive traffic.  */
  {
    int tos = IPTOS_LOWDELAY;
    if (setsockopt (STDIN_FILENO, IPPROTO_IP, IP_TOS,
		    (char *)&tos, sizeof(int)) < 0)
      syslog (LOG_WARNING, "setsockopt (IP_TOS): %m");
  }
#endif

#ifdef SO_OOBINLINE
  /* Try to handle urgent data inline.  */
  {
    int on = 1;
    if (setsockopt (STDIN_FILENO, SOL_SOCKET, SO_OOBINLINE,
		    (char *)&on, sizeof (on)) < 0)
      syslog (LOG_ERR, "setsockopt: %m");
  }
#endif

#ifdef SO_KEEPALIVE
  /* Set keepalives on the socket to detect dropped connections.  */
  {
    int keepalive = 1;
    if (setsockopt (STDIN_FILENO, SOL_SOCKET, SO_KEEPALIVE,
		    (char *)&keepalive, sizeof (keepalive)) < 0)
      syslog (LOG_WARNING, "setsockopt (SO_KEEPALIVE): %m");
  }
#endif

#ifdef	F_SETOWN
  if (fcntl (STDIN_FILENO, F_SETOWN, getpid ()) == -1)
    syslog (LOG_ERR, "fcntl F_SETOWN: %m");
#endif

  dolog (&his_addr, &cred);

  /* Deal with login disable.  */
  if (display_file (PATH_NOLOGIN, 530) == 0)
    {
      reply (530, "System not available.");
      exit (0);
    }

  /* Display a Welcome message if exists,
     N.B. reply(220,) must follow.  */
  (void) display_file (PATH_FTPWELCOME, 220);

  hostname = localhost ();
  if (! hostname)
    perror_reply (550, "Local resource failure: malloc");

  /* Tell them we're ready to roll.  */
  if (!no_version)
    reply (220, "%s FTP server (%s %s) ready.",
	   hostname, PACKAGE_NAME, PACKAGE_VERSION);
  else
    reply (220, "%s FTP server ready.", hostname);

  /* Set the jump, if we have an error parsing,
     come here and start fresh.  */
  (void) setjmp (errcatch);

  /* Roll.  */
  for (;;)
    (void) yyparse ();
  /* NOTREACHED */
}

static char *
curdir (void)
{
  static char *path = 0;
  extern char *xgetcwd __P ((void));
  if (path)
    free (path);
  path = xgetcwd ();
  if (! path)
    return  (char *)"";
  if (path[1] != '\0')	/* special case for root dir. */
    {
      char *tmp = realloc (path, strlen (path) + 2); /* '/' + '\0' */
      if (! tmp)
	{
	  free(path);
	  return (char *)"";
	}
      strcat(tmp, "/");
      path = tmp;
    }
  /* For guest account, skip / since it's chrooted */
  return (cred.guest ? path+1 : path);
}

static void
sigquit (int signo)
{
#ifdef HAVE_STRSIGNAL
  syslog (LOG_ERR, "got signal %s", strsignal (signo));
#else
  syslog (LOG_ERR, "got signal %d", signo);
#endif
  dologout (-1);
}


static void
lostconn (int signo)
{
  (void)signo;
  if (debug)
    syslog (LOG_DEBUG, "lost connection");
  dologout (-1);
}

/* Helper function.  */
char *
sgetsave (const char *s)
{
  char *string;
  size_t len;

  if (s == NULL)
    s = "";

  len = strlen (s) + 1;
  string = malloc (len);
  if (string == NULL)
    {
      perror_reply (421, "Local resource failure: malloc");
      dologout (1);
      /* NOTREACHED */
    }
  /*  (void) strcpy (string, s); */
  memcpy (string, s, len);
  return string;
}

static void
complete_login (struct credentials *pcred)
{
  if (setegid ((gid_t)pcred->gid) < 0)
    {
      reply (550, "Can't set gid.");
      return;
    }

#ifdef HAVE_INITGROUPS
  (void) initgroups (pcred->name, pcred->gid);
#endif

  /* open wtmp before chroot */
  (void)snprintf (ttyline, sizeof (ttyline), "ftp%d", getpid ());
  logwtmp_keep_open (ttyline, pcred->name, pcred->remotehost);

  if (pcred->guest)
    {
      /* We MUST do a chdir () after the chroot. Otherwise
	 the old current directory will be accessible as "."
	 outside the new root!  */
      if (chroot (pcred->rootdir) < 0 || chdir (pcred->homedir) < 0)
	{
	  reply (550, "Can't set guest privileges.");
	  goto bad;
	}
    }
  else if (pcred->dochroot)
    {
      if (chroot (pcred->rootdir) < 0 || chdir(pcred->homedir) < 0)
	{
	  reply (550, "Can't change root.");
	  goto bad;
	}
      setenv ("HOME", pcred->homedir, 1);
    }
  else if (chdir (pcred->rootdir) < 0)
    {
      if (chdir ("/") < 0)
	{
	  reply (530, "User %s: can't change directory to %s.",
		 pcred->name, pcred->homedir);
	  goto bad;
	}
      else
	lreply (230, "No directory! Logging in with home=/");
    }

  if (seteuid ((uid_t)pcred->uid) < 0)
    {
      reply (550, "Can't set uid.");
      goto bad;
    }

  /* Display a login message, if it exists.
    N.B. reply(230,) must follow the message.  */
  (void) display_file (PATH_FTPLOGINMESG, 230);

  if (pcred->guest)
    {
      reply (230, "Guest login ok, access restrictions apply.");
#ifdef HAVE_SETPROCTITLE
      snprintf (proctitle, sizeof (proctitle), "%s: anonymous",
		pcred->remotehost);
      setproctitle ("%s",proctitle);
#endif /* HAVE_SETPROCTITLE */
      if (logging)
	syslog (LOG_INFO, "ANONYMOUS FTP LOGIN FROM %s",
		pcred->remotehost);
    }
  else
    {
      reply (230, "User %s logged in.", pcred->name);
#ifdef HAVE_SETPROCTITLE
      snprintf (proctitle, sizeof (proctitle),
		"%s: %s", pcred->remotehost, pcred->name);
      setproctitle ("%s",proctitle);
#endif /* HAVE_SETPROCTITLE */
      if (logging)
	syslog (LOG_INFO, "FTP LOGIN FROM %s as %s",
		pcred->remotehost, pcred->name);
    }
  (void) umask(defumask);
  return;
bad:
  /* Forget all about it... */
  end_login (pcred);
}

/* USER command.
   Sets global passwd pointer pw if named account exists and is acceptable;
   sets askpasswd if a PASS command is expected.  If logged in previously,
   need to reset state.  */
void
user (const char *name)
{
  if (cred.logged_in)
    {
      if (cred.guest || cred.dochroot)
	{
	  reply (530, "Can't change user from guest login.");
	  return;
	}
      end_login (&cred);
    }

  /* Non zero means failed.  */
  if (auth_user (name, &cred) != 0)
    {
      /* If they gave us a reason.  */
      if (cred.message)
	{
	  reply (530, "%s", cred.message);
	  free (cred.message);
	  cred.message = NULL;
	}
      else
	reply (530, "User %s access denied.", name);
      if (logging)
	syslog(LOG_NOTICE, "FTP LOGIN REFUSED FROM %s, %s",
	       cred.remotehost, name);
      return;
    }

  /* If the server is set to serve anonymous service only
     the request have to come from a guest or a chrooted.  */
  if (anon_only && !cred.guest && !cred.dochroot)
    {
      reply (530, "Sorry, only anonymous ftp allowed");
      return;
    }

  if (logging)
    {
      strncpy (curname, name, sizeof (curname) - 1);
      curname [sizeof (curname) - 1] = '\0'; /* Make sure null terminated.  */
    }

  if (cred.message)
    {
      reply (331, "%s", cred.message);
      free (cred.message);
      cred.message = NULL;
    }
  else
    reply (331, "Password required for %s.", name);

  askpasswd = 1;

  /* Delay before reading passwd after first failed
     attempt to slow down passwd-guessing programs.  */
  if (login_attempts)
    sleep ((unsigned) login_attempts);
}

/* Terminate login as previous user, if any, resetting state;
   used when USER command is given or login fails.  */
static void
end_login (struct credentials *pcred)
{
  char *remotehost = pcred->remotehost;
  int atype = pcred->auth_type;
  (void) seteuid ((uid_t)0);
  if (pcred->logged_in)
    logwtmp_keep_open (ttyline, "", "");

  if (pcred->name)
    free (pcred->name);
  if (pcred->passwd)
    {
      memset (pcred->passwd, 0, strlen (pcred->passwd));
      free (pcred->passwd);
    }
  if (pcred->homedir)
    free (pcred->homedir);
  if (pcred->rootdir)
    free (pcred->rootdir);
  if (pcred->shell)
    free (pcred->shell);
  if (pcred->pass) /* ??? */
    {
      memset (pcred->pass, 0, strlen (pcred->pass));
      free (pcred->pass);
    }
  if (pcred->message)
    free (pcred->message);
  memset (pcred, 0, sizeof (*pcred));
  pcred->remotehost = remotehost;
  pcred->auth_type = atype;
}

void
pass (const char *passwd)
{
  if (cred.logged_in || askpasswd == 0)
    {
      reply(503, "Login with USER first.");
      return;
    }
  askpasswd = 0;

  if (!cred.guest) /* "ftp" is the only account allowed no password.  */
    {
      /* Try to authenticate the user.  Failed if != 0.  */
      if (auth_pass (passwd, &cred) != 0)
	{
	  /* Any particular reasons.  */
	  if (cred.message)
	    {
	      reply (530, "%s", cred.message);
	      free (cred.message);
	      cred.message = NULL;
	    }
	  else
	    reply (530, "Login incorrect.");
	  if (logging)
	    syslog (LOG_NOTICE, "FTP LOGIN FAILED FROM %s, %s",
		    cred.remotehost, curname);
	  if (login_attempts++ >= 5)
	    {
	      syslog(LOG_NOTICE, "repeated login failures from %s",
		     cred.remotehost);
	      exit(0);
	    }
	  return;
	}
    }
  cred.logged_in = 1; /* Everything seems to be allright.  */
  complete_login (&cred);
  login_attempts = 0; /* This time successful.  */
}

void
retrieve (const char *cmd, const char *name)
{
  FILE *fin, *dout;
  struct stat st;
  int (*closefunc) __P ((FILE *));
  size_t buffer_size = 0;

  if (cmd == 0)
    {
      fin = fopen (name, "r"), closefunc = fclose;
      st.st_size = 0;
    }
  else
    {
      char line[BUFSIZ];

      snprintf (line, sizeof line, cmd, name);
      name = line;
      fin = ftpd_popen (line, "r"), closefunc = ftpd_pclose;
      st.st_size = -1;
      buffer_size = BUFSIZ;
    }

  if (fin == NULL)
    {
      if (errno != 0)
	{
	  perror_reply (550, name);
	  if (cmd == 0)
	    {
	      LOGCMD("get", name);
	    }
	}
      return;
    }
  byte_count = -1;
  if (cmd == 0 && (fstat (fileno (fin), &st) < 0 || !S_ISREG (st.st_mode)
		   || !(buffer_size = ST_BLKSIZE (st))))
    {
      reply(550, "%s: not a plain file.", name);
      goto done;
    }
  if (restart_point)
    {
      if (type == TYPE_A)
	{
	  off_t i, n;
	  int c;

	  n = restart_point;
	  i = 0;
	  while (i++ < n)
	    {
	      c = getc (fin);
	      if (c == EOF)
		{
		  perror_reply (550, name);
		  goto done;
		}
	      if (c == '\n')
		i++;
	    }
	}
      else if (lseek (fileno (fin), restart_point, SEEK_SET) < 0)
	{
	  perror_reply (550, name);
	  goto done;
	}
    }
  dout = dataconn (name, st.st_size, "w");
  if (dout == NULL)
    goto done;
  send_data (fin, dout, buffer_size);
  (void) fclose (dout);
  data = -1;
  pdata = -1;
done:
  if (cmd == 0)
    LOGBYTES ("get", name, byte_count);
  (*closefunc) (fin);
}

void
store (const char *name, const char *mode, int unique)
{
  FILE *fout, *din;
  struct stat st;
  int (*closefunc) __P ((FILE *));

  if (unique && stat (name, &st) == 0
      && (name = gunique (name)) == NULL)
    {
      LOGCMD (*mode == 'w' ? "put" : "append", name);
      return;
    }

  if (restart_point)
    mode = "r+";
  fout = fopen (name, mode);
  closefunc = fclose;
  if (fout == NULL)
    {
      perror_reply (553, name);
      LOGCMD (*mode == 'w' ? "put" : "append", name);
      return;
    }
  byte_count = -1;
  if (restart_point)
    {
      if (type == TYPE_A)
	{
	  off_t i, n;
	  int c;

	  n = restart_point;
	  i = 0;
	  while (i++ < n)
	    {
	      c = getc (fout);
	      if (c == EOF)
		{
		  perror_reply (550, name);
		  goto done;
		}
	      if (c == '\n')
		i++;
	    }
	  /* We must do this seek to "current" position
	     because we are changing from reading to
	     writing.  */
	  if (fseek (fout, 0L, SEEK_CUR) < 0)
	    {
	      perror_reply (550, name);
	      goto done;
	    }
	}
      else if (lseek (fileno(fout), restart_point, SEEK_SET) < 0)
	{
	  perror_reply (550, name);
	  goto done;
	}
    }
  din = dataconn (name, (off_t)-1, "r");
  if (din == NULL)
    goto done;
  if (receive_data (din, fout) == 0)
    {
      if (unique)
	reply (226, "Transfer complete (unique file name:%s).", name);
      else
	reply (226, "Transfer complete.");
    }
  (void) fclose (din);
  data = -1;
  pdata = -1;
 done:
  LOGBYTES (*mode == 'w' ? "put" : "append", name, byte_count);
  (*closefunc) (fout);
}

static FILE *
getdatasock (const char *mode)
{
  int s, t, tries;

  if (data >= 0)
    return fdopen (data, mode);
  (void) seteuid ((uid_t)0);
  s = socket (AF_INET, SOCK_STREAM, 0);
  if (s < 0)
    goto bad;

  /* Enables local reuse address.  */
  {
    int on = 1;
    if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR,
		    (char *) &on, sizeof(on)) < 0)
      goto bad;
  }

  /* anchor socket to avoid multi-homing problems */
  data_source.sin_family = AF_INET;
  data_source.sin_addr = ctrl_addr.sin_addr;
  for (tries = 1; ; tries++)
    {
      if (bind (s, (struct sockaddr *)&data_source,
		sizeof(data_source)) >= 0)
	break;
      if (errno != EADDRINUSE || tries > 10)
	goto bad;
      sleep (tries);
    }
  (void) seteuid ((uid_t)cred.uid);

#if defined (IP_TOS) && defined (IPTOS_THROUGHPUT) && defined (IPPROTO_IP)
  {
    int on = IPTOS_THROUGHPUT;
    if (setsockopt(s, IPPROTO_IP, IP_TOS, (char *)&on, sizeof(int)) < 0)
      syslog(LOG_WARNING, "setsockopt (IP_TOS): %m");
  }
#endif

  return (fdopen(s, mode));
 bad:
  /* Return the real value of errno (close may change it) */
  t = errno;
  (void) seteuid ((uid_t)cred.uid);
  (void) close(s);
  errno = t;
  return NULL;
}

static FILE *
dataconn (const char *name, off_t size, const char *mode)
{
  char sizebuf[32];
  FILE *file;
  int retry = 0;

  file_size = size;
  byte_count = 0;
  if (size != (off_t) -1)
    (void) snprintf(sizebuf, sizeof(sizebuf), " (%s bytes)",
		    off_to_str (size));
  else
    *sizebuf = '\0';
  if (pdata >= 0)
    {
      struct sockaddr_in from;
      int s, fromlen = sizeof (from);

      (void) signal (SIGALRM, toolong);
      (void) alarm ((unsigned) timeout);
      s = accept (pdata, (struct sockaddr *)&from, &fromlen);
      (void) alarm (0);
      if (s < 0)
	{
	  reply(425, "Can't open data connection.");
	  (void) close (pdata);
	  pdata = -1;
	  return NULL;
	}
      (void) close (pdata);
      pdata = s;
#if defined (IP_TOS) && defined (IPTOS_THROUGHPUT) && defined (IPPROTO_IP)
      /* Optimize throughput.  */
      {
	int tos = IPTOS_THROUGHPUT;
	(void) setsockopt (s, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof (int));
      }
#endif
#ifdef SO_KEEPALIVE
      /* Set keepalives on the socket to detect dropped conns.  */
      {
	int keepalive = 1;
	(void) setsockopt (s, SOL_SOCKET, SO_KEEPALIVE,
			   (char *)&keepalive, sizeof (int));
      }
#endif
      reply (150, "Opening %s mode data connection for '%s'%s.",
	     type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
      return fdopen (pdata, mode);
    }
  if (data >= 0)
    {
      reply (125, "Using existing data connection for '%s'%s.",
	     name, sizebuf);
      usedefault = 1;
      return fdopen (data, mode);
    }
  if (usedefault)
    data_dest = his_addr;
  usedefault = 1;
  file = getdatasock (mode);
  if (file == NULL)
    {
      reply (425, "Can't create data socket (%s,%d): %s.",
	     inet_ntoa (data_source.sin_addr),
	     ntohs (data_source.sin_port), strerror(errno));
      return NULL;
    }
  data = fileno (file);
  while (connect (data, (struct sockaddr *)&data_dest,
		  sizeof (data_dest)) < 0)
    {
      if (errno == EADDRINUSE && retry < swaitmax)
	{
	  sleep ((unsigned) swaitint);
	  retry += swaitint;
	  continue;
	}
      perror_reply (425, "Can't build data connection");
      (void) fclose (file);
      data = -1;
      return NULL;
    }
  reply (150, "Opening %s mode data connection for '%s'%s.",
	 type == TYPE_A ? "ASCII" : "BINARY", name, sizebuf);
  return file;
}

/* Tranfer the contents of "instr" to "outstr" peer using the appropriate
   encapsulation of the data subject * to Mode, Structure, and Type.

   NB: Form isn't handled.  */
static void
send_data (FILE *instr, FILE *outstr, off_t blksize)
{
  int c, cnt, filefd, netfd;
  char *buf, *bp;
  off_t curpos;
  size_t len, filesize;

  transflag++;
  if (setjmp (urgcatch))
    {
      transflag = 0;
      return;
    }

  netfd = fileno (outstr);
  filefd = fileno (instr);
#ifdef HAVE_MMAP
  if (file_size > 0)
    {
      curpos = lseek (filefd, 0, SEEK_CUR);
      if (curpos >= 0)
	{
	  filesize = file_size - curpos;
	  buf = mmap (0, filesize, PROT_READ, MAP_SHARED, filefd, curpos);
	}
    }
#endif

  switch (type)
    {

    case TYPE_A:
#ifdef HAVE_MMAP
      if (file_size > 0 && curpos >= 0 && buf != MAP_FAILED)
	{
	  len = 0;
	  while (len < filesize)
	    {
	      byte_count++;
	      if (buf[len] == '\n')
		{
		  if (ferror (outstr))
		    break;
		  (void) putc ('\r', outstr);
		}
	      (void) putc (buf[len], outstr);
	      len++;
	    }
	  fflush (outstr);
	  transflag = 0;
	  munmap (buf, filesize);
	  if (ferror (outstr))
	    goto data_err;
	  reply (226, "Transfer complete.");
	  return;
	}
#endif
      while ((c = getc (instr)) != EOF)
	{
	  byte_count++;
	  if (c == '\n')
	    {
	      if (ferror (outstr))
		goto data_err;
	      (void) putc ('\r', outstr);
	    }
	  (void) putc (c, outstr);
	}
      fflush (outstr);
      transflag = 0;
      if (ferror (instr))
	goto file_err;
      if (ferror (outstr))
	goto data_err;
      reply (226, "Transfer complete.");
      return;

    case TYPE_I:
    case TYPE_L:
#ifdef HAVE_MMAP
      if (file_size > 0 && curpos >= 0 && buf != MAP_FAILED)
	{
	  bp = buf;
	  len = filesize;
	  do
	    {
	      cnt = write (netfd, bp, len);
	      len -= cnt;
	      bp += cnt;
	      if (cnt > 0) byte_count += cnt;
	    } while (cnt > 0 && len > 0);
	  transflag = 0;
	  munmap (buf, (size_t)filesize);
	  if (cnt < 0)
	    goto data_err;
	  reply (226, "Transfer complete.");
	  return;
	}
#endif
      buf = malloc ((u_int)blksize);
      if (buf == NULL)
	{
	  transflag = 0;
	  perror_reply (451, "Local resource failure: malloc");
	  return;
	}
      while ((cnt = read (filefd, buf, (u_int)blksize)) > 0 &&
	     write(netfd, buf, cnt) == cnt)
	byte_count += cnt;
      transflag = 0;
      (void)free (buf);
      if (cnt != 0)
	{
	  if (cnt < 0)
	    goto file_err;
	  goto data_err;
	}
      reply (226, "Transfer complete.");
      return;
    default:
      transflag = 0;
      reply (550, "Unimplemented TYPE %d in send_data", type);
      return;
    }

 data_err:
  transflag = 0;
  perror_reply (426, "Data connection");
  return;

 file_err:
  transflag = 0;
  perror_reply (551, "Error on input file");
}

/* Transfer data from peer to "outstr" using the appropriate encapulation of
   the data subject to Mode, Structure, and Type.

   N.B.: Form isn't handled.  */
static int
receive_data (FILE *instr, FILE *outstr)
{
  int c;
  int cnt, bare_lfs = 0;
  char buf[BUFSIZ];

  transflag++;
  if (setjmp (urgcatch))
    {
      transflag = 0;
      return -1;
    }
  switch (type)
    {
    case TYPE_I:
    case TYPE_L:
      while ((cnt = read (fileno(instr), buf, sizeof(buf))) > 0)
	{
	  if (write (fileno (outstr), buf, cnt) != cnt)
	    goto file_err;
	  byte_count += cnt;
	}
      if (cnt < 0)
	goto data_err;
      transflag = 0;
      return 0;

    case TYPE_E:
      reply (553, "TYPE E not implemented.");
      transflag = 0;
      return -1;

    case TYPE_A:
      while ((c = getc (instr)) != EOF)
	{
	  byte_count++;
	  if (c == '\n')
	    bare_lfs++;
	  while (c == '\r')
	    {
	      if (ferror (outstr))
		goto data_err;
	      c = getc (instr);
	      if (c != '\n')
		{
		  (void) putc ('\r', outstr);
		  if (c == '\0' || c == EOF)
		    goto contin2;
		}
	    }
	  (void) putc (c, outstr);
	contin2:	;
	}
      fflush(outstr);
      if (ferror (instr))
	goto data_err;
      if (ferror (outstr))
	goto file_err;
      transflag = 0;
      if (bare_lfs)
	{
	  lreply (226, "WARNING! %d bare linefeeds received in ASCII mode",
		  bare_lfs);
	  (void)printf ("   File may not have transferred correctly.\r\n");
	}
      return (0);
    default:
      reply (550, "Unimplemented TYPE %d in receive_data", type);
      transflag = 0;
      return -1;
    }

 data_err:
  transflag = 0;
  perror_reply (426, "Data Connection");
  return -1;

 file_err:
  transflag = 0;
  perror_reply (452, "Error writing file");
  return -1;
}

void
statfilecmd (const char *filename)
{
  FILE *fin;
  int c;
  char line[LINE_MAX];

  (void)snprintf (line, sizeof(line), "/bin/ls -lgA %s", filename);
  fin = ftpd_popen (line, "r");
  lreply (211, "status of %s:", filename);
  while ((c = getc (fin)) != EOF)
    {
      if (c == '\n')
	{
	  if (ferror (stdout))
	    {
	      perror_reply (421, "control connection");
	      (void) ftpd_pclose (fin);
	      dologout (1);
				/* NOTREACHED */
	    }
	  if (ferror (fin))
	    {
	      perror_reply (551, filename);
	      (void) ftpd_pclose (fin);
	      return;
	    }
	  (void) putc ('\r', stdout);
	}
      (void) putc (c, stdout);
    }
  (void) ftpd_pclose (fin);
  reply (211, "End of Status");
}

void
statcmd (void)
{
  struct sockaddr_in *sin;
  u_char *a, *p;

  lreply (211, "%s FTP server status:", hostname);
  if (!no_version)
    printf ("     ftpd (%s) %s\r\n",
	    PACKAGE_NAME, PACKAGE_VERSION);
  printf ("     Connected to %s", cred.remotehost);
  if (!isdigit (cred.remotehost[0]))
    printf (" (%s)", inet_ntoa (his_addr.sin_addr));
  printf ("\r\n");
  if (cred.logged_in)
    {
      if (cred.guest)
	printf ("     Logged in anonymously\r\n");
      else
	printf ("     Logged in as %s\r\n", cred.name);
    }
  else if (askpasswd)
    printf ("     Waiting for password\r\n");
  else
    printf ("     Waiting for user name\r\n");
  printf ("     TYPE: %s", typenames[type]);
  if (type == TYPE_A || type == TYPE_E)
    printf (", FORM: %s", formnames[form]);
  if (type == TYPE_L)
#ifdef CHAR_BIT
    printf (" %d", CHAR_BIT);
#else
#if NBBY == 8
  printf (" %d", NBBY);
#else
  printf (" %d", bytesize);	/* need definition! */
#endif
#endif
  printf ("; STRUcture: %s; transfer MODE: %s\r\n",
	  strunames[stru], modenames[stru_mode]);
  if (data != -1)
    printf ("     Data connection open\r\n");
  else if (pdata != -1)
    {
      printf ("     in Passive mode");
      sin = &pasv_addr;
      goto printaddr;
    }
  else if (usedefault == 0)
    {
      printf ("     PORT");
      sin = &data_dest;
    printaddr:
      a = (u_char *) &sin->sin_addr;
      p = (u_char *) &sin->sin_port;
#define UC(b) (((int) b) & 0xff)
      printf (" (%d,%d,%d,%d,%d,%d)\r\n", UC(a[0]),
	      UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
#undef UC
    }
  else
    printf ("     No data connection\r\n");
  reply (211, "End of status");
}

void
fatal (const char *s)
{
  reply (451, "Error in server: %s\n", s);
  reply (221, "Closing connection due to server error.");
  dologout (0);
  /* NOTREACHED */
}

void
reply (int n, const char *fmt, ...)
{
  va_list ap;
#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
  va_start (ap, fmt);
#else
  va_start (ap);
#endif
  (void)printf ("%d ", n);
  (void)vprintf (fmt, ap);
  (void)printf ("\r\n");
  (void)fflush (stdout);
  if (debug)
    {
      syslog (LOG_DEBUG, "<--- %d ", n);
#ifdef HAVE_VSYSLOG
      vsyslog (LOG_DEBUG, fmt, ap);
#endif
    }
}

void
lreply (int n, const char *fmt, ...)
{
  va_list ap;
#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
  va_start (ap, fmt);
#else
  va_start (ap);
#endif
  (void)printf ("%d- ", n);
  (void)vprintf (fmt, ap);
  (void)printf ("\r\n");
  (void)fflush (stdout);
  if (debug)
    {
      syslog (LOG_DEBUG, "<--- %d- ", n);
#ifdef HAVE_VSYSLOG
      vsyslog (LOG_DEBUG, fmt, ap);
#endif
    }
}

static void
ack (const char *s)
{
  reply (250, "%s command successful.", s);
}

void
nack (const char *s)
{
  reply (502, "%s command not implemented.", s);
}

void
delete (const char *name)
{
  struct stat st;

  LOGCMD ("delete", name);
  if (stat (name, &st) < 0)
    {
      perror_reply (550, name);
      return;
    }
  if (S_ISDIR (st.st_mode))
    {
      if (rmdir (name) < 0)
	{
	  perror_reply (550, name);
	  return;
	}
      goto done;
    }
  if (unlink (name) < 0)
    {
      perror_reply (550, name);
      return;
    }
 done:
  ack ("DELE");
}

void
cwd (const char *path)
{
  if (chdir (path) < 0)
    perror_reply (550, path);
  else
    ack ("CWD");
}

void
makedir (const char *name)
{
  extern char *xgetcwd __P ((void));

  LOGCMD ("mkdir", name);
  if (mkdir (name, 0777) < 0)
    perror_reply (550, name);
  else if (name[0] == '/')
    reply (257, "\"%s\" new directory created.");
  else
    {
      /* We have to figure out what our current directory is so that we can
	 give an absolute name in the reply.  */
      char *current = xgetcwd ();
      if (current)
	{
	  if (current[1] == '\0')
	    current[0] = '\0';
	  reply (257, "\"%s/%s\" new directory created.", current, name);
	  free (current);
	}
      else
	reply (257, "(unknown absolute name) new directory created.");
    }
}

void
removedir (const char *name)
{
  LOGCMD ("rmdir", name);
  if (rmdir (name) < 0)
    perror_reply (550, name);
  else
    ack("RMD");
}

void
pwd (void)
{
  extern char *xgetcwd __P ((void));
  char *path = xgetcwd ();
  if (path)
    {
      reply (257, "\"%s\" is current directory.", path);
      free (path);
    }
  else
    reply (550, "%s.", strerror (errno));
}

char *
renamefrom (const char *name)
{
  struct stat st;

  if (stat (name, &st) < 0)
    {
      perror_reply (550, name);
      return ((char *)0);
    }
  reply (350, "File exists, ready for destination name");
  return (char *)(name);
}

void
renamecmd (const char *from, const char *to)
{
  LOGCMD2 ("rename", from, to);
  if (rename (from, to) < 0)
    perror_reply (550, "rename");
  else
    ack ("RNTO");
}

static void
dolog (struct sockaddr_in *sin, struct credentials *pcred)
{
  const char *name;
  struct hostent *hp = gethostbyaddr ((char *)&sin->sin_addr,
				      sizeof (struct in_addr), AF_INET);

  if (hp)
    name = hp->h_name;
  else
    name = inet_ntoa (sin->sin_addr);

  if (pcred->remotehost)
    free (pcred->remotehost);
  pcred->remotehost = sgetsave (name);

#ifdef HAVE_SETPROCTITLE
  snprintf (proctitle, sizeof (proctitle), "%s: connected", pcred->remotehost);
  setproctitle ("%s",proctitle);
#endif /* HAVE_SETPROCTITLE */

  if (logging)
    syslog (LOG_INFO, "connection from %s", pcred->remotehost);
}

/*  Record logout in wtmp file
    and exit with supplied status.  */
void
dologout (int status)
{
  /* Racing condition with SIGURG: If SIGURG is receive
     here, it will jump back has root in the main loop
     David Greenman:dg@root.com.  */
  transflag = 0;

  if (cred.logged_in)
    {
      (void) seteuid ((uid_t)0);
      logwtmp_keep_open (ttyline, "", "");
    }
  /* beware of flushing buffers after a SIGPIPE */
  _exit (status);
}

static void
myoob (int signo)
{
  char *cp;

  (void)signo;
  /* only process if transfer occurring */
  if (!transflag)
    return;
  cp = tmpline;
  if (telnet_fgets (cp, 7, stdin) == NULL)
    {
      reply (221, "You could at least say goodbye.");
      dologout (0);
    }
  upper (cp);
  if (strcmp (cp, "ABOR\r\n") == 0)
    {
      tmpline[0] = '\0';
      reply (426, "Transfer aborted. Data connection closed.");
      reply (226, "Abort successful");
      longjmp (urgcatch, 1);
    }
  if (strcmp (cp, "STAT\r\n") == 0)
    {
      if (file_size != (off_t) -1)
	reply (213, "Status: %s of %s bytes transferred",
	       off_to_str (byte_count), off_to_str (file_size));
      else
	reply (213, "Status: %s bytes transferred",
	       off_to_str (byte_count));
    }
}

/* Note: a response of 425 is not mentioned as a possible response to
   the PASV command in RFC959. However, it has been blessed as
   a legitimate response by Jon Postel in a telephone conversation
   with Rick Adams on 25 Jan 89.  */
void
passive (void)
{
  int len;
  char *p, *a;

  pdata = socket (AF_INET, SOCK_STREAM, 0);
  if (pdata < 0)
    {
      perror_reply (425, "Can't open passive connection");
      return;
    }
  pasv_addr = ctrl_addr;
  pasv_addr.sin_port = 0;
  (void) seteuid ((uid_t)0);
  if (bind (pdata, (struct sockaddr *)&pasv_addr, sizeof (pasv_addr)) < 0)
    {
      (void) seteuid ((uid_t)cred.uid);
      goto pasv_error;
    }
  (void) seteuid ((uid_t)cred.uid);
  len = sizeof(pasv_addr);
  if (getsockname (pdata, (struct sockaddr *) &pasv_addr, &len) < 0)
    goto pasv_error;
  if (listen (pdata, 1) < 0)
    goto pasv_error;
  a = (char *) &pasv_addr.sin_addr;
  p = (char *) &pasv_addr.sin_port;

#define UC(b) (((int) b) & 0xff)

  reply (227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)", UC(a[0]),
	 UC(a[1]), UC(a[2]), UC(a[3]), UC(p[0]), UC(p[1]));
  return;

 pasv_error:
  (void) close (pdata);
  pdata = -1;
  perror_reply (425, "Can't open passive connection");
  return;
}

/* Generate unique name for file with basename "local".
   The file named "local" is already known to exist.
   Generates failure reply on error.  */
static char *
gunique (const char *local)
{
  static char *string = 0;
  struct stat st;
  int count;
  char *cp;

  cp = strrchr (local, '/');
  if (cp)
    *cp = '\0';
  if (stat(cp ? local : ".", &st) < 0)
    {
      perror_reply (553, cp ? local : ".");
      return ((char *) 0);
    }
  if (cp)
    *cp = '/';

  if (string)
    free (string);

  string = malloc (strlen (local) + 5); /* '.' + DIG + DIG + '\0' */
  if (string)
    {
      strcpy (string, local);
      cp = string + strlen (string);
      *cp++ = '.';
      for (count = 1; count < 100; count++)
	{
	  (void)sprintf (cp, "%d", count);
	  if (stat (string, &st) < 0)
	    return string;
	}
    }

  reply (452, "Unique file name cannot be created.");
  return NULL;
}

/*
 * Format and send reply containing system error number.
 */
void
perror_reply (int code, const char *string)
{
  reply (code, "%s: %s.", string, strerror (errno));
}

static char *onefile[] = {
	"",
	0
};

void
send_file_list (const char *whichf)
{
  struct stat st;
  DIR *dirp = NULL;
  struct dirent *dir;
  FILE *dout = NULL;
  char **dirlist, *dirname;
  int simple = 0;
  int freeglob = 0;
  glob_t gl;
  char *p = NULL;

  if (strpbrk(whichf, "~{[*?") != NULL)
    {
      int flags = GLOB_NOCHECK;

#ifdef GLOB_BRACE
      flags |= GLOB_BRACE;
#endif
#ifdef GLOB_QUOTE
      flags |= GLOB_QUOTE;
#endif
#ifdef GLOB_TILDE
      flags |= GLOB_TILDE;
#endif

      memset (&gl, 0, sizeof (gl));
      freeglob = 1;
      if (glob (whichf, flags, 0, &gl))
	{
	  reply (550, "not found");
	  goto out;
	}
      else if (gl.gl_pathc == 0)
	{
	  errno = ENOENT;
	  perror_reply (550, whichf);
	  goto out;
	}
      dirlist = gl.gl_pathv;
    }
  else
    {
      p = strdup (whichf);
      onefile[0] = p;
      dirlist = onefile;
      simple = 1;
    }

  if (setjmp (urgcatch))
    {
      transflag = 0;
      goto out;
    }
  while ((dirname = *dirlist++))
    {
      if (stat (dirname, &st) < 0)
	{
	  /* If user typed "ls -l", etc, and the client
	     used NLST, do what the user meant.  */
	  if (dirname[0] == '-' && *dirlist == NULL
	      && transflag == 0)
	    {
	      retrieve ("/bin/ls %s", dirname);
	      goto out;
	    }
	  perror_reply (550, whichf);
	  if (dout != NULL)
	    {
	      (void) fclose (dout);
	      transflag = 0;
	      data = -1;
	      pdata = -1;
	    }
	  goto out;
	}

      if (S_ISREG(st.st_mode))
	{
	  if (dout == NULL)
	    {
	      dout = dataconn ("file list", (off_t)-1, "w");
	      if (dout == NULL)
		goto out;
	      transflag++;
	    }
	  fprintf (dout, "%s%s\n", dirname,
		   type == TYPE_A ? "\r" : "");
	  byte_count += strlen (dirname) + 1;
	  continue;
	}
      else if (!S_ISDIR (st.st_mode))
	continue;

      dirp = opendir (dirname);
      if (dirp == NULL)
	continue;

      while ((dir = readdir (dirp)) != NULL)
	{
	  char *nbuf;

	  if (dir->d_name[0] == '.' && dir->d_name[1] == '\0')
	    continue;
	  if (dir->d_name[0] == '.' && dir->d_name[1] == '.' &&
	      dir->d_name[2] == '\0')
	    continue;

	  nbuf = (char *) alloca (strlen (dirname) + 1 +
				  strlen (dir->d_name) + 1);
	  sprintf (nbuf, "%s/%s", dirname, dir->d_name);

	  /* We have to do a stat to insure it's
	     not a directory or special file.  */
	  if (simple || (stat (nbuf, &st) == 0
			 && S_ISREG(st.st_mode)))
	    {
	      if (dout == NULL)
		{
		  dout = dataconn ("file list", (off_t)-1, "w");
		  if (dout == NULL)
		    goto out;
		  transflag++;
		}
	      if (nbuf[0] == '.' && nbuf[1] == '/')
		fprintf (dout, "%s%s\n", &nbuf[2], type == TYPE_A ? "\r" : "");
	      else
		fprintf (dout, "%s%s\n", nbuf, type == TYPE_A ? "\r" : "");
	      byte_count += strlen (nbuf) + 1;
	    }
	}
      (void) closedir (dirp);
    }

  if (dout == NULL)
    reply (550, "No files found.");
  else if (ferror (dout) != 0)
    perror_reply (550, "Data connection");
  else
    reply (226, "Transfer complete.");

  transflag = 0;
  if (dout != NULL)
    (void) fclose (dout);
  data = -1;
  pdata = -1;
 out:
  if (p)
    free (p);
  if (freeglob)
    {
      freeglob = 0;
      globfree (&gl);
    }
}

