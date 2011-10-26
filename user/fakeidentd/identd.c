#if 0 /* -*-  mode: c; c-file-style: "gnu"; tab-width: 8; -*-

#	This program is easy to compile. For example the following ways:
#		$ sh identd.c
#		$ sh identd.c -g -DDEBUG
#		$ sh identd.c -s -DXXXMULTI
#		$ CC=cc sh identd.c
#		$ CC=egcs sh identd.c -s -fomit-frame-pointer

NAME=`basename $0 .c`
[ x`uname` = xSunOS ] && L="-lsocket -lnsl" || L=
[ x$1 = x ] && set -- -s -O2
CMDLINE="${CC:-gcc} -Wall $@ -o $NAME $NAME.c $L"
echo $CMDLINE; exec $CMDLINE; exit -1

# */
#endif
/*
 * $Id: identd.c,v 2.0 2003/05/05 15:21:01 too Exp $
 *
 * Author: Tomi Ollila <too@iki.fi>
 *
 * Created: Sat Nov 25 15:34:07 EET 1995 too
 * Last modified: Sun May 04 23:36:16 EEST 2003 too
 *
 * This program is standalone 'fake' ident daemon. This program does
 * not fork() but is configured to handle up to 20 concurrent connections.
 * Since one connection should not last long, if all 20 connections are
 * in use, the next connection will close the oldest connection data
 * has been read. This way this program is not very vulnerable to so
 * called `denial of service' attack, thus making this ideal "identd"
 * to be used in a firewall.
 *
 * Program takes one (or many) arguments, which if exist, determines the
 * `user' name(s) that is returned for successful ident query.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * HISTORY
 * $Log: identd.c,v $
 * Revision 2.0  2003/05/05 15:21:01  too
 * 	Major update. Removed fdprintf(); replaced with use of
 * 	writev() and newly added outputstrings().
 * 	Removed many now obsolete defines and converted one to
 * 	constant character string.
 * 	Added one assert() (and left room for more). Did some
 * 	relativily small other adjustments.
 *
 * Revision 1.7  2002/09/29 07:50:20  too
 *   No longer chops up to IDSTR_MAX chars, but uses "%.*s" to limit length;
 *	now works also when XXXMULTI defined.
 *   Back-hacked self-compilable trick, with more tricks to avoid compiler
 *	warnings.
 *   Removed own define of FD_SETSIZE altogether;
 *	systems has it small to begin with.
 *   Line '415' (or whatever that is now) fixed. () -> (void) in func def.
 *   Some fine-tuning.
 *   Thanks to Cristian for his patches.
 *
 * Revision 1.6.1  2002-09-28 12:30:29 +0200  cii
 *   + added defines for IDSTR_MAX, IDENT_SUBSTR, IDSTR_BUFLEN and IDSTR_MAX
 *     (length limit on the id-string)
 *   + program arg 1 chopped after IDSTR_MAX characters (when applicable);
 *     reason is:
 *       - if the program is called with a relativelly long string as arg 1
 *         (tested with about 400 chars), a segfault occurs due to an internal
 *         buffer overflow (buffer space reserved for id-string is 128 chars,
 *         but never verified)
 *       - it may trigger buffer overflows in clients
 *   + put a proper comment at the top of the file
 *   + sorted out FD_SETSIZE (on Linux it's already defined)
 *       - moved it down below all the includes
 *   + added time.h include
 *   + added some short comments
 *   + conditionals '{', '}' enclosed
 *   + variable index -> idx in function closeOldest (killed a warning)
 *   + splitted multiple statements on a singel line
 *   + splitted long lines
 *   + prototypes ending in '()' -> '(void)'; changed by protoize
 *   + corrected most warnings, but "function declaration isn't a prototype"
 *     which still occurs on line: 415
 *   + added IDENT_PORT
 *   + added IDENT_SUBSTR
 *
 * Revision 1.6  2002/07/31 16:25:20  too
 * Now works when started as root (in Linux). Stupid me, tested
 * only starting as an ordinary loser.
 *
 * Revision 1.5  2002/07/29 14:02:42  too
 * Added possibility to have multible reply users, one (pseudo)randomly
 * chosen at each time.
 *
 * Revision 1.4  2001/02/09 08:45:42  too
 * Now GID is also changed to nobody/nogroup.
 *
 * Revision 1.3  2000/06/07 05:55:44  too
 * Fixed some Solaris compilation "bugs".
 * Changed LOG_PERROR to LOG_CONS
 *
 * Revision 1.2  1999/07/30 04:08:42  too
 * Added printing version string (and exit) with `-V' command line option.
 *
 * Revision 1.1  1999/04/21 17:23:20  too
 * - Writes process id to /var/run/identd.pid.
 * - Changes (effective) user id to `nobody' after initialization
 *	(binding socket etc.).
 * - Ignores some signals (HUP and PIPE).
 * - Handles some signals that aborts by default. The handler function
 *	tries to get rid of the pidfile.
 *
 * Revision 0.9b 1999/04/15 20:45:12  too
 * Not so much spaghetti anymore. Added documentation and more replies.
 *
 * Revision 0.9  1999/04/12 18:30:00  too
 * Version for unix systems. Standalone, supports 20 concurrent connections.
 * The code is quite a spaghetti. But that does not matter.
 *
 */

#ifdef DEBUG
#undef ndebug
#else
#define ndebug 1
#endif

#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>

#include <pwd.h>
#include <netdb.h>

#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#define IDENT_PORT	113
#define MAXCONNS	20
#define MAXIDLETIME	45

#if 1
static const char ident_substr[] = " : USERID : OTHER : ";
#else
static const char ident_substr[] = " : USERID : UNIX : ";
#endif
static const int ident_substr_len = sizeof ident_substr - 1;

#ifndef DEBUG
#define FCS		2	/* First Connection Socket */
#define TRACE(x, y);
#else
#define FCS		4
#define TRACE(x, y)	if (x) printf y
#endif

/* descriptors when debugging:
 *  0 = server socket
 *  1 = standard output (debugging output)
 *  2 = standard error
 *  3 = syslog fd (hopefully -- otherwise may work a bit wierdly)
 *  4 - 4 + MAXCONNS = connection sockets
 *
 * descriptors when not debugging
 *  0 = server socket
 *  1 = syslog fd (hopefully -- otherwise this won't work)
 *  2 = connection socket after detached from tty. standard error before that
 *  3 - 2 + MAXCONNS = rest connection sockets
 *
 * To try to make sure that syslog fd is what is "requested", the that fd
 * is closed before openlog() call. It can only severely fail if fd 0
 * is initially closed.
 */

/*
 * FD of the connection is always the index of the connection structure
 * in `conns' array + FCS
 */
struct {
  char		buf[20];
  int		len;
  time_t	lasttime;
} conns[MAXCONNS];


/*
 * To support multible usernames that can be replied by this fake identd
 * define `XXXMULTI' in compilation command line. This doesn't look guite
 * pretty, but alternatives looks even uglier.
 * XXX NOTE: multi currently only slightly tested XXXX.
 */
#ifdef XXXMULTI
#define IU_IN_STRUCT char ** identuserlist; int identusers
#define SET_IU(s, c) do { G.identuserlist = &(s); G.identusers = c; } while (0)
#define IU_IN_USAGESTR "[identuser [identuser2...]]"
#else
#define IU_IN_STRUCT char * identuser
#define SET_IU(s, c) G.identuser = (s)
#define IU_IN_USAGESTR "[identuser]"
#endif

/* When using global variables, bind those at least to a structure. */
struct {
  IU_IN_STRUCT;
  fd_set	readfds;
  int		conncnt;
} G;

static const char rcs_id[] =
/* */ "$Id: identd.c,v 2.0 2003/05/05 15:21:01 too Exp $";

/*
 * Prototypes
 */
static void reply(int s, char * buf);
static void replyError(int s, char * buf);
static const char * strerrno(void);

static const int one = 1;
static const char * const nobodystr = "nobody";

static inline void movefd(int from, int to)
{
  TRACE(1, ("movefd(from = %d, to = %d)\n", from, to));
  if (from != to)
    {
      dup2(from, to);
      close(from);
    }
}

/*
 * inetbind() must always return 0 or value < 0.
 * ... i.e. this version -- saves need for storage of the return value.
 */
static int inetbind(int port)
{
  int			s;
  struct sockaddr_in	addr = { 0 };
  int			len = sizeof addr;
  
  close(0);
  
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
      syslog(LOG_CRIT, "Can not create server socket: %s.", strerrno());
      return -1;
    }
  
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  
  if (bind(s, (struct sockaddr *)&addr, len) < 0)
    {
      syslog(LOG_CRIT, "Can not bind() server socket: %s.", strerrno());
      return -1;
    }
  
  if (listen(s, 5) < 0)
    {
      syslog(LOG_CRIT, "Can not listen() server socket: %s.", strerrno());
      return -1;
    }
  
  movefd(s, 0);
  
  return 0;
}

static void deleteConn(int s)
{
  int i = s - FCS;
  
  TRACE(1, ("deleteConn(): socket %d, conncnt %d\n", s, G.conncnt));
  
  close(s);
  
  G.conncnt--;
  
  /*
   * Most of the time there is 0 connections. Most often that there
   * is connections, there is just one connection. When this one connection
   * closes, i == G.conncnt = 0 -> no copying.
   * When there is more than one connection, the oldest connections closes
   * earlier on average. When this happens, the code below starts copying
   * the connection structure w/ highest index to the place which which is
   * just deleted. This means that the connection structures are no longer
   * in chronological order. I'd quess this means that when there is more
   * than 1 connection, on average every other connection structure needs
   * to be copied over the time all these connections are deleted.
   */
  if (i != G.conncnt)
    {
      memcpy(&conns[i], &conns[G.conncnt], sizeof conns[0]);
      movefd(G.conncnt + FCS, s);
    }
  
  TRACE(1, ("Clearing fd %d, readfds now 0x%x\n\n",
	    G.conncnt + FCS, *(int *)&G.readfds));
  
  FD_CLR(G.conncnt + FCS, &G.readfds);
}

static int closeOldest(void)
{
  time_t min = conns[0].lasttime;
  int	 idx = 0;
  int	 i;
  
  for (i = 1; i < MAXCONNS; i++)
    if (conns[i].lasttime < min)
      idx = i;

  TRACE(1, ("closeOldest(): index %d, socket %d\n", idx, idx + FCS));
  
  replyError(idx + FCS, "X-SERVER-TOO-BUSY");
  close(idx + FCS);
  
  return idx;
}


static int checkInput(char * buf, int len, int l)
{
  int	i;
  
  for (i = len; i < len + l; i++)
    if (buf[i] == '\n')
      return 1;
  
  return 0;
}


static int getport(void)
{
  struct servent * se;

  if ((se = getservbyname("identd", "tcp")) == NULL)
    return IDENT_PORT;
  else
    return se->s_port;
}

static const char * strerrno()
{
#if 1  
  return strerror(errno);
#else
  extern char * sys_errlist[];
  return sys_errlist[errno];
#endif  
}

#define WriteCS(f, s) write(f, s, sizeof s - 1)

static void writestrings(int fd, const char * str, ...)
{
  va_list ap;

  va_start(ap, str);

  while (str)
    {
      write(fd, str, strlen(str));
      str = va_arg(ap, const char *);
    }
  va_end(ap);
}
  
#ifndef DEBUG
static void godaemon(void)
{
  switch(fork())
    {
    case -1:	exit(-1);
    case 0:	close(1); close(2); setsid();  break;
    default:	exit(0);
    }
}
#endif

#define PIDFILE "/var/run/identd.pid"

static void delpidfile(void)
{
  /*
   * Usually nobody has no write/delete access to directory /var/run/
   * therefore if file cannot be deleted, it is truncated
   */
  if (unlink(PIDFILE) < 0)
    close(open(PIDFILE, O_WRONLY|O_CREAT|O_TRUNC, 0644));
}

static void handlexitsigs(void)
{
  delpidfile();
  exit(0);
}

static void writepid(uid_t nobody, uid_t nogrp)
     /* May succeed. If not, won't care. */
{
  char buf[24];
  int fd = open(PIDFILE, O_WRONLY|O_CREAT|O_TRUNC, 0664);

#ifdef DEBUG
  buf[23] = '\0';
#endif
  
  if (fd < 0)
    return;

  /* we don't use snprintf() here since it is not so portable...*/
  memset(buf, '\0', 24);
  sprintf(buf, "%d\n", getpid());
  assert(buf[23] == '\0');
  write(fd, buf, strlen(buf));
#ifndef EMBED
  fchown(fd, nobody, nogrp);
#endif
  close(fd);
  
  signal(SIGTERM, (void(*)(int))handlexitsigs);
  signal(SIGINT, (void(*)(int))handlexitsigs);
  signal(SIGQUIT, (void(*)(int))handlexitsigs);
  /* should this handle ILL, ... (see signal(7)) */
}


/* parses the `rcs_id' string for version information and prints the info. */
static void printversion(void)
{
  struct iovec iv[5];
  int		i;
  const char *	p;

  iv[3].iov_base = NULL;
  
  for (i = 0, p = rcs_id; *p && i < 4 ; i++)
    {
      while (*p != ' ' && *p != '\0')
	p++;

      if (*p++ == ' ' && *p != '\0')
	iv[i].iov_base = (void *)p;
    }

  TRACE(1, ("i = %d\n", i));
  
  if (iv[3].iov_base == NULL)
    {
      WriteCS(1, "identd: No version information found.\n");
      return;
    }

  TRACE(1, ("base = `%s'\n", iv[3].iov_base));
  
  p = iv[0].iov_base;
  while (*p != '.' && *p != ' ')
    p++;
      
  iv[0].iov_len = (void *)p - iv[0].iov_base;

  iv[1].iov_base--;
  iv[1].iov_len = (char *)iv[2].iov_base - (char *)iv[1].iov_base;

  iv[3].iov_len = (char *)iv[3].iov_base - (char *)iv[2].iov_base - 1;
  iv[3].iov_base = iv[2].iov_base;
  
  iv[2].iov_base = "(";
  iv[2].iov_len = 1;
  
  iv[4].iov_base = ").\n";
  iv[4].iov_len = 3;
  
  writev(1, iv, 5);
}

int main(int argc, char * argv[])
{
#ifndef EMBED
  uid_t nobody, nogrp;
#endif

  memset(conns, 0, sizeof conns);
  memset(&G, 0, sizeof G);
  FD_ZERO(&G.readfds);
  FD_SET(0, &G.readfds);

  TRACE(1, ("s: `%s', l = %d\n", ident_substr, ident_substr_len));
  
  if (argv[1])
    if (argv[1][0] == '-')
      if (argv[1][1] == 'V')
	{
	  printversion();
	  return 0;
	}
      else
	{
	  char b[2] = { argv[1][1], '\0' };

	  writestrings(2, argv[0], ": invalid option -- ", b, ".\n",
		       "Usage: ", argv[0], " [-V] ", IU_IN_USAGESTR "\n",
		       NULL);
	  return 1;
	}
    else
      SET_IU(argv[1], argc - 1);
  else
    SET_IU((char *)nobodystr, 1);
  
  
#ifndef DEBUG
  close(1); /* not debugging, openlog() hopefully uses fd 1. */
#else
  close(3); /* debugging, TRACE uses fd 1, openlog() hopefully fd 3 */
#endif
  
  openlog("identd", LOG_CONS, LOG_DAEMON);
 
#ifndef EMBED
  {
    struct passwd * pw = getpwnam(nobodystr);
    
    if (pw)
      {
	nobody = pw->pw_uid;
	nogrp = pw->pw_gid;
      }
    else
      {
	syslog(LOG_CRIT, "Can not find user `nobody': %s,", strerrno());
	return -1;
      }
  }
#endif
  
  if (inetbind(getport()) < 0)
      return -1;
  
  /* */
  {
    int i;
    
    for (i = FCS; i < MAXCONNS + FCS; i++)
      close(i);
  }
  
#ifdef DEBUG
#ifndef LOG_PERROR
#define LOG_PERROR 0
#endif
  openlog("identd", LOG_PERROR, LOG_DAEMON);
#else /* not DEBUG */
  godaemon();
  openlog("identd", 0, LOG_DAEMON);
  close(2);
  signal(SIGHUP, SIG_IGN);
#endif /* DEBUG */
  
  signal(SIGPIPE, SIG_IGN); /* connection closed when writing (raises ???) */

#ifndef EMBED
  writepid(nobody, nogrp);
  
  setegid(nogrp); setgid(nogrp); setuid(nobody); seteuid(nobody);

  {
    int i;
      
    for (i = 0; i < 4; i++)
      {
	char *	id = (char)NULL;
	unsigned int	rv = 0;
	
	switch (i)
	  {
	  case 0: rv = (unsigned int)getegid(); id = "egid"; break;
	  case 1: rv = (unsigned int)getgid();  id = "gid";  break;
	  case 2: rv = (unsigned int)geteuid(); id = "euid"; break;
	  case 3: rv = (unsigned int)getuid();  id = "uid";  break;
	  }
	
	if (rv == 0)
	  {
	    syslog(LOG_ERR,
		   "Can not drop all root privileges (%s) !!! %s !!!",
		   id, strerrno());
	    delpidfile();
	    return -1;
	  }
      }
  }
#else
  writepid(0, 0);
#endif
  
  while (2)
  {
    fd_set		rfds = G.readfds;
    struct timeval	tv = { 15, 0 };
    int			i;
    int			tim = time(NULL);
    
    TRACE(1, ("calling select(): n = %d, rfds = 0x%x\n\n",
	      G.conncnt + FCS, *(int *)&rfds));
    
    select(G.conncnt + FCS, &rfds, NULL, NULL, G.conncnt? &tv: NULL);
    
    for (i = G.conncnt - 1; i >= 0; i--)
      {
	int s = i + FCS;
	
	if (FD_ISSET(s, &rfds))
	  {
	    char *		buf = conns[i].buf;
	    unsigned int	len = conns[i].len;
	    unsigned int	l;
	    
	    TRACE(1, ("data socket fd_isset %d\n", s));
	    
	    if ((int)(l = read(s, buf + len, sizeof conns[0].buf - len)) > 0)
	      {
		if (checkInput(buf, len, l))
		  {
		    reply(s, buf);
		    goto deleteconn;
		  }
		else if (len + l >= sizeof conns[0].buf)
		  {
		    replyError(s, "X-INVALID-REQUEST");
		    goto deleteconn;
		  }
		else
		  conns[i].len += l;
	      }
	    else
	      goto deleteconn;
	    
	    conns[i].lasttime = tim;
	    continue;
	    
	  deleteconn:
	    deleteConn(s);
	  }
	else
	  {
	    /* implement as time_after() in linux kernel sources ... */
	    if (conns[i].lasttime + MAXIDLETIME <= tim)
	      {
		replyError(s, "X-TIMEOUT");
		deleteConn(s);
	      }
	  }
      }
    
    if (FD_ISSET(0, &rfds))
      {
	int s = accept(0, NULL, 0);
	
	TRACE(1, ("server socket fd_isset, %d accepted\n", s));
	
	if (s < 0)
	  {
	    if (errno != EINTR) /* EINTR */
	      syslog(LOG_ERR, "accept: %s", strerrno());
	  }
	else
	  {
	    if (G.conncnt == MAXCONNS)
	      i = closeOldest();
	    else
	      i = G.conncnt++;
	    
	    movefd(s, i + FCS); /* move if not already there */
	      
	    FD_SET(i + FCS, &G.readfds);
	      
	    conns[i].len = 0;
	    conns[i].lasttime = time(NULL);
	  }
      }
  }
}

static int parseAddrs(char * ptr, char ** myaddr, char ** heraddr);

static void replyError(int s, char * buf)
{
  struct iovec iv[3];

  iv[0].iov_base = "0, 0 : ERROR : ";	iv[0].iov_len = 15;
  iv[1].iov_base = buf;			iv[1].iov_len = strlen(buf);
  iv[2].iov_base = "\r\n";		iv[2].iov_len = 2;
    
  writev(s, iv, 3);
}

static void reply(int s, char * buf)
{
  char * myaddr, *heraddr;
  
  myaddr = heraddr = NULL;
  
  if (parseAddrs(buf, &myaddr, &heraddr))
    replyError(s, "X-INVALID-REQUEST");
  else
    {
      struct iovec iv[6];
#ifdef XXXMULTI
      char *iul = G.identuserlist[random() % G.identusers];
#endif      

      iv[0].iov_base = myaddr;		iv[0].iov_len = strlen(myaddr);
      iv[1].iov_base = ", ";		iv[1].iov_len = 2;
      iv[2].iov_base = heraddr;		iv[2].iov_len = strlen(heraddr);
      iv[3].iov_base = (void *)ident_substr;	iv[3].iov_len = ident_substr_len;
#ifdef XXXMULTI
      iv[4].iov_base = iul;		iv[4].iov_len = strlen(iul);
#else
      iv[4].iov_base = G.identuser;	iv[4].iov_len = strlen(G.identuser);
#endif
      iv[5].iov_base = "\r\n";	iv[5].iov_len = 2;

      writev(s, iv, 6);
    }
}

static int chmatch(char c, char * chars)
{
  for (; *chars; chars++)
    if (c == *chars)
      return 1;
  
  return 0;
}

static int skipchars(char ** p, char * chars)
{
  while (chmatch(**p, chars))
    (*p)++;
  
  if (**p == '\r' || **p == '\n')
    return 0;
  
  return 1;
}

static int parseAddrs(char * ptr, char ** myaddr, char ** heraddr)
{
  /* parse <port-on-server> , <port-on-client> */
  
  if (! skipchars(&ptr, " \t"))
    return -1;
  
  *myaddr = ptr;
  
  if (! skipchars(&ptr, "1234567890"))
    return -1;

  if (! chmatch(*ptr, " \t,"))
    return -1;
  
  *ptr++ = '\0';

  if (! skipchars(&ptr, " \t,") )
    return -1;

  *heraddr = ptr;
  
  skipchars(&ptr, "1234567890");
  
  if (! chmatch(*ptr, " \n\r"))
    return -1;

  *ptr = '\0';
  
  return 0;
}

/* EOF */
