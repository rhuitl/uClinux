/* inetd.c: Start up network services
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>
 * Copyright (C) 1999  D. Jeff Dionne     <jeff@lineo.ca>
 * Copyright (C) 2000  Lineo, Inc.  (www.lineo.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* Reworked code to allocate service structures dynamically.
 * Also compacted this structure a little and inlined functions
 * which are only called in one place.
 */
/* Fixed Null Pointer references caused by code in read_config()
 *                    - Rajiv Dhinakaran, 1 June 2000.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/utsname.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/autoconf.h>
#include <config/autoconf.h>

extern char **environ;

#include "cfgfile.h"

/* The MODIFY_CONFIG option means that our configuration file lives
 * in a writable file system and that we should support reloading of it
 * via a HUP signal.
 */
#undef DEBUG

#define MAX_CONNECT 8
#define MAX_ARGS  20

union sa {
        struct sockaddr sa;
        struct sockaddr_in sin;
#ifdef CONFIG_IPV6
        struct sockaddr_in6 sin6;
#endif
};

static void read_config(void);

#ifdef arm
#define inline
#endif

static void
set_signal(int sig, void (*handler)(int), int flags)
{
  struct sigaction action, oaction;
  memset(&action, 0, sizeof(struct sigaction));
  action.sa_handler = handler;
  action.sa_flags = flags;
  (void) sigaction(sig, &action, &oaction);
}

static void close_on_exec(int f)
{
	if (fcntl(f, F_SETFD, 1))
		perror("close on exec: ");
}

static inline void close_all_fds(int keep_top)
{
	int i, n;
	n = getdtablesize();
	for(i=keep_top+1;i<n;i++)
		close(i);
}

struct stService {
	struct stService *next;			// Reference to next service record
	int               port;			// Port to hang off
	int               master_socket;
	
	pid_t             pid[MAX_CONNECT];	// Seems less wasteful
        char             *args[MAX_ARGS];	// Command args

	short             limit;		// Max number of such processes
	short             current;		// How many child processes

	// Put the bit fields together to help reduce space use
	unsigned	  enabled :1;		// Service enabled
	unsigned	  changed :1;
	unsigned	  tcp :1;		// TCP or UDP
	unsigned	  ipv6 :1;		// ipv6 or ipv4
	unsigned	  reconfig :1;
	unsigned	  discard :1;		// Should this service be discarded when finished reconfig?
	
	// Dynamically allocated section for arguments
        char		  arg[0];
} *servicelist = NULL;


static inline int reap_child(int pid) {
  int reaped = 0;
  struct stService *p;

  for(p=servicelist; p!=NULL; p=p->next) {
    int j;
    for(j=0;j<MAX_CONNECT;j++)
      if (p->pid[j] == pid) {
        p->pid[j] = 0;
        p->current--;
      }
  }
  return reaped;
}

static inline int generate_select_fds(fd_set * readmask, fd_set * writemask)
{
  int max=0;
  struct stService *p;
  FD_ZERO(readmask);
  FD_ZERO(writemask);
#define FD_MSET(x,y) FD_SET((x),(y)); if ((x)>max) max = (x);

  for(p=servicelist; p!=NULL; p=p->next) {
    if (!strlen(p->args[0]) || (p->current >= p->limit) || !p->enabled)
      continue;

    FD_MSET(p->master_socket, readmask);

  }

  return max+1;
}

static char env_buffer[500];
static char *env_pointers[9];
static int env_used;
static int env_count;

static void init_env()
{
  env_used = 0;
  env_count = 0;
}

static void add_env(const char *format, ...)
{
  int len;

  va_list args;

  va_start(args, format);
  len = vsnprintf(env_buffer + env_used, sizeof(env_buffer) - env_used, format, args);
  env_pointers[env_count++] = env_buffer + env_used;
  env_used += len + 1;

  va_end(args);
}

static pid_t
start_child(struct stService *p, int fd, int tcp, int ipv6, int local_port, union sa *remote)
{
  pid_t pid;
  const char *proto = tcp ? "TCP" : "UDP";
#ifdef CONFIG_IPV6
  char buf[INET6_ADDRSTRLEN];
#endif

  init_env();
  add_env("PROTO=%s", proto);
  if (tcp) {
    union sa local;
    socklen_t local_size = sizeof(local);

#ifdef CONFIG_IPV6
    if (ipv6) {
      if (getsockname(fd, &local.sa, &local_size) == 0) {
        add_env("TCPLOCALIP=%s", inet_ntop(AF_INET6, &local.sin6.sin6_addr, buf, sizeof(buf)));
      }
      else {
        add_env("TCPLOCALIP=::");
      }
      add_env("TCPREMOTEIP=%s", inet_ntop(AF_INET6, &remote->sin6.sin6_addr, buf, sizeof(buf)));
      add_env("%sREMOTEPORT=%d", proto, ntohs(remote->sin6.sin6_port));
    } else
#endif
    {
      if (getsockname(fd, &local.sa, &local_size) == 0) {
        add_env("TCPLOCALIP=%s", inet_ntoa(local.sin.sin_addr));
      }
      else {
        add_env("TCPLOCALIP=0.0.0.0");
      }
      add_env("TCPREMOTEIP=%s", inet_ntoa(remote->sin.sin_addr));
      add_env("%sREMOTEPORT=%d", proto, ntohs(remote->sin.sin_port));
    }
  }
  add_env("%sLOCALPORT=%d", proto, local_port);
  add_env("PATH=%s", getenv("PATH") ?: "/bin:/usr/bin:/sbin:/usr/sbin");
  env_pointers[env_count] = 0;

#ifdef DEBUG
  fprintf(stderr, "start_child(%s port %d from %s)\n", proto, local_port, 
#ifdef CONFIG_IPV6
        ipv6 ? inet_ntop(AF_INET6, &remote->sin6.sin6_addr, buf, sizeof(buf)) :
#endif
        inet_ntoa(remote->sin.sin_addr));

  {
    int i;

    for (i = 0; env_pointers[i]; i++) {
      fprintf(stderr, "ENV[%d]: %s\n", i, env_pointers[i]);
    }
  }
#endif

  pid = vfork();

  if (pid == 0) {
    if (fd != 0)
      dup2(fd, 0);
    if (fd != 1)
      dup2(fd, 1);
#if 0
    /* Don't redirect stderr to stdout */
    if (fd != 2)
      dup2(fd, 2);
#endif
    if (fd > 2)
      close(fd);
    close_all_fds(2);

    /* There is no execvpe, so we kludge it */
    environ = env_pointers;
    execvp(p->args[0], p->args);
    fprintf(stderr, "execve failed!\n");
    _exit(0);
  }
  return(pid);
}


static inline void handle_incoming_fds(fd_set * readmask, fd_set * writemask)
{
  struct stService *p;


  for(p=servicelist; p!=NULL; p=p->next) {
    int fd;
    if (p->master_socket && FD_ISSET(p->master_socket, readmask)) {
      union sa remote;
      int j;
/*
 *    There is always at least one slot available in the loop below,
 *    see generate_select_fds(), the p->limit check.
 */
      for(j=0;j<MAX_CONNECT;j++)
        if (p->pid[j] == 0)
          break;

      if (p->tcp) {
        int remotelen = sizeof(remote);
        fd = accept(p->master_socket, &remote.sa, &remotelen);
        if (fd < 0) {
          fprintf(stderr, "accept failed\n");
          break;
        }
      } else {
        fd = p->master_socket;
      }

      p->current++;
      if ((p->pid[j] = start_child(p, fd, p->tcp, p->ipv6, p->port, &remote)) == -1) {
        /*
         * if we fail to start the child,  disable the service
         */
            p->enabled = 0;
            close(p->master_socket);
            p->master_socket = 0;
        p->current--;
      }

      if (p->tcp) {
        close(fd);
      }
    }
  }
}

static inline void start_services(void) {
  int s;
  struct stService *p;
  struct server_sockaddr;

  for(p=servicelist; p!=NULL; p=p->next) {
    union sa server_sockaddr;
    int family;

    if (p->master_socket || !strlen(p->args[0]))
      continue;

    p->enabled = 0;

#ifdef CONFIG_IPV6
    if (p->ipv6) {
      family = AF_INET6;
    } else
#endif
    {
      family = AF_INET;
    }

    if (p->tcp) {
      int true;

      if ((s = socket(family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
        fprintf(stderr, "Unable to create socket\n");
        continue;
      }

      close_on_exec(s);

      server_sockaddr.sa.sa_family = family;
#ifdef CONFIG_IPV6
      if (p->ipv6) {
        server_sockaddr.sin6.sin6_port = htons(p->port);
        memcpy(&server_sockaddr.sin6.sin6_addr.s6_addr, &in6addr_any, sizeof(in6addr_any));
      } else
#endif
      {
        server_sockaddr.sin.sin_port = htons(p->port);
        server_sockaddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
      }
      
      true = 1;

      if((setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&true, 
         sizeof(true))) == -1) {
        perror("setsockopt: ");
      }

      if (bind(s, &server_sockaddr.sa, sizeof(server_sockaddr)) == -1)  {
        if (p->changed) {
          fprintf(stderr, "Unable to bind server socket to port %d: %s\n", p->port, strerror(errno));
          p->changed = 0;
        }
        close(s);
        continue;
      }

      if(listen(s, 1) == -1) {
        fprintf(stderr, "Unable to listen to socket: %s\n", strerror(errno));
        close(s);
        continue;
      }
    } else {
      if ((s = socket(family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        fprintf(stderr, "Unable to create socket\n");
        continue;
      }

      close_on_exec(s);

      server_sockaddr.sa.sa_family = family;
#ifdef CONFIG_IPV6
      if (p->ipv6) {
        server_sockaddr.sin6.sin6_port = htons(p->port);
        memcpy(&server_sockaddr.sin6.sin6_addr.s6_addr, &in6addr_any, sizeof(in6addr_any));
      } else
#endif
      {
        server_sockaddr.sin.sin_port = htons(p->port);
        server_sockaddr.sin.sin_addr.s_addr = htonl(INADDR_ANY);
      }

      if (bind(s, &server_sockaddr.sa, sizeof(server_sockaddr)) == -1)  {
        if (p->changed) {
          fprintf(stderr, "Unable to bind server socket to port %d: %s\n", p->port, strerror(errno));
          p->changed = 0;
        }
        close(s);
        continue;
      }
    }
    p->master_socket = s;
    p->reconfig = 1;
    p->changed = 0;
    p->enabled = 1;
  }  
}

static inline void stop_services(void) {
  struct stService *p;
  struct server_sockaddr;
  
  for(p=servicelist; p!=NULL; p=p->next) {
    if(p->master_socket)
      close(p->master_socket);
    p->master_socket = 0;
  }
}

static void reap_children(void)
{
  int child;
  int status;
  while ((child = waitpid(-1, &status, WNOHANG)) > 0) {
    reap_child(child);
  }
}

#ifdef MODIFY_CONFIG
volatile int got_hup;
static void hup_handler(int signo)
{
	got_hup = 1;
}
#endif

volatile int got_cont;
static void cont_handler(int signo)
{
	got_cont = 1;
}

static void stop_handler(int signo)
{
	got_cont = 0;
	/* To reduce memory usage & prevent callers from getting gummed up */
	stop_services(); 
	while(!got_cont) {
		pause();
		reap_children();
	}
	got_cont = 0;
}

static void child_handler(int signo)
{
	/* Don't reap, just interrupt the syscall */
}

#ifdef MODIFY_CONFIG
static inline void close_service(struct stService *p)
{
  int j;

  if (p->master_socket) {
    close(p->master_socket);
    p->master_socket = 0;
  }

  for (j=0;j<MAX_CONNECT;j++) {
    if (p->pid[j] != 0) {
      kill(p->pid[j], SIGTERM);
      kill(p->pid[j], SIGHUP);
      p->pid[j] = 0;
    }
  }

  p->changed = p->reconfig = 0;
}

static inline void kill_changed_things(void)
{
  struct stService *p;

  for(p=servicelist; p!= NULL; p=p->next) {

    if (!p->changed || !p->reconfig)
      continue;
    
    close_service(p);
  }
}
#endif

static inline void run(void)
{
  fd_set rfds, wfds;
  struct timeval tv;
  int max;
  for(;;) {
    reap_children();
    start_services();

    max = generate_select_fds(&rfds, &wfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (select(max, &rfds, &wfds, 0, &tv) > 0) {
      handle_incoming_fds(&rfds, &wfds);
    }
#ifdef MODIFY_CONFIG
    if (got_hup) {
    	got_hup = 0;
	read_config();
    	kill_changed_things();
    	continue;
    }
#endif
  }
}

#ifdef MODIFY_CONFIG
/* Returns 0 if the two services have the same definition */
static int
compare_service(struct stService *p, struct stService *q)
{
  int i;

  if (p->limit != q->limit) {
    return(1);
  }

  for (i = 0; p->args[i]; i++) {
    if (!q->args[i]) {
      return(1);
    }
    if (strcmp(p->args[i], q->args[i]) != 0) {
      return(1);
    }
  }
  if (q->args[i]) {
    return(1);
  }

  return(0);
}
#endif

static void
read_config_lines(FILE *cfp)
{
  char **args;
  char *ap;

  int j, k;
  struct stService *p;
  size_t sz;
  struct servent *sent;

  for (;;) {
    if (!(args = cfgread(cfp))) break;

    for (j=0; (j<5 + MAX_ARGS) && (args[j]); j++);
    if (j<6) {
      fprintf(stderr,"Bad line in config file %s...\n",
	      args[0] ? args[0] : "");
      continue;
    }

    sz = sizeof(struct stService);
    for (k=5; k<j; k++) {
	    sz += strlen(args[k]) + 1;		// Must remember the terminator
    }
    
    p = malloc(sz);
    if (p == NULL) {
	    fprintf(stderr, "Malloc failed\n");
	    continue;
    }
    bzero(p, sz);

    /* copy in the args and exec path. */
    /* No possible overrun here as we've already calculated the sizes */
//    p->args[j - 5] = NULL;
    ap = p->arg;
    for (k=5; k<j; k++) {                       //
      p->args[k - 5] = ap;              	//
      if (args[k]) {                            // Fixup for NULL PTR
        strcpy(ap, args[k]);               	//      - Rajiv
        ap += strlen(args[k]);                  //
      }                                         //
      *ap++ = '\0';
    }

    if (strcmp(args[2], "tcp") == 0) {
      p->tcp = 1;
      p->ipv6 = 0;
    } else if (strcmp(args[2], "udp") == 0) {
      p->tcp = 0;
      p->ipv6 = 0;
    }
#ifdef CONFIG_IPV6
    else if (strcmp(args[2], "tcp6") == 0) {
      p->tcp = 1;
      p->ipv6 = 1;
    } else if (strcmp(args[2], "udp6") == 0) {
      p->tcp = 0;
      p->ipv6 = 1;
    } 
#endif
    else {
        fprintf(stderr, "unknown service type %s\n", args[2]);
        free(p);
        continue;
    }

	/* for "wait" processes,  only ever allow one to be run */

    p->limit = (strcmp(args[3], "wait") == 0) ? 1 : MAX_CONNECT;

    sent = getservbyname(args[0], p->tcp ? "tcp" : "udp");
    if (sent == NULL) {
      if (atoi(args[0]) > 0) {
        p->port = atoi(args[0]);
      }
      else {
        fprintf(stderr, "can't find service\n");
        free(p);
        continue;
      }
    }
    else {
      p->port = ntohs(sent->s_port);
    }

    p->master_socket = 0;
    p->changed = 1;
    p->enabled = 1;
    p->discard = 0;

#ifdef MODIFY_CONFIG
    {
      struct stService *q;
      /* Now see if this service is already in the list.
       * If it is, and it is identical, discard this one.
       * If it is, and it is NOT identical, remove that one and replace it with this one.
       * If it is not, add this one to the list.
       */
#ifdef DEBUG
      fprintf(stderr, "Searching for existing service: port=%d, tcp=%d, ipv6=%d, cmd=%s\n", p->port, p->tcp, p->ipv6, p->args[0]);
#endif

      for (q = servicelist; q; q = q->next) {
        if (p->port == q->port && p->tcp == q->tcp) {
          /* We have a match. Are they identical? */
          if (compare_service(p, q) == 0) {
            /* Yes, so we don't need this service */
            free(p);
            p = 0;

#ifdef DEBUG
            fprintf(stderr, "Existing service is identical, so discarding this one. Marking other with discard=0\n");
#endif

            /* Make sure we indicate that we need to keep the other one */
            q->discard = 0;
          }
          else {
#ifdef DEBUG
            fprintf(stderr, "Existing service is different, so discarding that one and replacing with this one\n");
#endif
          }
          break;
        }
      }
    }
#endif

    /* Add this one to the list */
    if (p) {
#ifdef DEBUG
      fprintf(stderr, "Adding service: port=%d, tcp=%d, ipv6=%d, cmd=%s\n", p->port, p->tcp, p->ipv6, p->args[0]);
#endif
      p->next = servicelist;
      servicelist = p;
    }
  }
}

/* Very simple file format, lines of the form
 * port# ignored tcp/udp ignored ignored <exec path> args...
 * this should be compatible with berkeley derived inetd
 */
#ifdef MODIFY_CONFIG
static void
#else
static inline void
#endif
read_config()
{
  FILE *cfp;
#ifdef MODIFY_CONFIG
  struct stService *p;
  struct stService *q;

  /* Mark all of the existing services with discard = 1
   * Any services which still exist will have this set to 0.
   * Also, mark any disabled services as reenabled.
   */
  for (p=servicelist; p!=NULL; p = p->next) {
    p->discard = 1;
    if (!p->enabled) {
      p->enabled = 1;
      p->changed = 1;
    }
  }
#endif

  if (!(cfp = fopen(INETD_CONF,"r"))) {
    perror("Can't open " INETD_CONF);
    exit(1);
  }
  read_config_lines(cfp);
  fclose(cfp);

#ifdef ALT_INETD_CONF
  if ((cfp = fopen(ALT_INETD_CONF,"r")) != 0) {
    read_config_lines(cfp);
    fclose(cfp);
  }
#endif

#ifdef MODIFY_CONFIG
  /* Now discard any services which have discard = 1, since they are
   * no longer in the list.
   */
  for (p=servicelist, servicelist = 0; p!=NULL; p = q) {
    q = p->next;

    if (p->discard) {
#ifdef DEBUG
      fprintf(stderr, "Discarding service: port=%d, tcp=%d, ipv6=%d, cmd=%s\n", p->port, p->tcp, p->ipv6, p->args[0]);
#endif
      close_service(p);
      free(p);
    }
    else {
#ifdef DEBUG
      fprintf(stderr, "Keeping service: port=%d, tcp=%d, ipv6=%d, cmd=%s\n", p->port, p->tcp, p->ipv6, p->args[0]);
#endif
      p->next = servicelist;
      servicelist = p;
    }
  }
#endif

#ifdef DEBUG
  /* Print this stuff out outside the above loop to ensure we
   * get the list processing correct too.
   */
  {
    struct stService *p;

    fprintf(stderr, "Service List:\n");

    for (p=servicelist; p!=NULL; p=p->next)
      fprintf(stderr, "  service %s port %d %s %s %s %s\n",
             p->args[0],
             p->port,
             p->tcp ? "tcp" : "udp",
             p->ipv6 ? "IPv6" : "IPv4",
             p->discard ? "discard" : "active",
             p->enabled ? "enabled" : "disabled");
  }
#endif
}

int creatpidfile()
{
	FILE	*f;
	pid_t	pid;
	char	*pidfile = "/var/run/inetd.pid";

	pid = getpid();
	if ((f = fopen(pidfile, "w")) == NULL)
		return(-1);
	fprintf(f, "%d\n", pid);
	fclose(f);
	return(0);
}

int
main(int argc, char *argv[], char *env[])
{
#ifdef EMBED
  set_signal(SIGPIPE, SIG_IGN, 0);
  set_signal(SIGSTOP, stop_handler, 0);
  set_signal(SIGTSTP, stop_handler, 0);
  set_signal(SIGCONT, cont_handler, 0);
  set_signal(SIGCHLD, child_handler, SA_INTERRUPT);
#ifdef MODIFY_CONFIG
  // This only makes sense if we've got a modifyable filesystem.
  set_signal(SIGHUP, hup_handler, 0);
#endif
  /*
   * we must have an open FD 0 as we use 0 to signify no-fd :-(
   */
  if (fcntl(0, F_GETFL) == -1)
  	open("/dev/null", O_RDWR);
#endif  

  /* Hack to fix problems with not dealing cleanly with fds of 0 */
  open("/dev/null", O_RDWR);

  creatpidfile();
 
  read_config();

  run();

  return 1;
  /* not reached */
}
