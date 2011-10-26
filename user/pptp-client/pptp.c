/* pptp.c ... client shell to launch call managers, data handlers, and
 *            the pppd from the command line.
 *            C. Scott Ananian <cananian@alumni.princeton.edu>
 *
 * $Id: pptp.c,v 1.20 2006-04-13 05:19:06 steveb Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <sys/wait.h>
#include <fcntl.h>
#include "pptp_callmgr.h"
#include "pptp_msg.h"
#include "pptp_gre.h"
#include "version.h"
#include "inststr.h"
#include "pty.h"
#include "util.h"

static char *call_id_str = NULL;

/*
 * because we can be run from init,  it seems unwise to just
 * exit quickly for errors that probably won't have resolved
 * themselves immediately,  wait a bit on exit just to slow
 * it all down a little
 */
#define RESPAWN_DELAY	10

#ifndef PPPD_BINARY
#define PPPD_BINARY "pppd"
#endif

struct in_addr get_ip_address(char *name);
int open_callmgr(struct in_addr inetaddr, int argc,char **argv,char **envp);
void launch_callmgr(struct in_addr inetaddr, int argc,char **argv,char **envp);
int get_call_id(int sock, pid_t gre,
		 u_int16_t *call_id, u_int16_t *peer_call_id);
void launch_pppd(char *ttydev, int argc, char **argv);

void usage(char *progname) {
  fprintf(stderr,
	  "%s\n"
	 "Usage:\n"
	 " %s hostname[,hostname[,...]] [pppd options]\n", version, progname);
  exit(1);
}

static int signaled = 0;

void do_nothing(int sig) { 
    /* do nothing signal handler. Better than SIG_IGN. */
    signaled = 1;
}

void do_alarm(int sig) {
    /* the SIGALRM handler */
}

sigjmp_buf env;
void sighandler(int sig) {
  siglongjmp(env, 1);
}

int main(int argc, char **argv, char **envp) {
  struct in_addr inetaddr;
  int callmgr_sock = -1;
  char ptydev[PTYMAX], ttydev[TTYMAX];
  int pty_fd = -1, tty_fd = -1;
  int gre_fd = -1;
  static volatile pid_t child_pid;
  u_int16_t call_id, peer_call_id;
  char *cp;
  
  openlog("pptp",LOG_PID,0);

  if (argc < 2)
    usage(argv[0]);

  /*
   * check for hard coded callid
   */
  if ((cp = strchr(argv[1], ':'))) {
	static char call_id_env[] = "pptp_callid=65536";
	*cp++ = '\0';
	call_id_str = cp;
    sprintf(call_id_env, "pptp_call_id=%d", atoi(cp) & 0xffff);
	putenv(call_id_env);
  }

  /* Step 1: Get IP address for the hostname in argv[1] */
  for (;;) {
    inetaddr = get_ip_address(argv[1]);
    if(inetaddr.s_addr != 0)
      break;
    sleep(RESPAWN_DELAY);
  }

  /*
   * open the GRE socket early so that we do not get
   * ENOPROTOOPT errors if the other end responds too
   * quickly to our initial connection
   */
  gre_fd = socket(AF_INET, SOCK_RAW, PPTP_PROTO);
  if (gre_fd < 0) {
	logmsg("socket: %s", strerror(errno));
    sleep(RESPAWN_DELAY);
	exit(1);
  }

  for (;;) {
    /* Step 2: Open connection to call manager
	 *         (Launch call manager if necessary.)
	 */
	callmgr_sock = open_callmgr(inetaddr, argc,argv,envp);
	if(callmgr_sock < 0){
      close(gre_fd);
	  logmsg("Could not open connection to call manager - terminating");
	  sleep(RESPAWN_DELAY);
	  exit(1);
	}
	pptp_debug("callmgr opened - fd = %x", callmgr_sock);

	/* Step 5: Exchange PIDs, get call ID */
	if (get_call_id(callmgr_sock, getpid(), &call_id, &peer_call_id) >= 0)
		break;

	close(callmgr_sock);
  }

  /* Step 3: Find an open pty/tty pair. */
  if (openpty(&pty_fd, &tty_fd, ttydev, NULL, NULL) == -1) {
	logmsg("Could not find free pty, %d.", errno);
    close(gre_fd);
    close(callmgr_sock);
	sleep(RESPAWN_DELAY);
	exit(1);
  }
  strcpy(ptydev, ttydev);
  cp = strstr(ptydev, "tty");
  if (cp)
	  *cp = 'p';
  pptp_debug("got a free ttydev");
  logmsg("Using pty %s,%s", ptydev, ttydev);
  
  /* Step 4: fork and wait. */
  signal(SIGUSR1, do_nothing); /* don't die */
  switch (child_pid = vfork()) {
  case -1:
    signal(SIGUSR1, SIG_DFL);
    pptp_debug("vfork failed %s", strerror(errno));
	sleep(RESPAWN_DELAY);
	goto shutdown;
  case 0: /* I'm the child! */
//    signal(SIGUSR1, SIG_DFL);
	pptp_debug("entered child");
    pptp_debug("callids established..");
	close(callmgr_sock);
	close(gre_fd);
	close(pty_fd);
    launch_pppd(ttydev, argc-2, argv+2); /* launch pppd */
	sleep(RESPAWN_DELAY);
	_exit(1); /* in case launch_pppd returns */
    break;
  default: /* parent */
    /*
     * There is still a very small race condition here.  If a signal
     * occurs after signaled is checked but before pause is called,
     * things will hang.
     */
#if 0
	if (!signaled) {
	  pause(); /* wait for the signal */
    }
    logmsg("Error %s", strerror(errno));
#endif /*0*/
    break;
  }

#if 0
  /* Step 5b: Send signal to wake up pppd task */
  kill(parent_pid, SIGUSR1);
  sleep(2);
#endif /*0*/

  if (sigsetjmp(env, 1)!=0) goto shutdown;
  signal(SIGINT,  sighandler);
  signal(SIGTERM, sighandler);
  signal(SIGKILL, sighandler);

  {
    char buf[128];
    snprintf(buf, sizeof(buf), "pptp: GRE-to-PPP gateway on %s", ptydev);
    inststr(argc,argv,envp, buf);
  }

  /* Step 6: Do GRE copy until close. */
  pptp_gre_copy(peer_call_id, call_id, pty_fd, gre_fd, inetaddr);

shutdown:
  /* Make sure pppd exits as well */
  if (child_pid > 0)
    kill(child_pid, SIGTERM);
  if (gre_fd != -1)
    close(gre_fd);
  if (pty_fd != -1)
    close(pty_fd);
  if (callmgr_sock != -1)
    close(callmgr_sock);
  if (tty_fd != -1)
    close(tty_fd);
  exit(0);
}

/*
 * search through a possible list of ',' seperated ip addresses, try
 * each one,  if it works then use that one
 */
struct in_addr get_ip_address(char *name) {
  struct in_addr retval;
  struct sockaddr_in dest;
  int s;
  char *cp, *np;

  retval.s_addr = 0;
  for (cp = name; cp && *cp; cp = np) {

    if ((np = strchr(cp, ',')) != 0) {
    	*np++ = '\0';
	}
    logmsg("Trying host %s ...", cp);
    if (inet_aton(cp, &retval) == 0) {
      struct hostent *host = gethostbyname(cp);
      if (host==NULL) {
	    if (h_errno == HOST_NOT_FOUND)
	      logmsg("gethostbyname: HOST NOT FOUND");
	    else if (h_errno == NO_ADDRESS)
	      logmsg("gethostbyname: NO IP ADDRESS");
	    else
	      logmsg("gethostbyname: name server error");
	    continue;
      }
      if (host->h_addrtype != AF_INET) {
	    logmsg("Host has non-internet address");
	    continue;
	  }
      memcpy(&retval.s_addr, host->h_addr, sizeof(retval.s_addr));
    }

    if (np)
    	*(np - 1) = ','; /* put string back how we found it */

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(PPTP_PORT);
    dest.sin_addr   = retval;
    pptp_debug("socket");
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      logmsg("Cannot get socket: %s", strerror(errno));
      continue;
    }
    pptp_debug("Connect");
    signal(SIGALRM, do_alarm);
    alarm(15);
    if (connect(s, (struct sockaddr *) &dest, sizeof(dest)) != -1) {
      alarm(0);
      logmsg("Connect succeeded");
      close(s);
      return(retval);
    }
    alarm(0);
	close(s);
    logmsg("Connect failed: %s",strerror(errno));
  }
  retval.s_addr = 0;
  return retval;
}

int open_callmgr(struct in_addr inetaddr, int argc, char **argv, char **envp) {
  /* Try to open unix domain socket to call manager. */
  struct sockaddr_un where;
  const int NUM_TRIES = 3;
  int i, fd;

  /* Open socket */
  if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    logmsg("Could not create unix domain socket: %s", strerror(errno));
    return(-1);
  }

  /* Make sure the socket is closed if callmgr is launched */
  fcntl(fd, F_SETFD, FD_CLOEXEC);

  /* Make address */
  where.sun_family = AF_UNIX;
  snprintf(where.sun_path, sizeof(where.sun_path), 
	   PPTP_SOCKET_PREFIX "%s%s%s", inet_ntoa(inetaddr),
	   call_id_str ? "." : "", call_id_str ? call_id_str : "");

  for (i=0; i<NUM_TRIES; i++) {
    if (connect(fd, (struct sockaddr *) &where, sizeof(where)) < 0) {
      /* couldn't connect.  We'll have to launch this guy. */
      launch_callmgr(inetaddr, argc,argv,envp);
      sleep(3);
    }
    else return fd;
  }
  close(fd);
  logmsg("Could not launch call manager after %d tries.", i);
  return -1;   /* make gcc happy */
}

void launch_callmgr(struct in_addr inetaddr, int argc,char**argv,char**envp) {
  pid_t pid;
  /*int status;*/
  const char *callmgr = PPTP_CALLMGR_BINARY;

  /* fork and launch call manager process */
  switch (pid=vfork()) {
  case -1: /* baaad */
	logmsg("callmgr vfork failed: %s", strerror(errno));
    break;
  case 0: /* child */
    { 
#if 0
      int callmgr_main(int argc, char**argv, char**envp);
      char *my_argv[2] = { argv[0], inet_ntoa(inetaddr) };
      char buf[128];
      snprintf(buf, sizeof(buf), "pptp: call manager for %s", my_argv[1]);
      inststr(argc,argv,envp,buf);
      exit(callmgr_main(2, my_argv, envp));
#endif
      execlp(callmgr, callmgr, inet_ntoa(inetaddr), NULL);
      logmsg("execlp() of call manager [%s] failed: %s", 
	      callmgr, strerror(errno));
      _exit(1); /* or we trash our parents stack */
    }
  default: /* parent */
#if 0 /* we don't care about status */
    waitpid(pid, &status, 0);
    if (status!=0)
      logmsg("Call manager exited with error %d", status);
#endif
    break;
  }
}

/* XXX need better error checking XXX */
int get_call_id(int sock, pid_t gre,
		 u_int16_t *call_id, u_int16_t *peer_call_id) {
  u_int16_t m_call_id, m_peer_call_id;
  /* write pid's to socket */
  /* don't bother with network byte order, because pid's are meaningless
   * outside the local host.
   */
  int rc;
  rc = write(sock, (char *)&gre, sizeof(gre));
  if (rc != sizeof(gre))
	  return -1;
  pptp_debug("wrote socket information, waiting for read...");
  rc = read(sock,  (char *)&m_call_id, sizeof(m_call_id));
  if (rc != sizeof(m_call_id))
	  return -1;
  rc = read(sock,  (char *)&m_peer_call_id, sizeof(m_peer_call_id));
  if (rc != sizeof(m_peer_call_id))
	  return -1;
  pptp_debug("Read socket information: call_id=%d, peer_call_id=%d",
		  m_call_id, m_peer_call_id);
  /* XXX FIX ME ... DO ERROR CHECKING & TIME-OUTS XXX */
  *call_id = m_call_id;
  *peer_call_id = m_peer_call_id;

  return 0;
}

void launch_pppd(char *ttydev, int argc, char **argv) {
  char *new_argv[argc+4]; /* XXX if not using GCC, hard code a limit here. */
  int i;

  new_argv[0] = PPPD_BINARY;
  new_argv[1] = ttydev;
  new_argv[2] = "38400";
  for (i=0; i<argc; i++)
    new_argv[i+3] = argv[i];
  new_argv[i+3] = NULL;
  execvp(new_argv[0], new_argv);
}

#if 0
/*************** COMPILE call manager into same binary *********/
#define main       callmgr_main
#define sighandler callmgr_sighandler
#define do_nothing callmgr_do_nothing
#include "pptp_callmgr.c"
#endif
