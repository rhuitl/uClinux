/* pptp_callmgr.c ... Call manager for PPTP connections.
 *                    Handles TCP port 1723 protocol.
 *                    C. Scott Ananian <cananian@alumni.princeton.edu>
 *
 * $Id: pptp_callmgr.c,v 1.16 2006-06-22 06:30:30 steveb Exp $
 */
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <errno.h>
#include "pptp_callmgr.h"
#include "pptp_ctrl.h"
#include "pptp_msg.h"
#include "dirutil.h"
#include "vector.h"
#include "util.h"

int open_inetsock(struct in_addr inetaddr);
int open_unixsock(struct in_addr inetaddr);
void close_inetsock(int fd, struct in_addr inetaddr);
void close_unixsock(int fd, struct in_addr inetaddr);

sigjmp_buf env;
void sighandler(int sig) {
  pptp_debug("Got handled-signal %d", sig);
  siglongjmp(env, 1);
}

struct local_callinfo {
  int unix_sock;
  pid_t pid[1];
};

struct local_conninfo {
  VECTOR * call_list;
  fd_set * call_set;
};

void do_nothing(int sig) {
  /* do nothing signal handler */
  pptp_debug("Got nothing-signal %d", sig);
}

/* Connection callback */
void conn_callback(PPTP_CONN *conn, enum conn_state state) {

  switch(state) {
  case CONN_OPEN_FAIL:
  case CONN_CLOSE_DONE:
    /* get outta here */
    siglongjmp(env, 1);
    break;
  default:
    logmsg("Unhandled connection callback state [%d].", (int) state);
    break;
  }
}

/* Call callback */
void call_callback(PPTP_CONN *conn, PPTP_CALL *call, enum call_state state) {
  struct local_callinfo *lci;
  struct local_conninfo *conninfo;
  u_int16_t call_id[2];

  switch(state) {
  case CALL_OPEN_DONE:
    /* okey dokey.  This means that the call_id and peer_call_id are now
     * valid, so lets send them on to our friends who requested this call.
     */
	pptp_debug("About to get the call closure stuff");
    lci = pptp_call_closure_get(conn, call); assert(lci != NULL);
    pptp_call_get_ids(conn, call, &call_id[0], &call_id[1]);
	pptp_debug("writing out the call_ids");
	if (lci)
    write(lci->unix_sock, (char *) &call_id, sizeof(call_id));
    /* Our duty to the fatherland is now complete. */
    break;
  case CALL_OPEN_FAIL:
  case CALL_CLOSE_RQST:
  case CALL_CLOSE_DONE:
    /* don't need to do anything here, except make sure tables are sync'ed */
    conninfo = pptp_conn_closure_get(conn);
    lci = pptp_call_closure_get(conn, call); 
    // assert(lci != NULL && conninfo != NULL);
    if (lci && conninfo &&
		vector_contains(conninfo->call_list, lci->unix_sock)) {
      vector_remove(conninfo->call_list, lci->unix_sock);
	  if (lci->unix_sock >= 0)
        FD_CLR(lci->unix_sock, conninfo->call_set);
//	  syslog(LOG_NOTICE, "Closing connection");
      kill(lci->pid[0], SIGTERM);
    }
	if (lci) {
	  pptp_debug("close %d", lci->unix_sock);
      close(lci->unix_sock);
	  lci->unix_sock = -1;
#if 0
	  memset(lci, 0, sizeof(*lci));
	  free(lci);
	  pptp_call_closure_put(conn, call, NULL); 
#endif
	}
    break;
  default:
    logmsg("Unhandled call callback state [%d].", (int) state);
    break;
  }
}

/* Call Manager */
int main(int argc, char **argv, char **envp) {
  struct in_addr inetaddr;
  int inet_sock, unix_sock;
  fd_set call_set;
  PPTP_CONN * conn;
  VECTOR * call_list;
  int max_fd=0;
  int first=1;
  int retval;
  int i;

  openlog("pptp_callmgr", LOG_PID, 0);

  /* Step 0: Check arguments */
  if (argc!=2){
    logmsg("Usage: %s ip.add.ress.here", argv[0]);
	exit(0);
  }
  if (inet_aton(argv[1], &inetaddr)==0){
    logmsg("Invalid IP address: %s", argv[1]);
	exit(0);
  }

  /*
  We need to connect to the unxisocket first becasue of the way this program
  is launched.  We need to check if we can bind to the Unix socket to see if we 
  have already started.
  */
  if ((unix_sock = open_unixsock(inetaddr)) < 0){
    logmsg("Could not open unix socket for %s", argv[1]);
	exit(0); /*Exit because there is nothing yet to be done in here*/
  }

  if ((inet_sock = open_inetsock(inetaddr)) < 0){  /* Step 1: Open sockets. */
    logmsg("Could not open control connection to %s", argv[1]);
	close_unixsock(unix_sock, inetaddr);
	sleep(2); /* so we don't respawn too quickly and annoy init */
	exit(0);
  }

#if 0 /* we are already an execing program if 2 exec model chosen */
  /* Step 1b: FORK and return status to calling process. */
  switch (fork()) {
  case 0: /* child. stick around. */
    break;
  default: /* Parent. Return status to caller. */
    exit(0);
  }
#endif

  /* Step 1c: Clean up unix socket on TERM */
  signal(SIGINT, sighandler);
  signal(SIGTERM, sighandler);
  signal(SIGKILL, sighandler);
  if (sigsetjmp(env, 1)!=0) goto cleanup;
  signal(SIGPIPE, do_nothing);
  signal(SIGUSR1, do_nothing); /* signal state change; wake up accept */

  /* Step 2: Open control connection and register callback */
  if ((conn = pptp_conn_open(inet_sock, 1, NULL/* callback */)) == NULL) {
    logmsg("Could not open connection.");
	sleep(2); /* so we don't respawn too quickly and annoy init */
	goto cleanup;
  }

  pptp_debug("Call Mgr Started for %s", argv[1]);

  FD_ZERO(&call_set);
  max_fd = inet_sock > unix_sock ? inet_sock : unix_sock;
  call_list = vector_create();
  { 
    struct local_conninfo *conninfo = malloc(sizeof(*conninfo));
    if (conninfo==NULL) {
      logmsg("No memory.");
	  goto cleanup;
    }
    conninfo->call_list = call_list;
    conninfo->call_set  = &call_set;
    pptp_conn_closure_put(conn, conninfo);
  }

  if (sigsetjmp(env, 1)!=0) { pptp_debug("signalled!"); goto shutdown; }

  setpgrp(); /* stop our dad from killing us */

  /* Step 3: Get FD_SETs */
  do {
    fd_set read_set, write_set, excpt_set = call_set;
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
	read_set = call_set; /* need to remember the calls */
	if (pptp_conn_established(conn) && unix_sock != -1)
      FD_SET(unix_sock, &read_set);
    pptp_fd_set(conn, &read_set, &write_set);

    /* Step 4: Wait on INET or UNIX event */
    if (select(max_fd+1, &read_set, &write_set, &excpt_set, NULL)<0) {
	  if (errno != EINTR) {
		logmsg("select: %s", strerror(errno));
	  }
	  sleep(1); /* hope the error goes away,  but be nice to the host also */
      /* a signal or somesuch. */
      continue;
	}

    /* Step 5a: Handle INET events */
    pptp_dispatch(conn, &read_set, &write_set);

    /* Step 5b: Handle new connection to UNIX socket */
    if (unix_sock >= 0 && FD_ISSET(unix_sock, &read_set)) {
      /* New call! */
      struct sockaddr_un from;
      int len = sizeof(from);
      PPTP_CALL * call;
      struct local_callinfo *lci;
      int s;

      /* Accept the socket */
      if ((s = accept(unix_sock, (struct sockaddr *) &from, &len))<0) {
		logmsg("Socket not accepted: %s", strerror(errno));
		goto skip_accept;
      }
	  pptp_debug("accepting unixsock %d", s);
      /* Allocate memory for local call information structure. */
      if ((lci = malloc(sizeof(*lci))) == NULL) {
		logmsg("Out of memory.");
		close(s);
		goto skip_accept;
      }
      lci->unix_sock = s;

      /* Give the initiator time to write the PIDs while we open the call */
      call = pptp_call_open(conn, call_callback);
	  if (call == NULL){
	    logmsg("Couldn't allocate new call");
	    close(s);
	    goto skip_accept;
	  }
      /* Read and store the associated pids */
	  pptp_debug("Waiting to read the pids");
      read(s, &lci->pid[0], sizeof(lci->pid[0]));
	  pptp_debug("pids read!!");
      /* associate the local information with the call */
      pptp_call_closure_put(conn, call, (void *) lci);
      /* The rest is done on callback. */
      
      /* Keep alive; wait for close */
      retval = vector_insert(call_list, s, call); assert(retval);
      if (s > max_fd) max_fd = s;
        FD_SET(s, &call_set);
      first = 0;
    }
  skip_accept:
  	if (pptp_conn_down(conn)) {
      logmsg("conn down!");
	  goto shutdown;
	}
    /* Step 5c: Handle socket close */
    for (i=0; i<=max_fd; i++) {
      if (FD_ISSET(i, &call_set) &&
	  		(FD_ISSET(i, &excpt_set) || FD_ISSET(i, &read_set))) {
	/* close it */
	PPTP_CALL * call;

	pptp_debug("exception/data on fd %d", i);
	retval = vector_search(call_list, i, &call);
	if (retval) {
#if 1
	  struct local_callinfo *lci = pptp_call_closure_get(conn, call);
	  if (lci) {
	  kill(lci->pid[0], SIGTERM);
      memset(lci, 0, sizeof(*lci));
	  free(lci);
	  }
	  pptp_call_closure_put(conn, call, NULL);
	  vector_remove(call_list, i);
#endif
	  /* soft shutdown.  Callback will do hard shutdown later */
	  pptp_call_close(conn, call);
	}
	FD_CLR(i, &call_set);
	pptp_debug("closing unixsock %d", i);
	close(i);
      }
	}
  } while (!pptp_conn_down(conn) && (vector_size(call_list)>0 || first));

  logmsg("Callmanager has no more calls ! exiting");
shutdown:
  pptp_debug("Shutdown");
  /* make sure we clean up properly if interrupted during shutdown */
  signal(SIGINT, sighandler);
  signal(SIGTERM, sighandler);
  signal(SIGKILL, sighandler);
  if (sigsetjmp(env, 1)!=0) goto cleanup;

  if (!pptp_conn_down(conn)) {
    fd_set read_set, write_set;

    pptp_debug("Shutdown cleanly");
    /* kill all open calls */
    for (i=0; i<vector_size(call_list); i++) {
      PPTP_CALL *call = vector_get_Nth(call_list, i);
      struct local_callinfo *lci = pptp_call_closure_get(conn, call);
	  if (lci) {
      kill(lci->pid[0], SIGTERM);
	  }
      pptp_call_close(conn, call);
    }
    /* attempt to dispatch these messages */
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    pptp_fd_set(conn, &read_set, &write_set);
    FD_ZERO(&read_set);
    pptp_dispatch(conn, &read_set, &write_set);
    if (i>0) sleep(2);
    /* no more open calls.  Close the connection. */
    pptp_conn_close(conn, PPTP_STOP_LOCAL_SHUTDOWN);
    FD_ZERO(&read_set);
    FD_ZERO(&write_set);
    pptp_fd_set(conn, &read_set, &write_set);
    FD_ZERO(&read_set);
    pptp_dispatch(conn, &read_set, &write_set);
    sleep(2);
    /* with extreme prejudice */
    pptp_conn_destroy(conn, 1);
    vector_destroy(call_list);
  }

cleanup:
  close_inetsock(inet_sock, inetaddr);
  inet_sock = -1;
  close_unixsock(unix_sock, inetaddr);
  unix_sock = -1;
  pptp_debug("Gone");
  return 0;
}

int open_inetsock(struct in_addr inetaddr) {
  struct sockaddr_in dest;
  int s;

  dest.sin_family = AF_INET;
  dest.sin_port   = htons(PPTP_PORT);
  dest.sin_addr   = inetaddr;

  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    logmsg("socket: %s", strerror(errno));
    return s;
  }
  if (connect(s, (struct sockaddr *) &dest, sizeof(dest)) < 0) {
    logmsg("connect: %s", strerror(errno));
    close(s); return -1;
  }
  return s;
}

int open_unixsock(struct in_addr inetaddr) {
  struct sockaddr_un where;
  struct stat st;
  char *dir;
  int s;
  char *call_id_str = getenv("pptp_call_id");

  if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    logmsg("socket: %s", strerror(errno));
    return s;
  }

  where.sun_family = AF_UNIX;
  snprintf(where.sun_path, sizeof(where.sun_path), 
	   PPTP_SOCKET_PREFIX "%s%s%s", inet_ntoa(inetaddr),
	   call_id_str ? "." : "", call_id_str ? call_id_str : "");

  if (stat(where.sun_path, &st) >= 0) {
    logmsg("Call manager for %s is already running.", inet_ntoa(inetaddr));
    close(s); return -1;
  }

  /* Make sure path is valid. */
  dir = dirname(where.sun_path);
  if (!make_valid_path(dir, 0770))
    logmsg("Could not make path to %s: %s", where.sun_path, strerror(errno));
  free(dir);

  if (bind(s, (struct sockaddr *) &where, sizeof(where)) < 0) {
    logmsg("bind: %s", strerror(errno));
    close(s); return -1;
  }
  pptp_debug("Bound unix domain socket: %s", where.sun_path);

  chmod(where.sun_path, 0777);

  listen(s, 127);

  return s;
}
void close_inetsock(int fd, struct in_addr inetaddr) {
  close(fd);
}
void close_unixsock(int fd, struct in_addr inetaddr) {
  struct sockaddr_un where;
  close(fd);
  snprintf(where.sun_path, sizeof(where.sun_path), 
	   PPTP_SOCKET_PREFIX "%s", inet_ntoa(inetaddr));
  unlink(where.sun_path);
  pptp_debug("unlink %s", where.sun_path);
}
  




