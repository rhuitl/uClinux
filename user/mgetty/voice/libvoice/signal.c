/*
 * signal.c
 *
 * Installs the signal handlers for the voice code and contains the
 * signal handler functions.
 * BUGS
 *    - Something I do not like is that it looks like we use non
 *      reentrant functions in the signal handlers (log, etc).
 *
 * $Id: signal.c,v 1.8 1999/10/09 20:13:04 marcs Exp $
 *
 */

#include "../include/voice.h"

static int signals_initialized = FALSE;

void (*old_sigalrm) (int);
void (*old_sigchld) (int);
void (*old_sighup) (int);
void (*old_sigint) (int);
void (*old_sigpipe) (int);
void (*old_sigquit) (int);
void (*old_sigterm) (int);
void (*old_sigusr1) (int);
void (*old_sigusr2) (int);

static void signal_sigalrm(int sig)
     {
     lprintf(L_WARN, "%s: Watchdog timer expired, exiting...",
      program_name);
     exit(FAIL);
     }

static void signal_sigchld(int sig)
     {
     pid_t pid;
     int status;
     pid = wait(&status); /* This appears to fix core dumps on HPUX. Maybe this
                           * also fixes the same problem on Solaris.
                           */
     signal(SIGCHLD, signal_sigchld);
     if (status) {
        lprintf(L_WARN, "%s: Got child %d exit status %d signal",
                program_name,
                pid,
                status);
     }
     else {
        lprintf(L_JUNK, "%s: Got child %d exit signal",
                program_name,
                pid);
     }
     queue_event(create_event(SIGNAL_SIGCHLD));
     }

static void signal_sighup(int sig)
     {
     signal(SIGHUP, signal_sighup);
     lprintf(L_JUNK, "%s: Got hangup signal", program_name);
     queue_event(create_event(SIGNAL_SIGHUP));
     }

static void signal_sigint(int sig)
     {
     signal(SIGINT, signal_sigint);
     lprintf(L_JUNK, "%s: Got interrupt signal", program_name);
     queue_event(create_event(SIGNAL_SIGINT));
     }

static void signal_sigpipe(int sig)
     {
     signal(SIGPIPE, signal_sigpipe);
     lprintf(L_JUNK, "%s: Got pipe signal", program_name);
     queue_event(create_event(SIGNAL_SIGPIPE));
     }

static void signal_sigquit(int sig)
     {
     signal(SIGQUIT, signal_sigquit);
     lprintf(L_JUNK, "%s: Got quit signal", program_name);
     queue_event(create_event(SIGNAL_SIGQUIT));
     }

static void signal_sigterm(int sig)
     {
     signal(SIGTERM, signal_sigterm);
     lprintf(L_JUNK, "%s: Got terminate signal", program_name);
     queue_event(create_event(SIGNAL_SIGTERM));
     }

static void signal_sigusr1(int sig)
     {
     signal(SIGUSR1, signal_sigusr1);
     lprintf(L_JUNK, "%s: Got user 1 signal", program_name);
     queue_event(create_event(SIGNAL_SIGUSR1));
     }

static void signal_sigusr2(int sig)
     {
     signal(SIGUSR2, signal_sigusr2);
     lprintf(L_JUNK, "%s: Got user 2 signal", program_name);
     queue_event(create_event(SIGNAL_SIGUSR2));
     }

int voice_install_signal_handler(void)
     {
     lprintf(L_NOISE, "%s: Installing signal handlers", program_name);

     if (signals_initialized)
          {
          lprintf(L_NOISE, "%s: Signal handlers are already installed",
           program_name);
          return(OK);
          };

     old_sigalrm = signal(SIGALRM, signal_sigalrm);
     old_sigchld = signal(SIGCHLD, signal_sigchld);
     old_sighup = signal(SIGHUP, signal_sighup);
     old_sigint = signal(SIGINT, signal_sigint);
     old_sigpipe = signal(SIGPIPE, signal_sigpipe);
     old_sigquit = signal(SIGQUIT, signal_sigquit);
     old_sigterm = signal(SIGTERM, signal_sigterm);
     old_sigusr1 = signal(SIGUSR1, signal_sigusr1);
     old_sigusr2 = signal(SIGUSR2, signal_sigusr2);
#ifdef HAVE_SIGINTERRUPT
     siginterrupt(SIGALRM, TRUE);
     siginterrupt(SIGCHLD, TRUE);
     siginterrupt(SIGHUP, TRUE);
     siginterrupt(SIGINT, TRUE);
     siginterrupt(SIGPIPE, TRUE);
     siginterrupt(SIGQUIT, TRUE);
     siginterrupt(SIGTERM, TRUE);
     siginterrupt(SIGUSR1, TRUE);
     siginterrupt(SIGUSR2, TRUE);
#endif
     alarm(cvd.watchdog_timeout.d.i);
     signals_initialized = TRUE;
     return(OK);
     }

int voice_restore_signal_handler(void)
     {
     lprintf(L_NOISE, "%s: Restoring signal handlers", program_name);

     if (!signals_initialized)
          {
          lprintf(L_NOISE, "%s: No signal handlers were installed",
           program_name);
          return(OK);
          };

     alarm(0);
     signal(SIGALRM, old_sigalrm);
     signal(SIGCHLD, old_sigchld);
     signal(SIGHUP, old_sighup);
     signal(SIGINT, old_sigint);
     signal(SIGPIPE, old_sigpipe);
     signal(SIGQUIT, old_sigquit);
     signal(SIGTERM, old_sigterm);
     signal(SIGUSR1, old_sigusr1);
     signal(SIGUSR2, old_sigusr2);
     signals_initialized = FALSE;
     return(OK);
     }
