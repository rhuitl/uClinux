#define __USE_BSD_SIGNAL

#include <signal.h>

#undef signal

/* The `sig' bit is set if the interrupt on it
 * is enabled via siginterrupt (). */
sigset_t _sigintr;

extern __sighandler_t
__signal (int sig, __sighandler_t handler, int flags);

__sighandler_t
__bsd_signal (int sig, __sighandler_t handler)
{
  int flags;
  if (!__sigismember (&_sigintr, sig)) {
#ifdef SA_RESTART
    flags = SA_RESTART;
#else
    flags = 0;
#endif
  }
  else {
#ifdef SA_INTERRUPT
    flags = SA_INTERRUPT;
#else
    aflags = 0;
#endif
  }
  return __signal(sig, handler, flags);
}

/* Change sig handling from interrupt or restart */
int siginterrupt(int sig, int flag) {
	if (flag) {	/* Interrupt on signal */
		__sigaddset(&_sigintr, sig);
	} else {	/* Restart on signal */
		__sigdelset(&_sigintr, sig);
	}
}
