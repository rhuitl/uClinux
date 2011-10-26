#include <signal.h>

__sighandler_t
__signal (int sig, __sighandler_t handler, int flags)
{
  int ret;
  struct sigaction action, oaction;
  memset(&action, 0, sizeof(struct sigaction));
  action.sa_handler = handler;
  action.sa_flags = flags;
  ret = sigaction (sig, &action, &oaction); 
  return (ret == -1) ? SIG_ERR : oaction.sa_handler;
}

__sighandler_t
signal (int sig, __sighandler_t handler)
{
  return __signal(sig, handler, (SA_ONESHOT | SA_NOMASK | SA_INTERRUPT) & ~SA_RESTART);
}
