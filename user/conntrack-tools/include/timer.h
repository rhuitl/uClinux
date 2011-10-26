#ifndef _TIMER_H_
#define _TIMER_H_

#include <sys/time.h>

struct timer {
	long credits;
	struct timeval start;
	struct timeval stop;
	struct timeval diff;
};

#define GET_CREDITS(x)   x.credits
#define GET_STARTTIME(x) x.start
#define GET_STOPTIME(x)  x.stop

#endif
