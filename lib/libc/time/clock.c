#include <time.h>
#include <sys/times.h>

/* Fairly simple implementation of the clock() call.
 * We accumulate the system and user times together as
 * an approximation to CPU time used.
 */
clock_t clock() {
	struct tms x;

	(void)times(&x);
	return x.tms_stime + x.tms_utime;
}
