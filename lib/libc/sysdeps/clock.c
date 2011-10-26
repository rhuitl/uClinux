#include <sys/time.h>
#include <sys/times.h>

clock_t clock(void)
{
	return times( 0 );
}
