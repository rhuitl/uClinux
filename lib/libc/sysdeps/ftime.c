#include <sys/time.h>
#include <sys/timeb.h>

int
ftime( struct timeb * tp )
{
	int RetVal = 0;
	struct timeval tv;

	if( !( RetVal = gettimeofday( &tv, 0 ) ) )
	{
		tp->time	= tv.tv_sec;
		tp->millitm	= tv.tv_usec / 1000;
	}

	return RetVal;
}
