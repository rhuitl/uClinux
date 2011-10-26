

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

void usleep(unsigned long usec)
{
	struct timeval tv;
	tv.tv_sec = usec / 1000000;
	tv.tv_usec = usec % 1000000;
	select(0,0,0,0, &tv);
}

int sleep(unsigned int sec)
{
	struct timeval tv;
	tv.tv_sec = sec;
	tv.tv_usec = 0;
	select(0,0,0,0, &tv);
	return tv.tv_sec;
}