
#include <time.h>

extern void __asctime();

char *
asctime_r(timeptr, buf)
__const struct tm * timeptr;
char * buf;
{

   if( timeptr == 0 ) return 0;
   __asctime(buf, timeptr);
   return buf;
}
