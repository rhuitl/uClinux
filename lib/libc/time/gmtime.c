
#include <time.h>

struct tm *
gmtime(timep)
__const time_t * timep;
{
#ifdef INCLUDE_TIMEZONE
   extern struct tm _tmbuf;
   extern struct tm *__tz_convert (const time_t *, int, struct tm *);
   return __tz_convert (timep, 0, &_tmbuf);
#else
   static struct tm tmb;
   extern void __tm_conv();

   __tm_conv(&tmb, timep, 0L);

   return &tmb;
#endif
}

