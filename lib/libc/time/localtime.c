
#include <time.h>

#ifdef INCLUDE_TIMEZONE
struct tm _tmbuf;
#endif

struct tm *
localtime(timep)
__const time_t * timep;
{
#ifdef INCLUDE_TIMEZONE
   extern struct tm *__tz_convert (const time_t *, int, struct tm *);
   return __tz_convert (timep, 1, &_tmbuf);
#else
   static struct tm tmb;
   struct timezone tz;
   time_t offt;
   extern void __tm_conv();

   gettimeofday((void*)0, &tz);

   offt = -tz.tz_minuteswest*60L;

   /* tmb.tm_isdst = ? */
   __tm_conv(&tmb, timep, offt);

   return &tmb;
#endif
}
