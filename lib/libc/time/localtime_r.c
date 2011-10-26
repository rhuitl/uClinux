
#include <time.h>

struct tm *
localtime_r(timep, tp)
__const time_t * timep;
struct tm * tp;
{
#ifdef INCLUDE_TIMEZONE
   extern struct tm *__tz_convert (const time_t *, int, struct tm *);
   return __tz_convert (timep, 1, tp);
#else
   extern void __tm_conv();
   struct timezone tz;
   time_t offt;

   gettimeofday((void*)0, &tz);

   offt = -tz.tz_minuteswest*60L;

   /* tmb.tm_isdst = ? */
   __tm_conv(tp, timep, offt);

   return tp;
#endif
}
