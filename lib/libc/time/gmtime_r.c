
#include <time.h>

struct tm *
gmtime_r(timep, tp)
__const time_t * timep;
struct tm * tp;
{
#ifdef INCLUDE_TIMEZONE
  extern struct tm *__tz_convert (const time_t *, int, struct tm *);
  return __tz_convert (timep, 0, tp);
#else
  extern void __tm_conv();

   __tm_conv(tp, timep, 0L);
   return tp;
#endif
}

