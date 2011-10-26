
#include <time.h>

extern void __tm_conv();
extern void __asctime();

char *
ctime_r(timep, buf)
__const time_t * timep;
char * buf;
{
  struct tm tmb;
  struct timezone tz;
  time_t offt;
  
  gettimeofday((void*)0, &tz);
  
  offt = -tz.tz_minuteswest*60L;
  
  /* tmb.tm_isdst = ? */
  __tm_conv(&tmb, timep, offt);
  
  __asctime(buf, &tmb);
  
  return buf;
}
