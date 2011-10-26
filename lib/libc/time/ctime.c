
#include <time.h>

char *
ctime(timep)
__const time_t * timep;
{
  /* The C Standard says ctime (t) is equivalent to asctime (localtime (t)).
     In particular, ctime and asctime must yield the same pointer.  */
  return asctime (localtime (timep));
}
