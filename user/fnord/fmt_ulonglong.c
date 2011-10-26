#include "fmt.h"

unsigned int fmt_ulonglong(char *dest,unsigned long long i) {
  register unsigned long len,len2;
  register unsigned long long tmp;
  /* first count the number of bytes needed */
  for (len=1, tmp=i; tmp>9; ++len) tmp/=10;
  if (dest)
    for (tmp=i, dest+=len, len2=len+1; --len2; tmp/=10)
      *--dest = (tmp%10)+'0';
  return len;
}
