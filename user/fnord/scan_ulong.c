#include "scan.h"

unsigned int scan_ulong(const char *src,unsigned long *dest) {
  register const char *tmp=src;
  register int l=0;
  register unsigned char c;
  while ((c=*tmp-'0')<10) {
    l=l*10+c;
    ++tmp;
  }
  *dest=l;
  return tmp-src;
}
