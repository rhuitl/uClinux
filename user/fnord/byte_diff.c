#include "byte.h"

/* byte_diff returns negative, 0, or positive, depending on whether the
 * string one[0], one[1], ..., one[len-1] is lexicographically smaller
 * than, equal to, or greater than the string one[0], one[1], ...,
 * one[len-1]. When the strings are different, byte_diff does not read
 * bytes past the first difference. */
int byte_diff(const void* a, unsigned int len, const void* b) {
  register const char* s=a;
  register const char* t=b;
  register const char* u=t+len;
  register int j;
  j=0;
  for (;;) {
    if (t==u) break; if ((j=(*s-*t))) break; ++s; ++t;
    if (t==u) break; if ((j=(*s-*t))) break; ++s; ++t;
    if (t==u) break; if ((j=(*s-*t))) break; ++s; ++t;
    if (t==u) break; if ((j=(*s-*t))) break; ++s; ++t;
  }
  return j;
}
