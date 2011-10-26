#include "str.h"

unsigned int str_copy(char *out,const char *in) {
  register char* s=out;
  register const char* t=in;
  for (;;) {
    if (!(*s=*t)) break; ++s; ++t;
    if (!(*s=*t)) break; ++s; ++t;
    if (!(*s=*t)) break; ++s; ++t;
    if (!(*s=*t)) break; ++s; ++t;
  }
  return s-out;
}
