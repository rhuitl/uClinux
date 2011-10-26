#include "str.h"

unsigned int str_len(const char *in) {
  register const char* t=in;
  for (;;) {
    if (!*t) break; ++t;
    if (!*t) break; ++t;
    if (!*t) break; ++t;
    if (!*t) break; ++t;
  }
  return t-in;
}
