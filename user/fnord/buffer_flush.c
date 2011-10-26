#include "buffer.h"

extern int buffer_stubborn(int (*op)(),int fd,const char* buf, unsigned int len);

extern int buffer_flush(buffer* b) {
  register int p;
  if (!(p=b->p)) return 0; /* buffer already empty */
  b->p=0;
  return buffer_stubborn(b->op,b->fd,b->x,p);
}
