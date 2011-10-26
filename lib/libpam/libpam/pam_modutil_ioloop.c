/*
 * $Id: pam_modutil_ioloop.c,v 1.1 2005/09/21 10:00:58 t8m Exp $
 *
 * These functions provides common methods for ensure a complete read or
 * write occurs. It handles EINTR and partial read/write returns.
 */

#include "pam_modutil_private.h"

#include <unistd.h>
#include <errno.h>

int
pam_modutil_read(int fd, char *buffer, int count)
{
       int block, offset = 0;

       while (count > 0) {
               block = read(fd, &buffer[offset], count);

               if (block < 0) {
                       if (errno == EINTR) continue;
                       return block;
               }
               if (block == 0) return offset;

               offset += block;
               count -= block;
       }

       return offset;
}

int
pam_modutil_write(int fd, const char *buffer, int count)
{
       int block, offset = 0;

       while (count > 0) {
               block = write(fd, &buffer[offset], count);

               if (block < 0) {
                       if (errno == EINTR) continue;
                       return block;
               }
               if (block == 0) return offset;

               offset += block;
               count -= block;
       }

       return offset;
}
