/* A slightly more convenient wrapper for gethostname

   Copyright (C) 1996, 1997, 2000 Free Software Foundation, Inc.

   Written by Miles Bader <miles@gnu.ai.mit.edu>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#if defined(STDC_HEADERS) || defined(HAVE_STDLIB_H)
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#if __STDC__
# define VOID void
#else
# define VOID char
#endif
extern VOID *xrealloc __P((VOID *p, size_t n));

/* Return the name of the localhost.  This is just a wrapper for gethostname,
   which takes care of allocating a big enough buffer, and caches the result
   after the first call (so the result should be copied before modification).
   If something goes wrong, 0 is returned, and errno set.  */
/* We know longer use static buffers, is to dangerous and
   cause subtile bugs.  */
char *
localhost (void)
{
  char *buf = NULL;
  size_t buf_len = 0;
  int status = 0;

  do
    {
      char *tmp;
      errno = 0;

      buf_len += 256;	/* Initial guess */
      tmp = xrealloc (buf, buf_len);

      if (tmp == NULL)
	{
	  errno = ENOMEM;
          free (buf);
	  return 0;
	}
      else
         buf = tmp;
    } while (((status = gethostname(buf, buf_len)) == 0 && !memchr (buf, '\0', buf_len))
#ifdef ENAMETOOLONG
	     || errno == ENAMETOOLONG
#endif
	     );

  if (status != 0 && errno != 0)
    /* gethostname failed, abort.  */
    {
      free (buf);
      buf = 0;
    }

  /* Determine FQDN */
  {
    struct hostent *hp = gethostbyname(buf);

    if (hp)
      {
	struct in_addr addr;
	addr.s_addr = *(unsigned int*) hp->h_addr;
	hp = gethostbyaddr((char *) &addr, sizeof(addr), AF_INET);
	if (hp)
	  {
	    free(buf);
	    buf = strdup(hp->h_name);
	  }
      }
  }
  return buf;
}
