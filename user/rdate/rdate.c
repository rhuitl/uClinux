/*
    Copyright (C) 2000 Red Hat, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/
/* By Elliot Lee <sopwith@redhat.com>, because some guy didn't bother
   to put a copyright/license on the previous rdate. See bugzilla.redhat.com, bug #8619. */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>

/* difference between Unix time and net time */
#define BASE1970	2208988800L
#define DEFAULT_PORT    37

#ifdef EMBED
static const char *program_invocation_short_name;
#endif

static int
rdate(const char *hostname, time_t *retval)
{
  struct servent *sent;
  struct sockaddr_in saddr;
  int fd;
  unsigned char time_buf[4];
  int nr, n_toread;

  assert(hostname);
  assert(retval);

  saddr.sin_family = AF_INET;

  if(!inet_aton(hostname, &saddr.sin_addr))
    {
      struct hostent *hent;

      hent = gethostbyname(hostname);
      if(!hent)
	{
	  fprintf(stderr, "%s: Unknown host %s: %s\n", program_invocation_short_name, hostname, hstrerror(h_errno));
	  return -1;
	}

      assert(hent->h_addrtype == AF_INET);
      memcpy(&saddr.sin_addr, hent->h_addr_list[0], hent->h_length);
    }

  if((sent = getservbyname("time", "tcp")))
    saddr.sin_port = sent->s_port;      
  else
    saddr.sin_port = htons(DEFAULT_PORT);

  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(fd < 0)
    {
      fprintf(stderr, "%s: couldn't create socket: %s\n", program_invocation_short_name, strerror(errno));
      return -1;
    }

  if(connect(fd, (struct sockaddr *)&saddr, sizeof(saddr)))
    {
      fprintf(stderr, "%s: couldn't connect to host %s: %s\n", program_invocation_short_name, hostname, strerror(errno));
      close(fd);
      return -1;
    }

  for(n_toread = sizeof(time_buf), nr = 1; nr > 0 && n_toread > 0; n_toread -= nr)
    nr = read(fd, time_buf + sizeof(time_buf) - n_toread, n_toread);
  if(n_toread)
    {
      if(nr)
	fprintf(stderr, "%s: error in read: %s\n", program_invocation_short_name, strerror(errno));
      else
	fprintf(stderr, "%s: got EOF from time server\n", program_invocation_short_name);
      close(fd);

      return -1;
    }

  /* See inetd's builtins.c for an explanation */
  *retval = (time_t)(ntohl(*(uint32_t *)time_buf) - 2208988800UL);

  return 0;
}

static void
usage(int iserr)
{
  fprintf(stderr, "Usage: %s [-s] [-p] <host> ...\n", program_invocation_short_name);
  exit(iserr?1:0);
}

int main(int argc, char *argv[])
{
  int i;
  int print_mode = 0, set_mode = 0;
  char **hosts = NULL;
  int nhosts = 0;
  int retval = 0;
  int success = 0;
  
#ifdef EMBED
  program_invocation_short_name = argv[0];
#endif
  for(i = 1; i < argc; i++)
    {
      switch(argv[i][0])
	{
	case '-':
	  switch(argv[i][1])
	    {
	    case 's':
	      set_mode = 1;
	      break;
	    case 'p':
	      print_mode = 1;
	      break;
	    case 'h':
	    case '?':
	      usage(0);
	      break;
	    default:
	      fprintf(stderr, "Unknown option %s\n", argv[i]);
	      break;
	    }
	  break;
	default:
	  hosts = realloc(hosts, sizeof(char *) * nhosts+1);
	  hosts[nhosts++] = argv[i];
	  break;
	}
    }

  if(!set_mode && !print_mode)
    print_mode = 1;

  for(i = 0; i < nhosts; i++)
    {
      time_t timeval;
      if(!rdate(hosts[i], &timeval))
	{
	  /* keep track of the succesful request */
	  success = 1;
	  
	  if(print_mode)
	    printf("[%s]\t%s", hosts[i], ctime(&timeval) /* ctime includes a trailing \n */);

	  /* Do specified action(s) */
	  if(set_mode && stime(&timeval) < 0)
	    {
	      fprintf(stderr, "%s: could not set system time: %s\n", program_invocation_short_name, strerror(errno));
	      retval = 1;
	      break;
	    }
	  set_mode = 0;
	}
    }

  if(!nhosts)
    usage(1);

  if (!retval && !success) retval = 1;
  return retval;
}

