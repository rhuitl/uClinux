/*
 * Code to handle preloading of entries into the dnsmasq cache.
 *
 * Chris Pascoe - Secure Computing 2006
 */

#include "dnsmasq.h"

#ifdef DO_PRELOAD

#define PARALLEL_PRELOAD_LOOKUPS 4
#define PRELOAD_QUERY_TIMEOUT (2.0)	/* Individual query timeout */
#define PRELOAD_RECHECK_DELAY (60.0)	/* How long do we wait between checks of the address list? */

char  *preload_lookup_slots[PARALLEL_PRELOAD_LOOKUPS];
time_t preload_lookup_times[PARALLEL_PRELOAD_LOOKUPS];
int    preload_lookups_pending = 0;

int    preload_fd = -1;
int    preload_lookup_sin_port = -1;
struct sockaddr_in preload_lookup_saddr;
char   preload_lookup_pbuf[MAXDNAME + 32 + sizeof(HEADER)];
int    preload_disabled = 0;
int    preload_addrlist_updated = 0;

void preload_notify(struct daemon *daemon)
{
  struct stat st;
  pid_t p;

  syslog(LOG_NOTICE, _("The preloaded address list was updated."));

  if (stat("/bin/preload_notify", &st) != 0)
    return;

  if ((p = fork()) != 0)
    {
      if (p != -1)
	{
	  int i;
	  for (i = 0; i < MAX_PROCS; i++)
	    if (daemon->tcp_pids[i] == 0)
	      {
		daemon->tcp_pids[i] = p;
		break;
	      }
	}
      return;
    }
  execl("/bin/preload_notify", "preload_notify", NULL);
}

int preload_lookup_search(char *name, int flush)
{
  int i;

  if (!name)
    return -1;

  for (i = 0; preload_lookups_pending && i < PARALLEL_PRELOAD_LOOKUPS; i++)
    if (preload_lookup_slots[i] != NULL && !strcmp(name, preload_lookup_slots[i]))
      {
	if (flush)
	  {
	    free(preload_lookup_slots[i]);
	    preload_lookup_slots[i] = NULL;
	    preload_lookups_pending--;
	  }
	return i;
      }

  return -1;
}

int preload_lookup(char *hn, time_t now)
{ 
  int i, hnlen = strlen(hn);
  float diff;
  static time_t last_slot_check;

  if (preload_lookups_pending == PARALLEL_PRELOAD_LOOKUPS && !((diff = difftime(last_slot_check, now)) < -1.0 || diff > 1.0))
    return -1;  /* No slots */

  for (i = 0; i < PARALLEL_PRELOAD_LOOKUPS; i++)
    {
      if (preload_lookup_slots[i] == NULL)
	break;
      diff = difftime(preload_lookup_times[i], now);
      if (diff < -PRELOAD_QUERY_TIMEOUT || diff > PRELOAD_QUERY_TIMEOUT)
	{
	  /* Query timed out.  Re-use slot. */
	  free(preload_lookup_slots[i]);
	  preload_lookup_slots[i] = NULL;
	  preload_lookups_pending--;
	  break;
	}
    }

  if (i >= PARALLEL_PRELOAD_LOOKUPS)
    {
      last_slot_check = now;
      return -2;  /* No slots */
    }

  preload_lookup_slots[i] = strdup(hn);
  if (preload_lookup_slots[i] == NULL)
    return -6;  /* No memory */

  preload_lookups_pending++;
  preload_lookup_times[i] = now;

  if (preload_fd < 0)
    {
       struct sockaddr_in oursock;
       socklen_t oursock_sz = sizeof(oursock);
       preload_fd = socket(AF_INET, SOCK_DGRAM, 0);
       if (preload_fd < 0 || !fix_fd(preload_fd))
	 return -3;  /* No fd */
   
       preload_lookup_saddr.sin_family = AF_INET;
       preload_lookup_saddr.sin_port = 0;
       preload_lookup_saddr.sin_addr.s_addr = htonl(0x7f000001);
#ifdef HAVE_SOCKADDR_SA_LEN
       preload_lookup_saddr.sin_len = sizeof(struct sockaddr_in);
#endif
   
       /* Bind our lookup connection to a random port */
       if (bind(preload_fd, (struct sockaddr *)&preload_lookup_saddr, sizeof(preload_lookup_saddr)) > 0)
	 {
	   perror("bind");
	   close(preload_fd);
	   preload_fd = -1;
	   return -3;  /* FD error */
	 }
       if (getsockname(preload_fd, (struct sockaddr *)&oursock, &oursock_sz))
	 {
	   perror("getsockname");
	   close(preload_fd);
	   preload_fd = -1;
	   return -3;  /* FD error */
	 }
       preload_lookup_sin_port = oursock.sin_port;

       preload_lookup_saddr.sin_port = htons(NAMESERVER_PORT);
       if (connect(preload_fd, (struct sockaddr *)&preload_lookup_saddr, sizeof(preload_lookup_saddr)) > 0)
	 {
	   perror("connect");
	   close(preload_fd);
	   preload_fd = -1;
	   return -3;  /* FD error */
	 }
    }

  if (hnlen < MAXDNAME)
    {
      HEADER *h = (HEADER *)preload_lookup_pbuf;
      char *lastcp = hn, *cp, *ptr = (char *)(h + 1);
      int ret;

      memset(h, 0, sizeof(HEADER));
      h->id = rand16();
      h->opcode = 0;
      h->rd = 1;
      h->qdcount = htons(1);

      while ((lastcp - hn) < hnlen)
	{
	  int slen;
    
	  cp = memchr(lastcp, '.', hnlen - (lastcp - hn));
	  if (!cp)
	    cp = hn + hnlen;
    
	  slen = cp - lastcp;
	  if (slen > 63)
	    return -4;  /* label too long */
	  if (slen == 0)
	    return -4;  /* zero length label is invalid */
    
	  *ptr++ = slen;
	  memcpy(ptr, lastcp, slen);
	  ptr += slen;
	  lastcp = cp + 1;
       }

      *ptr++ = 0; /* End label, len == 0 */
      *ptr++ = 0; *ptr++ = 1; /* Query type  == A  */
      *ptr++ = 0; *ptr++ = 1; /* Query class == IN */

      ret = send(preload_fd, preload_lookup_pbuf, (ptr - preload_lookup_pbuf), 0);
      if (ret < 0)
	return -5;  /* sendto failed */
    }

  return i;  /* slot number */
}

/* Preload hosts file into memory */
int do_preload(struct daemon *daemon, time_t now)
{
  static char fline[1025];
  static int fline_valid;
  struct crec *cr;
  int r, nreps = 0;

next_line:
  if (++nreps > 100)
    return 1;

  if (daemon->preload_stream && feof(daemon->preload_stream))
    {
      fclose(daemon->preload_stream);
      daemon->preload_stream = NULL;
    }
  if (daemon->preload_stream == NULL)
    {
      daemon->preload_stream = fopen(daemon->preload_file, "r");
      if (daemon->preload_stream == NULL)
	{
	  daemon->preload_last_poll = now;
	  return -1; /* No file */
	}
      daemon->preload_last_poll = 0;	/* in progress */
      fline_valid = 0;
    }

  if (!fline_valid && fgets(fline, sizeof(fline), daemon->preload_stream) == NULL)
    {
      daemon->preload_last_poll = now;
      return 0;
    }

  while (fline[strlen(fline) - 1] == '\n' || fline[strlen(fline) - 1] == '\r')
    fline[strlen(fline) - 1] = 0;

  /* Only valid DNS characters */
  if (strspn(fline, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/") != strlen(fline))
    goto next_line;

  /* Don't send A for A queries */
  if (strspn(fline, "0123456789.") == strlen(fline))
    goto next_line;

  /* Hostname must contain a . */
  if (!strchr(fline, '.'))
    goto next_line;

  /* Search for name in cache */
  cr = cache_find_by_name(NULL, fline, now, F_IPV4 | F_CNAME);
  if (cr != NULL)
    {
      /* Take host off pending lookup list. */
      r = preload_lookup_search(cache_get_name(cr), 1);

      /* Don't ever purge this result */
      cr->flags |= F_DONTPURGE;

      /* Don't trigger a relookup of the record if it hasn't yet expired. */
      if (!cache_is_expired_flags(now, cr, 0))
	{
	  fline_valid = 0;
	  goto next_line;
	}
    }

  r = preload_lookup(fline, now);
  if (r >= 0)  {
    fline_valid = 0;
  }	else {
    fline_valid = 1;
  }

  return 1;
}

void preload_drain(void)
{
  ssize_t t;

  while ((t = read(preload_fd, preload_lookup_pbuf, sizeof(preload_lookup_pbuf))) > 0)
    ;
}

void preload_tick(struct daemon *daemon, time_t now)
{
  float diff;

  if (daemon->preload_last_poll == 0 ||
      (diff = difftime(now, daemon->preload_last_poll)) >= PRELOAD_RECHECK_DELAY || diff < -PRELOAD_RECHECK_DELAY)
    {
      struct stat statbuf;

      if (stat(daemon->preload_file, &statbuf) == 0)
	{
	  if (statbuf.st_mtime != daemon->preload_file_mtime)
	    {
	      /* file updated */
	      if (daemon->preload_stream)
	        {
	          fclose(daemon->preload_stream);
	          daemon->preload_stream = NULL;
	          clear_cache_and_reload(now);
	        }
	      daemon->preload_file_mtime = statbuf.st_mtime;
	    }
	  do_preload(daemon, now);
	}
      else
	{
	  /* stat failed */
	  if (daemon->preload_last_poll == 0 || daemon->preload_file_mtime != 0)
	    syslog(LOG_WARNING, _("cannot access preload file %s: %s"), daemon->preload_file, strerror(errno));
	  if (daemon->preload_file_mtime)
	    {
	      if (daemon->preload_stream)
		{
		  fclose(daemon->preload_stream);
		  daemon->preload_stream = NULL;
		}
	      daemon->preload_file_mtime = 0;
	      clear_cache_and_reload(now);
	    }
	  daemon->preload_last_poll = now;
	}
    }
  else if (daemon->preload_last_poll != 0 && preload_addrlist_updated &&
	   ((diff = difftime(now, daemon->preload_last_poll)) > PRELOAD_QUERY_TIMEOUT || diff < -PRELOAD_QUERY_TIMEOUT))
    {
      preload_notify(daemon);
      preload_addrlist_updated = 0;
    }
}

#endif
