/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003,2004,2005  Aymeric MOIZARD jack@atosc.org
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifdef _WIN32_WCE
#define _INC_TIME		/* for wce.h */
#include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <osipparser2/osip_port.h>

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#include <time.h>

#if defined(__VXWORKS_OS__)
#include <selectLib.h>

/* needed for snprintf replacement */
#include <vxWorks.h>
#include <fioLib.h>
#include <string.h>

#elif (!defined(WIN32) && !defined(_WIN32_WCE))
#include <sys/time.h>
#elif defined(WIN32)
#include <windows.h>
#ifdef WIN32_USE_CRYPTO
#include <Wincrypt.h>
#endif
#endif

#if defined (HAVE_SYS_UNISTD_H)
#  include <sys/unistd.h>
#endif

#if defined (HAVE_UNISTD_H)
#  include <unistd.h>
#endif

#if defined (HAVE_SYSLOG_H)
#  include <syslog.h>
#endif

#if defined (HAVE_SYS_SELECT_H)
#  include <sys/select.h>
#endif

#ifdef HAVE_PTH_PTHREAD_H
#include <pthread.h>
#endif


FILE *logfile = NULL;
int tracing_table[END_TRACE_LEVEL];
static int use_syslog = 0;
static osip_trace_func_t *trace_func = 0;

static unsigned int random_seed_set = 0;

#ifndef WIN32
osip_malloc_func_t  *osip_malloc_func = 0;
osip_realloc_func_t *osip_realloc_func = 0;
osip_free_func_t    *osip_free_func = 0;
#endif

#ifndef WIN32_USE_CRYPTO
unsigned int
osip_build_random_number ()
#else
static unsigned int
osip_fallback_random_number ()
#endif
{
  if (!random_seed_set)
    {
      unsigned int ticks;
#ifdef WIN32
      LARGE_INTEGER lCount;
      QueryPerformanceCounter(&lCount);
      ticks = lCount.LowPart + lCount.HighPart;
#elif defined(_WIN32_WCE)
      ticks = GetTickCount();
#elif defined(__VXWORKS_OS__)
      struct timespec tp;
      clock_gettime(CLOCK_REALTIME, &tp);
      ticks = tp.tv_sec+tp.tv_nsec;
#else
      struct timeval tv;
      int fd;
      gettimeofday (&tv, NULL);
      ticks = tv.tv_sec + tv.tv_usec;
      fd=open("/dev/urandom",O_RDONLY);
      if (fd > 0)
	{
          unsigned int r;
	  int i;
          for (i=0;i<512;i++)
	    {
	      read(fd, &r, sizeof(r));
	      ticks += r;
	    }
	  close(fd);
	}
#endif

#ifdef HAVE_LRAND48
      srand48 (ticks);
#else
      srand (ticks);
#endif
      random_seed_set = 1;
    }

#ifdef HAVE_LRAND48
  return lrand48 ();
#else
  return rand ();
#endif
}

#ifdef WIN32_USE_CRYPTO

unsigned int
osip_build_random_number ()
{
  HCRYPTPROV crypto;
  BOOL err;
  unsigned int num;

  err =
    CryptAcquireContext (&crypto, NULL, NULL, PROV_RSA_FULL,
			 CRYPT_VERIFYCONTEXT);
  if (err)
    {
      err = CryptGenRandom (crypto, sizeof (num), (BYTE *) & num);
      CryptReleaseContext (crypto, 0);
    }
  if (!err)
    {
      num = osip_fallback_random_number ();
    }
  return num;
}

#endif

#if defined(__linux)
#include <limits.h>
#endif

int
osip_atoi (const char *number)
{
#if defined(__linux) || defined(HAVE_STRTOL)
  int i;
  if (number == NULL)
    return -1;
  i = strtol (number, (char **) NULL, 10);
  if (i == LONG_MIN || i == LONG_MAX)
    return -1;
  return i;
#endif

  return atoi (number);
}

char *
osip_strncpy (char *dest, const char *src, size_t length)
{
  strncpy (dest, src, length);
  dest[length] = '\0';
  return dest;
}

/* append string_osip_to_append to string at position cur
   size is the current allocated size of the element
*/
char *
__osip_sdp_append_string (char *string, size_t size, char *cur,
			  char *string_osip_to_append)
{
  size_t length = strlen (string_osip_to_append);

  if (cur - string + length > size)
    {
      size_t length2;

      length2 = cur - string;
      string = osip_realloc (string, size + length + 10);
      cur = string + length2;	/* the initial allocation may have changed! */
    }
  osip_strncpy (cur, string_osip_to_append, length);
  return cur + strlen (cur);
}

void
osip_usleep (int useconds)
{
#ifdef WIN32
  Sleep (useconds / 1000);
#else
  struct timeval delay;
  int sec;

  sec = (int) useconds / 1000000;
  if (sec > 0)
    {
      delay.tv_sec = sec;
      delay.tv_usec = 0;
    }
  else
    {
      delay.tv_sec = 0;
      delay.tv_usec = useconds;
    }
  select (0, 0, 0, 0, &delay);
#endif
}

#undef osip_strdup

char *
osip_strdup (const char *ch)
{
  char *copy;
  size_t length;
  if (ch == NULL)
    return NULL;
  length = strlen (ch);
  copy = (char *) osip_malloc (length + 1);
  osip_strncpy (copy, ch, length);
  return copy;
}

char *
osip_strdup_without_quote (const char *ch)
{
  char *copy = (char *) osip_malloc (strlen (ch) + 1);

  /* remove leading and trailing " */
  if ((*ch == '\"'))
    {
      osip_strncpy (copy, ch + 1, strlen (ch + 1));
      osip_strncpy (copy + strlen (copy) - 1, "\0", 1);
    }
  else
    osip_strncpy (copy, ch, strlen (ch));
  return copy;
}

int
osip_tolower (char *word)
{
#ifdef HAVE_CTYPE_H
  for (; *word; word++)
    *word = (char) tolower (*word);
#else
  size_t i;
  size_t len = strlen (word);

  for (i = 0; i <= len - 1; i++)
    {
      if ('A' <= word[i] && word[i] <= 'Z')
	word[i] = word[i] + 32;
    }
#endif
  return 0;
}

int
osip_strcasecmp (const char *s1, const char *s2)
{
#if defined(__VXWORKS_OS__)
  while ( (*s1 != '\0') && (tolower(*s1) == tolower(*s2)) )
  {
    s1++;
    s2++;
  }
  return (tolower(*s1) - tolower(*s2));
#elif (!defined WIN32 && !defined _WIN32_WCE)
  return strcasecmp (s1, s2);
#else
  return _stricmp (s1, s2);
#endif
}

int
osip_strncasecmp (const char *s1, const char *s2, size_t len)
{
#if defined(__VXWORKS_OS__)
  if ( len == 0 ) return 0;
  while ( (len > 0) && (tolower(*s1) == tolower(*s2)) )
  {
    len--;
    if ( (len == 0) || (*s1 == '\0') || (*s2 == '\0') )
            break;
    s1++;
    s2++;
  }
  return tolower(*s1) - tolower(*s2);
#elif (!defined WIN32 && !defined _WIN32_WCE)
  return strncasecmp (s1, s2, len);
#else
  return _strnicmp (s1, s2, len);
#endif
}

/* remove SPACE before and after the content */
int
osip_clrspace (char *word)
{
  char *pbeg;
  char *pend;
  size_t len;

  if (word == NULL)
    return -1;
  if (*word == '\0')
    return 0;
  len = strlen (word);

  pbeg = word;
  while ((' ' == *pbeg) || ('\r' == *pbeg) || ('\n' == *pbeg)
	 || ('\t' == *pbeg))
    pbeg++;

  pend = word + len - 1;
  while ((' ' == *pend) || ('\r' == *pend) || ('\n' == *pend)
	 || ('\t' == *pend))
    {
      pend--;
      if (pend < pbeg)
	{
	  *word = '\0';
	  return 0;
	}
    }

  /* Add terminating NULL only if we've cleared room for it */
  if (pend + 1 <= word + (len - 1))
    pend[1] = '\0';

  if (pbeg != word)
    memmove (word, pbeg, pend - pbeg + 2);

  return 0;
}

/* __osip_set_next_token:
   dest is the place where the value will be allocated
   buf is the string where the value is searched
   end_separator is the character that MUST be found at the end of the value
   next is the final location of the separator + 1

   the element MUST be found before any "\r" "\n" "\0" and
   end_separator

   return -1 on error
   return 1 on success
*/
int
__osip_set_next_token (char **dest, char *buf, int end_separator, char **next)
{
  char *sep;			/* separator */

  *next = NULL;

  sep = buf;
  while ((*sep != end_separator) && (*sep != '\0') && (*sep != '\r')
	 && (*sep != '\n'))
    sep++;
  if ((*sep == '\r') || (*sep == '\n'))
    {				/* we should continue normally only if this is the separator asked! */
      if (*sep != end_separator)
	return -1;
    }
  if (*sep == '\0')
    return -1;			/* value must not end with this separator! */
  if (sep == buf)
    return -1;			/* empty value (or several space!) */

  *dest = osip_malloc (sep - (buf) + 1);
  osip_strncpy (*dest, buf, sep - buf);

  *next = sep + 1;		/* return the position right after the separator */
  return 0;
}

#if 0
/*  not yet done!!! :-)
 */
int
__osip_set_next_token_better (char **dest, char *buf, int end_separator,
			      int *forbidden_tab[], int size_tab, char **next)
{
  char *sep;			/* separator */

  *next = NULL;

  sep = buf;
  while ((*sep != end_separator) && (*sep != '\0') && (*sep != '\r')
	 && (*sep != '\n'))
    sep++;
  if ((*sep == '\r') && (*sep == '\n'))
    {				/* we should continue normally only if this is the separator asked! */
      if (*sep != end_separator)
	return -1;
    }
  if (*sep == '\0')
    return -1;			/* value must not end with this separator! */
  if (sep == buf)
    return -1;			/* empty value (or several space!) */

  *dest = osip_malloc (sep - (buf) + 1);
  osip_strncpy (*dest, buf, sep - buf);

  *next = sep + 1;		/* return the position right after the separator */
  return 1;
}
#endif

/* in quoted-string, many characters can be escaped...   */
/* __osip_quote_find returns the next quote that is not escaped */
char *
__osip_quote_find (const char *qstring)
{
  char *quote;

  quote = strchr (qstring, '"');
  if (quote == qstring)		/* the first char matches and is not escaped... */
    return quote;

  if (quote == NULL)
    return NULL;		/* no quote at all... */

  /* this is now the nasty cases where '"' is escaped
     '" jonathan ros \\\""'
     |                  |
     '" jonathan ros \\"'
     |                |
     '" jonathan ros \""'
     |                |
     we must count the number of preceeding '\' */
  {
    int i = 1;

    for (;;)
      {
	if (0 == strncmp (quote - i, "\\", 1))
	  i++;
	else
	  {
	    if (i % 2 == 1)	/* the '"' was not escaped */
	      return quote;

	    /* else continue with the next '"' */
	    quote = strchr (quote + 1, '"');
	    if (quote == NULL)
	      return NULL;
	    i = 1;
	  }
	if (quote - i == qstring - 1)
	  /* example: "\"john"  */
	  /* example: "\\"jack" */
	  {
	    /* special case where the string start with '\' */
	    if (*qstring == '\\')
	      i++;		/* an escape char was not counted */
	    if (i % 2 == 0)	/* the '"' was not escaped */
	      return quote;
	    else
	      {			/* else continue with the next '"' */
		qstring = quote + 1;	/* reset qstring because
					   (*quote+1) may be also == to '\\' */
		quote = strchr (quote + 1, '"');
		if (quote == NULL)
		  return NULL;
		i = 1;
	      }

	  }
      }
    return NULL;
  }
}

char *
osip_enquote (const char *s)
{
  char *rtn;
  char *t;

  t = rtn = osip_malloc (strlen (s) * 2 + 3);
  *t++ = '"';
  for (; *s != '\0'; s++)
    {
      switch (*s)
	{
	case '"':
	case '\\':
	case 0x7f:
	  *t++ = '\\';
	  *t++ = *s;
	  break;
	case '\n':
	case '\r':
	  *t++ = ' ';
	  break;
	default:
	  *t++ = *s;
	  break;
	}
    }
  *t++ = '"';
  *t++ = '\0';
  return rtn;
}

void
osip_dequote (char *s)
{
  size_t len;

  if (*s == '\0')
    return;
  if (*s != '"')
    return;
  len = strlen (s);
  memmove (s, s + 1, len--);
  if (len > 0 && s[len - 1] == '"')
    s[--len] = '\0';
  for (; *s != '\0'; s++, len--)
    {
      if (*s == '\\')
	memmove (s, s + 1, len--);
    }
}

/**********************************************************/
/* only MACROS from osip/trace.h should be used by others */
/* TRACE_INITIALIZE(level,file))                          */
/* TRACE_ENABLE_LEVEL(level)                              */
/* TRACE_DISABLE_LEVEL(level)                             */
/* IS_TRACE_LEVEL_ACTIVATE(level)                         */
/**********************************************************/
#ifndef ENABLE_TRACE
void
osip_trace_initialize_func (osip_trace_level_t level, osip_trace_func_t *func)
{
}
void
osip_trace_initialize_syslog (osip_trace_level_t level, char *ident)
{
}
void
osip_trace_initialize (osip_trace_level_t level, FILE * file)
{
}
void
osip_trace_enable_level (osip_trace_level_t level)
{
}
void
osip_trace_disable_level (osip_trace_level_t level)
{
}

int
osip_is_trace_level_activate (osip_trace_level_t level)
{
  return LOG_FALSE;
}

#else

/* initialize log */
/* all lower levels of level are logged in file. */
void
osip_trace_initialize (osip_trace_level_t level, FILE * file)
{
  osip_trace_level_t i = 0;

  /* enable trace in log file by default */
  logfile = NULL;
  if (file != NULL)
    logfile = file;
#ifndef SYSTEM_LOGGER_ENABLED
  else
    logfile = stdout;
#endif

  /* enable all lower levels */
  while (i < END_TRACE_LEVEL)
    {
      if (i < level)
	tracing_table[i] = LOG_TRUE;
      else
	tracing_table[i] = LOG_FALSE;
      i++;
    }
}

void
osip_trace_initialize_syslog (osip_trace_level_t level, char *ident)
{
  osip_trace_level_t i = 0;
#if defined (HAVE_SYSLOG_H)
  openlog (ident, LOG_CONS | LOG_PID, LOG_DAEMON);
  use_syslog = 1;
#endif
  /* enable all lower levels */
  while (i < END_TRACE_LEVEL)
    {
      if (i < level)
	tracing_table[i] = LOG_TRUE;
      else
	tracing_table[i] = LOG_FALSE;
      i++;
    }
}

void
osip_trace_enable_until_level (osip_trace_level_t level)
{
  int i = 0;
  while (i < END_TRACE_LEVEL)
    {
      if (i < level)
	tracing_table[i] = LOG_TRUE;
      else
	tracing_table[i] = LOG_FALSE;
      i++;
    }
}

void
osip_trace_initialize_func (osip_trace_level_t level, osip_trace_func_t *func)
{
  int i = 0;
  trace_func = func;

  /* enable all lower levels */
  while (i < END_TRACE_LEVEL)
    {
      if (i < level)
	tracing_table[i] = LOG_TRUE;
      else
	tracing_table[i] = LOG_FALSE;
      i++;
    }
}

/* enable a special debugging level! */
void
osip_trace_enable_level (osip_trace_level_t level)
{
  tracing_table[level] = LOG_TRUE;
}

/* disable a special debugging level! */
void
osip_trace_disable_level (osip_trace_level_t level)
{
  tracing_table[level] = LOG_FALSE;
}

/* not so usefull? */
int
osip_is_trace_level_activate (osip_trace_level_t level)
{
  return tracing_table[level];
}
#endif

int
osip_trace (char *fi, int li, osip_trace_level_t level, FILE * f, char *chfr,
	    ...)
{
#ifdef ENABLE_TRACE
  va_list ap;

#if !defined(WIN32) && !defined(SYSTEM_LOGGER_ENABLED)
  if (logfile == NULL && use_syslog == 0 && trace_func == NULL)
    {				/* user did not initialize logger.. */
      return 1;
    }
#endif

  if (tracing_table[level] == LOG_FALSE)
    return 0;

  if (f == NULL && trace_func == NULL)
    f = logfile;

  VA_START (ap, chfr);

#ifdef __VXWORKS_OS__
  /* vxworks can't have a local file */
  f = stdout;
#endif

  if (f && use_syslog == 0)
    {
      if (level == OSIP_FATAL)
	fprintf (f, "| FATAL | <%s: %i> ", fi, li);
      else if (level == OSIP_BUG)
	fprintf (f, "|  BUG  | <%s: %i> ", fi, li);
      else if (level == OSIP_ERROR)
	fprintf (f, "| ERROR | <%s: %i> ", fi, li);
      else if (level == OSIP_WARNING)
	fprintf (f, "|WARNING| <%s: %i> ", fi, li);
      else if (level == OSIP_INFO1)
	fprintf (f, "| INFO1 | <%s: %i> ", fi, li);
      else if (level == OSIP_INFO2)
	fprintf (f, "| INFO2 | <%s: %i> ", fi, li);
      else if (level == OSIP_INFO3)
	fprintf (f, "| INFO3 | <%s: %i> ", fi, li);
      else if (level == OSIP_INFO4)
	fprintf (f, "| INFO4 | <%s: %i> ", fi, li);

      vfprintf (f, chfr, ap);

      fflush (f);
    }
  else if (trace_func) 
    {
      trace_func(fi, li, level, chfr, ap);
    }
#if defined (HAVE_SYSLOG_H)
  else if (use_syslog == 1)
    {
      char buffer[512];
      int in = 0;
      memset (buffer, 0, sizeof (buffer));
      if (level == OSIP_FATAL)
	in = snprintf (buffer, 511, "| FATAL | <%s: %i> ", fi, li);
      else if (level == OSIP_BUG)
	in = snprintf (buffer, 511, "|  BUG  | <%s: %i> ", fi, li);
      else if (level == OSIP_ERROR)
	in = snprintf (buffer, 511, "| ERROR | <%s: %i> ", fi, li);
      else if (level == OSIP_WARNING)
	in = snprintf (buffer, 511, "|WARNING| <%s: %i> ", fi, li);
      else if (level == OSIP_INFO1)
	in = snprintf (buffer, 511, "| INFO1 | <%s: %i> ", fi, li);
      else if (level == OSIP_INFO2)
	in = snprintf (buffer, 511, "| INFO2 | <%s: %i> ", fi, li);
      else if (level == OSIP_INFO3)
	in = snprintf (buffer, 511, "| INFO3 | <%s: %i> ", fi, li);
      else if (level == OSIP_INFO4)
	in = snprintf (buffer, 511, "| INFO4 | <%s: %i> ", fi, li);

      vsnprintf (buffer + in, 511 - in, chfr, ap);
      if (level == OSIP_FATAL)
	syslog (LOG_ERR, "%s", buffer);
      else if (level == OSIP_BUG)
	syslog (LOG_ERR, "%s", buffer);
      else if (level == OSIP_ERROR)
	syslog (LOG_ERR, "%s", buffer);
      else if (level == OSIP_WARNING)
	syslog (LOG_WARNING, "%s", buffer);
      else if (level == OSIP_INFO1)
	syslog (LOG_INFO, "%s", buffer);
      else if (level == OSIP_INFO2)
	syslog (LOG_INFO, "%s", buffer);
      else if (level == OSIP_INFO3)
	syslog (LOG_DEBUG, "%s", buffer);
      else if (level == OSIP_INFO4)
	syslog (LOG_DEBUG, "%s", buffer);
    }
#endif
#ifdef SYSTEM_LOGGER_ENABLED
  else
    {
      char buffer[512];
      int in = 0;
      memset (buffer, 0, sizeof (buffer));
      if (level == OSIP_FATAL)
	in = _snprintf (buffer, 511, "| FATAL | <%s: %i> ", fi, li);
      else if (level == OSIP_BUG)
	in = _snprintf (buffer, 511, "|  BUG  | <%s: %i> ", fi, li);
      else if (level == OSIP_ERROR)
	in = _snprintf (buffer, 511, "| ERROR | <%s: %i> ", fi, li);
      else if (level == OSIP_WARNING)
	in = _snprintf (buffer, 511, "|WARNING| <%s: %i> ", fi, li);
      else if (level == OSIP_INFO1)
	in = _snprintf (buffer, 511, "| INFO1 | <%s: %i> ", fi, li);
      else if (level == OSIP_INFO2)
	in = _snprintf (buffer, 511, "| INFO2 | <%s: %i> ", fi, li);
      else if (level == OSIP_INFO3)
	in = _snprintf (buffer, 511, "| INFO3 | <%s: %i> ", fi, li);
      else if (level == OSIP_INFO4)
	in = _snprintf (buffer, 511, "| INFO4 | <%s: %i> ", fi, li);

      _vsnprintf (buffer + in, 511 - in, chfr, ap);
      OutputDebugString (buffer);
    }
#endif

  va_end (ap);
#endif
  return 0;
}



#ifdef WIN32

#undef osip_malloc
void *osip_malloc(size_t size)
{
  void *ptr = malloc(size);
  if(ptr!=NULL)
    memset(ptr,0,size);
  return ptr;
}

#undef osip_realloc
void *osip_realloc(void *ptr, size_t size)
{
  return realloc(ptr, size);
}

#undef osip_free
void osip_free(void *ptr)
{
  if (ptr==NULL) return;
  free(ptr);
}

#else

void osip_set_allocators(osip_malloc_func_t  *malloc_func, 
                         osip_realloc_func_t *realloc_func, 
                         osip_free_func_t    *free_func)
{
    osip_malloc_func = malloc_func;
    osip_realloc_func = realloc_func;
    osip_free_func = free_func;
}

#endif

#if defined(__VXWORKS_OS__)

typedef struct
{
  char* str;
  int   max;
  int   len;
} _context;

STATUS _cb_snprintf( char* buffer, int nc, int arg );

STATUS _cb_snprintf( char* buffer, int nc, int arg )
{
  _context *ctx = (_context*)arg;
  
  if( ctx->max - ctx->len - nc < 1 ) /* retain 1 pos for terminating \0 */
  {
    nc = ctx->max - ctx->len - 1;
  }
 
  if( nc > 0 )
  {
    memcpy( ctx->str + ctx->len, buffer, nc );
    ctx->len += nc;
  }

  ctx->str[ctx->len] = '\0';

  return OK;
}


int osip_vsnprintf( char* buf, int max, const char *fmt, va_list ap )
{
  _context ctx;  
  ctx.str = buf;
  ctx.max = max;
  ctx.len = 0;

  if( fioFormatV( fmt, ap, _cb_snprintf, (int)&ctx ) != OK )
  {
    return -1;
  }

  return ctx.len;
}

int osip_snprintf( char* buf, int max, const char* fmt, ... )
{
  int retval;
  va_list ap;
  va_start( ap, fmt );
  retval = osip_vsnprintf( buf, max, fmt, ap );
  va_end( ap );
  return retval;
}

#endif
