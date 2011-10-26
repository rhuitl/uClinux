#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "camserv.h"
#include "log.h"

void camserv_log( const char *module, const char *pattern, ... ){
  char decent_buffer[ 1024 ], timebuf[ 1024 ];
  va_list ap;
  time_t curtime;
  struct tm loctime;

  va_start( ap, pattern );
  vsnprintf( decent_buffer, sizeof( decent_buffer ), pattern, ap );
  va_end( ap );

  time( &curtime );
  loctime = *localtime( &curtime );
  sprintf( timebuf, "%4d-%02d-%02d %02d:%02d:%02d", 
	   loctime.tm_year + 1900, loctime.tm_mon + 1, loctime.tm_mday, 
	   loctime.tm_hour, loctime.tm_min, loctime.tm_sec );

  fprintf( stderr, "%s [%s] %s\n", timebuf, module, decent_buffer );
}
