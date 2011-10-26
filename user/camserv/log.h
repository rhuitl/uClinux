#ifndef LOG_DOT_H
#define LOG_DOT_H

void camserv_log( const char *module, const char *pattern, ... ) 
#ifdef __GNUC__
     __attribute__ ((format( printf, 2, 3)));
#else
;
#endif

#endif
