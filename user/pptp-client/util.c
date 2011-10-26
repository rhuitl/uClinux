/* util.c ....... error message utilities.
 *                C. Scott Ananian <cananian@alumni.princeton.edu>
 *
 * $Id: util.c,v 1.1 2000-07-19 06:40:32 matthewr Exp $
 */

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include "util.h"

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "(unknown)"
#endif

static void open_log(void) __attribute__ ((constructor));
static void close_log(void) __attribute__ ((destructor));

static void open_log(void) {
  openlog(PROGRAM_NAME, LOG_PERROR | LOG_PID, LOG_DAEMON);
}
static void close_log(void) {
  closelog();
}


