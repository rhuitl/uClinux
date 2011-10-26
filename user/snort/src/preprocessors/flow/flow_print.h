#ifndef _FLOW_PRINT_H
#define _FLOW_PRINT_H

#include "util.h"

int flow_printf(const char *format, ...);
NORETURN void flow_fatalerror(const char *format, ...);
NORETURN void flow_errormsg(const char *format, ...);
int flow_set_daemon(void);


#endif /* _FLOW_PRINT_H */

