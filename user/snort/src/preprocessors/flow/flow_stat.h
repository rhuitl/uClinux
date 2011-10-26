#ifndef _FLOW_STAT_H
#define _FLOW_STAT_H

#include <stdio.h>
#include <time.h>

#include "flow.h"

int flowstat_clear(FLOWSTATS *fsp);
int flowstat_print(FLOWSTATS *fsp);
int flowstat_increment(FLOWSTATS *fsp, int direction, time_t cur, u_int32_t bytes);
int flowstat_callback(FLOW_POSITION position, FLOW *flow, int direction, time_t cur, FLOWPACKET *p);
#endif /* _FLOW_STAT_H */
