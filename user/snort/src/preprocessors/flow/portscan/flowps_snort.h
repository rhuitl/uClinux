#ifndef _FLOWPS_SNORT_H
#define _FLOWPS_SNORT_H

#include "flow.h"

void SetupFlowPS(void);

int flowps_newflow_callback(FLOW_POSITION position, FLOW *flowp, int direction, time_t cur, FLOWPACKET *p);

#endif /* _FLOWPS_SNORT_H */
