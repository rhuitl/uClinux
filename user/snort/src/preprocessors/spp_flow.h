#ifndef _SPP_FLOW_H
#define _SPP_FLOW_H

#include "decode.h"
#include "flow/flow.h"

void SetupFlow(void);
int CheckFlowShutdown(Packet *p);
int SppFlowIsRunning(void);

#endif /* _SPP_FLOW_H */
