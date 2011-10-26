#ifndef _FLOW_CLASS_H
#define _FLOW_CLASS_H

#define FLOW_IPV4 1

#include "flow_packet.h"

int flow_classifier(FLOWPACKET *p, int *flowtype);

#endif /* _FLOW_CLASS_H */
