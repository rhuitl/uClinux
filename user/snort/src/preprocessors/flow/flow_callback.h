#ifndef _FLOW_CALLBACK_H
#define _FLOW_CALLBACK_H

#include "flow.h"
#include "flow_cache.h"

typedef struct _FLOWCALLBACKDATA
{
    char use_once;
    /* do the matching on the initiator side of a conversation */
    u_int32_t resp_address;
    u_int32_t resp_port;
    /* do the matching on the reponder side of a conversation */

    u_int32_t init_address;
    u_int32_t init_port;
    
    time_t expiration;    
    unsigned char postition; /* where in the flow back module we should be called */
    unsigned char order;     /* when sorting out the callbacks, 0,1,2... undefined between the same orders */
    // int (*flow_callback)(int position, FLOW *flow, int direction, Packet *p);
} FLOWCALLBACKDATA;

int flow_callbacks(FLOW_POSITION position, FLOW *flowp, int direction, FLOWPACKET *p);

#endif /* _FLOW_CALLBACK_H */
