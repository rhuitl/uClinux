#include "flow_class.h"
#include "flow_error.h"

/** 
 * Find the relevant flow processing scheme for a packet
 * 
 * @param p packet to find the flow scheme for
 * 
 * @return 0 on success, 1 on failure
 */
int flow_classifier(FLOWPACKET *p, int *flowtype)
{
    if(p == NULL)
    {
        return FLOW_ENULL;
    }

    if(IsIPv4Packet(p))
    {
        *flowtype = FLOW_IPV4;            
        return FLOW_SUCCESS;
    }

    return FLOW_EINVALID;
}
