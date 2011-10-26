/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include "flow.h"
#include "flow_cache.h"
#include "flow_stat.h"
#include "flow_packet.h"

/** 
 * Reinitialize the flowstats
 * 
 * @param fsp flowstat pointer
 * 
 * @return 0 on success, else failure
 */
int flowstat_clear(FLOWSTATS *fsp)
{
    if(fsp == NULL)
    {
        return 1;
    }

    memset(fsp, 0, sizeof(FLOWSTATS));
    
    return 0;
}

int flowstat_print(FLOWSTATS *fsp)
{
    if(!fsp)
    {
        return 1;
    }
         
    flow_printf("fsp: %p fp: %u lp: %u bs: %u br: %u ps: %u pr: %u flags: %u ft: %x lt: %x ac: %u",
                fsp,
                (unsigned int) fsp->first_packet,
                (unsigned int) fsp->last_packet,
                fsp->bytes_sent,
                fsp->bytes_recv,
                fsp->packets_sent,
                fsp->packets_recv,
                fsp->flow_flags,
                fsp->first_talker,
                fsp->last_talker,
                fsp->alerts_seen);
    return 0;
}

int flowstat_increment(FLOWSTATS *fsp, int direction, time_t cur, u_int32_t bytes)
{
    switch(direction)
    {
    case FROM_INITIATOR:
        fsp->bytes_sent += bytes;
        fsp->packets_sent++;

        if(fsp->first_talker == 0)
        {
            fsp->first_talker = FROM_INITIATOR;
            fsp->first_packet = cur;
        }
        else
        {
            /* not a typo - only update once */
            fsp->last_talker = FROM_INITIATOR;
        }        
        break;
    case FROM_RESPONDER:
        fsp->bytes_recv += bytes;
        fsp->packets_recv++;
        fsp->last_talker = FROM_RESPONDER;
        break;
    default:
        flow_printf("flowstat_increment: unable to handle\n");
        return -1;
    }

    
    fsp->last_packet = cur;            
        
    return 0;
}

/** 
* The callback for the flowstats processor
* 
* @param position where in the flow module this is being called from
* @param flow the flow that the stats are kept for
* @param direction the direction of the flow
* @param cur the current time
* @param p the current packet (may be NULL)
* 
* @return TBD
*/
int flowstat_callback(FLOW_POSITION position, FLOW *flowp, int direction,
                      time_t cur, FLOWPACKET *p)
{
    int dsize;

    switch(position)
    {
    case FLOW_SHUTDOWN:
        /* 
           flow_printf("flow:");
           flowkey_print(&flowp->key);
           flowstat_print(&flowp->stats);
           flow_printf("\n");
        */
        break;
    case FLOW_NEW:
    case FLOW_ADDITIONAL:
        if(p)
        {
            dsize = GetIPv4Len(p);            
            flowstat_increment(&flowp->stats, direction, cur, dsize);
        }
    default:                        
    case FLOW_FIRST_BIDIRECTIONAL:
        break;
    }

    return 0;
}
