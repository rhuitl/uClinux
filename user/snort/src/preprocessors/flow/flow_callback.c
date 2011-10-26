/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <time.h>


#include "packet_time.h"

#include "flow_callback.h"
#include "flow_cache.h"

/* needed for flow stats callback */
#include "flow_stat.h"

/* portscan detector */
#include "portscan/flowps_snort.h"

static int s_debug = 0;

int flow_callbacks(FLOW_POSITION position, FLOW *flowp, int direction, Packet *p)
{
    time_t now;
    
    if(flowp == NULL)
    {
        return FLOW_ENULL;
    }

    if(position < FLOW_NEW || position >= FLOW_MAX)
    {
        return FLOW_EINVALID;
    }

    if(s_debug > 5)
    {
#ifndef WIN32
        flow_printf("DEBUG: %s called at postition %s on flow: %p ",__func__,
               flowcache_pname(position), flowp);
#else
        flow_printf("DEBUG: %s(%d) called at postition %s on flow: %p ",__FILE__,__LINE__,
               flowcache_pname(position), flowp);
#endif
        flowkey_print(&flowp->key);
        flow_printf("\n");
    }

    /* we have to be prepared to get rid of a flow without a packet */   
    now = packet_timeofday();
    
    switch(position)
    {
    case FLOW_NEW:
        flowps_newflow_callback(position, flowp, direction, now ,p);        
        flowstat_callback(position, flowp, direction, now, p);
        break;
    case FLOW_ADDITIONAL:
        flowstat_callback(position, flowp, direction, now, p);
        break;
    case FLOW_FIRST_BIDIRECTIONAL:
        /* be careful putting callbacks here because this is really
         * used in addition to the FLOW_ADDITIONAL stage.
         */
        break;        
    case FLOW_SHUTDOWN:
        flowstat_callback(position, flowp, direction, now, p);
        break;
    default:
        flow_printf("Unknown position: %d\n", position);
        return 1;
    }
    
    return FLOW_SUCCESS;
}
/** 
 * Install a new flow plugin
 * 
 * This will install a new plugin for callbacks and install the plugin
 * at the correct location for that.
 *
 * 
 * @param position where to add this callback
 * @param flowp what tp match
 * @param direction which direction to match
 * @param fire_once only trigger on
 * @param timeout when this callback is no longer valid (0) means forever.
 */
/* int fcb_register(FLOW_POSITION position, FLOW *flowp, int direction, int order, int fire_once, int timeout) */
/* { */
    
/* } */
                 
