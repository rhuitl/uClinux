#ifndef _FLOW_H
#define _FLOW_H

#include "flow_error.h"
#include "util_math.h"
#include "common_defs.h"
#include "flow_print.h"
#include "flow_packet.h"
#include "bitop.h"

#define FROM_INITIATOR 1
#define FROM_RESPONDER 2

/* flow flags */
#define FLOW_REVERSED 0x00000001 /**< this flow was swapped */
#define FLOW_CLOSEME  0x00000002 /**< shutdown this flow ASAP */

typedef struct _FLOWDATA
{
    BITOP boFlowbits;
    unsigned char flowb[1];
} FLOWDATA;

typedef enum {
    FLOW_NEW, /**< first packet in flow */
    FLOW_FIRST_BIDIRECTIONAL,  /**< first response packet in flow */
    FLOW_ADDITIONAL, /**< additional data on an existing flow */
    FLOW_SHUTDOWN,  /**< shutdown of a existing flow due to timeout or protocol layer */
    FLOW_MAX /** this should not be used and should always be the
                 biggest in the enum for flow_callbacks() */
} FLOW_POSITION;

typedef struct _FLOWKEY
{
    u_int32_t init_address;
    u_int32_t resp_address;
    u_int16_t init_port;
    u_int16_t resp_port;
    u_int8_t  protocol;
} FLOWKEY;

typedef struct _FLOWSTATS
{
    time_t first_packet;
    time_t last_packet;

    u_int32_t packets_sent;
    u_int32_t packets_recv;

    u_int32_t bytes_sent;
    u_int32_t bytes_recv;

    u_int32_t flow_flags; /* normal, timeout, etc. */
    
    char first_talker;
    char last_talker;    
    u_int16_t alerts_seen;

    char direction;

} FLOWSTATS;

typedef struct _FLOW
{
    FLOWKEY key; 
    FLOWSTATS stats;
    FLOWDATA data;
} FLOW;

typedef enum {
    HASH1 = 1,
    HASH2 = 2
} FLOWHASHID;
    

int flow_init(FLOW *flow, char protocol,
              u_int32_t init_address, u_int16_t init_port,
              u_int32_t resp_address, u_int16_t resp_port);

int flow_alloc(int family, FLOW **flow, int *size);

/** 
 * Mark a flow with a particular flag
 * 
 * @param flow 
 * @param flags 
 */
static INLINE void flow_mark(FLOW *flow, int flags)
{
    flow->stats.flow_flags |= flags;
}

/** 
 * Check to see if a particular flag exists
 * 
 * @param flow 
 * @param flags 
 */
static INLINE int flow_checkflag(FLOW *flow, u_long flags)
{
    return ((flow->stats.flow_flags & flags) == flags);
}

int flowkey_reverse(FLOWKEY *key);
int flowkey_make(FLOWKEY *key, FLOWPACKET *p);
int flowkey_print(FLOWKEY *key);
int flowkey_normalize(FLOWKEY *dst, const FLOWKEY *src);
int flowkeycmp_fcn(const void *s1, const void *s2, size_t n);


#endif /* _FLOW_H */
