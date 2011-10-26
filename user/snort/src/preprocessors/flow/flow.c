/**
 * @file   flow.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Thu May 29 15:38:05 2003
 * 
 * @brief  FLOW and associated operations
 * 
 * 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flow.h"
#include "flow_stat.h"
#include "flow_print.h"

#include <stdlib.h>
#include <string.h> /* for memcpy */

int flow_init(FLOW *flow,
              char protocol,
              u_int32_t init_address,
              u_int16_t init_port,
              u_int32_t resp_address,
              u_int16_t resp_port)
{
    if(flow == NULL)
    {
        return FLOW_ENULL;
    }

    flow->key.protocol = protocol;
    flow->key.init_address = init_address;
    flow->key.init_port = init_port;
    flow->key.resp_address = resp_address;
    flow->key.resp_port = resp_port;

    if(flowstat_clear(&flow->stats))
    {
        flow_printf("unable to clear flow stats\n");
        return FLOW_EINVALID;
    }

    /** have not done anything with the flow->data section yet */
    return FLOW_SUCCESS;
}

/** 
 * Calloc a FLOW object of the right type -- this function is not needed
 *
 * @param family address family
 * @param flow paramter to return the actual flow in
 * @param size # of bytes allocated for a new flow
 * 
 * @return 0 on sucess, else failure
 */
int flow_alloc(int family, FLOW **flow, int *size)
{
    int tmpsize = sizeof(FLOW);   
    FLOW *fp;

    if(!flow || !size)
    {
        return FLOW_ENULL;
    }
    
    fp = (FLOW *) calloc(1,tmpsize);

    if(fp == NULL)
    {
        *size = 0;
        return FLOW_ENOMEM;
    }

    *size = tmpsize;
    *flow = fp;

    return FLOW_SUCCESS;
    
}

/** 
 * Given a packet, generate a key.
 *
 * @todo ICMP errors on an existing flow
 * 
 * @param key where to set the key
 * @param p Packet to make a key from
 * 
 * @return FLOW_SUCCESS on success, else failure
 */
int flowkey_make(FLOWKEY *key, FLOWPACKET *p)
{
    u_int8_t proto;
    
    if(!key || !p)
        return FLOW_ENULL;

    memset(key, 0, sizeof(FLOWKEY));
    
    /* IPV4 path */
    if(IsIPv4Packet(p))
    {
        proto = GetIPv4Proto(p);
        
        switch(proto)
        {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            key->init_port = GetIPv4SrcPort(p);
            key->resp_port = GetIPv4DstPort(p);
        default:
            key->protocol = proto;
            key->init_address = GetIPv4SrcIp(p);
            key->resp_address = GetIPv4DstIp(p);
        }

        return FLOW_SUCCESS;
    }

    return FLOW_EINVALID;
}


/** 
 * print out a key to a file stream
 * 
 * @param key what to print
 * 
 * @return 0 on sucess
 */
int flowkey_print(FLOWKEY *key)
{
    flow_printf(" Protocol   : %d", key->protocol);
    flow_printf(" InitAddress: %s", inet_ntoa(*(struct in_addr *) &key->init_address));
    flow_printf(" InitPort   : %d", key->init_port);
    flow_printf(" RespAddress: %s", inet_ntoa(*(struct in_addr *) &key->resp_address));
    flow_printf(" RespPort   : %d", key->resp_port);
    return 0;
}

/** 
 * Copy into dst from src and normalize the results so that things
 * will hash to the same entry no matter what.
 *
 * This should only be used for SEARCHING as it doesn't store much else.
 * 
 * @param dst where to copy to
 * @param src where to copy from
 */
int flowkey_normalize(FLOWKEY *dst, const FLOWKEY *src)
{
    
    /* normal memcpy */
    dst->protocol  = src->protocol;

    if(src->init_address > src->resp_address)
    {
        dst->resp_port    = src->init_port;
        dst->init_port    = src->resp_port;
        dst->init_address = src->resp_address;
        dst->resp_address = src->init_address;
    }
    else
    {
        dst->init_port   = src->init_port;
        dst->resp_port   = src->resp_port;
        dst->init_address = src->init_address;
        dst->resp_address = src->resp_address;
    }

    return 0;
}

/** 
 * perform key comparison
 * 
 * @param s1 pointer to A
 * @param s2 pointer to B
 * @param n size of each node
 * 
 * @return 0 if they are equal, else they aren't equal
 */
int flowkeycmp_fcn(const void *s1, const void *s2, size_t n)
{
    FLOWKEY *a = (FLOWKEY *) s1;
    FLOWKEY *b = (FLOWKEY *) s2;

    if(a->init_port != b->init_port)
        return -1;

    if(a->init_address != b->init_address)
        return -1;

    if(a->resp_address != b->resp_address)
        return -1;

    if(a->resp_port != b->resp_port)
        return -1;

    if(a->protocol != b->protocol)
        return -1;
    
    return 0;
}

