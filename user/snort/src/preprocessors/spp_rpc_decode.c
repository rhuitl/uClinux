/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* $Id$ */
/* spp_rpc_decode 
 * 
 * Purpose:
 *
 * This preprocessor normalizes the RPC requests from remote machines by
 * converting all fragments into one continous stream.
 * This is very useful for doing things like defeating hostile attackers
 * trying to stealth themselves from IDSs by fragmenting the request so the
 * string 0186A0 is broken up.
 *
 * Arguments:
 *   
 * This plugin takes a list of integers representing the TCP ports that the
 * user is interested in having normalized
 *
 * Effect:
 *
 * Changes the data in the packet payload and changes
 * p->dsize to reflect the new (smaller) payload size.
 *
 * Comments:
 *
 */

#ifdef HAVE_CONFIG_H	 
#include "config.h"	 
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef HAVE_STRINGS_H	 
#include <strings.h>	 
#endif

#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "log.h"
#include "debug.h"
#include "util.h"

#include "mstring.h"
#include "snort.h"
#include "detect.h"
#include "log.h"
#include "generators.h"
#include "event_queue.h"

#include "profiler.h"

extern char *file_name;
extern int file_line;
extern int do_detect;

#define OPT_ALERT_FRAGMENTS "alert_fragments"
#define OPT_ALERT_MULTIPLE_REQUESTS "no_alert_multiple_requests"
#define OPT_ALERT_LARGE_FRAGMENTS "no_alert_large_fragments"
#define OPT_ALERT_INCOMPLETE "no_alert_incomplete"

#define TEXT_ALERT_MULTIPLE_REQUESTS "alert_multiple_requests"
#define TEXT_ALERT_LARGE_FRAGMENTS "alert_large_fragments"
#define TEXT_ALERT_INCOMPLETE "alert_incomplete"

#define RPC_CLASS DECODE_CLASS /* use the same classification as the other decoder alerts */

typedef struct _RpcDecodeData
{
    char alert_fragments;    /* Alert when we see ANY fragmented RPC requests */
    char alert_incomplete; /* Alert when we don't see all of a request in one packet */
    char alert_multi;        /* Alert when we see multiple requests in one packet */
    char alert_large;        /* Alert when we see multiple requests in one packet */
} RpcDecodeData;

static RpcDecodeData rpcpreprocdata; /* Configuration Set */
static char RpcDecodePorts[65536/8];

#ifdef PERF_PROFILING
PreprocStats rpcdecodePerfStats;
#endif

void RpcDecodeInit(u_char *);
void RpcDecodeInitIgnore(u_char *);
void PreprocRpcDecode(Packet *, void *);
void SetRpcPorts(char *);
int ConvertRPC(Packet *);

/*
 * Function: SetupRpcDecode()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupRpcDecode()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterPreprocessor("rpc_decode", RpcDecodeInit);

    DEBUG_WRAP(DebugMessage(DEBUG_RPC,"Preprocessor: RpcDecode in setup...\n"););
}


/*
 * Function: RpcDecodeInit(u_char *)
 *
 * Purpose: Processes the args sent to the preprocessor, sets up the
 *          port list, links the processing function into the preproc
 *          function list
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void RpcDecodeInit(u_char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_RPC,"Preprocessor: RpcDecode Initialized\n"););

    bzero(&rpcpreprocdata,sizeof(RpcDecodeData));

    /* turn on the following alerts by default */
    rpcpreprocdata.alert_multi = 1;
    rpcpreprocdata.alert_incomplete = 1;
    rpcpreprocdata.alert_large = 1;
    
    /* parse the argument list into a list of ports to normalize */
    SetRpcPorts(args);

    /* Set the preprocessor function into the function list */
    AddFuncToPreprocList(PreprocRpcDecode, PRIORITY_APPLICATION, PP_RPCDECODE);

#ifdef PREF_PROFILING
    RegisterPreprocessorProfile("rpcdecode", &rpcdecodePerfStats, 0, &totalPerfStats);
#endif
}

/*
 * Function: SetRpcPorts(char *)
 *
 * Purpose: Reads the list of port numbers from the argument string and
 *          parses them into the port list data struct
 *
 * Arguments: portlist => argument list
 *
 * Returns: void function
 *
 */
void SetRpcPorts(char *portlist)
{
    char portstr[STD_BUF];
    char **toks;
    int is_reset = 0;
    int num_toks;
    int num;

    if(portlist == NULL || *portlist == '\0')
    {
        portlist = "111 32771";
    }

    /* tokenize the argument list */
    toks = mSplit(portlist, " ", 31, &num_toks, '\\');

    LogMessage("rpc_decode arguments:\n");
    
    /* convert the tokens and place them into the port list */
    for(num = 0; num < num_toks; num++)
    {
        if(isdigit((int)toks[num][0]))
        {
            char *num_p = NULL; /* used to determine last position in string */
            long t_num;

            t_num = strtol(toks[num], &num_p, 10);

            if(*num_p != '\0')
            {
                FatalError("ERROR %s(%d) => Port Number invalid format: %s\n",
                           file_name, file_line, toks[num]);
            }
            else if(t_num < 0 || t_num > 65535)
            {
	        FatalError("ERROR %s(%d) => Port Number out of range: %ld\n",
                           file_name, file_line, t_num);
            }

            /* user specified a legal port number and it should override the default
               port list, so reset it unless already done */
            if(!is_reset)
            {
                bzero(&RpcDecodePorts, sizeof(RpcDecodePorts));
                portstr[0] = '\0';
                is_reset = 1;
            }

            /* mark this port as being interesting using some portscan2-type voodoo,
               and also add it to the port list string while we're at it so we can
               later print out all the ports with a single LogMessage() */
            RpcDecodePorts[(t_num/8)] |= 1<<(t_num%8);
            strlcat(portstr, toks[num], STD_BUF - 1);
            strlcat(portstr, " ", STD_BUF - 1);
        }
        else if(!strcasecmp(OPT_ALERT_MULTIPLE_REQUESTS,toks[num]))
        {
            rpcpreprocdata.alert_multi = 0;
        }
        else if(!strcasecmp(OPT_ALERT_INCOMPLETE,toks[num]))
        {
            rpcpreprocdata.alert_incomplete = 0;
        }
        else if(!strcasecmp(OPT_ALERT_LARGE_FRAGMENTS,toks[num]))
        {
            rpcpreprocdata.alert_large = 0;
        }
        else if(!strcasecmp(OPT_ALERT_FRAGMENTS,toks[num]))
        {
            rpcpreprocdata.alert_fragments = 1;
        }
        else
        {
            FatalError("ERROR %s(%d) => Unknown argument to rpc_decode "
                       "preprocessor: \"%s\"\n",
                       file_name, file_line, toks[num]);
        }
    }

    mSplitFree(&toks, num_toks);

    /* print out final port list */
    LogMessage("    Ports to decode RPC on: %s\n", portstr);
    LogMessage("    %s: %s\n", OPT_ALERT_FRAGMENTS, rpcpreprocdata.alert_fragments ? "ACTIVE": "INACTIVE");
    LogMessage("    %s: %s\n", TEXT_ALERT_LARGE_FRAGMENTS, rpcpreprocdata.alert_large ? "ACTIVE": "INACTIVE");
    LogMessage("    %s: %s\n", TEXT_ALERT_INCOMPLETE, rpcpreprocdata.alert_incomplete ? "ACTIVE": "INACTIVE");
    LogMessage("    %s: %s\n", TEXT_ALERT_MULTIPLE_REQUESTS, rpcpreprocdata.alert_multi ? "ACTIVE": "INACTIVE");
}                                                                               
   

/*
 * Function: PreprocRpcDecode(Packet *)
 *
 * Purpose: Inspects the packet's payload for fragment records and 
 *          converts them into one infragmented record.
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
void PreprocRpcDecode(Packet *p, void *context)
{
    int ret = 0; /* return code for ConvertRPC */
    PROFILE_VARS;
    
    DEBUG_WRAP(DebugMessage(DEBUG_RPC,"rpc decoder init on %d bytes\n", p->dsize););

    /* check to make sure we're talking TCP and that the TWH has already
       completed before processing anything */
    if(!PacketIsTCP(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_RPC,"It isn't TCP session traffic\n"););
        return;
    }

    if((snort_runtime.capabilities.stateful_inspection == 1) &&
       (p->packet_flags & PKT_FROM_SERVER))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_RPC,"This is from a server\n"););
        return;
    }


    /* check the port list */
    if(!(RpcDecodePorts[(p->dp/8)] & (1<<(p->dp%8))))
    {
        return;
    }

    PREPROC_PROFILE_START(rpcdecodePerfStats);

    ret = ConvertRPC(p);
    DEBUG_WRAP(DebugMessage(DEBUG_RPC,"Got ret: %d from ConvertRPC\n", ret););
    
    if(ret != 0)
    {
        switch(ret)
        {
        case RPC_FRAG_TRAFFIC:
            if(rpcpreprocdata.alert_fragments)
            {
                SnortEventqAdd(GENERATOR_SPP_RPC_DECODE, RPC_FRAG_TRAFFIC, 
                        1, RPC_CLASS, 3, RPC_FRAG_TRAFFIC_STR, 0);
            }
            break;
        case RPC_MULTIPLE_RECORD:
            if(rpcpreprocdata.alert_multi)
            {
                SnortEventqAdd(GENERATOR_SPP_RPC_DECODE, RPC_MULTIPLE_RECORD, 
                        1, RPC_CLASS, 3, RPC_MULTIPLE_RECORD_STR, 0);
            }
            break;
        case RPC_LARGE_FRAGSIZE:
            if(rpcpreprocdata.alert_large)
            {
                SnortEventqAdd(GENERATOR_SPP_RPC_DECODE, RPC_LARGE_FRAGSIZE, 
                        1, RPC_CLASS, 3, RPC_LARGE_FRAGSIZE_STR, 0);
            }
            break;
        case RPC_INCOMPLETE_SEGMENT:
            if(rpcpreprocdata.alert_incomplete)
            {
                SnortEventqAdd(GENERATOR_SPP_RPC_DECODE, RPC_INCOMPLETE_SEGMENT, 
                        1, RPC_CLASS, 3, RPC_INCOMPLETE_SEGMENT_STR, 0);
            }
            break;
        case RPC_ZERO_LENGTH_FRAGMENT:
            if(rpcpreprocdata.alert_multi)
            {
                SnortEventqAdd(GENERATOR_SPP_RPC_DECODE, RPC_ZERO_LENGTH_FRAGMENT, 
                        1, RPC_CLASS, 3, RPC_ZERO_LENGTH_FRAGMENT_STR, 0);
            }
            break;
        }
    }
    
    PREPROC_PROFILE_END(rpcdecodePerfStats);
    return;    
}

/* most significant bit */
#define MSB 0x80000000

/*
 * For proto ref, see rfc1831 section 10 and page 445 UNP vol2
 *  
 * check to make sure we've got enough data to process a record
 *
 * Where did the original 16 come from?  It seems that it could be
 * a last frag of 0 length according to spec.
 *
 * The minimum "valid" packet for us is 8 fields * 4 bytes
 *
 * This decoder is ignorant of TCP state so we'll have to assume
 * that reassembled TCP stuff is reinjected to the preprocessor
 * chain
 *
 * This decoder is also ignorant of multiple RPC requests in a
 * single stream.  To compensate, we can configure alerts
 *
 * Additionally, we don't do anything to verify that this is
 * really an RPC service port so we don't decode anything that
 * happens as a result
 *
 * From rfc1831:
 *
 *  Fragment Header ( 1 flag bit, 31 bit uint )
 *     RPC Body
 *  
 *        unsigned int xid 
 *        struct call_body {
 *             unsigned int rpcvers;  // must be equal to two (2) 
 *             unsigned int prog;
 *             unsigned int vers;
 *             unsigned int proc;
 *             opaque_auth  cred;
 *             opaque_auth  verf;
 *        }
 */

int ConvertRPC(Packet *p)
{
    u_int8_t *data = p->data;   /* packet data */
    u_int16_t *size = &(p->dsize); /* size of packet data */
    u_int8_t *rpc;       /* this is where the converted data will be written */
    u_int8_t *index;     /* this is the index pointer to walk thru the data */
    u_int8_t *end;       /* points to the end of the payload for loop control */
    u_int16_t psize = *size;     /* payload size */
    int i = 0;           /* loop counter */
    int length;          /* length of current fragment */
    int last_fragment = 0; /* have we seen the last fragment sign? */
    int decoded_len = 4; /* our decoded length is always atleast a 0 byte header */
    u_int32_t fraghdr;   /* Used to store the RPC fragment header data */
    int fragcount = 0;   /* How many fragment counters have we seen? */
    
    if(psize < 32)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_RPC, "Returning due to"
                                " small packet size: %d\n ", psize););
        return 0;
    }

    /* on match, normalize the data */
    DEBUG_WRAP(DebugMessage(DEBUG_RPC, "Got RPC traffic (%d bytes)!\n", psize););

    /* cheesy alignment safe fraghdr = *(uint32_t *) data*/
    *((u_int8_t *) &fraghdr)       = data[0];
    *(((u_int8_t *) &fraghdr) + 1) = data[1];
    *(((u_int8_t *) &fraghdr) + 2) = data[2];
    *(((u_int8_t *) &fraghdr) + 3) = data[3];
    

    /* The fragment header is 4 bytes in network byte order */
    fraghdr = ntohl(fraghdr);
    length = fraghdr & 0x7FFFFFFF;
    
    /* Check to see if we are on the last fragment */
    if(fraghdr & MSB)
    {
        /* on match, normalize the data */
        DEBUG_WRAP(DebugMessage(DEBUG_RPC, "Found Last Fragment: %u!\n",fraghdr););

        if((length + 4 != psize) && !(p->packet_flags & PKT_REBUILT_STREAM))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_RPC, "It's not the only thing in this buffer!"
                                    " length: %d psize: %d!\n", length, psize););            
            return RPC_MULTIPLE_RECORD;
        }
        else if ( length == 0 )
        {
            DEBUG_WRAP(DebugMessage(DEBUG_RPC, "Zero-length RPC fragment detected."
                                    " length: %d psize: %d.\n", length, psize););            
            return RPC_ZERO_LENGTH_FRAGMENT;
        }
        return 0;
    }
    else if(rpcpreprocdata.alert_fragments)
    {
        return RPC_FRAG_TRAFFIC;
    }

    rpc =   (u_int8_t *) data;
    index = (u_int8_t *) data;
    end =   (u_int8_t *) data + psize;


    /* now we know it's in fragmented records, 4 bytes of 
     * header(of which the most sig bit fragment (0=yes 1=no). 
     * The header is followed by the value move pointer up 4 
     * bytes, we need to stuff header in first 4 bytes.  
     * But the header has the total length...we don't know 
     * until the end 
     */
    
    /* This is where decoded data will be written */
    rpc += 4;

    /* always make sure that we have enough data to process atleast
     * the header and that we only process at most, one fragment
     */
    
    while(((end - index) >= 4) && (last_fragment == 0))
    {
        /* get the fragment length (31 bits) and move the pointer to
           the start of the actual data */
        
        *((u_int8_t *) &fraghdr)       = index[0];
        *(((u_int8_t *) &fraghdr) + 1) = index[1];
        *(((u_int8_t *) &fraghdr) + 2) = index[2];
        *(((u_int8_t *) &fraghdr) + 3) = index[3];

        fraghdr = ntohl(fraghdr);
        length = fraghdr & 0x7FFFFFFF;
        
        /* move the current index into the packet past the
           fragment header */
        index += 4; 
        
        if(fraghdr & MSB)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_RPC, "Last Fragment detected\n"););
            last_fragment = 1;
        }

        if((length + decoded_len) < decoded_len)
        {
            /* don't allow integer overflow to confuse us.  Should be
             * caught by length > psize but who knows when weird
             * psize's might be allowed */
            
            DEBUG_WRAP(DebugMessage(DEBUG_RPC, "Integer Overflow"
                                    " field(%d) exceeds packet size(%d)\n",
                                    length, psize););
            return RPC_LARGE_FRAGSIZE;
        }

        decoded_len += length;

        if(length > psize)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_RPC, "Length of"
                                    " field(%d) exceeds packet size(%d)\n",
                                    length, psize););

            
            return RPC_INCOMPLETE_SEGMENT;
        }
        else if(decoded_len > psize)
        {
            /* The entire request is larger than our current packet
             *  size
             */
            DEBUG_WRAP(DebugMessage(DEBUG_RPC, " Decoded Length (%d)"
                                    "exceeds packet size(%d)\n",
                                    decoded_len, psize););
            return RPC_LARGE_FRAGSIZE;
        }
        else if((index + length) > end)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_RPC,
                                    "returning LARGE_FRAGSIZE"
                                    "since we'd read past our end\n"););
            return RPC_LARGE_FRAGSIZE;
        }
        else
        {
            fragcount++;
            
            DEBUG_WRAP(DebugMessage(DEBUG_RPC,
                                    "length: %d size: %d decoded_len: %d\n",
                                    length, psize, decoded_len););                        

            if(fragcount == 1)
            {
                /* adjust the indexes because the records are already
                 * in the right spot */
                rpc += length;
                index += length; /* index is checked against the end above */
            }
            else
            {                
                for (i=0; i < length; i++, rpc++, index++)
                {
                    *rpc = *index;
                }
            }
        }
    }

    /* rewrite the header on the request packet */
    /* move the fragment header back onto the data */

    
    fraghdr = ntohl(decoded_len); /* size */

    data[0] = *((u_int8_t *) &fraghdr);
    data[1] = *(((u_int8_t *) &fraghdr) + 1);
    data[2] = *(((u_int8_t *) &fraghdr) + 2);
    data[3] = *(((u_int8_t *) &fraghdr) + 3);
    
    data[0] |=  0x80;             /* Mark as unfragmented */
    
    /* is there another request encoded that is trying to evade us by doing
     *
     * frag last frag [ more data ]?
     */
    if(decoded_len + ((fragcount - 1) * 4) != psize)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_RPC, "decoded len does not compute: %d\n",
                                decoded_len););
        return RPC_MULTIPLE_RECORD;
    }

    
    /* set the payload size to reflect the new size
     *
     * sizeof(Header) + total payload size of a single message
     */
    *size = decoded_len; /* this potentially throws away data... */

    DEBUG_WRAP(DebugMessage(DEBUG_RPC, "New size: %d\n", decoded_len);
               DebugMessage(DEBUG_RPC, "converted data:\n");
               //PrintNetData(stdout, data, decoded_len);
               );
    return 0;
}

