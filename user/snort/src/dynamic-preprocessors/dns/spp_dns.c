/* $Id */

/*
** Copyright (C) 2006 Sourcefire Inc.
**
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


/*
 * DNS preprocessor
 * Author: Steven Sturges
 *
 *
 * Alert for DNS client rdata buffer overflow.
 * Alert for Obsolete or Experimental RData types (per RFC 1035)
 * 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif  /* HAVE_CONFIG_H */

#include "sf_snort_packet.h"
#include "sf_dynamic_preprocessor.h"
#include "sf_snort_plugin_api.h"

#include "preprocids.h"
#include "debug.h"
#include "spp_dns.h"

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#ifndef WIN32
#include <sys/time.h>
#endif
#include <stdlib.h>
#include <ctype.h>

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats dnsPerfStats;
#endif

/*
 * Generator id. Define here the same as the official registry
 * in generators.h
 */
#define GENERATOR_SPP_DNS   131

/*
 * Function prototype(s)
 */
DNSSessionData* GetDNSSessionData( SFSnortPacket* );
static void DNSInit( u_char* );
static void PrintDNSConfig();
static void FreeDNSSessionData( void* );
static void  ParseDNSArgs( u_char* );
static void ProcessDNS( void*, void* );
static void DNSConfigCheck( void );
static inline int CheckDNSPort( u_int16_t );

/* Ultimately calls SnortEventqAdd */
/* Arguments are: gid, sid, rev, classification, priority, message, rule_info */
#define DNS_ALERT(x,y) { _dpd.alertAdd(GENERATOR_SPP_DNS, x, 1, 0, 3, y, 0 ); }

/* Convert port value into an index for the dns_config.ports array */
#define PORT_INDEX(port) port/8

/* Convert port value into a value for bitwise operations */
#define CONV_PORT(port) 1<<(port%8)

#define DNS_RR_PTR 0xC0
/*
 * DNS preprocessor global configuration structure.
 */
static DNSConfig dns_config =
{
#if 0
    0,                              /* Autodetection */
#endif
    DNS_ALERT_NONE,                  /* Enabled alerts */
};

extern DynamicPreprocessorData _dpd;

/* Called at preprocessor setup time. Links preprocessor keyword
 * to corresponding preprocessor initialization function.
 *
 * PARAMETERS:  None.
 * 
 * RETURNS: Nothing.
 *
 */
void SetupDNS()
{
    /* Link preprocessor keyword to initialization function 
     * in the preprocessor list.
     */
    _dpd.registerPreproc( "dns", DNSInit );

    memset(dns_config.ports, 0, sizeof(char) * (MAX_PORTS/8));
}

/* Initializes the DNS preprocessor module and registers
 * it in the preprocessor list.
 * 
 * PARAMETERS:  
 *
 * argp:        Pointer to argument string to process for config
 *                      data.
 *
 * RETURNS:     Nothing. 
 */
static void DNSInit( u_char* argp )
{
    _dpd.addPreproc( ProcessDNS, PRIORITY_APPLICATION, PP_DNS );
    _dpd.addPreprocConfCheck( DNSConfigCheck );
    
    ParseDNSArgs( argp );
    
#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("dns", (void *)&dnsPerfStats, 0, _dpd.totalPerfStats);
#endif
}

/* Verify configuration and that Stream API is available.
 *
 * PARAMETERS:  None
 *
 * RETURNS:     Nothing.
 */
static void DNSConfigCheck( void )
{
    if ((!_dpd.streamAPI) || (_dpd.streamAPI->version < STREAM_API_VERSION4))
    {
        DynamicPreprocessorFatalMessage("DNSConfigCheck() Streaming & reassembly must be "
                                        "enabled\n");
    }
}

/* Parses and processes the configuration arguments 
 * supplied in the DNS preprocessor rule.
 *
 * PARAMETERS: 
 *
 * argp:        Pointer to string containing the config arguments.
 * 
 * RETURNS:     Nothing.
 */
static void ParseDNSArgs( u_char* argp )
{
    char* cur_tokenp = NULL;
    char* argcpyp = NULL;
    int port;
    
    /* Set up default port to listen on */
    dns_config.ports[ PORT_INDEX( DNS_PORT ) ] |= CONV_PORT(DNS_PORT);
    
    /* Sanity check(s) */
    if ( !argp )
    {
        PrintDNSConfig();
        return;
    }
    
    argcpyp = strdup( (char*) argp );
    
    if ( !argcpyp )
    {
        DynamicPreprocessorFatalMessage("Could not allocate memory to parse DNS options.\n");
        return;
    }
    
    cur_tokenp = strtok( argcpyp, " ");
    
    while ( cur_tokenp )
    {
        if ( !strcmp( cur_tokenp, DNS_PORTS_KEYWORD ))
        {
            /* If the user specified ports, remove 'DNS_PORT' for now since 
             * it now needs to be set explicitely. */
            dns_config.ports[ PORT_INDEX( DNS_PORT ) ] = 0;
            
            /* Eat the open brace. */
            cur_tokenp = strtok( NULL, " ");
            if (( !cur_tokenp ) || ( strcmp(cur_tokenp, "{" )))
            {
                DynamicPreprocessorFatalMessage("%s(%d) Bad value specified for %s.  Must start "
                                                "with '{' and be space seperated.\n",
                                                *(_dpd.config_file), *(_dpd.config_line),
                                                DNS_PORTS_KEYWORD);
                free(argcpyp);
                return;
            }
            
            cur_tokenp = strtok( NULL, " ");
            while (( cur_tokenp ) && strcmp(cur_tokenp, "}" ))
            {
                if ( !isdigit( cur_tokenp[0] ))
                {
                    DynamicPreprocessorFatalMessage("%s(%d) Bad port %s.\n", 
                                                    *(_dpd.config_file), *(_dpd.config_line), cur_tokenp );
                    free(argcpyp);
                    return;
                }
                else
                {
                    port = atoi( cur_tokenp );
                    if( port < 0 || port > MAX_PORTS ) 
                    {
                        DynamicPreprocessorFatalMessage("%s(%d) Port value illegitimate: %s\n",
                                                        *(_dpd.config_file), *(_dpd.config_line),
                                                        cur_tokenp );
                        free(argcpyp);
                        return;
                    }
                    
                    dns_config.ports[ PORT_INDEX( port ) ] |= CONV_PORT(port);
                }
                
                cur_tokenp = strtok( NULL, " ");
            }
        }
        else if ( !strcmp( cur_tokenp, DNS_ENABLE_RDATA_OVERFLOW_KEYWORD ))
        {
            dns_config.enabled_alerts |= DNS_ALERT_RDATA_OVERFLOW;
        }
        else if ( !strcmp( cur_tokenp, DNS_ENABLE_OBSOLETE_TYPES_KEYWORD ))
        {
            dns_config.enabled_alerts |= DNS_ALERT_OBSOLETE_TYPES;
        }
        else if ( !strcmp( cur_tokenp, DNS_ENABLE_EXPERIMENTAL_TYPES_KEYWORD ))
        {
            dns_config.enabled_alerts |= DNS_ALERT_EXPERIMENTAL_TYPES;
        }
#if 0
        else if ( !strcmp( cur_tokenp, DNS_AUTODETECT_KEYWORD ))
        {
            dns_config.autodetect++;
        }
#endif
        else
        {
            DynamicPreprocessorFatalMessage("Invalid argument: %s\n", cur_tokenp);
            return;
        }
        
        cur_tokenp = strtok( NULL, " " );
    }
    
    PrintDNSConfig();
    free(argcpyp);
}

/* Display the configuration for the DNS preprocessor. 
 * 
 * PARAMETERS:  None.
 *
 * RETURNS: Nothing.
 */
static void PrintDNSConfig()
{
    int index;
    
    _dpd.logMsg("DNS config: \n");
#if 0
    _dpd.logMsg("    Autodetection: %s\n", 
        dns_config.autodetect ? 
        "ENABLED":"DISABLED");
#endif
    _dpd.logMsg("    DNS Client rdata txt Overflow Alert: %s\n",
        dns_config.enabled_alerts & DNS_ALERT_RDATA_OVERFLOW ?
        "ACTIVE" : "INACTIVE" );
    _dpd.logMsg("    Obsolete DNS RR Types Alert: %s\n",
        dns_config.enabled_alerts & DNS_ALERT_OBSOLETE_TYPES ?
        "ACTIVE" : "INACTIVE" );
    _dpd.logMsg("    Experimental DNS RR Types Alert: %s\n",
        dns_config.enabled_alerts & DNS_ALERT_EXPERIMENTAL_TYPES ?
        "ACTIVE" : "INACTIVE" );
    
    /* Printing ports */
    _dpd.logMsg("    Ports:"); 
    for(index = 0; index < MAX_PORTS; index++) 
    {
        if( dns_config.ports[ PORT_INDEX(index) ] & CONV_PORT(index) )
        {
            _dpd.logMsg(" %d", index);
        }
    }
    _dpd.logMsg("\n");
}

/* Retrieves the DNS data block registered with the stream 
 * session associated w/ the current packet. If none exists,
 * allocates it and registers it with the stream API. 
 *
 * PARAMETERS:
 *
 * p: Pointer to the packet from which/in which to
 *      retrieve/store the DNS data block.
 *
 * RETURNS: Pointer to an DNS data block, upon success.
 *      NULL, upon failure.
 */
static DNSSessionData udpSessionData;
#define MIN_UDP_PAYLOAD 0x1FFF
DNSSessionData* GetDNSSessionData( SFSnortPacket* p )
{
    DNSSessionData* dnsSessionData = NULL;

    /* This is done in the calling function, don't need to
     * do it again here.
     *
     * Sanity check 
    if (!p)
    {
        return NULL;
    }
     */

    if (p->udp_header)
    {
        if (!(dns_config.enabled_alerts & DNS_ALERT_OBSOLETE_TYPES) &&
            !(dns_config.enabled_alerts & DNS_ALERT_EXPERIMENTAL_TYPES))
        {
            if (dns_config.enabled_alerts & DNS_ALERT_RDATA_OVERFLOW)
            {
                /* Checking RData Overflow... */
                if (p->payload_size <
                     (sizeof(DNSHdr) + sizeof(DNSRR) + MIN_UDP_PAYLOAD))
                {
                    /* But we don't have sufficient data.  Go away. */
                    return NULL;
                }
            }
            else
            {
                /* Not checking for experimental or obsolete types. Go away. */
                return NULL;
            }
        }

        /* Its a UDP packet, use the "stateless" one */
        dnsSessionData = &udpSessionData;
        memset(dnsSessionData, 0, sizeof(DNSSessionData));
        return dnsSessionData;
    }
    
    /* More Sanity check(s) */
    if ( !p->stream_session_ptr )
    {
        return NULL;
    }
    
    /* Attempt to get a previously allocated DNS block. If none exists,
     * allocate and register one with the stream layer.
     */
    dnsSessionData = _dpd.streamAPI->get_application_data( 
        p->stream_session_ptr, PP_DNS );
    
    if ( !dnsSessionData )
    {
        dnsSessionData = calloc( 1, sizeof( DNSSessionData ));
        
        if ( !dnsSessionData )
            return NULL;
        
        /*Register the new DNS data block in the stream session. */
        _dpd.streamAPI->set_application_data( 
            p->stream_session_ptr, 
            PP_DNS, dnsSessionData, FreeDNSSessionData );
    }
    
    return dnsSessionData;
}

/* Registered as a callback with the DNS data when they are
 * added to the stream session. Called by stream when a
 * session is about to be destroyed to free that data.
 * 
 * PARAMETERS:
 *
 * application_data:  Pointer to the DNS data
 *
 * RETURNS: Nothing.
 */
static void FreeDNSSessionData( void* application_data )
{
    DNSSessionData* dnsSessionData = (DNSSessionData*)application_data;
    if ( dnsSessionData )
    {
        free( dnsSessionData );
    }
}

/* Validates given port as an DNS server port.
 *
 * PARAMETERS:
 *
 * port:    Port to validate.
 *
 * RETURNS: DNS_TRUE, if the port is indeed an DNS server port.
 *      DNS_FALSE, otherwise.
 */
static inline int CheckDNSPort( u_int16_t port )
{
    if ( dns_config.ports[ PORT_INDEX(port) ] & CONV_PORT( port ) )
    {
        return 1;
    }
    
    return 0;
}

static u_int16_t ParseDNSHeader(unsigned char *data,
                                u_int16_t bytes_unused,
                                DNSSessionData *dnsSessionData)
{
    if (bytes_unused == 0)
    {
        return bytes_unused;
    }

    switch (dnsSessionData->state)
    {
    case DNS_RESP_STATE_LENGTH:
        /* First two bytes are length in TCP */
        dnsSessionData->length = ((u_int8_t)*data) << 8;
        dnsSessionData->state = DNS_RESP_STATE_LENGTH_PART;
        data++;
        bytes_unused--;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_LENGTH_PART:
        dnsSessionData->length |= ((u_int8_t)*data);
        dnsSessionData->state = DNS_RESP_STATE_HDR_ID;
        data++;
        bytes_unused--;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_ID:
        dnsSessionData->hdr.id = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_ID_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_ID_PART:
        dnsSessionData->hdr.id |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_FLAGS;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_FLAGS:
        dnsSessionData->hdr.flags = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_FLAGS_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_FLAGS_PART:
        dnsSessionData->hdr.flags |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_QS;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_QS:
        dnsSessionData->hdr.questions = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_QS_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_QS_PART:
        dnsSessionData->hdr.questions |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_ANSS;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_ANSS:
        dnsSessionData->hdr.answers = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_ANSS_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_ANSS_PART:
        dnsSessionData->hdr.answers |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_AUTHS;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_AUTHS:
        dnsSessionData->hdr.authorities = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_AUTHS_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_AUTHS_PART:
        dnsSessionData->hdr.authorities |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_ADDS;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_ADDS:
        dnsSessionData->hdr.additionals = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_HDR_ADDS_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_HDR_ADDS_PART:
        dnsSessionData->hdr.additionals |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->state = DNS_RESP_STATE_QUESTION;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    default:
        /* Continue -- we're beyond the header */
        break;
    }

    return bytes_unused;
}


u_int16_t ParseDNSName(unsigned char *data,
                       u_int16_t bytes_unused,
                       DNSSessionData *dnsSessionData)
{
    u_int16_t bytes_required = dnsSessionData->curr_txt.txt_len - dnsSessionData->curr_txt.txt_bytes_seen;

    while (dnsSessionData->curr_txt.name_state != DNS_RESP_STATE_NAME_COMPLETE)
    {
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }

        switch (dnsSessionData->curr_txt.name_state)
        {
        case DNS_RESP_STATE_NAME_SIZE:
            dnsSessionData->curr_txt.txt_len = (u_int8_t)*data;
            data++;
            bytes_unused--;
            dnsSessionData->bytes_seen_curr_rec++;
            if (dnsSessionData->curr_txt.txt_len == 0)
            {
                dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_NAME_COMPLETE;
                return bytes_unused;
            }

            dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_NAME;
            dnsSessionData->curr_txt.txt_bytes_seen = 0;

            if ((dnsSessionData->curr_txt.txt_len & DNS_RR_PTR) == DNS_RR_PTR)
            {
                /* A reference to another location... */
                /* This is an offset */
                dnsSessionData->curr_txt.offset = (dnsSessionData->curr_txt.txt_len & ~0xC0) << 8;
                bytes_required = dnsSessionData->curr_txt.txt_len = 1;
                dnsSessionData->curr_txt.relative = 1;
                /* Setup to read 2nd Byte of Location */
            }
            else
            {
                bytes_required = dnsSessionData->curr_txt.txt_len;
                dnsSessionData->curr_txt.offset = 0;
                dnsSessionData->curr_txt.relative = 0;
            }

            if (bytes_unused == 0)
            {
                return bytes_unused;
            }

            /* Fall through */
        case DNS_RESP_STATE_NAME:
            if (bytes_required <= bytes_unused)
            {
                bytes_unused -= bytes_required;
                if (dnsSessionData->curr_txt.relative)
                {
                    /* If this one is a relative offset, read that extra byte */
                    dnsSessionData->curr_txt.offset |= *data;
                }
                data += bytes_required;
                dnsSessionData->bytes_seen_curr_rec += bytes_required;
                dnsSessionData->curr_txt.txt_bytes_seen += bytes_required;

                if (bytes_unused == 0)
                {
                    return bytes_unused;
                }
            }
            else
            {
                dnsSessionData->bytes_seen_curr_rec+= bytes_unused;
                dnsSessionData->curr_txt.txt_bytes_seen += bytes_unused;
                return 0;
            }
            if (dnsSessionData->curr_txt.relative)
            {
                /* And since its relative, we're done */
                dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_NAME_COMPLETE;
                return bytes_unused;
            }
            break;
        }
        
        /* Go to the next portion of the name */
        dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_NAME_SIZE;
    }

    return bytes_unused;
}

static u_int16_t ParseDNSQuestion(unsigned char *data,
                                  u_int16_t data_size,
                                  u_int16_t bytes_unused,
                                  DNSSessionData *dnsSessionData)
{
    u_int16_t bytes_used = 0;
    u_int16_t new_bytes_unused = 0;

    if (bytes_unused == 0)
    {
        return bytes_unused;
    }

    if (dnsSessionData->curr_rec_state < DNS_RESP_STATE_Q_NAME_COMPLETE)
    {
        new_bytes_unused = ParseDNSName(data, bytes_unused, dnsSessionData);
        bytes_used = bytes_unused - new_bytes_unused;

        if (dnsSessionData->curr_txt.name_state == DNS_RESP_STATE_NAME_COMPLETE)
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_TYPE;
            bzero(&dnsSessionData->curr_txt, sizeof(DNSNameState));
            data = data + bytes_used;
            bytes_unused = new_bytes_unused;

            if (bytes_unused == 0)
            {
                /* ran out of data */
                return bytes_unused;
            }
        }
        else
        {
            /* Should be 0 -- ran out of data */
            return new_bytes_unused;
        }
    }

    switch (dnsSessionData->curr_rec_state)
    {
    case DNS_RESP_STATE_Q_TYPE:
        dnsSessionData->curr_q.type = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_TYPE_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_Q_TYPE_PART:
        dnsSessionData->curr_q.type |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_CLASS;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_Q_CLASS:
        dnsSessionData->curr_q.dns_class = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_CLASS_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_Q_CLASS_PART:
        dnsSessionData->curr_q.dns_class |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_COMPLETE;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    default:
        /* Continue -- we're beyond this question */
        break;
    }

    return bytes_unused;
}

u_int16_t ParseDNSAnswer(unsigned char *data,
                         u_int16_t data_size,
                         u_int16_t bytes_unused,
                         DNSSessionData *dnsSessionData)
{
    u_int16_t bytes_used = 0;
    u_int16_t new_bytes_unused = 0;

    if (bytes_unused == 0)
    {
        return bytes_unused;
    }

    if (dnsSessionData->curr_rec_state < DNS_RESP_STATE_RR_NAME_COMPLETE)
    {
        new_bytes_unused = ParseDNSName(data, bytes_unused, dnsSessionData);
        bytes_used = bytes_unused - new_bytes_unused;

        if (dnsSessionData->curr_txt.name_state == DNS_RESP_STATE_NAME_COMPLETE)
        {
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TYPE;
            bzero(&dnsSessionData->curr_txt, sizeof(DNSNameState));
            data = data + bytes_used;
        }
        bytes_unused = new_bytes_unused;

        if (bytes_unused == 0)
        {
            /* ran out of data */
            return bytes_unused;
        }
    }
    
    switch (dnsSessionData->curr_rec_state)
    {
    case DNS_RESP_STATE_RR_TYPE:
        dnsSessionData->curr_rr.type = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TYPE_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_RR_TYPE_PART:
        dnsSessionData->curr_rr.type |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_CLASS;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_RR_CLASS:
        dnsSessionData->curr_rr.dns_class = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_CLASS_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_RR_CLASS_PART:
        dnsSessionData->curr_rr.dns_class |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TTL;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_RR_TTL:
        dnsSessionData->curr_rr.ttl = (u_int8_t)*data << 24;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_TTL_PART;
        dnsSessionData->bytes_seen_curr_rec = 1;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_RR_TTL_PART:
        while (dnsSessionData->bytes_seen_curr_rec < 4)
        {
            dnsSessionData->bytes_seen_curr_rec++;
            dnsSessionData->curr_rr.ttl |= 
                (u_int8_t)*data << (4-dnsSessionData->bytes_seen_curr_rec)*8;
            data++;
            bytes_unused--;
            if (bytes_unused == 0)
            {
                return bytes_unused;
            }
        }
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDLENGTH;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
    case DNS_RESP_STATE_RR_RDLENGTH:
        dnsSessionData->curr_rr.length = (u_int8_t)*data << 8;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDLENGTH_PART;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    case DNS_RESP_STATE_RR_RDLENGTH_PART:
        dnsSessionData->curr_rr.length |= (u_int8_t)*data;
        data++;
        bytes_unused--;
        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDATA_START;
        if (bytes_unused == 0)
        {
            return bytes_unused;
        }
        /* Fall through */
    default:
        /* Continue -- we're beyond this answer */
        break;
    }

    return bytes_unused;
}

/* The following check is to look for an attempt to exploit
 * a vulnerability in the DNS client, per MS 06-041.
 *
 * For details, see:
 * http://www.microsoft.com/technet/security/bulletin/ms06-007.mspx
 * http://cve.mitre.org/cgi-bin/cvename.cgi?name=2006-3441
 *
 * Vulnerability Research by Lurene Grenier, Judy Novak,
 * and Brian Caswell.
 */
u_int16_t CheckRRTypeTXTVuln(unsigned char *data,
                       u_int16_t bytes_unused,
                       DNSSessionData *dnsSessionData)
{
    u_int16_t bytes_required = dnsSessionData->curr_txt.txt_len - dnsSessionData->curr_txt.txt_bytes_seen;

    while (dnsSessionData->curr_txt.name_state != DNS_RESP_STATE_RR_NAME_COMPLETE)
    {
        if (dnsSessionData->bytes_seen_curr_rec == dnsSessionData->curr_rr.length)
        {
            /* Done with the name */
            dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_RR_NAME_COMPLETE;
            /* Got to the end of the rdata in this packet! */
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_COMPLETE;
            return bytes_unused;
        }

        if (bytes_unused == 0)
        {
            return bytes_unused;
        }

        switch (dnsSessionData->curr_txt.name_state)
        {
        case DNS_RESP_STATE_RR_NAME_SIZE:
            dnsSessionData->curr_txt.txt_len = (u_int8_t)*data;
            dnsSessionData->curr_txt.txt_count++;
            dnsSessionData->curr_txt.total_txt_len += dnsSessionData->curr_txt.txt_len + 1; /* include the NULL */

            if (!dnsSessionData->curr_txt.alerted)
            {
                u_int32_t overflow_check = (dnsSessionData->curr_txt.txt_count * 4) +
                                           (dnsSessionData->curr_txt.total_txt_len * 2) + 4;
                /* if txt_count * 4 + total_txt_len * 2 + 4 > FFFF, vulnerability! */
                if (overflow_check > 0xFFFF)
                {
                    if (dns_config.enabled_alerts & DNS_ALERT_RDATA_OVERFLOW)
                    {
                        /* Alert on obsolete DNS RR types */
                        DNS_ALERT(DNS_EVENT_RDATA_OVERFLOW, DNS_EVENT_RDATA_OVERFLOW_STR);
                    }

                    dnsSessionData->curr_txt.alerted = 1;
                }
            }

            data++;
            bytes_unused--;
            dnsSessionData->bytes_seen_curr_rec++;
            if (dnsSessionData->curr_txt.txt_len > 0)
            {
                dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_RR_NAME;
                dnsSessionData->curr_txt.txt_bytes_seen = 0;
                bytes_required = dnsSessionData->curr_txt.txt_len;
            }
            else
            {
                continue;
            }
            if (bytes_unused == 0)
            {
                return bytes_unused;
            }
            /* Fall through */
        case DNS_RESP_STATE_RR_NAME:
            if (bytes_required <= bytes_unused)
            {
                bytes_unused -= bytes_required;
                dnsSessionData->bytes_seen_curr_rec += bytes_required;
                data += bytes_required;
                dnsSessionData->curr_txt.txt_bytes_seen += bytes_required;
                if (bytes_unused == 0)
                {
                    return bytes_unused;
                }
            }
            else
            {
                dnsSessionData->curr_txt.txt_bytes_seen += bytes_unused;
                dnsSessionData->bytes_seen_curr_rec += bytes_unused;
                return 0;
            }
            break;
        }
        
        /* Go to the next portion of the name */
        dnsSessionData->curr_txt.name_state = DNS_RESP_STATE_RR_NAME_SIZE;
    }

    return bytes_unused;
}

u_int16_t SkipDNSRData(unsigned char *data,
                       u_int16_t bytes_unused,
                       DNSSessionData *dnsSessionData)
{
    u_int16_t bytes_required = dnsSessionData->curr_rr.length - dnsSessionData->bytes_seen_curr_rec;

    if (bytes_required <= bytes_unused)
    {
        bytes_unused -= bytes_required;
        data += bytes_required;
        dnsSessionData->bytes_seen_curr_rec += bytes_required;
    }
    else
    {
        dnsSessionData->bytes_seen_curr_rec += bytes_unused;
        return 0;
    }

    /* Got to the end of the rdata in this packet! */
    dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_COMPLETE;
    return bytes_unused;
}

u_int16_t ParseDNSRData(SFSnortPacket *p,
                        unsigned char *data,
                        u_int16_t bytes_unused,
                        DNSSessionData *dnsSessionData)
{
    if (bytes_unused == 0)
    {
        return bytes_unused;
    }

    switch (dnsSessionData->curr_rr.type)
    {
    case DNS_RR_TYPE_TXT:
        /* Check for RData Overflow */
        bytes_unused = CheckRRTypeTXTVuln(data, bytes_unused, dnsSessionData);
        break;

    case DNS_RR_TYPE_MD:
    case DNS_RR_TYPE_MF:
        if (dns_config.enabled_alerts & DNS_ALERT_OBSOLETE_TYPES)
        {
            /* Alert on obsolete DNS RR types */
            DNS_ALERT(DNS_EVENT_OBSOLETE_TYPES, DNS_EVENT_OBSOLETE_TYPES_STR);
        }
        bytes_unused = SkipDNSRData(data, bytes_unused, dnsSessionData);
        break;

    case DNS_RR_TYPE_MB:
    case DNS_RR_TYPE_MG:
    case DNS_RR_TYPE_MR:
    case DNS_RR_TYPE_NULL:
    case DNS_RR_TYPE_MINFO:
        if (dns_config.enabled_alerts & DNS_ALERT_EXPERIMENTAL_TYPES)
        {
            /* Alert on experimental DNS RR types */
            DNS_ALERT(DNS_EVENT_EXPERIMENTAL_TYPES, DNS_EVENT_EXPERIMENTAL_TYPES_STR);
        }
        bytes_unused = SkipDNSRData(data, bytes_unused, dnsSessionData);
        break;
    case DNS_RR_TYPE_A:
    case DNS_RR_TYPE_NS:
    case DNS_RR_TYPE_CNAME:
    case DNS_RR_TYPE_SOA:
    case DNS_RR_TYPE_WKS:
    case DNS_RR_TYPE_PTR:
    case DNS_RR_TYPE_HINFO:
    case DNS_RR_TYPE_MX:
        bytes_unused = SkipDNSRData(data, bytes_unused, dnsSessionData);
        break;
    default:
        /* Not one of the known types.  Stop looking at this session
         * as DNS. */
        dnsSessionData->flags |= DNS_FLAG_NOT_DNS;
        break;
    }

    return bytes_unused;
}

void ParseDNSResponseMessage(SFSnortPacket *p, DNSSessionData *dnsSessionData)
{
    u_int16_t bytes_unused = p->payload_size;
    int i;
    unsigned char *data = p->payload;

    while (bytes_unused)
    {
        /* Parse through the DNS Header */
        if (dnsSessionData->state < DNS_RESP_STATE_QUESTION)
        {
            /* Length only applies on a TCP packet, skip to header ID
             * if at beginning of a UDP Response.
             */
            if ((dnsSessionData->state == DNS_RESP_STATE_LENGTH) &&
                (p->udp_header))
            {
                dnsSessionData->state = DNS_RESP_STATE_HDR_ID;
            }

            bytes_unused = ParseDNSHeader(data, bytes_unused, dnsSessionData);
            if (bytes_unused > 0)
            {
                data = p->payload + (p->payload_size - bytes_unused);
            }
            else
            {
                /* No more data */
                return;
            }

            dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_NAME;
            dnsSessionData->curr_rec = 0;
        }

        /* Print out the header (but only once -- when we're ready to parse the Questions */
#ifdef DEBUG
        if ((dnsSessionData->curr_rec_state == DNS_RESP_STATE_Q_NAME) &&
            (dnsSessionData->curr_rec == 0))
        {
            _dpd.debugMsg(DEBUG_DNS,
                            "DNS Header: length %d, id 0x%x, flags 0x%x, "
                            "questions %d, answers %d, authorities %d, additionals %d\n",
                            dnsSessionData->length, dnsSessionData->hdr.id,
                            dnsSessionData->hdr.flags, dnsSessionData->hdr.questions,
                            dnsSessionData->hdr.answers,
                            dnsSessionData->hdr.authorities,
                            dnsSessionData->hdr.additionals);
        }
#endif

        if (!(dnsSessionData->hdr.flags & DNS_HDR_FLAG_RESPONSE))
        {
            /* Not a response */
            return;
        }

        /* Handle the DNS Queries */
        if (dnsSessionData->state == DNS_RESP_STATE_QUESTION)
        {
            /* Skip over the 4 byte question records... */
            for (i=dnsSessionData->curr_rec; i< dnsSessionData->hdr.questions; i++)
            {
                bytes_unused = ParseDNSQuestion(data, p->payload_size, bytes_unused, dnsSessionData);

                if (dnsSessionData->curr_rec_state == DNS_RESP_STATE_Q_COMPLETE)
                {
                    DEBUG_WRAP(
                        _dpd.debugMsg(DEBUG_DNS,
                            "DNS Question %d: type %d, class %d\n",
                            i, dnsSessionData->curr_q.type,
                            dnsSessionData->curr_q.dns_class);
                            );
                    dnsSessionData->curr_rec_state = DNS_RESP_STATE_Q_NAME;
                    dnsSessionData->curr_rec++;  
                }
                if (bytes_unused > 0)
                {
                    data = p->payload + (p->payload_size - bytes_unused);
                }
                else
                {
                    /* No more data */
                    return;
                }
            }
            dnsSessionData->state = DNS_RESP_STATE_ANS_RR;
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
            dnsSessionData->curr_rec = 0;
        }

        /* Handle the RRs */
        switch (dnsSessionData->state)
        {
        case DNS_RESP_STATE_ANS_RR: /* ANSWERS section */
            for (i=dnsSessionData->curr_rec; i<dnsSessionData->hdr.answers; i++)
            {
                bytes_unused = ParseDNSAnswer(data, p->payload_size,
                                                bytes_unused, dnsSessionData);

                if (bytes_unused == 0)
                {
                    /* No more data */
                    return;
                }

                switch (dnsSessionData->curr_rec_state)
                {
                case DNS_RESP_STATE_RR_RDATA_START:
                    DEBUG_WRAP(
                        _dpd.debugMsg(DEBUG_DNS, 
                                    "DNS ANSWER RR %d: type %d, class %d, "
                                    "ttl %d rdlength %d\n", i,
                                    dnsSessionData->curr_rr.type,
                                    dnsSessionData->curr_rr.dns_class,
                                    dnsSessionData->curr_rr.ttl,
                                    dnsSessionData->curr_rr.length);
                            );

                    dnsSessionData->bytes_seen_curr_rec = 0;
                    dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDATA_MID;
                    /* Fall through */
                case DNS_RESP_STATE_RR_RDATA_MID:
                    /* Data now points to the beginning of the RDATA */
                    data = p->payload + (p->payload_size - bytes_unused);
                    bytes_unused = ParseDNSRData(p, data, bytes_unused, dnsSessionData);
                    if (dnsSessionData->curr_rec_state != DNS_RESP_STATE_RR_COMPLETE)
                    {
                        /* Out of data, pick up on the next packet */
                        return;
                    }
                    else
                    {
                        /* Go to the next record */
                        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
                        dnsSessionData->curr_rec++;

                        if (dnsSessionData->curr_rr.type == DNS_RR_TYPE_TXT)
                        {
                            /* Reset the state tracking for this record */
                            bzero(&dnsSessionData->curr_txt, sizeof(DNSNameState));
                        }
                        data = p->payload + (p->payload_size - bytes_unused);
                    }
                }
            }
            dnsSessionData->state = DNS_RESP_STATE_AUTH_RR;
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
            dnsSessionData->curr_rec = 0;
            /* Fall through */
        case DNS_RESP_STATE_AUTH_RR: /* AUTHORITIES section */
            for (i=dnsSessionData->curr_rec; i<dnsSessionData->hdr.authorities; i++)
            {
                bytes_unused = ParseDNSAnswer(data, p->payload_size,
                                                bytes_unused, dnsSessionData);

                if (bytes_unused == 0)
                {
                    /* No more data */
                    return;
                }

                switch (dnsSessionData->curr_rec_state)
                {
                case DNS_RESP_STATE_RR_RDATA_START:
                    DEBUG_WRAP(
                        _dpd.debugMsg(DEBUG_DNS, 
                                    "DNS AUTH RR %d: type %d, class %d, "
                                    "ttl %d rdlength %d\n", i,
                                    dnsSessionData->curr_rr.type,
                                    dnsSessionData->curr_rr.dns_class,
                                    dnsSessionData->curr_rr.ttl,
                                    dnsSessionData->curr_rr.length);
                            );

                    dnsSessionData->bytes_seen_curr_rec = 0;
                    dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDATA_MID;
                    /* Fall through */
                case DNS_RESP_STATE_RR_RDATA_MID:
                    /* Data now points to the beginning of the RDATA */
                    data = p->payload + (p->payload_size - bytes_unused);
                    bytes_unused = ParseDNSRData(p, data, bytes_unused, dnsSessionData);
                    if (dnsSessionData->curr_rec_state != DNS_RESP_STATE_RR_COMPLETE)
                    {
                        /* Out of data, pick up on the next packet */
                        return;
                    }
                    else
                    {
                        /* Go to the next record */
                        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
                        dnsSessionData->curr_rec++;

                        if (dnsSessionData->curr_rr.type == DNS_RR_TYPE_TXT)
                        {
                            /* Reset the state tracking for this record */
                            bzero(&dnsSessionData->curr_txt, sizeof(DNSNameState));
                        }
                        data = p->payload + (p->payload_size - bytes_unused);
                    }
                }
            }
            dnsSessionData->state = DNS_RESP_STATE_ADD_RR;
            dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
            dnsSessionData->curr_rec = 0;
            /* Fall through */
        case DNS_RESP_STATE_ADD_RR: /* ADDITIONALS section */
            for (i=dnsSessionData->curr_rec; i<dnsSessionData->hdr.authorities; i++)
            {
                bytes_unused = ParseDNSAnswer(data, p->payload_size,
                                                bytes_unused, dnsSessionData);

                if (bytes_unused == 0)
                {
                    /* No more data */
                    return;
                }

                switch (dnsSessionData->curr_rec_state)
                {
                case DNS_RESP_STATE_RR_RDATA_START:
                    DEBUG_WRAP(
                        _dpd.debugMsg(DEBUG_DNS, 
                                    "DNS ADDITONAL RR %d: type %d, class %d, "
                                    "ttl %d rdlength %d\n", i,
                                    dnsSessionData->curr_rr.type,
                                    dnsSessionData->curr_rr.dns_class,
                                    dnsSessionData->curr_rr.ttl,
                                    dnsSessionData->curr_rr.length);
                            );

                    dnsSessionData->bytes_seen_curr_rec = 0;
                    dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_RDATA_MID;
                    /* Fall through */
                case DNS_RESP_STATE_RR_RDATA_MID:
                    /* Data now points to the beginning of the RDATA */
                    data = p->payload + (p->payload_size - bytes_unused);
                    bytes_unused = ParseDNSRData(p, data, bytes_unused, dnsSessionData);
                    if (dnsSessionData->curr_rec_state != DNS_RESP_STATE_RR_COMPLETE)
                    {
                        /* Out of data, pick up on the next packet */
                        return;
                    }
                    else
                    {
                        /* Go to the next record */
                        dnsSessionData->curr_rec_state = DNS_RESP_STATE_RR_NAME_SIZE;
                        dnsSessionData->curr_rec++;

                        if (dnsSessionData->curr_rr.type == DNS_RR_TYPE_TXT)
                        {
                            /* Reset the state tracking for this record */
                            bzero(&dnsSessionData->curr_txt, sizeof(DNSNameState));
                        }
                        data = p->payload + (p->payload_size - bytes_unused);
                    }
                }
            }
            /* Done with this one, onto the next -- may also be in this packet */
            dnsSessionData->state = DNS_RESP_STATE_LENGTH;
            dnsSessionData->curr_rec_state = 0;
            dnsSessionData->curr_rec = 0;
        }
    }

    return;
}

/* Main runtime entry point for DNS preprocessor. 
 * Analyzes DNS packets for anomalies/exploits. 
 * 
 * PARAMETERS:
 *
 * p:           Pointer to current packet to process. 
 * context:     Pointer to context block, not used.
 *
 * RETURNS:     Nothing.
 */
static void ProcessDNS( void* packetPtr, void* context )
{
    DNSSessionData* dnsSessionData = NULL;
    u_int8_t src = 0;
    u_int8_t dst = 0;
    u_int8_t known_port = 0;
    u_int8_t direction = 0; 
    SFSnortPacket* p;
    PROFILE_VARS;
    
    p = (SFSnortPacket*) packetPtr;

    /* Do we have a IP packet? */
    if (( !p ) ||
        ( !p->ip4_header ) )
    {
        return;
    }

    /* DNS only goes over TCP or UDP */
    if (!p->tcp_header && !p->udp_header)
    {
        return;
    }

    /* Check the ports to make sure this is a DNS port.
#if 0
     * Otherwise no need to examine the traffic.
#endif
     */
    src = CheckDNSPort( p->src_port );
    dst = CheckDNSPort( p->dst_port );

    /* See if a known server port is involved. */
    known_port = ( src || dst ? 1 : 0 );
      
#if 0
    if ( !dns_config.autodetect && !src && !dst )
    {
        /* Not one of the ports we care about. */
        return;
    }
#endif
    if (!known_port)
    {
        /* Not one of the ports we care about. */
        return;
    }
    
    /* For TCP, do a few extra checks... */
    if (p->tcp_header)
    {
        /* If session picked up mid-stream, do not process further.
         * Would be almost impossible to tell where we are in the
         * data stream. */
        if ( _dpd.streamAPI->get_session_flags(
            p->stream_session_ptr) & SSNFLAG_MIDSTREAM )
        {
            return;
        }

        if ( !_dpd.streamAPI->is_stream_sequenced(p->stream_session_ptr,
                    SSN_DIR_SERVER))
        {
            return;
        }

        if (!(_dpd.streamAPI->get_reassembly_direction(p->stream_session_ptr) & SSN_DIR_SERVER))
        {
            /* This should only happen for the first packet (SYN or SYN-ACK)
             * in the TCP session */
            _dpd.streamAPI->set_reassembly(p->stream_session_ptr,
                STREAM_FLPOLICY_FOOTPRINT, SSN_DIR_SERVER,
                STREAM_FLPOLICY_SET_APPEND);

            return;
        }

        /* If we're waiting on stream reassembly, don't process this packet. */
        if ( p->flags & FLAG_STREAM_INSERT)
        {
            return;
        }

        /* Get the direction of the packet. */
        direction = ( (p->flags & FLAG_FROM_SERVER ) ? 
                        DNS_DIR_FROM_SERVER : DNS_DIR_FROM_CLIENT );
    }
    else if (p->udp_header)
    {
        if (src)
            direction = DNS_DIR_FROM_SERVER;
        else if (dst)
            direction = DNS_DIR_FROM_CLIENT;
    }
        

    /* check if we have data to work with */
    if (( !p->payload ) ||
        ( !p->payload_size ))
    {
        return;
    }

    PREPROC_PROFILE_START(dnsPerfStats);
    
    /* Check the stream session. If it does not currently
     * have our DNS data-block attached, create one.
     */
    dnsSessionData = GetDNSSessionData( p );
    
    if ( !dnsSessionData )
    {
        /* Could not get/create the session data for this packet. */
        PREPROC_PROFILE_END(dnsPerfStats);
        return;
    }

    if (dnsSessionData->flags & DNS_FLAG_NOT_DNS)
    {
        /* determined that this session wasn't DNS, we're done */
        PREPROC_PROFILE_END(dnsPerfStats);
        return;
    }

    if (direction == DNS_DIR_FROM_SERVER)
    {
        ParseDNSResponseMessage(p, dnsSessionData);
    }
    
    PREPROC_PROFILE_END(dnsPerfStats);
}

