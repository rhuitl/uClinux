/* $Id$ */
/*
 * Copyright(C) 2002 Sourcefire, Inc.
 * 
 * Author(s):  Andrew R. Baker <andrewb@snort.org>
 *             Martin Roesch   <roesch@sourcefire.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

/* includes */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef WIN32
#include <netdb.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "util.h"
#include "mstring.h"
#include "parser.h"
#include "debug.h"

#include "IpAddrSet.h"

IpAddrSet *IpAddrSetCreate()
{
    IpAddrSet *tmp;

    tmp = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));

    return tmp;
}


void IpAddrSetDestroy(IpAddrSet *ipAddrSet)
{
    IpAddrSet *next;

    while(ipAddrSet)
    {
        next = ipAddrSet->next;
        free(ipAddrSet);
        ipAddrSet = next;
    }
}

static char buffer[1024];

void IpAddrSetPrint(char *prefix, IpAddrSet *ipAddrSet)
{
    struct in_addr in;
    int ret;
    
    while(ipAddrSet)
    {
        buffer[0] = '\0';

        if(ipAddrSet->addr_flags & EXCEPT_IP)
        {
            ret = SnortSnprintfAppend(&buffer[0], sizeof(buffer), "NOT ");
            if (ret != SNORT_SNPRINTF_SUCCESS)
                return;
        }

        in.s_addr = ipAddrSet->ip_addr;
        ret = SnortSnprintfAppend(&buffer[0], sizeof(buffer), "%s/", inet_ntoa(in));
        if (ret != SNORT_SNPRINTF_SUCCESS)
            return;

        in.s_addr = ipAddrSet->netmask;
        ret = SnortSnprintfAppend(&buffer[0], sizeof(buffer), "%s", inet_ntoa(in));
        if (ret != SNORT_SNPRINTF_SUCCESS)
            return;

        if (prefix)
            LogMessage("%s%s\n", prefix, buffer);
        else
            LogMessage("%s%s\n", buffer);

        ipAddrSet = ipAddrSet->next;
    }
}

IpAddrSet *IpAddrSetCopy(IpAddrSet *ipAddrSet)
{
    IpAddrSet *newIpAddrSet = NULL;
    IpAddrSet *current = NULL;
    IpAddrSet *prev = NULL;

    while(ipAddrSet)
    {
        if(!(current = (IpAddrSet *)malloc(sizeof(IpAddrSet))))
        {
            /* ENOMEM */
            goto failed;
        }
        
        current->ip_addr = ipAddrSet->ip_addr;
        current->netmask = ipAddrSet->netmask;
        current->addr_flags = ipAddrSet->addr_flags;
        current->next = NULL;

        if(!prev)
            newIpAddrSet = current;
        else
            prev->next = current;

        ipAddrSet = ipAddrSet->next;
        prev = current;
    }

    return newIpAddrSet;

failed:
    if(newIpAddrSet)
        IpAddrSetDestroy(newIpAddrSet);
    return NULL; /* XXX ENOMEM */
}


/* XXX: legacy support function */
/*
 * Function: ParseIP(char *, IpAddrSet *)
 *
 * Purpose: Convert a supplied IP address to it's network order 32-bit long
 *          value.  Also convert the CIDR block notation into a real
 *          netmask.
 *
 * Arguments: char *addr  => address string to convert
 *            IpAddrSet * =>
 *            
 *
 * Returns: 0 for normal addresses, 1 for an "any" address
 */
int ParseIP(char *paddr, IpAddrSet *address_data)
{
    char **toks;        /* token dbl buffer */
    int num_toks;       /* number of tokens found by mSplit() */
    int cidr = 1;       /* is network expressed in CIDR format */
    int nmask = -1;     /* netmask temporary storage */
    char *addr;         /* string to parse, eventually a
                         * variable-contents */
    struct hostent *host_info;  /* various struct pointers for stuff */
    struct sockaddr_in sin; /* addr struct */
    char broadcast_addr_set = 0;

    addr = paddr;

    if(*addr == '!')
    {
        address_data->addr_flags |= EXCEPT_IP;

        addr++;  /* inc past the '!' */
    }

    /* check for wildcards */
    if(!strcasecmp(addr, "any"))
    {
        address_data->ip_addr = 0;
        address_data->netmask = 0;
        return 1;
    }
    /* break out the CIDR notation from the IP address */
    toks = mSplit(addr, "/", 2, &num_toks, 0);

    /* "/" was not used as a delimeter, try ":" */
    if(num_toks == 1)
    {
        mSplitFree(&toks, num_toks);
        toks = mSplit(addr, ":", 2, &num_toks, 0);
    }

    /*
     * if we have a mask spec and it is more than two characters long, assume
     * it is netmask format
     */
    if((num_toks > 1) && strlen(toks[1]) > 2)
    {
        cidr = 0;
    }

    switch(num_toks)
    {
        case 1:
            address_data->netmask = netmasks[32];
            break;

        case 2:
            if(cidr)
            {
                /* convert the CIDR notation into a real live netmask */
                nmask = atoi(toks[1]);

                /* it's pain to differ whether toks[1] is correct if netmask */
                /* is /0, so we deploy some sort of evil hack with isdigit */

                if(!isdigit((int) toks[1][0]))
                    nmask = -1;

                /* if second char is != '\0', it must be a digit
                 * by Daniel B. Cid, dcid@sourcefire.com
                 */ 
                if((toks[1][1] != '\0')&&(!isdigit((int) toks[1][1]) ))
                    nmask = -1;
                
                if((nmask > -1) && (nmask < 33))
                {
                    address_data->netmask = netmasks[nmask];
                }
                else
                {
                    FatalError("ERROR %s(%d): Invalid CIDR block for IP addr "
                            "%s\n", file_name, file_line, addr);
                           
                }
            }
            else
            {
                /* convert the netmask into its 32-bit value */

                /* broadcast address fix from 
                 * Steve Beaty <beaty@emess.mscd.edu> 
                 */

                /*
                 * if the address is the (v4) broadcast address, inet_addr *
                 * returns -1 which usually signifies an error, but in the *
                 * broadcast address case, is correct.  we'd use inet_aton() *
                 * here, but it's less portable.
                 */
                if(!strncmp(toks[1], "255.255.255.255", 15))
                {
                    address_data->netmask = INADDR_BROADCAST;
                }
                else if((address_data->netmask = inet_addr(toks[1])) == -1)
                {
                    FatalError("ERROR %s(%d): Unable to parse rule netmask "
                            "(%s)\n", file_name, file_line, toks[1]);
                }
                /* Set nmask so we don't try to do a host lookup below.
                 * The value of 0 is irrelevant. */
                nmask = 0;
            }
            break;

        default:
            FatalError("ERROR %s(%d) => Unrecognized IP address/netmask %s\n",
                    file_name, file_line, addr);
            break;
    }
    sin.sin_addr.s_addr = inet_addr(toks[0]);

#ifndef WORDS_BIGENDIAN
    /*
     * since PC's store things the "wrong" way, shuffle the bytes into the
     * right order.  Non-CIDR netmasks are already correct.
     */
    if(cidr)
    {
        address_data->netmask = htonl(address_data->netmask);
    }
#endif
    /* broadcast address fix from Steve Beaty <beaty@emess.mscd.edu> */
    /* Changed location */
    if(!strncmp(toks[0], "255.255.255.255", 15))
    {
        address_data->ip_addr = INADDR_BROADCAST;
        broadcast_addr_set = 1;
    }
    else if (nmask == -1)
    {
        /* Try to do a host lookup if the address didn't
         * convert to a valid IP and there were not any
         * mask bits specified (CIDR or dot notation). */
        if(sin.sin_addr.s_addr == INADDR_NONE)
        {
            /* get the hostname and fill in the host_info struct */
            if((host_info = gethostbyname(toks[0])))
            {
                /* protecting against malicious DNS servers */
                if(host_info->h_length <= sizeof(sin.sin_addr))
                {
                    bcopy(host_info->h_addr, (char *) &sin.sin_addr, host_info->h_length);
                }
                else
                {
                    bcopy(host_info->h_addr, (char *) &sin.sin_addr, sizeof(sin.sin_addr));
                }
            }
            /* Using h_errno */
            else if(h_errno == HOST_NOT_FOUND)
            /*else if((sin.sin_addr.s_addr = inet_addr(toks[0])) == INADDR_NONE)*/
            {
                FatalError("ERROR %s(%d): Couldn't resolve hostname %s\n",
                    file_name, file_line, toks[0]);
            }
        }
        else
        {
            /* It was a valid IP address with no netmask specified. */
            /* Noop */
        }
    }
    else
    {
        if(sin.sin_addr.s_addr == INADDR_NONE)
        {
            /* It was not a valid IP address but had a valid netmask. */
            FatalError("ERROR %s(%d): Rule IP addr (%s) didn't translate\n",
                file_name, file_line, toks[0]);
        }
    }

    /* Only set this if we haven't set it above as 255.255.255.255 */
    if (!broadcast_addr_set)
    {
        address_data->ip_addr = ((u_long) (sin.sin_addr.s_addr) &
            (address_data->netmask));
    }
    mSplitFree(&toks, num_toks);
    return 0;
}                                                                                            


IpAddrSet *IpAddrSetParse(char *addr)
{
    IpAddrSet *ias = NULL;
    IpAddrSet *tmp_ias = NULL;
    char **toks;
    int num_toks;
    int i;
    char *tmp;
    char *enbracket;
    char *index;
    int flags = 0;

    index = addr;
    
    while(isspace((int)*index)) index++;
    
    if(*index == '!')
    {
        flags = EXCEPT_IP;
    }

    if(*index == '$')
    {
        if((tmp = VarGet(index+1)) == NULL)
        {
            FatalError("%s(%d) => Undefined variable %s\n", file_name, file_line,
                    index);
        }
    }
    else
    {
        tmp = index;
    }

    if(*tmp == '[')
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Found IP list!\n"););

        enbracket = strrchr(tmp, (int)']'); /* null out the en-bracket */

        if(enbracket) 
            *enbracket = '\x0';
        else
            FatalError("%s(%d) => Unterminated IP List\n", file_name, file_line);

        toks = mSplit(tmp+1, ",", 128, &num_toks, 0);

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"mSplit got %d tokens...\n", 
                    num_toks););

        for(i=0; i< num_toks; i++)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"adding %s to IP "
                        "address list\n", toks[i]););
            tmp = toks[i];

            while (isspace((int)*tmp)||*tmp=='[') tmp++;

            enbracket = strrchr(tmp, (int)']'); /* null out the en-bracket */

            if(enbracket) 
                *enbracket = '\x0';

            if (!strlen(tmp))
                continue;
                
            if(!ias)
            {
                ias = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));
                tmp_ias = ias;
            }
            else
            {
                tmp_ias->next = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));
                tmp_ias = tmp_ias->next;
            }
            
            ParseIP(tmp, tmp_ias);
        }

        mSplitFree(&toks, num_toks);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                    "regular IP address, processing...\n"););

        ias = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));

        ParseIP(tmp, ias);
    }

    return ias;
}


int IpAddrSetContains(IpAddrSet *ias, struct in_addr test_addr)
{
    IpAddrSet *index;
    u_int32_t raw_addr;
    int exception_flag = 0;


    raw_addr = test_addr.s_addr;
    
    for(index = ias; index != NULL; index = index->next)
    {
        if(index->addr_flags & EXCEPT_IP) exception_flag = 1;

        if(((index->ip_addr == (raw_addr & index->netmask)) ^ exception_flag))
        {
            return 1;
        }
    }

    return 0;
}
