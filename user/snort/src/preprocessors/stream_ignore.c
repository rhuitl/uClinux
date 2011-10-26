/* $Id$ */

/*
** Copyright (C) 2005 Sourcefire, Inc.
** AUTHOR: Steven Sturges
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

/* stream_ignore.c
 * 
 * Purpose: Handle hash table storage and lookups for ignoring
 *          entire data streams.
 *
 * Arguments:
 *   
 * Effect:
 *
 * Comments:
 *
 * Any comments?
 *
 */
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */
#include <time.h>

#include "debug.h"
#include "decode.h"
#include "stream_api.h"
#include "sfghash.h"
#include "util.h"

/* Reasonably small, and prime */
#define IGNORE_HASH_SIZE 1021
typedef struct _IgnoreNode
{
    u_int32_t ip1;
    short port1;
    u_int32_t ip2;
    short port2;
    char protocol;
    time_t expires;
    int direction;
    int numOccurances;
} IgnoreNode;

typedef struct _IgnoreHashKey
{
    u_int32_t ip1;
    u_int32_t ip2;
    short port;
    char protocol;
    char pad;
} IgnoreHashKey;

/* The hash table of ignored channels */
static SFGHASH *channelHash = NULL;

int IgnoreChannel(u_int32_t cliIP, u_int16_t cliPort,
                  u_int32_t srvIP, u_int16_t srvPort,
                  char protocol, char direction, char flags,
                  u_int32_t timeout)
{
    IgnoreHashKey hashKey;
    time_t now;
    IgnoreNode *node = NULL;
    short portToHash = cliPort != UNKNOWN_PORT ? cliPort : srvPort;
    u_int32_t ip1, ip2;

    if (!channelHash)
    {
        /* Create the hash table */
        channelHash = sfghash_new(IGNORE_HASH_SIZE,
                                  sizeof(IgnoreHashKey), 0, free);
    }
   
    time(&now);

    /* Add the info to a tree that marks this channel as one to ignore.
     * Only one of the port values may be UNKNOWN_PORT.  
     * As a sanity check, the IP addresses may not be 0 or 255.255.255.255.
     */
    if ((cliPort == UNKNOWN_PORT) && (srvPort == UNKNOWN_PORT))
        return -1;

    if ((cliIP == 0) || (cliIP == 0xFFFFFFFF) ||
        (srvIP == 0) || (srvIP == 0xFFFFFFFF) )
        return -1;

    if (cliIP < srvIP)
    {
        ip1 = cliIP;
        ip2 = srvIP;
    }
    else
    {
        ip1 = srvIP;
        ip2 = cliIP;
    }

    /* Actually add it to the hash table with a timestamp of now.
     * so we can expire entries that are older than a configurable
     * time.  Those entries will be for sessions that we missed or
     * never occured.  Should not keep the entry around indefinitely.
     */
    hashKey.ip1 = ip1;
    hashKey.ip2 = ip2;
    hashKey.port = portToHash;
    hashKey.protocol = protocol;
    hashKey.pad = 0;

    node = sfghash_find(channelHash, &hashKey);
    if (node)
    {
        /*
         * This handles the case where there is already an entry
         * for this key (IP addresses/port).  It could occur when
         * multiple users from behind a NAT'd Firewall all go to the
         * same site when in FTP Port mode.  To get around this issue,
         * we keep a counter of the number of pending open channels
         * with the same known endpoints (2 IPs & a port).  When that
         * channel is actually opened, the counter is decremented, and
         * the entry is removed when the counter hits 0.
         * Because all of this is single threaded, there is no potential
         * for a race condition.
         */
        int expired = (node->expires != 0) && (now > node->expires);
        if (expired)
        {
            node->ip1 = cliIP;
            node->port1 = cliPort;
            node->ip2 = srvIP;
            node->port2 = srvPort;
            node->direction = direction;
            node->protocol = protocol;
        }
        else
        {
            node->numOccurances++;
        }
        if (flags & IGNORE_FLAG_ALWAYS)
            node->expires = 0;
        else
            node->expires = now + timeout;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                   "Updating ignore channel node\n"););
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                   "Adding ignore channel node\n"););

        node = malloc(sizeof(IgnoreNode));
        if (!node)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Memory alloc error\n"););
            return -1;
        }
        node->ip1 = cliIP;
        node->port1 = cliPort;
        node->ip2 = srvIP;
        node->port2 = srvPort;
        node->direction = direction;
        node->protocol = protocol;
        /* now + 5 minutes (configurable?)
         *
         * use the time that we keep sessions around
         * since this info would effectively be invalid
         * after that anyway because the session that
         * caused this will be gone.
         */
        if (flags & IGNORE_FLAG_ALWAYS)
            node->expires = 0;
        else
            node->expires = now + timeout;
        node->numOccurances = 1;

        /* Add it to the table */
        if (sfghash_add(channelHash, &hashKey, (void *)node)
            != SFGHASH_OK)
        {
            /* Uh, shouldn't get here...
             * There is already a node or couldn't alloc space
             * for key.  This means bigger problems, but fail
             * gracefully.
             */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                       "Failed to add channel node to hash table\n"););
            free(node);
            return -1;
        }
    }

    return 0;
}

char CheckIgnoreChannel(Packet *p)
{
    u_int32_t srcIP, dstIP;
    short srcPort, dstPort;
    char protocol;

    IgnoreHashKey hashKey;
    time_t now;
    int match = 0;
    int retVal = 0;
    IgnoreNode *node = NULL;
    int expired = 0;
    int i;

    /* No hash table, or its empty?  Get out of dodge.  */
    if (!channelHash || channelHash->count == 0)
        return retVal;

    srcIP = p->iph->ip_src.s_addr;
    dstIP = p->iph->ip_dst.s_addr;
    srcPort = p->sp;
    dstPort = p->dp;
    protocol = p->iph->ip_proto;
    
    /* First try the hash table using the dstPort.
     * For FTP data channel this would be the client's port when the PORT
     * command is used and the server is initiating the connection.
     * This is done first because it is the most common case for FTP clients.
     */
    if (dstIP < srcIP)
    {
        hashKey.ip1 = dstIP;
        hashKey.ip2 = srcIP;
    }
    else
    {
        hashKey.ip1 = srcIP;
        hashKey.ip2 = dstIP;
    }
    hashKey.port = dstPort;
    hashKey.protocol = protocol;
    hashKey.pad = 0;

    node = sfghash_find(channelHash, &hashKey);

    if (!node)
    {
        /* Okay, next try the hash table using the srcPort.
         * For FTP data channel this would be the servers's port when the
         * PASV command is used and the client is initiating the connection.
         */
        hashKey.port = srcPort;
        node = sfghash_find(channelHash, &hashKey);

        /* We could also check the reverses of these, ie. use 
         * srcIP then dstIP in the hashKey.  Don't need to, though.
         *
         * Here's why:
         * 
         * Since there will be an ACK that comes back from the server
         * side, we don't need to look for the hash entry the other
         * way -- it will be found when we get the ACK.  This approach
         * results in 2 checks per packet -- and 2 checks on the ACK.
         * If we find a match, cool.  If not we've done at most 4 checks
         * between the packet and the ACK.
         * 
         * Whereas, if we check the reverses, we do 4 checks on each
         * side, or 8 checks between the packet and the ACK.  While
         * this would more quickly find the channel to ignore, it is
         * a performance hit when we the session in question is
         * NOT being ignored.  Err on the side of performance here.
         */
    }


    /* Okay, found the key --> verify that the info in the node
     * does in fact match and has not expired.
     */
    time(&now);
    if (node)
    {
        /* If the IPs match and if the ports match (or the port is
         * "unknown"), we should ignore this channel.
         */
        if (node->ip1 == srcIP && node->ip2 == dstIP &&
            (node->port1 == srcPort || node->port1 == UNKNOWN_PORT) &&
            (node->port2 == dstPort || node->port2 == UNKNOWN_PORT) )
        {
            match = 1;
        }
        else if (node->ip2 == srcIP && node->ip1 == dstIP &&
                 (node->port2 == srcPort || node->port2 == UNKNOWN_PORT) &&
                 (node->port1 == dstPort || node->port1 == UNKNOWN_PORT) )
        {
            match = 1;
        }

        /* Make sure the packet direction is correct */
        switch (node->direction)
        {
            case SSN_DIR_BOTH:
                break;
            case SSN_DIR_CLIENT:
                if (!(p->packet_flags & PKT_FROM_CLIENT))
                    match = 0;
                break;
            case SSN_DIR_SERVER:
                if (!(p->packet_flags & PKT_FROM_SERVER))
                    match = 0;
                break;
        }

        if (node->expires)
            expired = (now > node->expires);
        if (match)
        {
            /* Uh, just check to be sure it hasn't expired,
             * in case we missed a packet and this is a
             * different connection.  */
            if ((node->numOccurances > 0) && (!expired))
            {
                node->numOccurances--;
                /* Matched & Still valid --> ignore it! */
                retVal = node->direction;

#ifdef DEBUG
                {
                    /* Have to allocate & copy one of these since inet_ntoa
                     * clobbers the info from the previous call. */
                    struct in_addr tmpAddr;
                    char srcAddr[17];
                    tmpAddr.s_addr = srcIP;
                    SnortStrncpy(srcAddr, inet_ntoa(tmpAddr), sizeof(srcAddr));
                    tmpAddr.s_addr = dstIP;

                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                           "Ignoring channel %s:%d --> %s:%d\n",
                           srcAddr, srcPort,
                           inet_ntoa(tmpAddr), dstPort););
                }
#endif
            }
        }

        if (((node->numOccurances <= 0) || (expired)) &&
                (node->expires != 0))

        {
            /* Either expired or was the only one in the hash
             * table.  Remove this node.  */
            sfghash_remove(channelHash, &hashKey);
        }
    }

    /* Clean the hash table of at most 5 expired nodes */
    for (i=0;i<5 && channelHash->count>0;i++)
    {
        SFGHASH_NODE *hash_node = sfghash_findfirst(channelHash);
        if (hash_node)
        {
            node = hash_node->data;
            if (node)
            {
                expired = (node->expires != 0) && (now > node->expires);
                if (expired)
                {
                    /* sayonara baby... */
                    sfghash_remove(channelHash, hash_node->key);
                }
                else
                {
                    /* This one's not expired, fine...
                     * no need to prune further.
                     */
                    break;
                }
            }
        }
    }

    return retVal;
}
