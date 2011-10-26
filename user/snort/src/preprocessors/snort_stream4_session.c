/* $Id$ */

/*
** Copyright (C) 2005 Sourcefire, Inc.
** AUTHOR: Steven Sturges <ssturges@sourcefire.com>
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

/* snort_stream4_session.c
 * 
 * Purpose: Hash Table implementation of session management functions for
 *          TCP stream preprocessor.
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

#define _STREAM4_INTERNAL_USAGE_ONLY_

#include "sfxhash.h"
#include "decode.h"
#include "debug.h"
#include "stream.h"
#include "log.h"
#include "util.h"

/* Stuff defined in stream4.c that we use */
extern void DeleteSession(Session *, u_int32_t);
extern Stream4Data s4data;
extern u_int32_t stream4_memory_usage;

static SFXHASH *sessionHashTable = NULL;
static SFXHASH *udpSessionHashTable = NULL;

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
extern PreprocStats stream4LUSessPerfStats;
#endif

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

int GetSessionCount(Packet *p)
{
    if (p->iph)
    {
        if (p->iph->ip_proto == IPPROTO_TCP)
        {
            if (sessionHashTable)
                return sessionHashTable->count;
            else
                return 0;
        }
        else
        {
            if (udpSessionHashTable)
                return udpSessionHashTable->count;
            else
                return 0;
        }
    }
    return 0;
}

int GetSessionKey(Packet *p, SessionHashKey *key)
{
    u_int32_t srcIp, dstIp;
    u_int16_t srcPort, dstPort;

    if (!key)
        return 0;

    memset(key, 0, sizeof(SessionHashKey));

    srcIp = p->iph->ip_src.s_addr;
    dstIp = p->iph->ip_dst.s_addr;
    if (p->tcph)
    {
        srcPort = p->tcph->th_sport;
        dstPort = p->tcph->th_dport;
    }
#ifdef STREAM4_UDP
    else if (p->udph)
    {
        srcPort = p->udph->uh_sport;
        dstPort = p->udph->uh_dport;
    }
#endif
    else
    {
        srcPort = 0;
        dstPort = 0;
    }
    
    if (srcIp < dstIp)
    {
        key->lowIP = srcIp;
        key->port = srcPort;
        key->highIP = dstIp;
        key->port2 = dstPort;
    }
    else if (srcIp == dstIp)
    {
        key->lowIP = srcIp;
        key->highIP = dstIp;
        if (srcPort < dstPort)
        {
            key->port = srcPort;
            key->port2 = dstPort;
        }
        else
        {
            key->port2 = srcPort;
            key->port = dstPort;
        }
    }
    else
    {
        key->lowIP = dstIp;
        key->port = dstPort;
        key->highIP = srcIp;
        key->port2 = srcPort;
    }

    key->proto = p->iph->ip_proto;

#ifdef _LP64
    key->pad1 = key->pad2 = 0;
#endif

    return 1;
}

Session *GetSessionFromHashTable(Packet *p)
{
    Session *returned = NULL;
    SFXHASH_NODE *hnode;
    SessionHashKey sessionKey;
    SFXHASH *table;

    if (!GetSessionKey(p, &sessionKey))
        return NULL;

    if (sessionKey.proto == IPPROTO_TCP)
    {
        table = sessionHashTable;
    }
    else /* Implied IPPROTO_UDP */
    {
        table = udpSessionHashTable;
    }

    hnode = sfxhash_find_node(table, &sessionKey);

    if (hnode && hnode->data)
    {
        /* This is a unique hnode, since the sfxhash finds the
         * same key before returning this node.
         */
        returned = (Session *)hnode->data;
    }
    return returned;
}

int RemoveSessionFromHashTable(Session *ssn)
{
    SFXHASH *table;
    if (ssn->hashKey.proto == IPPROTO_TCP)
    {
        table = sessionHashTable;
    }
    else /* Implied IPPROTO_UDP */
    {
        table = udpSessionHashTable;
    }

    return sfxhash_remove(table, &(ssn->hashKey));
}

int CleanHashTable(SFXHASH *table, u_int32_t thetime, Session *save_me, int memCheck)
{
    Session *idx;
    u_int32_t pruned = 0;
    u_int32_t timeout = s4data.timeout;

    if (thetime != 0)
    {
        char got_one;
        idx = (Session *) sfxhash_lru(table);

        if(idx == NULL)
        {
            return 0;
        }

        do
        {
            got_one = 0;            
            if(idx == save_me)
            {
                SFXHASH_NODE *lastNode = sfxhash_lru_node(table);
                sfxhash_gmovetofront(table, lastNode);
                lastNode = sfxhash_lru_node(table);
                if ((lastNode) && (lastNode->data != idx))
                {
                    idx = (Session *)lastNode->data;
                    continue;
                }
                else
                {
                    return pruned;
                }
            }

            timeout = s4data.timeout;
            if(idx->drop_traffic)
            {
                /* If we're dropping traffic on the session, keep
                 * it around longer.  */
                timeout = s4data.timeout * 2;
            }

            if((idx->last_session_time+timeout) < thetime)
            {
                Session *savidx = idx;

                if(sfxhash_count(table) > 1)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "pruning stale session\n"););
                    DeleteSession(savidx, thetime);
                    idx = (Session *) sfxhash_lru(table);
                    pruned++;
                    got_one = 1;
                }
                else
                {
                    DeleteSession(savidx, thetime);
                    pruned++;
                    return pruned;
                }
            }
            else
            {
                return pruned;
            }

            if (pruned > s4data.cache_clean_sessions)
            {
                /* Don't bother cleaning more than XXX at a time */
                break;
            }
        } while ((idx != NULL) && (got_one == 1));

        return pruned;
    }
    else
    {
        /* Free up xxx sessions at a time until we get under the
         * memcap or free enough sessions to be able to create
         * new ones.
         *
         * This loop repeats while we're over the memcap or we have
         * more sessions than the max less what we're supposed to
         * cleanup at a time.
         */
        while ((sfxhash_count(table) > 1) &&
                ((memCheck && (stream4_memory_usage > s4data.memcap)) ||
                 (table->count > (s4data.max_sessions - s4data.cache_clean_sessions)) ||
                 (pruned < s4data.cache_clean_sessions)))
        {
            u_int32_t i;
            idx = (Session *) sfxhash_lru(table);

            for (i=0;i<s4data.cache_clean_sessions && 
                     (sfxhash_count(table) > 1); i++)
            {
                if(idx != save_me)
                {
                    DeleteSession(idx, thetime);
                    pruned++;
                    idx = (Session *) sfxhash_lru(table);
                }
                else
                {
                    SFXHASH_NODE *lastNode = sfxhash_lru_node(table);
                    sfxhash_gmovetofront(table, lastNode);
                    lastNode = sfxhash_lru_node(table);
                    if ((lastNode) && (lastNode->data == idx))
                    {
                        /* Okay, this session is the only one left */
                        break;
                    }
                    idx = (Session *) sfxhash_lru(table);
                    i--; /* Didn't clean this one */
                }
            }
        }
    }
    return pruned;
}

Session *GetNewSession(Packet *p)
{
    Session *retSsn = NULL;
    SessionHashKey sessionKey;
    SFXHASH_NODE *hnode = NULL;
    SFXHASH *table;

    if (!GetSessionKey(p, &sessionKey))
        return retSsn;

    if (sessionKey.proto == IPPROTO_TCP)
    {
        table = sessionHashTable;
    }
    else /* Implied IPPROTO_UDP */
    {
        table = udpSessionHashTable;
    }

    if (sfxhash_count(table) < s4data.max_sessions &&
        stream4_memory_usage < s4data.memcap)
    {
        hnode = sfxhash_get_node(table, &sessionKey);
    }

    if (!hnode)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "HashTable full, clean it\n"););

        if (!CleanHashTable(table, p->pkth->ts.tv_sec, NULL, 0))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "HashTable full, no timeouts, clean it\n"););

            CleanHashTable(table, 0, NULL, 0);
        }

        /* Should have some freed nodes now */
        hnode = sfxhash_get_node(table, &sessionKey);
        if (!hnode)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Problem, no freed nodes\n"););
        }
    }
    if (hnode && hnode->data)
    {
        retSsn = hnode->data;

        /* Zero everything out */
        memset(retSsn, 0, sizeof(Session));

        /* Save the session key for future use */
        memcpy(&(retSsn->hashKey), &sessionKey,
                        sizeof(SessionHashKey));
    }

    return retSsn;
}

Session *RemoveSession(Session *ssn)
{
    if (!RemoveSessionFromHashTable(ssn) )
        return ssn;
    else
        return NULL;
}

Session *GetSession(Packet *p)
{
    Session *ssn;
    PROFILE_VARS;
    PREPROC_PROFILE_START(stream4LUSessPerfStats);
    ssn = GetSessionFromHashTable(p);
    PREPROC_PROFILE_END(stream4LUSessPerfStats);

    /* Handle a timeout of existing session */
    if(ssn)
    {
        int timeout = s4data.timeout;
        if(ssn->drop_traffic)
        {
            /* If we're dropping traffic on the session, keep
             * it around longer.  */
            timeout *= 2;
        }
        if ((ssn->last_session_time+timeout) < p->pkth->ts.tv_sec)
        {
            DeleteSession(ssn, p->pkth->ts.tv_sec);
            ssn = NULL;
        }
    }

    return ssn;
}

void InitSessionCache()
{
    if (!sessionHashTable)
    {
        /* Create the hash table --
         * SESSION_HASH_TABLE_SIZE hash buckets
         * keysize = 12 bytes (2x 32bit IP, 2x16bit port)
         * data size = sizeof(Session) object
         * no max mem
         * no automatic node recovery
         * NULL node recovery free function
         * NULL user data free function
         * recycle nodes
         */
        /* Rule of thumb, size should be 1.4 times max to avoid
         * collisions.
         */
        int hashTableSize = sfxhash_calcrows((int)(s4data.max_sessions * 1.4));
        //int maxSessionMem = s4data.max_sessions * (
        //                     sizeof(Session) +
        //                     sizeof(SFXHASH_NODE) +
        //                     sizeof(SessionHashKey) +
        //                     sizeof (SFXHASH_NODE *));
        //int tableMem = (hashTableSize +1) * sizeof(SFXHASH_NODE*);
        //int maxMem = maxSessionMem + tableMem;
        sessionHashTable = sfxhash_new(hashTableSize,
                        sizeof(SessionHashKey),
                        //sizeof(Session), maxMem, 0, NULL, NULL, 1);
                        sizeof(Session), 0, 0, NULL, NULL, 1);

#ifdef STREAM4_UDP
        /* And create the udp one */
        hashTableSize = sfxhash_calcrows((int)(s4data.max_udp_sessions * 1.4));
        //maxSessionMem = s4data.max_udp_sessions * (
        //                     sizeof(Session) +
        //                     sizeof(SFXHASH_NODE) +
        //                     sizeof(SessionHashKey) +
        //                     sizeof (SFXHASH_NODE *));
        //tableMem = (hashTableSize +1) * sizeof(SFXHASH_NODE*);
        //maxMem = maxSessionMem + tableMem;
        udpSessionHashTable = sfxhash_new(hashTableSize,
                        sizeof(SessionHashKey),
                        //sizeof(Session), maxMem, 0, NULL, NULL, 1);
                        sizeof(Session), 0, 0, NULL, NULL, 1);
#endif
    }
}

void PurgeSessionCache()
{
    Session *ssn = NULL;
    ssn = (Session *)sfxhash_mru(sessionHashTable);
    while (ssn)
    {
        DeleteSession(ssn, 0);
        ssn = (Session *)sfxhash_mru(sessionHashTable);
    }
}

void PrintSessionCache()
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "%lu streams active, %u bytes in use\n", 
                            sfxhash_count(sessionHashTable), stream4_memory_usage););
    return;
}

int PruneSessionCache(u_int8_t proto, u_int32_t thetime, int mustdie, Session *save_me)
{
    SFXHASH *table;
    if (proto == IPPROTO_TCP)
    {
        table = sessionHashTable;
    }
    else /* Implied IPPROTO_UDP */
    {
        table = udpSessionHashTable;
    }

    return CleanHashTable(table, thetime, save_me, 1);
}

