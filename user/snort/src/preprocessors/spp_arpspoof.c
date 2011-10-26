/* $Id$ */
/*
** Copyright (C) 2001-2004 Jeff Nathan <jeff@snort.org>
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

/* Snort ARPspoof Preprocessor Plugin
 *   by Jeff Nathan <jeff@snort.org>
 *   Version 0.1.4
 *
 * Purpose:
 *
 * This preprocessor looks for anomalies in ARP traffic and attempts to 
 * maliciously overwrite  ARP cache information on hosts.
 *
 * Arguments:
 *
 * To check for unicast ARP requests use:
 * arpspoof: -unicast
 *
 * WARNING: this can generate false positives as Linux systems send unicast 
 * ARP requests repetatively for entries in their cache.
 *
 * This plugin also takes a list of IP addresses and MAC address in the form:
 * arpspoof_detect_host: 10.10.10.10 29:a2:9a:29:a2:9a
 * arpspoof_detect_host: 192.168.40.1 f0:0f:00:f0:0f:00
 * and so forth...
 *
 * Effect:
 * By comparing information in the Ethernet header to the ARP frame, obvious
 * anomalies are detected.  Also, utilizing a user supplied list of IP 
 * addresses and MAC addresses, ARP traffic appearing to have originated from 
 * any IP in that list is carefully examined by comparing the source hardware 
 * address to the user supplied hardware address.  If there is a mismatch, an 
 * alert is generated as either an ARP request or REPLY can be used to 
 * overwrite cache information on a remote host.  This should only be used for 
 * hosts/devices on the **same layer 2 segment** !!
 *
 * Bugs:
 * This is a proof of concept ONLY.  It is clearly not complete.  Also, the 
 * lookup function LookupIPMacEntryByIP is in need of optimization.  The
 * arpspoof_detect_host functionality may false alarm in redundant environments. * Also, see the comment above pertaining to Linux systems.
 *
 * Thanks:
 *
 * First and foremost Patrick Mullen who sat beside me and helped every step of
 * the way.  Andrew Baker for graciously supplying the tougher parts of this 
 * code.  W. Richard Stevens for readable documentation and finally 
 * Marty for being a badass.  All your packets are belong to Marty.
 *
 */

/*  I N C L U D E S  ************************************************/
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#if !defined(WIN32)
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#elif defined(WIN32)
    #include <time.h>
#endif

#include "generators.h"
#include "log.h"
#include "detect.h"
#include "decode.h"
#include "event.h"
#include "plugbase.h"
#include "parser.h"
#include "mstring.h"
#include "debug.h"
#include "util.h"
#include "event_queue.h"

#include "snort.h"
#include "profiler.h"


/*  D E F I N E S  **************************************************/
#define MODNAME "spp_arpspoof"
#define WITHUNICAST "-unicast"


/*  D A T A   S T R U C T U R E S  **********************************/
typedef struct _IPMacEntry
{
    u_int32_t ipv4_addr;
    u_int8_t  mac_addr[6];
    u_int8_t  pad[2];
} IPMacEntry;

typedef struct _IPMacEntryListNode
{
    IPMacEntry *ip_mac_entry;
    struct _IPMacEntryListNode *next;
} IPMacEntryListNode;

typedef struct _IPMacEntryList
{
    int size;
    IPMacEntryListNode *head;
    IPMacEntryListNode *tail;
} IPMacEntryList;


/*  G L O B A L S  **************************************************/
int check_unicast_arp, check_overwrite;
u_int8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static IPMacEntryList *ipmel = NULL;

#ifdef PERF_PROFILING
PreprocStats arpPerfStats;
#endif

/*  P R O T O T Y P E S  ********************************************/
void ARPspoofInit(u_char *args);
void ARPspoofHostInit(u_char *args);
void ParseARPspoofArgs(char *args);
void ParseARPspoofHostArgs(char *args);
void DetectARPattacks(Packet *p, void *context);
void ARPspoofCleanExit(int signal, void *unused);
void FreeIPMacEntryList(IPMacEntryList *ip_mac_entry_list);
int AddIPMacEntryToList(IPMacEntryList *ip_mac_entry_list, 
        IPMacEntry *ip_mac_entry);
IPMacEntry *LookupIPMacEntryByIP(IPMacEntryList *ip_mac_entry_list, 
        u_int32_t ipv4_addr);
#if defined(DEBUG)
    void PrintIPMacEntryList(IPMacEntryList *ip_mac_entry_list);
#endif


void SetupARPspoof(void)
{
    RegisterPreprocessor("arpspoof", ARPspoofInit);
    RegisterPreprocessor("arpspoof_detect_host", ARPspoofHostInit);

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, 
            "Preprocessor: ARPspoof is setup...\n"););

    return;
}


void ARPspoofInit(u_char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, 
            "Preprocessor: ARPspoof Initialized\n"););

    /* Parse the arpspoof arguments from snort.conf */
    ParseARPspoofArgs(args);

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("arpspoof", &arpPerfStats, 0, &totalPerfStats);
#endif

    /* Add arpspoof to the preprocessor function list */
    AddFuncToPreprocList(DetectARPattacks, PRIORITY_NETWORK, PP_ARPSPOOF);

    /* Restart and CleanExit are identical */
    AddFuncToPreprocCleanExitList(ARPspoofCleanExit, NULL, PRIORITY_LAST, PP_ARPSPOOF);
    AddFuncToPreprocRestartList(ARPspoofCleanExit, NULL, PRIORITY_LAST, PP_ARPSPOOF);

    return;
}


/**
 * Parse arguments passed to the arpspoof keyword.
 *
 * @param args preprocessor argument string
 * 
 * @return void function
 */
void ParseARPspoofArgs(char *args)
{
    char **toks;
    int num_toks;
    int num;

    if (!args)
        return;

    toks = mSplit(args, " ", 2, &num_toks, '\\');

    if (num_toks > 1)
    {      
        FatalError(MODNAME ": ERROR: %s (%d) => ARPspoof configuration "
                "format: -unicast\n", file_name, file_line);
    } 

    for (num = 0; num < num_toks; num++)
    {
        if (!strncasecmp(WITHUNICAST, toks[num], sizeof WITHUNICAST))
            check_unicast_arp = 1;
    }

    mSplitFree(&toks, num_toks);
}


void ARPspoofHostInit(u_char *args)
{
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, 
            "Preprocessor: ARPspoof (overwrite list) Initialized\n"););

    if (ipmel == NULL)
        ipmel = (IPMacEntryList *)SnortAlloc(sizeof(IPMacEntryList));

    /* Add MAC/IP pairs to ipmel */
    ParseARPspoofHostArgs(args);

    if (check_overwrite == 0)
        check_overwrite = 1;

    return;
}


/**
 * Parse arguments passed to the arpspoof_detect_host keyword.
 *
 * @param args preprocessor argument string
 * 
 * @return void function
 */
void ParseARPspoofHostArgs(char *args)
{
    char **toks;
    char **macbytes; 
    int num_toks, num_macbytes;
    int i;
    struct in_addr IP_struct;
    IPMacEntry *ipme = NULL;

    if (ipmel == NULL)
    {
        FatalError("%s(%d) => Please activate arpspoof before trying to "
                "use arpspoof_detect_host\n", file_name, file_line);
    }

    toks = mSplit(args, " ", 2, &num_toks, '\\');

    if (num_toks != 2)
    {
        FatalError("Arpspoof %s(%d) => Invalid arguments to "
                   "arpspoof_detect_host\n", file_name, file_line);
    }

    /* Add entries */
    ipme = (IPMacEntry *)SnortAlloc(sizeof(IPMacEntry));

    if ((IP_struct.s_addr = inet_addr(toks[0])) == -1)
    {
        FatalError("Arpspoof %s(%d) => Invalid IP address as first argument of "
                "IP/MAC pair to arpspoof_detect_host\n", file_name, file_line);
    }

    ipme->ipv4_addr = (u_int32_t)IP_struct.s_addr;

    macbytes = mSplit(toks[1], ":", 6, &num_macbytes, '\\');

    if (num_macbytes < 6)
    {
        FatalError("Arpspoof %s(%d) => Invalid MAC address as second "
                   "argument of IP/MAC pair to arpspoof_detect_host\n", 
                   file_name, file_line);
    }
    else
    {
        for (i = 0; i < 6; i++)
            ipme->mac_addr[i] = (u_int8_t) strtoul(macbytes[i], NULL, 16);
    }

    AddIPMacEntryToList(ipmel, ipme);

    mSplitFree(&toks, num_toks);
    mSplitFree(&macbytes, num_macbytes);

#if defined(DEBUG)
    PrintIPMacEntryList(ipmel);
#endif

    return;
}


/**
 * Detect ARP anomalies and overwrite attacks.
 *
 * @param p packet to detect anomalies and overwrite attacks on
 * @param context unused
 *
 * @return void function
 */
void DetectARPattacks(Packet *p, void *context)
{
    IPMacEntry *ipme;
    PROFILE_VARS;

    /* is the packet valid? */
    if (p == NULL)
        return;

    /* are the Ethernet and ARP headers present? */
    if (p->eh == NULL || p->ah == NULL)
        return;

    /* is the ARP protocol type IP and the ARP hardware type Ethernet? */
    if ((ntohs(p->ah->ea_hdr.ar_hrd) != 0x0001) || 
            (ntohs(p->ah->ea_hdr.ar_pro) != ETHERNET_TYPE_IP))
        return;

    PREPROC_PROFILE_START(arpPerfStats);

    switch(ntohs(p->ah->ea_hdr.ar_op))
    {
        case ARPOP_REQUEST:
            if (check_unicast_arp) 
            {
                if (memcmp((u_char *)p->eh->ether_dst, (u_char *)bcast, 6) != 0)
                {
                    SnortEventqAdd(GENERATOR_SPP_ARPSPOOF,
                            ARPSPOOF_UNICAST_ARP_REQUEST, 1, 0, 3,
                            ARPSPOOF_UNICAST_ARP_REQUEST_STR, 0);
                            
                    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                            "MODNAME: Unicast request\n"););
                }
            }
            else if (memcmp((u_char *)p->eh->ether_src, 
                    (u_char *)p->ah->arp_sha, 6) != 0) 
            {
                SnortEventqAdd(GENERATOR_SPP_ARPSPOOF,
                        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC, 1, 0, 3,
                        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC_STR, 0);

                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                            "MODNAME: Ethernet/ARP mismatch request\n"););
            }
            break;
        case ARPOP_REPLY:
            if (memcmp((u_char *)p->eh->ether_src, 
                    (u_char *)p->ah->arp_sha, 6) != 0)
            {
                SnortEventqAdd(GENERATOR_SPP_ARPSPOOF,
                        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC, 1, 0, 3,
                        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_SRC_STR, 0);

                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                        "MODNAME: Ethernet/ARP mismatch reply src\n"););
            }
            else if (memcmp((u_char *)p->eh->ether_dst, 
                    (u_char *)p->ah->arp_tha, 6) != 0)
            {
                SnortEventqAdd(GENERATOR_SPP_ARPSPOOF,
                        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST, 1, 0, 3,
                        ARPSPOOF_ETHERFRAME_ARP_MISMATCH_DST_STR, 0);

                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                        "MODNAME: Ethernet/ARP mismatch reply dst\n"););
            }
            break;
    }
    PREPROC_PROFILE_END(arpPerfStats);

    /* return if the overwrite list hasn't been initialized */
    if (!check_overwrite)
        return;

    /* LookupIPMacEntryByIP() is too slow, will be fixed later */
    if ((ipme = LookupIPMacEntryByIP(ipmel, 
            *(u_int32_t *)&p->ah->arp_spa)) == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                "MODNAME: LookupIPMacEntryByIp returned NULL\n"););
        return;
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                "MODNAME: LookupIPMacEntryByIP returned %p\n", ipme););

        /* If the Ethernet source address or the ARP source hardware address
         * in p doesn't match the MAC address in ipme, then generate an alert
         */
        if ((memcmp((u_int8_t *)p->eh->ether_src, 
                (u_int8_t *)ipme->mac_addr, 6)) || 
                (memcmp((u_int8_t *)p->ah->arp_sha, 
                (u_int8_t *)ipme->mac_addr, 6)))
        {
            SnortEventqAdd(GENERATOR_SPP_ARPSPOOF,
                    ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK, 1, 0, 3,
                    ARPSPOOF_ARP_CACHE_OVERWRITE_ATTACK_STR, 0);

            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                    "MODNAME: Attempted ARP cache overwrite attack\n"););

            return;
        }
    } 
}


/**
 * Add IP/MAC pair to a linked list.
 *
 * @param ip_mac_entry_list pointer to the list structure
 * @param ip_mac_entry linked list structure node
 *
 * @return 0 if the node is added successfully, 1 otherwise
 */
int AddIPMacEntryToList(IPMacEntryList *ip_mac_entry_list, 
        IPMacEntry *ip_mac_entry)
{
    IPMacEntryListNode *newNode;

    if (ip_mac_entry == NULL || ip_mac_entry_list == NULL)
        return 1;

    newNode = (IPMacEntryListNode *)SnortAlloc(sizeof(IPMacEntryListNode));
    newNode->ip_mac_entry = ip_mac_entry;
    newNode->next = NULL;

    if (ip_mac_entry_list->head == NULL)
    {
        ip_mac_entry_list->head = newNode;
        ip_mac_entry_list->size = 1;
    }
    else
    {
        ip_mac_entry_list->tail->next = newNode;
        ip_mac_entry_list->size += 1;
    }
    ip_mac_entry_list->tail = newNode;
    return 0;
}


/**
 * Locate a linked list structure node by an IP address.
 *
 * @param ip_mac_entry_list pointer to the list structure
 * @param ipv4_addr IPv4 address as an unsigned 32-bit integer
 *
 * @return pointer to a structure node if a match is found, NULL otherwise
 */
IPMacEntry *LookupIPMacEntryByIP(IPMacEntryList *ip_mac_entry_list, 
        u_int32_t ipv4_addr)
{
    IPMacEntryListNode *current;
#if defined(DEBUG)
    struct in_addr ina, inb;
    char *cha, *chb;
#endif

    if (ip_mac_entry_list == NULL)
        return NULL;

    for (current = ip_mac_entry_list->head; current != NULL; 
            current = current->next)
    {
#if defined(DEBUG)
        ina.s_addr = ipv4_addr;
        inb.s_addr = current->ip_mac_entry->ipv4_addr;
        cha = strdup(inet_ntoa(ina));
        chb = strdup(inet_ntoa(inb));

        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
            "MODNAME: LookupIPMacEntryByIP() comparing %s to %s\n", cha, chb););
#endif
        if (current->ip_mac_entry->ipv4_addr == ipv4_addr)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                    "MODNAME: LookupIPMecEntryByIP() match!"););

            return current->ip_mac_entry;
        }
    }
    return NULL;
}


/**
 * Free the linked list of IP/MAC address pairs
 *
 * @param ip_mac_entry_list pointer to the list structure
 *
 * @return void function
 */
void FreeIPMacEntryList(IPMacEntryList *ip_mac_entry_list)
{
    IPMacEntryListNode *prev;
    IPMacEntryListNode *current;

    if (ip_mac_entry_list == NULL)
        return;

    current = ip_mac_entry_list->head;
    while (current != NULL)
    {
        if (current->ip_mac_entry != NULL)
            free(current->ip_mac_entry);

        prev = current;
        current = current->next;
        free(prev);
    }
    ip_mac_entry_list->head = NULL;
    ip_mac_entry_list->size = 0;

    return;
}


void ARPspoofCleanExit(int signal, void *unused)
{
    if (ipmel != NULL)
    {
        FreeIPMacEntryList(ipmel);
        free(ipmel);
        ipmel = NULL;
    }
    check_unicast_arp = check_overwrite = 0;
    return;
}


#if defined(DEBUG)
/**
 * Print the overwrite list for debugging purposes
 *
 * @param ip_mac_entry_list pointer to the list structure
 *
 * @return void function
 */
void PrintIPMacEntryList(IPMacEntryList *ip_mac_entry_list)
{
    IPMacEntryListNode *current;
    int i;
    struct in_addr in;
    if (ip_mac_entry_list == NULL)
        return;

    current = ip_mac_entry_list->head;
    printf("Arpspoof IPMacEntry List");
    printf("  Size: %i\n", ip_mac_entry_list->size);
    while (current != NULL)
    {
        in.s_addr = current->ip_mac_entry->ipv4_addr;
        printf("%s -> ", inet_ntoa(in));
        for (i = 0; i < 6; i++)
        {
            printf("%02x", current->ip_mac_entry->mac_addr[i]);
            if (i != 5)
                printf(":");
        }
        printf("\n");
        current = current->next;
    }    
    return;
}
#endif
