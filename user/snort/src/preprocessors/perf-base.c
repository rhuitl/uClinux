/*
** $Id$
**
** perf-base.c
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker <droelker@sourcefire.com>
** Marc Norton <mnorton@sourcefire.com>
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
**
**  DESCRIPTION
**    The following subroutines are concerned with getting
**    basic stats on packet bytes and times that an app
**    takes in processing packets.  The times measured are
**    kernel and user time for the process.   Real-time
**    (wall clock) is also measured to show when processing
**    has reached capacity and to measure the true processing 
**    that the app is currently doing.
**
**  NOTES
**    4.8.02  : Initial Code (DJR,MAN)
**    4.22.02 : Added Comments (DJR)
**    7.10.02 : Added sfprocpidstats code for SMP linux (DJR)
**    8.8.02  : Added stream4 instrumentation (cmg)
**    9.1.04  : Removed NO_PKTS, ACCUMULATE/RESET #defines, now we use SFBASE->iReset
**              and the permonitor command has 'reset' and 'accrue' commands instead.(MAN)
*/

#include <time.h>
#ifndef WIN32
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include "snort.h"
#include "inline.h"
#include "util.h"
#include "mpse.h"

#ifndef UINT32_MAX
#define UINT32_MAX         (4294967295U)
#endif

int GetPktDropStats(SFBASE *sfBase, SFBASE_STATS *sfBaseStats);
int DisplayBasePerfStatsConsole(SFBASE_STATS *sfBaseStats, int iFlags);
int CalculateBasePerfStats(SFBASE *sfPerf, SFBASE_STATS *sfBaseStats);
int LogBasePerfStats(SFBASE_STATS *sfBaseStats,  FILE * fh );

/*
**  NAME
**    InitBaseStats
**  DESCRIPTION
**    Initializes structs and variables for the next performance
**    sample.
**
**  FORMAL INPUTS
**    SFBASE * -- pointer to structure to initialize
** 
**  FORMAL OUTPUTS
**    int -- 0 is successful
*/ 
int InitBaseStats(SFBASE *sfBase)
{
#ifndef LINUX_SMP
    int rusageRet = -1;
#endif
    int todRet = -1;
    struct timeval tvTime;

#ifndef WIN32
#ifndef LINUX_SMP
    struct rusage  rusage;
#endif
    
#ifdef LINUX_SMP
    static int first_time = 0;

    if(!first_time)
    {
        sfInitProcPidStats(&(sfBase->sfProcPidStats));
        first_time = 1;
    }
    todRet = gettimeofday(&tvTime, NULL);
#else
    
    rusageRet = getrusage(RUSAGE_SELF, &rusage);
    todRet = gettimeofday(&tvTime, NULL);

    if (rusageRet >= 0)
    {
        sfBase->usertime_sec   = (double)rusage.ru_utime.tv_sec +
                                 ((double)rusage.ru_utime.tv_usec * 1.0e-6);
        sfBase->systemtime_sec = (double)rusage.ru_stime.tv_sec +
                                 ((double)rusage.ru_stime.tv_usec * 1.0e-6);
    }
    else
    {
        sfBase->usertime_sec = 0;
        sfBase->systemtime_sec = 0;
    }

#endif  /* !LINUX_SMP */
#else
    sfBase->usertime_sec = 0;
    sfBase->systemtime_sec = 0;
    todRet = gettimeofday(&tvTime, NULL);
#endif  /* !WIN32 */

    if(todRet >= 0)
    {
        sfBase->realtime_sec = (double)tvTime.tv_sec +
                               ((double)tvTime.tv_usec * 1.0e-6);
    }
    else
    {
        sfBase->realtime_sec = 0;
    }

    sfBase->total_blocked_packets = 0;
    sfBase->total_wire_packets = 0;
    sfBase->total_ipfragmented_packets = 0;
    sfBase->total_ipreassembled_packets = 0;
    sfBase->total_packets = 0;
    sfBase->total_rebuilt_packets = 0;

    sfBase->total_wire_bytes = 0;
    sfBase->total_ipfragmented_bytes = 0;
    sfBase->total_ipreassembled_bytes = 0;
    sfBase->total_bytes = 0;
    sfBase->total_rebuilt_bytes = 0;
    sfBase->total_blocked_bytes = 0;

    sfBase->iNewSessions = 0;
    sfBase->iDeletedSessions = 0;

    sfBase->iStreamFlushes = 0;
    sfBase->iStreamFaults = 0;
    sfBase->iStreamTimeouts = 0;
    
    sfBase->iFragCreates = 0;
    sfBase->iFragCompletes = 0;
    sfBase->iFragInserts = 0;
    sfBase->iFragDeletes = 0;
    sfBase->iFragAutoFrees = 0;
    sfBase->iFragFlushes = 0;
    sfBase->iFragTimeouts = 0;
    sfBase->iFragFaults = 0;
    
    return 0;
}

/*
**  NAME
**    UpdateBaseStats
**
**  DESCRIPTION
**    Simple update of stats.
**
**  FORMAL INPUTS
**    SFBASE * - structure to update
**    int      - length of packet payload in bytes
**
**  FORMAL OUTPUTS
**    int - 0 is successful
**
**  Add in Ethernet Overhead - assume a standerd Ethernet service
**
**   Ethernet Frame
**   ---------------
**           | <-----------   PCAP Packet  --------> |
**   Preamble  Dest Mac  Src Mac   Type      Payload   CRC        IFG
** | 8 bytes | 6 Bytes | 6 Bytes | 2-Bytes | 46-1500 | 4 Bytes |  12      |
**
** Len = PCAP Packet + 4 bytes for CRC
** Overhead = 20 bytes
** Min on the wire == 84 bytes
** Min Size of PCAP packet = 60 bytes (84 - 20 overhead - 4 CRC)
**
** Len is the amount of user data being sent.  This will be less then
** actual wire-speed, because of the interframe gap (96 bits) and preamble
** (8 bytes).
**
** A 60 byte minimum packet uses 672 bits (60 bytes + 4 CRC), this limits a
** 1000 Mbit network to 1.488 Million packets with a bandwidth of 760
** Mbits.  The lost 240 Mbits is due to interframe gap (96 bits) and preamble
** (8 bytes).
**
** Even if the actual data is only 40 bytes per packet (ie, an empty
** TCP ACK), wire data is still 64 bytes per packet, even though actual
** packet size is 40 bytes.  Bandwith drops to 480 Mbits.  
**
** This explains why when a network goes over 50% capactiy you are closer to
** the edge than you realize, depending on the traffic profile.  At 75% you 
** are at the limit of your network, if you can get there.
**
** iRebuiltPkt determines whether the packet is rebuilt or not.  We keep
** separate statistics between wire pkts and rebuilt pkts.
**
*/
int UpdateBaseStats(SFBASE *sfBase, int len, int iRebuiltPkt)
{
    /* If rebuilt, count info for TCP rebuilt packet */
    if(iRebuiltPkt)
    {
        sfBase->total_rebuilt_bytes += len;
        sfBase->total_rebuilt_packets++;
    }
    else
    {
        len += 4; /* for the CRC */
    }

    /* Includes wire, IP reassembled & TCP rebuilt packets
     * that make it to the application layer.
     */
    sfBase->total_packets++;

    sfBase->total_bytes += len;

    return 0;
}

/*
**  NAME
**    UpdateWireStats
**
**  DESCRIPTION
**    Simple update of stats for "on the wire".
**
**  FORMAL INPUTS
**    SFBASE * - structure to update
**    int      - length of packet payload in bytes
**
**  FORMAL OUTPUTS
**    none
*/
void UpdateWireStats(SFBASE *sfBase, int len)
{
    sfBase->total_wire_packets++;

    len += 4; /* for the CRC */
    sfBase->total_wire_bytes += len;
   
    if( InlineWasPacketDropped() )
    {
      sfBase->total_blocked_packets++;
      sfBase->total_blocked_bytes += len;
    }
}

/*
**  NAME
**    UpdateIPFragStats
**
**  DESCRIPTION
**    Simple update of stats for IP fragmented packets
**
**  FORMAL INPUTS
**    SFBASE * - structure to update
**    int      - length of packet payload in bytes
**
**  FORMAL OUTPUTS
**    none
*/
void UpdateIPFragStats(SFBASE *sfBase, int len)
{
    sfBase->total_ipfragmented_packets++;

    len += 4; /* for the CRC */
    sfBase->total_wire_bytes += len;
    sfBase->total_ipfragmented_bytes += len;
}

/*
**  NAME
**    UpdateIPReassStats
**
**  DESCRIPTION
**    Simple update of stats for IP reassembled packets
**
**  FORMAL INPUTS
**    SFBASE * - structure to update
**    int      - length of packet payload in bytes
**
**  FORMAL OUTPUTS
**    none
*/
void UpdateIPReassStats(SFBASE *sfBase, int len)
{
    sfBase->total_ipreassembled_packets++;

    len += 4; /* for the CRC */
    sfBase->total_wire_bytes += len;
    sfBase->total_ipreassembled_bytes += len;
}

/*
**  NAME
**    AddStreamSession
**
**  DESCRIPTION
**    Add a session count
**
**  FORMAL INPUTS
**    SFBASE * - ptr to update.
**
**  FORMAL OUTPUTS
**    int - 0 is successful
*/

int AddStreamSession(SFBASE *sfBase)
{    
    sfBase->iTotalSessions++;
    sfBase->iNewSessions++;

    if(sfBase->iTotalSessions > sfBase->iMaxSessions)
        sfBase->iMaxSessions = sfBase->iTotalSessions;

    return 0;
}

/*
**  NAME
**    RemoveStreamSession
**
**  DESCRIPTION
**    Add a session count
**
**  FORMAL INPUTS
**    SFBASE * - ptr to update.
**
**  FORMAL OUTPUTS
**    int - 0 is successful
*/

int RemoveStreamSession(SFBASE *sfBase)
{
    sfBase->iTotalSessions--;
    sfBase->iDeletedSessions++;
    return 0;
}

/*
**  NAME
**    AddUDPSession
**
**  DESCRIPTION
**    Add a session count
**
**  FORMAL INPUTS
**    SFBASE * - ptr to update.
**
**  FORMAL OUTPUTS
**    int - 0 is successful
*/
int AddUDPSession(SFBASE *sfBase)
{    
    sfBase->iTotalUDPSessions++;
    sfBase->iNewUDPSessions++;

    if(sfBase->iTotalUDPSessions > sfBase->iMaxUDPSessions)
        sfBase->iMaxUDPSessions = sfBase->iTotalUDPSessions;

    return 0;
}

/*
**  NAME
**    RemoveUDPSession
**
**  DESCRIPTION
**    Add a session count
**
**  FORMAL INPUTS
**    SFBASE * - ptr to update.
**
**  FORMAL OUTPUTS
**    int - 0 is successful
*/

int RemoveUDPSession(SFBASE *sfBase)
{
    sfBase->iTotalUDPSessions--;
    sfBase->iDeletedUDPSessions++;
    return 0;
}

/*
**  NAME
**    ProcessBaseStats
**
**  DESCRIPTION
**    Main function to process Base Stats.
**
**  FORMAL INPUTS
**    SFBASE * - ptr to update.
**
**  FORMAL OUTPUTS
**    int - 0 is successful
*/
int ProcessBaseStats(SFBASE *sfBase, int console, int file, FILE * fh)
{
    SFBASE_STATS sfBaseStats;

    if( console || file )
    {
        if(CalculateBasePerfStats(sfBase, &sfBaseStats))
            return -1;
    }


    if( console )
        DisplayBasePerfStatsConsole(&sfBaseStats, sfBase->iFlags);
    
    if( file )
        LogBasePerfStats(&sfBaseStats, fh );

    return 0;
}

int GetProcessingTime(SYSTIMES *Systimes, SFBASE *sfBase)
{
    int todRet = -1;
    struct timeval tvTime;
#ifdef LINUX_SMP

    if(sfProcessProcPidStats(&(sfBase->sfProcPidStats)))
        return -1;
    todRet = gettimeofday(&tvTime, NULL);
#else
    struct rusage  rusage;
    int rusageRet;
#ifndef WIN32
    rusageRet = getrusage(RUSAGE_SELF, &rusage);
#else
    rusageRet = -1;
#endif  /* !WIN32 */
    todRet = gettimeofday(&tvTime, NULL);

    if (rusageRet < 0)
    {
        rusage.ru_utime.tv_sec = 0;
        rusage.ru_utime.tv_usec = 0;
        rusage.ru_stime.tv_sec = 0;
        rusage.ru_stime.tv_usec = 0;
    }
    Systimes->usertime   = ((double)rusage.ru_utime.tv_sec +
                           ((double)rusage.ru_utime.tv_usec * 1.0e-6)) -
                           sfBase->usertime_sec;
    Systimes->systemtime = ((double)rusage.ru_stime.tv_sec +
                           ((double)rusage.ru_stime.tv_usec * 1.0e-6)) -
                           sfBase->systemtime_sec;
    Systimes->totaltime  = Systimes->usertime + Systimes->systemtime;
#endif  /* LINUX_SMP */

    if (todRet < 0)
    {
        return todRet;
    }

    Systimes->realtime =  ((double)tvTime.tv_sec + 
                          ((double)tvTime.tv_usec * 1.0e-6)) -
                          sfBase->realtime_sec;
    return 0;
}

int GetEventsPerSecond(SFBASE *sfBase, SFBASE_STATS *sfBaseStats, 
                       SYSTIMES *Systimes)
{
    sfBaseStats->alerts_per_second = 
        (double)(pc.alert_pkts - sfBase->iAlerts) / Systimes->realtime;

    sfBase->iAlerts = pc.alert_pkts;

    sfBaseStats->total_sessions = sfBase->iTotalSessions;
    sfBaseStats->max_sessions = sfBase->iMaxSessions;

    sfBaseStats->syns_per_second = 
        (double)(sfBase->iSyns) / Systimes->realtime;

    sfBaseStats->synacks_per_second = 
        (double)(sfBase->iSynAcks) / Systimes->realtime;

    sfBaseStats->deleted_sessions_per_second = 
        (double)(sfBase->iDeletedSessions) / Systimes->realtime;

    sfBaseStats->new_sessions_per_second = 
        (double)(sfBase->iNewSessions) / Systimes->realtime;


    sfBaseStats->stream_flushes_per_second = 
        (double)sfBase->iStreamFlushes / Systimes->realtime;

    sfBaseStats->stream_faults = sfBase->iStreamFaults;
    sfBaseStats->stream_timeouts = sfBase->iStreamTimeouts;
    
    sfBaseStats->frag_creates_per_second = 
        (double)sfBase->iFragCreates / Systimes->realtime;
    
    sfBaseStats->frag_completes_per_second = 
        (double)sfBase->iFragCompletes / Systimes->realtime;
    
    sfBaseStats->frag_inserts_per_second = 
        (double)sfBase->iFragInserts / Systimes->realtime;
    
    sfBaseStats->frag_deletes_per_second = 
        (double)sfBase->iFragDeletes / Systimes->realtime;
    
    sfBaseStats->frag_autofrees_per_second = 
        (double)sfBase->iFragAutoFrees / Systimes->realtime;
    
    sfBaseStats->frag_flushes_per_second = 
        (double)sfBase->iFragFlushes / Systimes->realtime;

    sfBaseStats->max_frags = sfBase->iMaxFrags;
    sfBaseStats->current_frags = sfBase->iCurrentFrags;
    sfBaseStats->frag_timeouts = sfBase->iFragTimeouts;
    sfBaseStats->frag_faults = sfBase->iFragFaults;
    
    sfBase->iSyns = 0;
    sfBase->iSynAcks = 0;
    sfBase->iNewSessions = 0;
    sfBase->iDeletedSessions = 0;

    sfBase->iStreamFlushes = 0;
    sfBase->iStreamFaults = 0;
    sfBase->iStreamTimeouts = 0;
    
    sfBase->iFragCreates = 0;
    sfBase->iFragCompletes = 0;
    sfBase->iFragInserts = 0;
    sfBase->iFragDeletes = 0;
    sfBase->iFragAutoFrees = 0;
    sfBase->iFragFlushes = 0;
    sfBase->iFragTimeouts = 0;
    sfBase->iFragFaults = 0;

    sfBaseStats->total_udp_sessions = sfBase->iTotalUDPSessions;
    sfBaseStats->max_udp_sessions = sfBase->iMaxUDPSessions;
    sfBaseStats->deleted_udp_sessions_per_second = 
        (double)(sfBase->iDeletedUDPSessions) / Systimes->realtime;

    sfBaseStats->new_udp_sessions_per_second = 
        (double)(sfBase->iNewUDPSessions) / Systimes->realtime;

    sfBase->iNewUDPSessions = 0;
    sfBase->iDeletedUDPSessions = 0;
    
    return 0;
}
    
int GetPacketsPerSecond(SFBASE *sfBase, SFBASE_STATS *sfBaseStats,
                        SYSTIMES *Systimes)
{
    sfBaseStats->kpackets_per_sec.realtime   = 
        (double)((double)sfBase->total_packets / 1000) / Systimes->realtime;

    if(sfBase->iFlags & MAX_PERF_STATS)
    {
        sfBaseStats->kpackets_per_sec.usertime   = 
            (double)((double)sfBase->total_packets / 1000) / 
            Systimes->usertime;
        sfBaseStats->kpackets_per_sec.systemtime = 
            (double)((double)sfBase->total_packets / 1000) / 
            Systimes->systemtime;
        sfBaseStats->kpackets_per_sec.totaltime  = 
            (double)((double)sfBase->total_packets / 1000) / 
            Systimes->totaltime;
    }

    sfBaseStats->kpackets_wire_per_sec.realtime   = 
        (double)((double)sfBase->total_wire_packets / 1000) / Systimes->realtime;

    if(sfBase->iFlags & MAX_PERF_STATS)
    {
        sfBaseStats->kpackets_wire_per_sec.usertime   = 
            (double)((double)sfBase->total_wire_packets / 1000) / 
            Systimes->usertime;
        sfBaseStats->kpackets_wire_per_sec.systemtime = 
            (double)((double)sfBase->total_wire_packets / 1000) / 
            Systimes->systemtime;
        sfBaseStats->kpackets_wire_per_sec.totaltime  = 
            (double)((double)sfBase->total_wire_packets / 1000) / 
            Systimes->totaltime;
    }

    sfBaseStats->kpackets_ipfrag_per_sec.realtime   = 
        (double)((double)sfBase->total_ipfragmented_packets / 1000) / Systimes->realtime;

    if(sfBase->iFlags & MAX_PERF_STATS)
    {
        sfBaseStats->kpackets_ipfrag_per_sec.usertime   = 
            (double)((double)sfBase->total_ipfragmented_packets / 1000) / 
            Systimes->usertime;
        sfBaseStats->kpackets_ipfrag_per_sec.systemtime = 
            (double)((double)sfBase->total_ipfragmented_packets / 1000) / 
            Systimes->systemtime;
        sfBaseStats->kpackets_ipfrag_per_sec.totaltime  = 
            (double)((double)sfBase->total_ipfragmented_packets / 1000) / 
            Systimes->totaltime;
    }

    sfBaseStats->kpackets_ipreass_per_sec.realtime   = 
        (double)((double)sfBase->total_ipreassembled_packets / 1000) / Systimes->realtime;

    if(sfBase->iFlags & MAX_PERF_STATS)
    {
        sfBaseStats->kpackets_ipreass_per_sec.usertime   = 
            (double)((double)sfBase->total_ipreassembled_packets / 1000) / 
            Systimes->usertime;
        sfBaseStats->kpackets_ipreass_per_sec.systemtime = 
            (double)((double)sfBase->total_ipreassembled_packets / 1000) / 
            Systimes->systemtime;
        sfBaseStats->kpackets_ipreass_per_sec.totaltime  = 
            (double)((double)sfBase->total_ipreassembled_packets / 1000) / 
            Systimes->totaltime;
    }

    sfBaseStats->kpackets_rebuilt_per_sec.realtime   = 
        (double)((double)sfBase->total_rebuilt_packets / 1000) / Systimes->realtime;

    if(sfBase->iFlags & MAX_PERF_STATS)
    {
        sfBaseStats->kpackets_rebuilt_per_sec.usertime   = 
            (double)((double)sfBase->total_rebuilt_packets / 1000) / 
            Systimes->usertime;
        sfBaseStats->kpackets_rebuilt_per_sec.systemtime = 
            (double)((double)sfBase->total_rebuilt_packets / 1000) / 
            Systimes->systemtime;
        sfBaseStats->kpackets_rebuilt_per_sec.totaltime  = 
            (double)((double)sfBase->total_rebuilt_packets / 1000) / 
            Systimes->totaltime;
    }

    
    return 0;
}

int GetuSecondsPerPacket(SFBASE *sfBase, SFBASE_STATS *sfBaseStats, 
                         SYSTIMES *Systimes)
{
    sfBaseStats->usecs_per_packet.usertime   = (Systimes->usertime * 1.0e6) /
                                               (double)sfBase->total_packets;
    sfBaseStats->usecs_per_packet.systemtime = (Systimes->systemtime * 1.0e6) /
                                               (double)sfBase->total_packets;
    sfBaseStats->usecs_per_packet.totaltime  = (Systimes->totaltime * 1.0e6) /
                                               (double)sfBase->total_packets;
    sfBaseStats->usecs_per_packet.realtime   = (Systimes->realtime * 1.0e6) /
                                               (double)sfBase->total_packets;

    return 0;
}

int GetMbitsPerSecond(SFBASE *sfBase, SFBASE_STATS *sfBaseStats, 
                      SYSTIMES *Systimes)
{
    /*
    **  These Mbits stats are for the Snort Maximum Performance stats
    **  that can't reliably be gotten from Linux SMP kernels.  So
    **  we don't do them.
    */
    if(sfBase->iFlags & MAX_PERF_STATS)
    {
        sfBaseStats->mbits_per_sec.usertime   = ((double)
                                                (sfBase->total_bytes<<3) *
                                                1.0e-6) /
                                                Systimes->usertime;
        sfBaseStats->mbits_per_sec.systemtime = ((double)
                                                (sfBase->total_bytes<<3) *
                                                1.0e-6) /
                                                Systimes->systemtime;
        sfBaseStats->mbits_per_sec.totaltime  = ((double)
                                                (sfBase->total_bytes<<3) *
                                                1.0e-6) /
                                                Systimes->totaltime;
    }

    sfBaseStats->mbits_per_sec.realtime   = ((double)(sfBase->total_bytes<<3) *
                                             1.0e-6) /
                                            Systimes->realtime;
    sfBaseStats->wire_mbits_per_sec.realtime   = 
                                    ((double)(sfBase->total_wire_bytes<<3) *
                                    1.0e-6) /
                                    Systimes->realtime;
    sfBaseStats->rebuilt_mbits_per_sec.realtime   = 
                                    ((double)(sfBase->total_rebuilt_bytes<<3) *
                                    1.0e-6) /
                                    Systimes->realtime;

    sfBaseStats->ipfrag_mbits_per_sec.realtime   = 
                                    ((double)(sfBase->total_ipfragmented_bytes<<3) *
                                    1.0e-6) /
                                    Systimes->realtime;

    sfBaseStats->ipreass_mbits_per_sec.realtime   = 
                                    ((double)(sfBase->total_ipreassembled_bytes<<3) *
                                    1.0e-6) /
                                    Systimes->realtime;

    return 0;
}

int GetCPUTime(SFBASE *sfBase, SFBASE_STATS *sfBaseStats, SYSTIMES *Systimes)
{
#ifndef LINUX_SMP
    unsigned char needToNormalize = 0;
    sfBaseStats->user_cpu_time   = (Systimes->usertime   / 
                                   Systimes->realtime) * 100;
    sfBaseStats->system_cpu_time = (Systimes->systemtime / 
                                   Systimes->realtime) * 100;
    sfBaseStats->idle_cpu_time   = ((Systimes->realtime -
                                     Systimes->totaltime) /
                                     Systimes->realtime) * 100;

    /* percentages can be < 0 because of a small variance between
     * when the snapshot is taken of the CPU times and snapshot of
     * the real time.  So these are just a safe-guard to normalize
     * the data so we see positive values.
     */
    if (sfBaseStats->user_cpu_time < 0)
    {
        sfBaseStats->user_cpu_time = 0;
        needToNormalize = 1;
    }
    if (sfBaseStats->system_cpu_time < 0)
    {
        sfBaseStats->system_cpu_time = 0;
        needToNormalize = 1;
    }
    if (sfBaseStats->idle_cpu_time < 0)
    {
        sfBaseStats->idle_cpu_time = 0;
        needToNormalize = 1;
    }

    if (needToNormalize)
    {
        double totalPercent = sfBaseStats->user_cpu_time +
                              sfBaseStats->system_cpu_time +
                              sfBaseStats->idle_cpu_time;


        sfBaseStats->user_cpu_time = (sfBaseStats->user_cpu_time /
                                      totalPercent) * 100;
        sfBaseStats->system_cpu_time = ( sfBaseStats->system_cpu_time /
                                      totalPercent) * 100;
        sfBaseStats->idle_cpu_time = ( sfBaseStats->idle_cpu_time /
                                      totalPercent) * 100;

    }
#endif
    return 0;
}


/*
**  NAME
**    CalculateBasePerfStats
**
**  DESCRIPTION
**    This is the main function that calculates the stats. Stats 
**    that we caculate are:
**      *uSecs per Packet
**      *Packets per Second
**      *Mbits per Second
**      *Average bytes per Packet
**      *CPU Time
**      *Dropped Packets
**    These statistics are processed and then stored in the
**    SFBASE_STATS structure.  This allows output functions to
**    be easily formed and inserted.
**    NOTE: We can break up these statistics into functions for easier
**    reading.
**
**  FORMAL INPUTS
**    SFBASE *       - ptr to performance struct
**    SFBASE_STATS * - ptr to struct to fill in performance stats
**
**  FORMAL OUTPUTS
**    int - 0 is successful
*/
int CalculateBasePerfStats(SFBASE *sfBase, SFBASE_STATS *sfBaseStats)
{
    SYSTIMES       Systimes;
    time_t   clock;

#ifdef LINUX_SMP
    
    /*
    **  We also give sfBaseStats access to the CPU usage
    **  contained in sfProcPidStats.  This way we don't need
    **  to complicate sfBaseStats further.
    */
    sfBaseStats->sfProcPidStats = &(sfBase->sfProcPidStats);

#endif 
    if(GetProcessingTime(&Systimes, sfBase))
        return -1;

    sfBaseStats->total_blocked_packets = sfBase->total_blocked_packets;

    /*
    **  Avg. bytes per Packet
    */
    if (sfBase->total_packets > 0)
        sfBaseStats->avg_bytes_per_packet =
                (int)((double)(sfBase->total_bytes) /
                (double)(sfBase->total_packets));
    else
        sfBaseStats->avg_bytes_per_packet = 0;

    if (sfBase->total_wire_packets > 0)
        sfBaseStats->avg_bytes_per_wire_packet =
                (int)((double)(sfBase->total_wire_bytes) /
                (double)(sfBase->total_wire_packets));
    else
        sfBaseStats->avg_bytes_per_wire_packet = 0;

    if (sfBase->total_ipfragmented_packets > 0)
        sfBaseStats->avg_bytes_per_ipfrag_packet =
                (int)((double)(sfBase->total_ipfragmented_bytes) /
                (double)(sfBase->total_ipfragmented_packets));
    else
        sfBaseStats->avg_bytes_per_ipfrag_packet = 0;

    if (sfBase->total_ipreassembled_packets > 0)
        sfBaseStats->avg_bytes_per_ipreass_packet =
                (int)((double)(sfBase->total_ipreassembled_bytes) /
                (double)(sfBase->total_ipreassembled_packets));
    else
        sfBaseStats->avg_bytes_per_ipreass_packet = 0;

    if (sfBase->total_rebuilt_packets > 0)
        sfBaseStats->avg_bytes_per_rebuilt_packet =
                (int)((double)(sfBase->total_rebuilt_bytes) /
                (double)(sfBase->total_rebuilt_packets));
    else
        sfBaseStats->avg_bytes_per_rebuilt_packet = 0;

    /*
    **  CPU time
    */
    GetCPUTime(sfBase, sfBaseStats, &Systimes);

    /*
    **  Get Dropped Packets
    */
    GetPktDropStats(sfBase, sfBaseStats);

    /*
    **  Total packets
    */
    sfBaseStats->total_packets = sfBase->total_wire_packets;

    /*
    *   Pattern Matching Performance in Real and User time
    */
    sfBaseStats->patmatch_percent = 100.0 * mpseGetPatByteCount() /
                                    sfBase->total_wire_bytes;

    mpseResetByteCount();

    if(sfBase->iFlags & MAX_PERF_STATS)
    {
        /*
        **  uSeconds per Packet
        **  user, system, total time
        */
        GetuSecondsPerPacket(sfBase, sfBaseStats, &Systimes);
    }

    /*
    **  Mbits per sec
    **  user, system, total time
    */
    GetMbitsPerSecond(sfBase, sfBaseStats, &Systimes);

    /*
    **  EventsPerSecond
    **  We get the information from the global variable
    **  PacketCount.
    */
    GetEventsPerSecond(sfBase, sfBaseStats, &Systimes);

    /*
    **  Packets per seconds
    **  user, system, total time
    */
    GetPacketsPerSecond(sfBase, sfBaseStats, &Systimes);

    /*
    **  Set the date string for print out
    */
    time(&clock);
    sfBaseStats->time = clock;

    return 0;
}

/*
**  NAME
**    GetPktDropStats
**
**  DESCRIPTION
**    Gets the packet drop statisitics from OS.
**    NOTE:  Currently only pcap-based sniffing is supported.  Should
**    add native OS calls.
**
**  FORMAL INPUT
**    SFBASE *       - ptr to struct
**    SFBASE_STATS * - ptr to struct to fill in with perf stats
**
**  FORMAL OUTPUT
**    int - 0 is successful
*/
int GetPktDropStats(SFBASE *sfBase, SFBASE_STATS *sfBaseStats)
{
    /*
    **  Network Interfaces.  Right now we only check
    **  the first interface
    */
    extern pcap_t *pd;
    struct pcap_stat pcapStats;
    
    if((!pd)
#ifdef WIN32
        || (pv.readmode_flag)
#endif
        )
    {
        if (sfBase->iReset == 0)
        {
            sfBaseStats->pkt_stats.pkts_recv = sfBase->total_wire_packets;
        }
        else
        {
            sfBaseStats->pkt_stats.pkts_recv += sfBase->total_wire_packets;
        }
        sfBaseStats->pkt_stats.pkts_drop = 0;
        sfBaseStats->pkt_drop_percent    = 0.0;
        return 0;
    }
    
    if(pcap_stats(pd, &pcapStats) < 0)
    {
        if (sfBase->iReset == 0)
        {
            sfBaseStats->pkt_stats.pkts_recv = sfBase->total_wire_packets;
        }
        else
        {
            sfBaseStats->pkt_stats.pkts_recv += sfBase->total_wire_packets;
        }
        sfBaseStats->pkt_stats.pkts_drop = 0;
        sfBaseStats->pkt_drop_percent    = 0.0;
    }
    else
    {
        if( sfBase->iReset == 0 )
        {
            if (pcapStats.ps_recv < (u_int32_t)sfBase->pkt_stats.pkts_recv)
            {
                /* Rollover of the pcap stat value */
                sfBaseStats->pkt_stats.pkts_recv = pcapStats.ps_recv +
                    (UINT32_MAX - (u_int32_t)sfBase->pkt_stats.pkts_recv);
            }
            else
            {
                sfBaseStats->pkt_stats.pkts_recv = pcapStats.ps_recv -
                    (u_int32_t)sfBase->pkt_stats.pkts_recv;
            }
            if (pcapStats.ps_drop < (u_int32_t)sfBase->pkt_stats.pkts_drop)
            {
                /* Rollover of the pcap stat value */
                sfBaseStats->pkt_stats.pkts_drop = pcapStats.ps_drop +
                    (UINT32_MAX - (u_int32_t)sfBase->pkt_stats.pkts_drop);
            }
            else
            {
                sfBaseStats->pkt_stats.pkts_drop = pcapStats.ps_drop -
                    (u_int32_t)sfBase->pkt_stats.pkts_drop;
            }
        }
        else
        {
            sfBaseStats->pkt_stats.pkts_recv = pcapStats.ps_recv;
            sfBaseStats->pkt_stats.pkts_drop = pcapStats.ps_drop;
        }
        
        sfBaseStats->pkt_drop_percent =
            ((double)sfBaseStats->pkt_stats.pkts_drop /
             (double)sfBaseStats->pkt_stats.pkts_recv) * 100;
        
        /*
        **  Reset sfBase stats for next go round.
        */
        sfBase->pkt_stats.pkts_recv = pcapStats.ps_recv;
        sfBase->pkt_stats.pkts_drop = pcapStats.ps_drop;
    }
    
    return 0;
}

/*
 *   
 *   Log Base Per Stats to File for Use by the MC 
 *
 * unixtime(in secs since epoch)
 * %pkts dropped
 * mbits/sec (wire)
 * alerts/sec
 * K-Packets/Sec (wire)
 * Avg Bytes/Pkt  (wire)
 * %bytes pattern matched 
 * syns/sec
 * synacks/sec
 * new-sessions/sec (stream cache)
 * del-sessions/sec (stream cache)
 * total-sessions open (stream cache)
 * max-sessions (stream cache)
 * streamflushes/sec
 * streamfaults/sec
 * streamtimeouts
 * fragcreates/sec
 * fragcompletes/sec
 * fraginserts/sec
 * fragdeletes/sec
 * fragflushes/sec
 * current-frags open (frag cache)
 * max-frags (frag cache)
 * fragtimeouts
 * fragfaults
 * num cpus (following triple is repeated for each CPU)
 * %user-cpu usage
 * %sys-cpu usage
 * %idle-cpu usage
 * mbits/sec (wire)
 * mbits/sec (ip fragmented)
 * mbits/sec (ip reassembled)
 * mbits/sec (stream rebuilt)
 * mbits/sec (app layer)
 * Avg Bytes/Pkt  (wire)
 * Avg Bytes/Pkt  (ip fragmented)
 * Avg Bytes/Pkt  (ip reassembled)
 * Avg Bytes/Pkt  (stream rebuilt)
 * Avg Bytes/Pkt  (app layer)
 * K-Packets/Sec (wire)
 * K-Packets/Sec (ip fragmented)
 * K-Packets/Sec (ip reassembled)
 * K-Packets/Sec (stream rebuilt)
 * K-Packets/Sec (app layer)
 * Pkts recieved
 * Pkts dropped
 * Blocked-KPackets  (wire)
 *
 */
int LogBasePerfStats(SFBASE_STATS *sfBaseStats,  FILE * fh )
{
    double sys=0.0,usr=0.0,idle=0.0;

#ifdef LINUX_SMP
    int iCtr;
#endif 
    if( ! fh ) return 0;
 
    fprintf(fh,"%lu,%.3f,%.1f,%.1f,%.1f,%d,%.2f,",
                (unsigned long)sfBaseStats->time,
                sfBaseStats->pkt_drop_percent,
                sfBaseStats->wire_mbits_per_sec.realtime,
                sfBaseStats->alerts_per_second,
                sfBaseStats->kpackets_per_sec.realtime,
                sfBaseStats->avg_bytes_per_packet,
                sfBaseStats->patmatch_percent);
       
    /* Session estimation statistics */

    fprintf(fh,
#ifdef WIN32
                "%.1f,%.1f,%.1f,%.1f,%I64i,%I64i,",
#else
                "%.1f,%.1f,%.1f,%.1f,%llu,%llu,",
#endif       
                sfBaseStats->syns_per_second,
                sfBaseStats->synacks_per_second,
                sfBaseStats->new_sessions_per_second,
                sfBaseStats->deleted_sessions_per_second,
                sfBaseStats->total_sessions,
                sfBaseStats->max_sessions);


    fprintf(fh,
#ifdef WIN32
                "%.1f,%I64i,%I64i,",
#else
                "%.1f,%llu,%llu,",
#endif       
                sfBaseStats->stream_flushes_per_second,
                sfBaseStats->stream_faults,
                sfBaseStats->stream_timeouts);

    fprintf(fh,
#ifdef WIN32
                "%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%I64i,%I64i,%I64i,%I64i,",
#else
                "%.1f,%.1f,%.1f,%.1f,%.1f,%.1f,%llu,%llu,%llu,%llu,",
#endif       
                sfBaseStats->frag_creates_per_second,
                sfBaseStats->frag_completes_per_second,
                sfBaseStats->frag_inserts_per_second,
                sfBaseStats->frag_deletes_per_second,
                sfBaseStats->frag_autofrees_per_second,
                sfBaseStats->frag_flushes_per_second,
                sfBaseStats->current_frags,
                sfBaseStats->max_frags,
                sfBaseStats->frag_timeouts,
                sfBaseStats->frag_faults);
   
    /* CPU STATS - at the end of output record */ 
#ifdef LINUX_SMP
    /* First the number of CPUs */
    fprintf(fh, "%d,", sfBaseStats->sfProcPidStats->iCPUs); 

    /* Next, stats for each CPU (a triple) */
    for(iCtr = 0; iCtr < sfBaseStats->sfProcPidStats->iCPUs; iCtr++)
    {
        usr= sfBaseStats->sfProcPidStats->SysCPUs[iCtr].user;
        sys= sfBaseStats->sfProcPidStats->SysCPUs[iCtr].sys;
        idle= sfBaseStats->sfProcPidStats->SysCPUs[iCtr].idle;
    
        fprintf(fh,"%.1f,%.1f,%.1f,",usr,sys,idle);
    }

#else

    usr=sfBaseStats->user_cpu_time;
    sys=sfBaseStats->system_cpu_time;
    idle=sfBaseStats->idle_cpu_time;
  
    /* 1 CPU hardcoded */ 
    fprintf(fh,"1,%.1f,%.1f,%.1f,",usr,sys,idle);

#endif

    /* Status for MBits/s, Bytes/Pkt, KPkts/s for each of
     * wire, IP Fragmented, IP Reassembled, Stream Reassembled,
     * App Layer (data that reaches protocol decoders). */
    fprintf(fh,"%.2f,%.2f,%.2f,%.2f,%.2f,",
            sfBaseStats->wire_mbits_per_sec.realtime,
            sfBaseStats->ipfrag_mbits_per_sec.realtime,
            sfBaseStats->ipreass_mbits_per_sec.realtime,
            sfBaseStats->rebuilt_mbits_per_sec.realtime,
            sfBaseStats->mbits_per_sec.realtime);
            
    fprintf(fh,"%d,%d,%d,%d,%d,",
        sfBaseStats->avg_bytes_per_wire_packet,
        sfBaseStats->avg_bytes_per_ipfrag_packet,
        sfBaseStats->avg_bytes_per_ipreass_packet,
        sfBaseStats->avg_bytes_per_rebuilt_packet,
        sfBaseStats->avg_bytes_per_packet);
        
    fprintf(fh,"%.2f,%.2f,%.2f,%.2f,%.2f,",
        sfBaseStats->kpackets_wire_per_sec.realtime,
        sfBaseStats->kpackets_ipfrag_per_sec.realtime,
        sfBaseStats->kpackets_ipreass_per_sec.realtime,
        sfBaseStats->kpackets_rebuilt_per_sec.realtime,
        sfBaseStats->kpackets_per_sec.realtime);
    
    fprintf(fh,"%llu,",sfBaseStats->pkt_stats.pkts_recv);
    fprintf(fh,"%llu,", sfBaseStats->pkt_stats.pkts_drop);
    
    fprintf(fh,"%llu,", sfBaseStats->total_blocked_packets);

    fprintf(fh,
#ifdef WIN32
                "%.1f,%.1f,%I64i,%I64i,",
#else
                "%.1f,%.1f,%llu,%llu,",
#endif       
                sfBaseStats->new_udp_sessions_per_second,
                sfBaseStats->deleted_udp_sessions_per_second,
                sfBaseStats->total_udp_sessions,
                sfBaseStats->max_udp_sessions);

    fprintf(fh,"\n");
 
    fflush(fh);

#ifdef LINUX   
   //LogScheduler();
#endif
   
    return 0;
}


/*
**  NAME 
**    DisplayBasePerfStats
** 
**  DESCRIPTION
**    Output Function.  We can easily code multiple output buffers
**    because all that is received is a SFBASE_STATS struct which
**    holds all the information to output.  This current output
**    function just prints to stdout.
**
**  FORMAL INPUTS
**    SFBASE_STATS * - struct with perf information
**    int            - flags for output
**
**  FORMAL OUTPUTS
**    int - 0 is successful
*/
int DisplayBasePerfStatsConsole(SFBASE_STATS *sfBaseStats, int iFlags)
{
#ifdef LINUX_SMP
    int iCtr;
#endif

    LogMessage("\n\nSnort Realtime Performance  : %s--------------------------\n", 
               ctime(&sfBaseStats->time));

    LogMessage("Pkts Recv:   %llu\n",   sfBaseStats->pkt_stats.pkts_recv);
    LogMessage("Pkts Drop:   %llu\n",   sfBaseStats->pkt_stats.pkts_drop);
    LogMessage("%% Dropped:   %.2f%%\n",sfBaseStats->pkt_drop_percent);
    LogMessage("Blocked:     %llu\n\n",sfBaseStats->total_blocked_packets);

    LogMessage("Mbits/Sec:   %.2f (wire)\n", 
            sfBaseStats->wire_mbits_per_sec.realtime);
    LogMessage("Mbits/Sec:   %.2f (ip fragmented)\n",    
            sfBaseStats->ipfrag_mbits_per_sec.realtime);
    LogMessage("Mbits/Sec:   %.2f (ip reassembled)\n",    
            sfBaseStats->ipreass_mbits_per_sec.realtime);
    LogMessage("Mbits/Sec:   %.2f (tcp rebuilt)\n", 
            sfBaseStats->rebuilt_mbits_per_sec.realtime);
    LogMessage("Mbits/Sec:   %.2f (app layer)\n\n",    
            sfBaseStats->mbits_per_sec.realtime);

    LogMessage("Bytes/Pkt:   %d (wire)\n",
        sfBaseStats->avg_bytes_per_wire_packet);
    LogMessage("Bytes/Pkt:   %d (ip fragmented)\n",
        sfBaseStats->avg_bytes_per_ipfrag_packet);
    LogMessage("Bytes/Pkt:   %d (ip reassembled)\n",
        sfBaseStats->avg_bytes_per_ipreass_packet);
    LogMessage("Bytes/Pkt:   %d (tcp rebuilt)\n",
        sfBaseStats->avg_bytes_per_rebuilt_packet);
    LogMessage("Bytes/Pkt:   %d (app layer)\n\n",
        sfBaseStats->avg_bytes_per_packet);

    LogMessage("KPkts/Sec:   %.2f (wire)\n",
        sfBaseStats->kpackets_wire_per_sec.realtime);
    LogMessage("KPkts/Sec:   %.2f (ip fragmented)\n",
        sfBaseStats->kpackets_ipfrag_per_sec.realtime);
    LogMessage("KPkts/Sec:   %.2f (ip reassembled)\n",
        sfBaseStats->kpackets_ipreass_per_sec.realtime);
    LogMessage("KPkts/Sec:   %.2f (tcp rebuilt)\n",
        sfBaseStats->kpackets_rebuilt_per_sec.realtime);
    LogMessage("KPkts/Sec:   %.2f (app layer)\n\n",
        sfBaseStats->kpackets_per_sec.realtime);

    LogMessage("PatMatch:    %.2f%%\n\n",  sfBaseStats->patmatch_percent);

    /*
    **  The following ifdefs are for CPU stats dealing with multiple
    **  CPUs in Linux.  Snort will show user, system and idle time for
    **  each CPU.  The methods of calculating this are different though,
    **  since getrusage is broken for multiple CPUs in Linux.  We get the
    **  CPU stats instead from the proc filesystem on Linux.
    */
#ifdef LINUX_SMP

    for(iCtr = 0; iCtr < sfBaseStats->sfProcPidStats->iCPUs; iCtr++)
    {
    LogMessage("CPU%d Usage:  %.2f%% (user)  %.2f%% (sys)  %.2f%% (idle)\n", 
                iCtr,
                sfBaseStats->sfProcPidStats->SysCPUs[iCtr].user,
                sfBaseStats->sfProcPidStats->SysCPUs[iCtr].sys,
                sfBaseStats->sfProcPidStats->SysCPUs[iCtr].idle);
    }
    printf("\n");

#else

    LogMessage("CPU Usage:   %.2f%% (user)  %.2f%% (sys)  %.2f%% (idle)\n\n", 
                sfBaseStats->user_cpu_time,
                sfBaseStats->system_cpu_time,
                sfBaseStats->idle_cpu_time);

#endif

    /*
    **  Shows the number of snort alerts per second.
    */
    LogMessage("Alerts/Sec             :  %.1f\n",   sfBaseStats->alerts_per_second);

    /* Session estimation statistics */
    LogMessage("Syns/Sec               :  %.1f\n", sfBaseStats->syns_per_second);
    LogMessage("Syn-Acks/Sec           :  %.1f\n", sfBaseStats->synacks_per_second);
    LogMessage("New Cached Sessions/Sec:  %.1f\n", sfBaseStats->new_sessions_per_second);
    LogMessage("Cached Sessions Del/Sec:  %.1f\n", sfBaseStats->deleted_sessions_per_second);    
    LogMessage("Current Cached Sessions:  %llu\n", sfBaseStats->total_sessions);
    LogMessage("Max Cached Sessions    :  %llu\n", sfBaseStats->max_sessions);

    /* more instrumentation for stream4/frag2 */
    LogMessage("Stream Flushes/Sec     :  %.1f\n", sfBaseStats->stream_flushes_per_second);
    LogMessage("Stream Cache Faults/Sec:  %llu\n", sfBaseStats->stream_faults);
    LogMessage("Stream Cache Timeouts  :  %llu\n", sfBaseStats->stream_timeouts);

    LogMessage("Frag Creates()s/Sec    :  %.1f\n", sfBaseStats->frag_creates_per_second);
    LogMessage("Frag Completes()s/Sec  :  %.1f\n", sfBaseStats->frag_completes_per_second);
    LogMessage("Frag Inserts()s/Sec    :  %.1f\n", sfBaseStats->frag_inserts_per_second);
    LogMessage("Frag Deletes/Sec       :  %.1f\n", sfBaseStats->frag_deletes_per_second);
    LogMessage("Frag AutoFrees/Sec     :  %.1f\n", sfBaseStats->frag_autofrees_per_second);
    LogMessage("Frag Flushes/Sec       :  %.1f\n", sfBaseStats->frag_flushes_per_second);
    LogMessage("Current Cached Frags   :  %llu\n", sfBaseStats->current_frags);
    LogMessage("Max Cached Frags       :  %llu\n", sfBaseStats->max_frags);
    LogMessage("Frag Timeouts          :  %llu\n", sfBaseStats->frag_timeouts);
    LogMessage("Frag Faults            :  %llu\n\n", sfBaseStats->frag_faults);

    LogMessage("New Cached UDP Ssns/Sec:  %.1f\n", sfBaseStats->new_udp_sessions_per_second);
    LogMessage("Cached UDP Ssns Del/Sec:  %.1f\n", sfBaseStats->deleted_udp_sessions_per_second);    
    LogMessage("Current Cached UDP Ssns:  %llu\n", sfBaseStats->total_udp_sessions);
    LogMessage("Max Cached UDP Ssns    :  %llu\n", sfBaseStats->max_udp_sessions);
    /*
    **  Snort Maximum Performance Statistics
    **  These statistics calculate the maximum performance that 
    **  snort could attain by using the getrusage numbers.  We've
    **  seen in testing that these numbers come close to the actual
    **  throughput for Mbits/Sec and Pkt/Sec.  But note that these
    **  are not hard numbers and rigorous testing is necessary to
    **  establish snort performance on any hardware setting.
    */
    if(iFlags & MAX_PERF_STATS)
    {
    
        LogMessage("Snort Maximum Performance\n");
        LogMessage("-------------------------\n\n");
    
        LogMessage("Mbits/Second\n");
        LogMessage("----------------\n");
        LogMessage("Snort:       %.2f\n",sfBaseStats->mbits_per_sec.usertime);
        LogMessage("Sniffing:    %.2f\n",sfBaseStats->mbits_per_sec.systemtime);
        LogMessage("Combined:    %.2f\n\n",sfBaseStats->mbits_per_sec.totaltime);
    

        LogMessage("uSeconds/Pkt\n");
        LogMessage("----------------\n");
        LogMessage("Snort:       %.2f\n",sfBaseStats->usecs_per_packet.usertime);
        LogMessage("Sniffing:    %.2f\n",sfBaseStats->usecs_per_packet.systemtime);
        LogMessage("Combined:    %.2f\n\n",sfBaseStats->usecs_per_packet.totaltime);

        LogMessage("KPkts/Second\n");
        LogMessage("------------------\n");
        LogMessage("Snort:       %.2f\n",sfBaseStats->kpackets_per_sec.usertime);
        LogMessage("Sniffing:    %.2f\n",sfBaseStats->kpackets_per_sec.systemtime);
        LogMessage("Combined:    %.2f\n\n",sfBaseStats->kpackets_per_sec.totaltime);
    }

    return 0;
}

