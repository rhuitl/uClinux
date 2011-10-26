/* $Id$ */

/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2003-2005 Sourcefire, Inc.
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

/* spp_stream4 
 * 
 * Purpose: Stateful inspection and tcp stream reassembly in Snort
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

/*
 * 04 Feb 2005: SAS Updated to handle favor_old and favor_new options.
 *                  favor_new traverses the tree in the opposite
 *                  direction and builds the stream using newer packets.
 *                  Also added checks for:
 *                  - PAWS (Timestamp option is set and 0) on an
 *                  establiahed session and ACK in the packet.  Win32
 *                  uses 0 Timestamp on Syn-only packets.
 *                  - Checks for NULL TCP flags in established session.
 *                  After the TWHS, all packets should have at least
 *                  ACK, RST, or FIN.
 *                  - Checks for overlaps (larger than an option
 *                  specified overlap_limit) in the reassembled stream.
 *                  When the overlap limit is reached, that side of the
 *                  stream is flushed and an evasion alert is raised.  
 *
 * 08 Feb 2005: AJM Update ACK when server sends RST, which enables client
 *                  stream to be reassembled upon flush.
 *                  - Also enable client reassembly upon client RST.
 *                  - Reset session alert count after flushing rebuilt packet.
 *
 * 28 Feb 2005: SAS Update to use hash table to Session storage.  Added new
 *                  files snort_stream_session.{c,h} that contain the sfxhash
 *                  interfaces.
 *                  - Added max_sessions configuration option.  Impacts the
 *                  meaning of memcap in that memcap now only relates to the
 *                  memory consumed by stored packets, not memory for session
 *                  structure.
 *
 * 07 Mar 2005: JRB/SAS Add user configurable flushpoints.  Added options:
 *                  flush_behavior, flush_base, flush_seed, flush_range to
 *                  stream4_reassemble preproc config.
 *
 * 31 Mar 2005: SAS Added server_inspect_limit option to limit the
 *                  amount of data that goes through rules inspection on
 *                  the server side.  The counter is reset when a client
 *                  packet is seen (ie, a request).
 */

/*  I N C L U D E S  ************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef DEBUG
#ifndef INLINE
#ifdef inline
#define INLINE inline
#else
#define INLINE
#endif
#endif
#else
#ifdef INLINE
#undef INLINE
#endif
#define INLINE   
#endif /* DEBUG */

#define _STREAM4_INTERNAL_USAGE_ONLY_

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
#include <rpc/types.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "bounds.h"
#include "decode.h"
#include "event.h"
#include "debug.h"
#include "util.h"
#include "plugbase.h"
#include "parser.h"
#include "mstring.h"
#include "checksum.h"
#include "log.h"
#include "generators.h"
#include "detect.h"
#include "perf.h"
#include "timersub.h"
#include "snort.h"
#include "stream.h"
#include "spp_stream4.h"
#include "snort_packet_header.h"
#include "event_queue.h"
#include "inline.h"

#include "snort_stream4_session.h"
#include "snort_stream4_udp.h"

#include "stream_ignore.h"
#include "stream_api.h"

#include "flow.h" /* For flowbits, now handled by Stream API */

#include "profiler.h"

/*  D E F I N E S  **************************************************/

/* normal TCP states */
#define CLOSED       0
#define LISTEN       1
#define SYN_RCVD     2
#define SYN_SENT     3
#define ESTABLISHED  4
#define CLOSE_WAIT   5
#define LAST_ACK     6
#define FIN_WAIT_1   7
#define CLOSING      8
#define FIN_WAIT_2   9
#define TIME_WAIT   10

/* extended states for fun stuff */
#define NMAP_FINGERPRINT_2S         30
#define NMAP_FINGERPRINT_NULL       31
#define NMAP_FINGERPRINT_UPSF       32
#define NMAP_FINGERPRINT_ZERO_ACK   33

#define ACTION_NOTHING                  0x00000000
#define ACTION_FLUSH_SERVER_STREAM      0x00000001
#define ACTION_FLUSH_CLIENT_STREAM      0x00000002
#define ACTION_DROP_SESSION             0x00000004
#define ACTION_ACK_SERVER_DATA          0x00000008
#define ACTION_ACK_CLIENT_DATA          0x00000010
#define ACTION_DATA_ON_SYN              0x00000020
#define ACTION_SET_SERVER_ISN           0x00000040
#define ACTION_COMPLETE_TWH             0x00000080
#define ACTION_ALERT_NMAP_FINGERPRINT   0x00000100
#define ACTION_INC_PORT                 0x00000200

#define PRUNE_QUANTA    30              /* seconds to timeout a session */
#define STREAM4_MEMORY_CAP     8388608  /* 8MB */
#define STREAM4_MAX_SESSIONS   8192     /* 8k */
#define STREAM4_CLEANUP   5             /* Cleanup 5 sessions at a time */
#define STREAM4_CACHE_PERCENT 0.1       /* Or cleanup 0.1 % sessions at a time */
#define STREAM4_TTL_LIMIT 5             /* default for TTL Limit */
#define DEFAULT_STREAM_TRACKERS 256000  /* 256k sessions by default */

#define STATS_HUMAN_READABLE   1
#define STATS_MACHINE_READABLE 2
#define STATS_BINARY           3

#define STATS_MAGIC  0xDEAD029A   /* magic for the binary stats file */

#define REVERSE     0
#define NO_REVERSE  1

#define ENFORCE_STATE_NONE 0
#define ENFORCE_STATE      1
#define ENFORCE_STATE_DROP 2

#define METHOD_FAVOR_NEW  0x01
#define METHOD_FAVOR_OLD  0x02

/* # of packets that we accept on an unestab conn */
#define UNESTABLISHED_MAX_PCOUNT 300

/* what pcap can hold is how this limit comes about -- cmg */
#define MAX_STREAM_SIZE (IP_MAXPACKET - IP_HEADER_LEN - TCP_HEADER_LEN - ETHERNET_HEADER_LEN) 

/* Macros to deal with sequence numbers - p810 TCP Illustrated vol 2 */
#define SEQ_LT(a,b)  ((int)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int)((a) - (b)) >= 0)
#define SEQ_EQ(a,b)  ((int)((a) - (b)) == 0)

#define NO_CHK_SEQ  0
#define CHK_SEQ     1


/* these are needed in snort versions before 2.0build something */
#ifndef SNORT_20
extern char *file_name;
extern int *file_line;
#endif /* SNORT_20 */

/* values for the smartbits detector/self perservation */
#define SELF_PRES_THRESHOLD        50
#define SELF_PRES_PERIOD           90

#define SUSPEND_THRESHOLD   200
#define SUSPEND_PERIOD      30

#define OPS_NORMAL              0
#define OPS_SELF_PRESERVATION   1
#define OPS_SUSPEND             2

#define MAXSIZE_IP              65535
#define MAX_TRACKER_AMOUNT      (MAX_STREAM_SIZE + 4000)



/* Support dynamic flush points */
#define FCOUNT 64
#define STREAM4_FLUSH_BASE 512
#define STREAM4_FLUSH_RANGE 1213

#define FLUSH_BEHAVIOR_RANDOM -1
#define FLUSH_BEHAVIOR_DEFAULT 0
#define FLUSH_BEHAVIOR_LARGE 1

/* Old flushpoints, for backward compat.  Use flush_behavior default */
static u_int32_t old_flush_points[FCOUNT] = { 128, 217, 189, 130, 240, 221, 134, 129,
                                               250, 232, 141, 131, 144, 177, 201, 130,
                                               230, 190, 177, 142, 130, 200, 173, 129,
                                               250, 244, 174, 151, 201, 190, 180, 198,
                                               220, 201, 142, 185, 219, 129, 194, 140,
                                               145, 191, 197, 183, 199, 220, 231, 245,
                                               233, 135, 143, 158, 174, 194, 200, 180,
                                               201, 142, 153, 187, 173, 199, 143, 201 };

static u_int32_t new_flush_points[FCOUNT] = { 1280, 2176, 1895, 1303, 2402, 2211, 1340, 1298,
                                              2500, 2320, 1413, 1313, 1444, 1776, 2015, 1305,
                                              2130, 1190, 1377, 1492, 1380, 2100, 1373, 1029,
                                              750, 444, 874, 551, 401, 390, 1801, 1898,
                                              2260, 2601, 642, 485, 619, 929, 794, 340,
                                              445, 1911, 497, 883, 399, 2201, 2431, 2145,
                                              433, 735, 543, 658, 1174, 2042, 1200, 1800,
                                              2015, 1142, 1530, 487, 673, 899, 743, 2101 };

#ifdef DEBUG
static char *state_names[] = { "CLOSED",
                              "LISTEN",
                              "SYN_RCVD",
                              "SYN_SENT",
                              "ESTABLISHED",
                              "CLOSE_WAIT",
                              "LAST_ACK",
                              "FIN_WAIT_1",
                              "CLOSING",
                              "FIN_WAIT_2",
                              "TIME_WAIT"};
#endif

/*  D A T A   S T R U C T U R E S  **********************************/
typedef struct _OverlapData
{
    u_int32_t seq_low;
    u_int32_t seq_hi;

} OverlapData;

typedef struct _BuildData
{
    Stream *stream;
    u_int8_t *buf;
    u_int32_t total_size;
    /* u_int32_t build_flags; -- reserved for the day when we generate 1 stream event and log the stream */
} BuildData;

typedef struct _BinStats
{
    u_int32_t start_time;
    u_int32_t end_time;
    u_int32_t sip;
    u_int32_t cip;
    u_int16_t sport;
    u_int16_t cport;
    u_int32_t spackets;
    u_int32_t cpackets;
    u_int32_t sbytes;
    u_int32_t cbytes;
} BinStats;

typedef struct _StatsLog
{
    FILE *fp;
    char *filename;

} StatsLog;

typedef struct _StatsLogHeader
{
    u_int32_t magic;
    u_int32_t version_major;
    u_int32_t version_minor;
    u_int32_t timezone;
} StatsLogHeader;

typedef struct _S4Emergency
{
    long end_time;
    char old_reassemble_client;
    char old_reassemble_server;
    char old_reassembly_alerts;
    int old_assurance_mode;
    char old_stateful_mode;
    u_int32_t new_session_count;
    int status;
} S4Emergency;

typedef struct _StreamKey
{
    u_int32_t sip;
    u_int32_t cip;
    u_int16_t sport;
    u_int16_t cport;
} STREAM_KEY;

typedef Session *SessionPtr;

StatsLog *stats_log;

u_int32_t safe_alloc_faults;

/* we keep a stream packet queued up and ready to go for reassembly */
Packet *stream_pkt;

/*  G L O B A L S  **************************************************/

extern int do_detect, do_detect_content;
extern OptTreeNode *otn_tmp;

/* external globals from rules.c */
FILE *session_log;
Stream4Data s4data;
u_int32_t stream4_memory_usage;
u_int32_t ps_memory_usage;

/* stream4 emergency mode counters... */
S4Emergency s4_emergency;

/* List of Dynamic flushpoints */
u_int32_t flush_points[FCOUNT];

#ifdef PERF_PROFILING
PreprocStats stream4PerfStats;
PreprocStats stream4InsertPerfStats;
PreprocStats stream4BuildPerfStats;
PreprocStats stream4NewSessPerfStats;
PreprocStats stream4LUSessPerfStats;
PreprocStats stream4StatePerfStats;
PreprocStats stream4StateAsyncPerfStats;
PreprocStats stream4ActionPerfStats;
PreprocStats stream4ActionAsyncPerfStats;
PreprocStats stream4PrunePerfStats;
PreprocStats stream4FlushPerfStats;
PreprocStats stream4ProcessRebuiltPerfStats;
#endif

/*  P R O T O T Y P E S  ********************************************/
void *SafeAlloc(unsigned long, int, Session *);
void ParseStream4Args(char *);
void Stream4InitReassembler(u_char *);
void Stream4InitExternalOptions(u_char *);
void ReassembleStream4(Packet *, void *);
Session *CreateNewSession(Packet *, u_int32_t, u_int32_t);
void DropSession(Session *);
void DeleteSession(Session *, u_int32_t);
void DeleteSpd(StreamPacketData **);
int GetDirection(Session *, Packet *);
static int s4_shutdown = 0;
void Stream4ShutdownFunction(int, void *);
void Stream4CleanExitFunction(int, void *);
void Stream4RestartFunction(int, void *);
void PrintSessionCache();
int CheckRst(Session *, int, u_int32_t, Packet *);
int PruneSessionCache(u_int8_t, u_int32_t, int, Session *);
void StoreStreamPkt2(Session *, Packet *, u_int32_t);
void FlushStream(Stream *, Packet *, int);
void InitStream4Pkt();
void Stream4VerifyConfig(void);
int BuildPacket(Stream *, u_int32_t, Packet *, int);
int CheckPorts(u_int16_t, u_int16_t);
void PortscanWatch(Session *, u_int32_t);
void PortscanDeclare(Packet *);
int LogStream(Stream *);
void WriteSsnStats(BinStats *);
void OpenStatsFile();
void Stream4Init(u_char *);
void PreprocFunction(Packet *);
void PreprocRestartFunction(int);
void PreprocCleanExitFunction(int);
static INLINE int isBetween(u_int32_t low, u_int32_t high, u_int32_t cur);
static INLINE int NotForStream4(Packet *p);
static INLINE int SetFinSent(Session *ssn, int direction, u_int32_t pkt_seq, Packet *p);
static INLINE int WithinSessionLimits(Packet *p, Stream *stream);

 /* helpers for dealing with session byte_counters */
static INLINE void StreamSegmentSub(Stream *stream, u_int16_t sub);
static INLINE void StreamSegmentAdd(Stream *stream, u_int16_t add);

static StreamPacketData *RemoveSpd(Stream *s, StreamPacketData *spd);
static void AddSpd(Stream *s, StreamPacketData *prev, StreamPacketData *new);
static int DupSpd(Packet *p, Stream *s, StreamPacketData *left, StreamPacketData **retSpd);
static StreamPacketData *SpdSeqExists(Stream *s, u_int32_t pkt_seq);

/*
  Here is where we separate which functions will be called in the
  normal case versus in the asynchronus state

*/
   
//int UpdateState(Session *, Packet *, u_int32_t); 
int UpdateState2(Session *, Packet *, u_int32_t); 
int UpdateStateAsync(Session *, Packet *, u_int32_t);

static void TcpAction(Session *ssn, Packet *p, int action, int direction, 
                      u_int32_t pkt_seq, u_int32_t pkt_ack);
static void TcpActionAsync(Session *ssn, Packet *p, int action, int direction, 
                           u_int32_t pkt_seq, u_int32_t pkt_ack);

/*
 * Define the functions for the Stream API
 */
static int Stream4MidStreamDropAlert() { return s4data.ms_inline_alerts; }
static void Stream4UpdateDirection(
                    void * ssnptr,
                    char dir,
                    u_int32_t ip,
                    u_int16_t port) { }
static void SetIgnoreChannel(
                    void * ssnptr,
                    Packet *p,
                    char dir,
                    int32_t bytes,
                    int response);
static int Stream4IgnoreChannel(
                    u_int32_t srcIP,
                    u_int16_t srcPort,
                    u_int32_t dstIP,
                    u_int16_t dstPort,
                    char protocol,
                    char direction,
                    char flags);
static void Stream4ResumeInspection(
                    void *ssnptr,
                    char dir) { }
static void Stream4DropTraffic(
                    void *ssnptr,
                    char dir);
static void Stream4DropPacket(
                    Packet *p);
static void Stream4SetApplicationData(
                    void *ssnptr,
                    u_int32_t protocol,
                    void *data,
                    StreamAppDataFree free_func);
static void *Stream4GetApplicationData(void *, u_int32_t);
static u_int32_t Stream4SetSessionFlags(void *, u_int32_t);
static u_int32_t Stream4GetSessionFlags(void *);
static int AlertFlushStream(Packet *);
static int ForceFlushStream(Packet *);
static int Stream4AddSessionAlert(void *ssnptr,
                                  Packet *p,
                                  u_int32_t gid,
                                  u_int32_t sid);
static int Stream4CheckSessionAlert(void *ssnptr,
                                  Packet *p,
                                  u_int32_t gid,
                                  u_int32_t sid);
static char Stream4SetReassembly(void *ssnptr,
                                   u_int8_t flush_policy,
                                   char dir,
                                   char flags);
static char Stream4GetReassemblyDirection(void *ssnptr);
static char Stream4GetReassemblyFlushPolicy(void *ssnptr, char dir);
static char Stream4IsStreamSequenced(void *ssnptr, char dir);

/* Not an API function but part of the Session alert tracking */
void CleanSessionAlerts(Session *ssn, Packet *flushed_pkt);
static int Stream4TraverseReassembly(
                    Packet *p,
                    PacketIterator callback,
                    void *userdata);
static StreamFlowData *Stream4GetFlowData(
                    Packet *p);

StreamAPI s4api = {
    STREAM_API_VERSION4,
    Stream4MidStreamDropAlert,
    Stream4UpdateDirection, /* Not supporrted in Stream4 */
    SetIgnoreChannel,
    Stream4IgnoreChannel,
    Stream4ResumeInspection, /* Not supported in Stream4 */
    Stream4DropTraffic,
    Stream4DropPacket,
    Stream4SetApplicationData,
    Stream4GetApplicationData,
    Stream4SetSessionFlags,
    Stream4GetSessionFlags,
    AlertFlushStream,
    ForceFlushStream,
    Stream4TraverseReassembly,
    Stream4AddSessionAlert,
    Stream4CheckSessionAlert,
    Stream4GetFlowData,
    Stream4SetReassembly,
    Stream4GetReassemblyDirection,
    Stream4GetReassemblyFlushPolicy,
    Stream4IsStreamSequenced
            /* More to follow */
};



/** 
 * See if a sequence number is in range.
 * 
 * @param low base sequence number
 * @param high acknowledged sequence number
 * @param cur sequence number to check
 * 
 * @return 1 if we are between these sequence numbers, 0 otherwise
 */
static INLINE int isBetween(u_int32_t low, u_int32_t high, u_int32_t cur)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"(%u,%u,%u) = (low, high, cur)\n",
                low,high,cur););
    return (cur - low) <= (high - low);
}


static void TraverseFunc(StreamPacketData *NodePtr, void *build_data)
{
    Stream *s;
    StreamPacketData *spd;
    BuildData *bd;
    u_int8_t *buf;
    int trunc_size;
    int offset = 0;

    if(s4data.stop_traverse)
        return;

    spd = (StreamPacketData *) NodePtr;
    bd = (BuildData *) build_data;
    s = bd->stream;
    buf = bd->buf;

    /* Don't reassemble if there's nothing to reassemble.
     * The first two cases can probably never happen. I personally
     * prefer strong error checking (read: paranoia).
     */
    if(spd->payload_size == 0)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "not reassembling because "
                    "the payload size is zero.\n"););
        spd->chuck = SEG_FULL;
        return;
    }
    else if(SEQ_EQ(s->base_seq, s->last_ack))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "not reassembling because "
                    "base_seq = last_ack (%u).\n", s->base_seq););
        return;
    }

    /* Packet is completely before the current window. */
    else if(SEQ_LEQ(spd->seq_num, s->base_seq) &&
            SEQ_LEQ(spd->seq_num + spd->payload_size, s->base_seq))
    {
        /* ignore this segment, we've already looked at it */
        spd->chuck = SEG_FULL;
        return;
    }
    /* Packet starts outside the window and ends inside it. */
    else if(SEQ_LT(spd->seq_num, s->base_seq) &&
            isBetween(s->base_seq+1, s->last_ack, (spd->seq_num + spd->payload_size)))
    {
        /* case where we've got a segment that wasn't completely ack'd 
         * last time it was processed, do a partial copy into the buffer
         */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Incompleted segment, copying up "
                    "to last-ack\n"););

        /* calculate how much un-ack'd data to copy */
        trunc_size = (spd->seq_num+spd->payload_size) - s->base_seq;

        /* figure out where in the original data payload to start copying */
        offset = s->base_seq - spd->seq_num;

        if (offset < 0)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Negative offset, not using "
                        "old packet: Base: 0x%x Packet: 0x%x Offset: %d\n",
                        s->base_seq, spd->seq_num, offset););
            spd->chuck = SEG_FULL;
            return;
        }

        if(trunc_size < 65500 && trunc_size > 0)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Copying %d bytes into buffer, "
                        "offset %d, buf %p\n", trunc_size, offset, 
                        buf););
            SafeMemcpy(buf, spd->payload+offset, trunc_size,
                    stream_pkt->data, stream_pkt->data + MAX_STREAM_SIZE);            
            pc.rebuilt_segs++;
            bd->total_size += trunc_size;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Woah, got bad TCP segment "
                        "trunctation value (%d)\n", trunc_size););
        }

        spd->chuck = SEG_FULL;
    }
    /* if it's in bounds... */
    else if(isBetween(s->base_seq, s->last_ack-1, spd->seq_num) &&
            isBetween(s->base_seq, s->last_ack, (spd->seq_num + spd->payload_size)))
    {
        offset = spd->seq_num - s->base_seq;

        if (offset < 0)
        {
            /* This shouldn't happen because of the bounds check above */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Negative offset, not using "
                        "old packet: Base: 0x%x Packet: 0x%x Offset: %d\n",
                        s->base_seq, spd->seq_num, offset););
            spd->chuck = SEG_FULL;
            return;
        }

        s->next_seq = spd->seq_num + spd->payload_size;

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Copying %d bytes into buffer, "
                    "offset %d, buf %p\n", spd->payload_size, offset, 
                    buf););

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "spd->seq_num (%u)  s->last_ack (%u) "
                    "s->base_seq(%u) size: (%u) s->next_seq(%u), "
                    "offset(%u), MAX(%u)\n",
                    spd->seq_num, s->last_ack, s->base_seq,
                    spd->payload_size, s->next_seq, offset, 
                    MAX_STREAM_SIZE));

        SafeMemcpy(buf+offset, spd->payload, spd->payload_size,
                stream_pkt->data, stream_pkt->data + MAX_STREAM_SIZE);

        pc.rebuilt_segs++;

        spd->chuck = SEG_FULL;
        bd->total_size += spd->payload_size;
    } 
    else if(isBetween(s->base_seq, s->last_ack-1, spd->seq_num) &&
            SEQ_GT((spd->seq_num + spd->payload_size), s->last_ack))
    {
        /*
         *  if it starts in bounds and hasn't been completely ack'd, 
         *  truncate the last piece and copy it in 
         */
        trunc_size = s->last_ack - spd->seq_num; 

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Truncating overlap of %d bytes\n", 
                    spd->seq_num + spd->payload_size - s->last_ack);
                DebugMessage(DEBUG_STREAM, "    => trunc info seq: 0x%X   "
                    "size: %d  last_ack: 0x%X\n", 
                    spd->seq_num, spd->payload_size, s->last_ack);
                );

        offset = spd->seq_num - s->base_seq;

        if (offset < 0)
        {
            /* This shouldn't happen because of the bounds check above */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Negative offset, not using "
                        "old packet: Base: 0x%x Packet: 0x%x Offset: %d\n",
                        s->base_seq, spd->seq_num, offset););
            spd->chuck = SEG_FULL;
            return;
        }

        if(trunc_size < (65500-offset) && trunc_size > 0)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Copying %d bytes into buffer, "
                        "offset %d, buf %p\n", trunc_size, offset, 
                        buf););
            SafeMemcpy(buf+offset, spd->payload, trunc_size,
                    stream_pkt->data, stream_pkt->data + MAX_STREAM_SIZE);            
            pc.rebuilt_segs++;
            bd->total_size += trunc_size;
            spd->chuck = SEG_PARTIAL;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Woah, got bad TCP segment "
                        "trunctation value (%d)\n", trunc_size););
        }
    }
    else if(SEQ_GEQ(spd->seq_num,s->last_ack))
    {
        /* we're all done, we've walked past the end of the ACK'd data */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                    "   => Segment is past last ack'd data, "
                    "ignoring for now...\n");
                DebugMessage(DEBUG_STREAM,  "        => (%d bytes @ seq 0x%X, "
                    "ack: 0x%X)\n", spd->payload_size, spd->seq_num, s->last_ack);
                );

        /* since we're reassembling in order, once we hit an overflow condition
         * let's stop trying for now
         */
        s4data.stop_traverse = 1;
        //s4data.stop_seq = spd->seq_num;
        s4data.stop_seq = s->last_ack;
    }
    else
    {
        /* The only case that should reach this point is if
         * spd->seq_num < s->base_seq &&
         * spd->seq_num + spd->payload_size >= s->last_ack
         * Can that ever happen?
         */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "Ended up in the default case somehow.. !\n"
                    "spd->seq_num(%u) spd->payload_size(%u)\n",
                    spd->seq_num, spd->payload_size););        
    }
} 

void SegmentCleanTraverse(Stream *s)
{
    StreamPacketData *spd;
    StreamPacketData *foo;

    spd = s->seglist;

    while(spd != NULL)
    {
        if(spd->chuck == SEG_FULL || SEQ_GEQ(s->last_ack,(spd->seq_num+spd->payload_size)))
        {
            StreamPacketData *savspd = spd;
            spd = spd->next;
#ifdef DEBUG
            if(savspd->chuck == SEG_FULL)
            {
                DebugMessage(DEBUG_STREAM, "[sct] chucking used segment\n");
            }
            else
            {
                DebugMessage(DEBUG_STREAM, "[sct] tossing unused segment\n");
            }
#endif /*DEBUG*/

            /* Break out if we hit the packet where we stopped because
             * of a gap.  The rest will be cleaned when we reassemble
             * after the gap. */
            if (s4data.seq_gap)
            {
                /* SEQ_GT to handle wrapped seq */
                if  (SEQ_GT(savspd->seq_num, s4data.stop_seq))
                {
                    break;
                }
            }

            foo = RemoveSpd(s, savspd);
            StreamSegmentSub(s, foo->payload_size);

            stream4_memory_usage -= foo->pkt_size;
            free(foo->pktOrig);
            stream4_memory_usage -= sizeof(StreamPacketData);
            free(foo);
        }
        else
        {
            /* We just break out of the loop here since the
             * packets are stored in order */
            break;
        }
    }
}

/* XXX: this will be removed as we clean up the modularization */
void DirectLogTcpdump(struct pcap_pkthdr *, u_int8_t *);

static void LogTraverse(StreamPacketData *NodePtr, void *foo)
{
    StreamPacketData *spd;

    spd = (StreamPacketData *) NodePtr;
    /* XXX: modularization violation */
    DirectLogTcpdump((struct pcap_pkthdr *)&spd->pkth, spd->pkt); 
}

void *SafeAlloc(unsigned long size, int tv_sec, Session *ssn)
{
    void *tmp;

    stream4_memory_usage += size;

    /* if we use up all of our RAM, try to free up some stale sessions */
    if(stream4_memory_usage > s4data.memcap)
    {
        pc.str_mem_faults++;
        sfPerf.sfBase.iStreamFaults++;
        if(!PruneSessionCache(IPPROTO_TCP, (u_int32_t)tv_sec, 0, ssn))
        {
            /* if we can't prune due to time, just nuke 5 random sessions */
            PruneSessionCache(IPPROTO_TCP, 0, 5, ssn);            
        }
    }

    tmp = (void *) calloc(size, sizeof(char));

    if(tmp == NULL)
    {
        FatalError("Unable to allocate memory! (%lu bytes in use)\n", 
                   (unsigned long)stream4_memory_usage);
    }

    return tmp;
}


/*
 * Function: SetupStream4()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.  This is the function that
 *          gets called from InitPreprocessors() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 */
void SetupStream4()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterPreprocessor("stream4", Stream4Init);
    RegisterPreprocessor("stream4_reassemble", Stream4InitReassembler);
    RegisterPreprocessor("stream4_external", Stream4InitExternalOptions);

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "Preprocessor: Stream4 is setup...\n"););
}


/*
 * Function: Stream4Init(u_char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 */
void Stream4Init(u_char *args)
{
    char logfile[STD_BUF];

    if (stream_api == NULL)
        stream_api = &s4api;
    else
        FatalError("Cannot use both Stream4 & Stream5 simultaneously\n");

    s4data.stream4_active = 1;
    pv.stateful = 1;
    s4data.memcap = STREAM4_MEMORY_CAP;
    s4data.max_sessions = STREAM4_MAX_SESSIONS;
#ifdef STREAM4_UDP
    s4data.max_udp_sessions = STREAM4_MAX_SESSIONS;
    s4data.udp_ignore_any = 0;
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "log_dir is %s\n", pv.log_dir););

    /* initialize the self preservation counters */
    s4data.sp_threshold      = SELF_PRES_THRESHOLD;
    s4data.sp_period         = SELF_PRES_PERIOD;
    s4data.suspend_threshold = SUSPEND_THRESHOLD;
    s4data.suspend_period    = SUSPEND_PERIOD;
    s4data.state_protection  = 0; 
    
    s4_emergency.end_time = 0;
    s4_emergency.new_session_count = 0;
    s4_emergency.status = OPS_NORMAL;
   
    /* parse the argument list from the rules file */
    ParseStream4Args(args);

    SnortSnprintf(logfile, STD_BUF, "%s/%s", pv.log_dir, "session.log");
    
    if(s4data.track_stats_flag)
    {
        if((session_log = fopen(logfile, "a+")) == NULL)
        {
            FatalError("Unable to write to \"%s\": %s\n", logfile, 
                       strerror(errno));
        }
    }

    s4data.last_prune_time = 0;
    
    stream_pkt = (Packet *) SafeAlloc(sizeof(Packet), 0, NULL);

    /* Need to do this later.  We have dynamic preprocessors
     * and a dynamic preproc bit field that is set based on number of
     * preprocessors */
    //InitStream4Pkt();

    /* tell the rest of the program that we're stateful */
    snort_runtime.capabilities.stateful_inspection = 1;
   
    InitSessionCache();

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "Preprocessor: Stream4 Initialized\n"););

    /* Set the preprocessor function into the function list */
    AddFuncToPreprocList(ReassembleStream4, PRIORITY_TRANSPORT, PP_STREAM4);
    AddFuncToPreprocShutdownList(Stream4ShutdownFunction, NULL, PRIORITY_FIRST, PP_STREAM4);
    AddFuncToPreprocCleanExitList(Stream4CleanExitFunction, NULL, PRIORITY_FIRST, PP_STREAM4);
    AddFuncToPreprocRestartList(Stream4RestartFunction, NULL, PRIORITY_FIRST, PP_STREAM4);    
    AddFuncToConfigCheckList(Stream4VerifyConfig);

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("s4", &stream4PerfStats, 0, &totalPerfStats);
    RegisterPreprocessorProfile("s4PktInsert", &stream4InsertPerfStats, 1, &stream4PerfStats);
    RegisterPreprocessorProfile("s4NewSess", &stream4NewSessPerfStats, 1, &stream4PerfStats);
    RegisterPreprocessorProfile("s4GetSess", &stream4LUSessPerfStats, 1, &stream4PerfStats);
    RegisterPreprocessorProfile("s4State", &stream4StatePerfStats, 1, &stream4PerfStats);
    RegisterPreprocessorProfile("s4StateAsync", &stream4StateAsyncPerfStats, 1, &stream4PerfStats);
    RegisterPreprocessorProfile("s4StateAction", &stream4ActionPerfStats, 1, &stream4PerfStats);
    RegisterPreprocessorProfile("s4Flush", &stream4FlushPerfStats, 1, &stream4PerfStats);
    RegisterPreprocessorProfile("s4BuildPacket", &stream4BuildPerfStats, 2, &stream4FlushPerfStats);
    RegisterPreprocessorProfile("s4ProcessRebuilt", &stream4ProcessRebuiltPerfStats, 2, &stream4FlushPerfStats);
    RegisterPreprocessorProfile("s4StateActionAsync", &stream4ActionAsyncPerfStats, 1, &stream4PerfStats);
    RegisterPreprocessorProfile("s4Prune", &stream4PrunePerfStats, 1, &stream4PerfStats);
#endif
}

void Stream4VerifyConfig()
{
    /* Finish setup of reassembly packet */
    InitStream4Pkt();

#ifdef STREAM4_UDP
    Stream4UdpConfigure();
#endif
}

void DisplayStream4Config(void) 
{
    LogMessage("Stream4 config:\n");
    LogMessage("    Stateful inspection: %s\n", 
               s4data.stateful_inspection_flag ? "ACTIVE": "INACTIVE");
    LogMessage("    Session statistics: %s\n", 
               s4data.track_stats_flag ? "ACTIVE":"INACTIVE");
    LogMessage("    Session timeout: %d seconds\n", s4data.timeout);
    LogMessage("    Session memory cap: %lu bytes\n", (unsigned long)s4data.memcap);
    LogMessage("    Session count max: %d sessions\n", (unsigned long)s4data.max_sessions);
#ifdef STREAM4_UDP
    LogMessage("    UDP Tracking Enabled: %s\n",
                s4data.enable_udp_sessions ? "YES" : "NO");
    if (s4data.enable_udp_sessions)
    {
        LogMessage("    UDP Session count max: %d sessions\n", (unsigned long)s4data.max_udp_sessions);
        LogMessage("    UDP Ignore Traffic on port without port-specific rules: %s\n",
                s4data.udp_ignore_any ? "YES" : "NO");
    }
#endif

    LogMessage("    Session cleanup count: %d\n", s4data.cache_clean_sessions);
    LogMessage("    State alerts: %s\n", 
               s4data.state_alerts ? "ACTIVE":"INACTIVE");
    LogMessage("    Evasion alerts: %s\n", 
               s4data.evasion_alerts ? "ACTIVE":"INACTIVE");
    LogMessage("    Scan alerts: %s\n", 
               s4data.ps_alerts ? "ACTIVE":"INACTIVE");
    LogMessage("    Log Flushed Streams: %s\n",
               s4data.log_flushed_streams ? "ACTIVE":"INACTIVE");
    LogMessage("    MinTTL: %d\n", s4data.min_ttl);
    LogMessage("    TTL Limit: %d\n", s4data.ttl_limit);
    LogMessage("    Async Link: %d\n", s4data.asynchronous_link);
    LogMessage("    State Protection: %d\n", s4data.state_protection);
    LogMessage("    Self preservation threshold: %d\n", s4data.sp_threshold);
    LogMessage("    Self preservation period: %d\n", s4data.sp_period);
    LogMessage("    Suspend threshold: %d\n", s4data.suspend_threshold);
    LogMessage("    Suspend period: %d\n", s4data.suspend_period);
    LogMessage("    Enforce TCP State: %s %s\n",
            s4data.enforce_state ? "ACTIVE" : "INACTIVE",
            s4data.enforce_state & ENFORCE_STATE_DROP ? "and DROPPING" : " ");
    LogMessage("    Midstream Drop Alerts: %s\n",
            s4data.ms_inline_alerts ? "ACTIVE" : "INACTIVE");
    LogMessage("    Allow Blocking of TCP Sessions in Inline: %s\n",
            s4data.allow_session_blocking ? "ACTIVE" : "INACTIVE");
    if (s4data.server_inspect_limit > 0)
        LogMessage("    Server Data Inspection Limit: %d\n", 
                    s4data.server_inspect_limit);

}


/*
 * Function: ParseStream4Args(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 */
void ParseStream4Args(char *args)
{
    char **toks;
    int num_toks;
    int i;
    char *index;
    char **stoks = NULL;
    int s_toks;

    s4data.timeout = PRUNE_QUANTA;
    s4data.memcap = STREAM4_MEMORY_CAP;
    s4data.max_sessions = STREAM4_MAX_SESSIONS;
#ifdef STREAM4_UDP
    s4data.max_udp_sessions = STREAM4_MAX_SESSIONS;
    s4data.enable_udp_sessions = 0;
#endif
    s4data.cache_clean_sessions = STREAM4_CLEANUP;
    s4data.stateful_inspection_flag = 1;
    s4data.state_alerts = 0;
    s4data.evasion_alerts = 1;
    s4data.ps_alerts = 0;
    s4data.reassemble_client = s4data.reassemble_server = 0;
    s4data.log_flushed_streams = 0;
    s4data.min_ttl = 1;
    s4data.path_mtu = 1460;
    s4data.ttl_limit = STREAM4_TTL_LIMIT;
    s4data.asynchronous_link = 0;
    s4data.flush_data_diff_size = 500; 
    s4data.zero_flushed_packets = 0;
    s4data.flush_on_alert = 0;
    s4data.overlap_limit = -1;
    s4data.server_inspect_limit = -1;
    /* Default is to block session on inline drop */
    s4data.allow_session_blocking = 1;
    
    /* dynamic flush points */
    s4data.flush_behavior = FLUSH_BEHAVIOR_DEFAULT;
    s4data.flush_range = STREAM4_FLUSH_RANGE;
    s4data.flush_base = STREAM4_FLUSH_BASE;
    s4data.flush_seed = getpid() + time(NULL);

#ifdef STREAM4_UDP
    /* Ports on which to do UDP sessions.
     * Derived from rules that have "flow" keyword
     */
    //s4data.udp_ports[x] = UDP_SESSION;
#endif

    /* if no arguments, go ahead and return */
    if(args == NULL || args[0] == '\0')
    {
        DisplayStream4Config();
        return;
    }

    i=0;

    toks = mSplit(args, ",", 20, &num_toks, 0);
    
    while(i < num_toks)
    {
        index = toks[i];

        while(isspace((int)*index)) index++;

        stoks = mSplit(index, " ", 4, &s_toks, 0);

        if(!strcasecmp(stoks[0], "noinspect"))
        {
            s4data.stateful_inspection_flag = 0;
        }
        else if(!strcasecmp(stoks[0], "asynchronous_link"))
        {
            s4data.asynchronous_link = 1;
        }
        else if(!strcasecmp(stoks[0], "keepstats"))
        {
            s4data.track_stats_flag = STATS_HUMAN_READABLE;

            if(s_toks > 1)
            {
                if(!strcasecmp(stoks[1], "machine"))
                {
                    s4data.track_stats_flag = STATS_MACHINE_READABLE;
                }
                else if(!strcasecmp(stoks[1], "binary"))
                {
                    s4data.track_stats_flag = STATS_BINARY;
                    stats_log = (StatsLog *)SnortAlloc(sizeof(StatsLog));
                    stats_log->filename = strdup("snort-unified.stats");
                    OpenStatsFile();
                } 
                else
                {
                    ErrorMessage("Bad stats mode for stream4, ignoring\n");
                    s4data.track_stats_flag = 0;
                }
            }
        }
        else if(!strcasecmp(stoks[0], "detect_scans"))
        {
            s4data.ps_alerts = 1;
        }
        else if(!strcasecmp(stoks[0], "log_flushed_streams"))
        {
            s4data.log_flushed_streams = 1;
        }
        else if(!strcasecmp(stoks[0], "detect_state_problems"))
        {
            s4data.state_alerts = 1;
        }
        else if(!strcasecmp(stoks[0], "disable_evasion_alerts"))
        {
            s4data.evasion_alerts = 0;
        }
        else if(!strcasecmp(stoks[0], "timeout"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.timeout = atoi(stoks[1]);
            }
            else
            {
                LogMessage("WARNING %s(%d) => Bad timeout in config file, "
                           "defaulting to %d seconds\n", file_name, file_line, 
                           PRUNE_QUANTA);

                s4data.timeout = PRUNE_QUANTA;
            }
        }
        else if(!strcasecmp(stoks[0], "memcap"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.memcap = atoi(stoks[1]);

                if(s4data.memcap < 16384)
                {
                    LogMessage("WARNING %s(%d) => Ludicrous (<16k) memcap "
                               "size, setting to default (%d bytes)\n", file_name, 
                               file_line, STREAM4_MEMORY_CAP);
                    
                    s4data.memcap = STREAM4_MEMORY_CAP;
                }
            }
            else
            {
                FatalError("%s(%d) => Bad memcap in config file, %d\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "max_sessions"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.max_sessions = atoi(stoks[1]);

                if(s4data.max_sessions < 8192)
                {
                    LogMessage("WARNING %s(%d) => Ludicrous (<8k) max_sessions "
                               "size, setting to default (%d sessions)\n", file_name, 
                               file_line, STREAM4_MAX_SESSIONS);
                    
                    s4data.max_sessions = STREAM4_MAX_SESSIONS;
                }
            }
            else
            {
                FatalError("%s(%d) => Bad max_sessions in config file, %d\n",
                           file_name, file_line);
            }
        }
#ifdef STREAM4_UDP
        else if(!strcasecmp(stoks[0], "enable_udp_sessions"))
        {
            s4data.enable_udp_sessions = 1;
        }
        else if(!strcasecmp(stoks[0], "max_udp_sessions"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.max_udp_sessions = atoi(stoks[1]);

                if(s4data.max_udp_sessions < 8192)
                {
                    LogMessage("WARNING %s(%d) => Ludicrous (<8k) max_udp_sessions "
                               "size, setting to default (%d sessions)\n", file_name, 
                               file_line, STREAM4_MAX_SESSIONS);
                    
                    s4data.max_udp_sessions = STREAM4_MAX_SESSIONS;
                }
            }
            else
            {
                FatalError("%s(%d) => Bad max_udp_sessions in config file, %d\n",
                           file_name, file_line);
            }
        }
#if 0
        else if(!strcasecmp(stoks[0], "udp_ports"))
        {
            /* Unset the default ports */
            bzero(&s4data.udp_ports, sizeof(s4data.udp_ports));
            for (i=1;i<s_toks;i++)
            {
                char *endPtr;
                unsigned int value = strtoul(stoks[i], &endPtr, 10);
                u_int16_t port;

                if ((endPtr == stoks[i]) || (value == 0) || (value > 65535))
                {
                    LogMessage("WARNING %s(%d) => Invalid UDP port specified, "
                        "ignoring\n", file_name, file_line, stoks[i]);
                    continue;
                }

                port = (u_int16_t)value;
                s4data.udp_ports[port] |= UDP_SESSION | UDP_INSPECT;
            }
        }
#endif
        else if(!strcasecmp(stoks[0], "udp_ignore_any"))
        {
            s4data.udp_ignore_any = 1;
        }
#endif
        else if(!strcasecmp(stoks[0], "cache_clean_sessions"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.cache_clean_sessions = atoi(stoks[1]);
                if (s4data.cache_clean_sessions < 1)
                {
                    LogMessage("WARNING %s(%d) => Zero Session Cache Cleanup, "
                        "reverting to default of %d\n", 
                        file_name, file_line, STREAM4_CLEANUP);

                    s4data.cache_clean_sessions = STREAM4_CLEANUP;
                }
            }
            else
            {
                FatalError("%s(%d) => Bad cache cleanup value in "
                           "config file\n", file_name, file_line);

            }
        }
        else if(!strcasecmp(stoks[0], "ttl_limit"))
        {
            if(s_toks > 1)
            {
                if(stoks[1] == NULL || stoks[1][0] == '\0')
                {
                    FatalError("%s(%d) => ttl_limit requires an integer argument\n",
                            file_name,file_line);
                }
            
                if(isdigit((int)stoks[1][0]))
                {
                    s4data.ttl_limit = atoi(stoks[1]);
                }
                else
                {
                    LogMessage("WARNING %s(%d) => Bad TTL Limit"
                               "size, setting to default (%d\n", file_name, 
                               file_line, STREAM4_TTL_LIMIT);

                    s4data.ttl_limit = STREAM4_TTL_LIMIT;
                }
            }
            else
            {
                FatalError("%s(%d) => ttl_limit requires an integer argument\n",
                        file_name,file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "self_preservation_threshold"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.sp_threshold = atoi(stoks[1]);
            }
            else
            {
                LogMessage("WARNING %s(%d) => Bad sp_threshold in config file, "
                           "defaulting to %d new sessions/second\n", file_name, 
                           file_line, SELF_PRES_THRESHOLD);

                s4data.sp_threshold = SELF_PRES_THRESHOLD;
            }
        }
        else if(!strcasecmp(stoks[0], "self_preservation_period"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.sp_period = atoi(stoks[1]);
            }
            else            {
                LogMessage("WARNING %s(%d) => Bad sp_period in config file, "
                           "defaulting to %d seconds\n", file_name, file_line, 
                           SELF_PRES_PERIOD);

                s4data.sp_period = SELF_PRES_PERIOD;
            }
        }
        else if(!strcasecmp(stoks[0], "suspend_threshold"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.suspend_threshold = atoi(stoks[1]);
            }
            else
            {
                LogMessage("WARNING %s(%d) => Bad suspend_threshold in config "
                        "file, defaulting to %d new sessions/second\n", 
                        file_name, file_line, SUSPEND_THRESHOLD);

                s4data.suspend_threshold = SUSPEND_THRESHOLD;
            }
        }
        else if(!strcasecmp(stoks[0], "suspend_period"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.suspend_period = atoi(stoks[1]);
            }
            else
            {
                LogMessage("WARNING %s(%d) => Bad suspend_period in config file, "
                           "defaulting to %d seconds\n", file_name, file_line, 
                           SUSPEND_PERIOD);

                s4data.suspend_period = SUSPEND_PERIOD;
            }
        }
        else if(!strcasecmp(stoks[0], "enforce_state"))
        {
            s4data.enforce_state |= ENFORCE_STATE;
            if (s_toks > 1 && stoks[1])
            {
                if (!strcasecmp(stoks[1], "drop"))
                {
                    s4data.enforce_state |= ENFORCE_STATE_DROP;
                }
            }
        }
        else if(!strcasecmp(stoks[0], "midstream_drop_alerts"))
        {
            s4data.ms_inline_alerts = 1;
        }
        else if(!strcasecmp(stoks[0], "state_protection"))
        {
            s4data.state_protection = 1;
        }
        else if(!strcasecmp(stoks[0], "server_inspect_limit"))
        {
            if(isdigit((int)stoks[1][0]))
            {
                s4data.server_inspect_limit = atoi(stoks[1]);
            }
            else
            {
                FatalError("WARNING %s(%d) => Bad server_inspect_limit in "
                           "config file\n", file_name, file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "disable_session_blocking"))
        {
            s4data.allow_session_blocking = 0;
        }
        else
        {
            FatalError("%s(%d) => Unknown stream4: option: %s\n",
                       file_name, file_line, stoks[0]);
        }

        mSplitFree(&stoks, s_toks);

        i++;
    }

    mSplitFree(&toks, num_toks);

    DisplayStream4Config();
}

void Stream4InitExternalOptions(u_char *args)
{
    char **toks;
    int num_toks;
    int i=0;
    char *index;
    int got_favor = 0;
    int got_alert = 0;
    int got_overlap_limit = 0;
    int got_inspect_limit = 0;
    int got_max_sessions = 0;
    int got_zero_flushed = 0;
    int got_enforce_state = 0;
    int got_allow_session_blocking = 0;
#ifdef STREAM4_UDP
    int got_max_udp = 0;
    int got_udp_enable = 0;
    int got_udp_ignore_any = 0;
#endif
    char **stoks = NULL;
    int s_toks;
    toks = mSplit(args, ",", 12, &num_toks, 0);

    if ((s4data.reassemble_client == 0) &&
        (s4data.reassemble_server == 0))
    {
        FatalError("Please enable stream reassembly before specifying "
                   "external options for Stream4\n");
    }

    while(i < num_toks)
    {
        index = toks[i];
        while(isspace((int)*index)) index++;

        stoks = mSplit(index, " ", 2, &s_toks, 0);

        if(!strcasecmp(stoks[0], "favor_old"))
        {
            s4data.reassy_method = METHOD_FAVOR_OLD;
            got_favor = 1;
        }
        else if(!strcasecmp(stoks[0], "favor_new"))
        {
            s4data.reassy_method = METHOD_FAVOR_NEW;
            got_favor = 1;
        }
        else if(!strcasecmp(stoks[0], "flush_on_alert"))
        {
            s4data.flush_on_alert = 1;
            got_alert = 1;
        }
        else if(!strcasecmp(stoks[0], "enforce_state"))
        {
            s4data.enforce_state |= ENFORCE_STATE;
            if (s_toks > 1 && stoks[1])
            {
                if (!strcasecmp(stoks[1], "drop"))
                {
                    s4data.enforce_state |= ENFORCE_STATE_DROP;
                }
            }
            got_enforce_state = 1;
        }
        else if(!strcasecmp(stoks[0], "overlap_limit"))
        {
            if ((s_toks == 2) && stoks[1] && isdigit((int)stoks[1][0]))
            {
                s4data.overlap_limit = atoi(stoks[1]);
            }
            else
            {
                FatalError("WARNING %s(%d) => Bad cache cleanup value in "
                           "config file\n", file_name, file_line);
            }

            got_overlap_limit = 1;
        }
        else if(!strcasecmp(stoks[0], "server_inspect_limit"))
        {
            if ((s_toks == 2) && stoks[1] && isdigit((int)stoks[1][0]))
            {
                s4data.server_inspect_limit = atoi(stoks[1]);
            }
            else
            {
                FatalError("WARNING %s(%d) => Bad server_inspect_limit in "
                           "config file\n", file_name, file_line);
            }
            got_inspect_limit = 1;
        }
        else if(!strcasecmp(stoks[0], "max_sessions"))
        {
            if((s_toks == 2) && stoks[1] && isdigit((int)stoks[1][0]))
            {
                s4data.max_sessions = atoi(stoks[1]);

                if(s4data.max_sessions < 8192)
                {
                    LogMessage("WARNING %s(%d) => Ludicrous (<8k) max_sessions "
                               "size, setting to default (%d sessions)\n", file_name, 
                               file_line, STREAM4_MAX_SESSIONS);
                    
                    s4data.max_sessions = STREAM4_MAX_SESSIONS;
                }
            }
            else
            {
                FatalError("%s(%d) => Bad max_sessions in config file, %d\n",
                           file_name, file_line);
            }
            got_max_sessions = 1;
        }
        else if(!strcasecmp(index, "zero_flushed_packets"))
        {
            s4data.zero_flushed_packets = 1;
            got_zero_flushed = 1;
        }
        else if(!strcasecmp(stoks[0], "disable_session_blocking"))
        {
            s4data.allow_session_blocking = 0;
            got_allow_session_blocking = 1;
        }
#ifdef STREAM4_UDP
        else if(!strcasecmp(stoks[0], "enable_udp_sessions"))
        {
            s4data.enable_udp_sessions = 1;
            got_udp_enable = 1;
        }
        else if(!strcasecmp(stoks[0], "max_udp_sessions"))
        {
            if((s_toks == 2) && stoks[1] && isdigit((int)stoks[1][0]))
            {
                s4data.max_udp_sessions = atoi(stoks[1]);

                if(s4data.max_udp_sessions < 8192)
                {
                    LogMessage("WARNING %s(%d) => Ludicrous (<8k) max_udp_sessions "
                               "size, setting to default (%d sessions)\n", file_name, 
                               file_line, STREAM4_MAX_SESSIONS);
                    
                    s4data.max_udp_sessions = STREAM4_MAX_SESSIONS;
                    got_max_udp = 1;
                }
            }
            else
            {
                FatalError("%s(%d) => Bad max_udp_sessions in config file, %d\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp(stoks[0], "udp_ignore_any"))
        {
            s4data.udp_ignore_any = 1;
            got_udp_ignore_any = 1;
        }
#endif
        else
        {
            FatalError("%s(%d) => Bad stream4_external option "
                       "specified: \"%s\"\n", file_name, file_line, toks[i]);
        }
        mSplitFree(&stoks, s_toks);
        i++;
    }
    LogMessage("stream4_external config (overrides values from "
               "stream4 & stream4_reassemble configs):\n");
    if (got_favor)
        LogMessage("    Reassembler Packet Preferance : %s\n", 
                   s4data.reassy_method == METHOD_FAVOR_NEW ?
                   "Favor New" : "Favor Old");
    if (got_alert)
        LogMessage("    Flush stream on alert: %s\n", 
                   s4data.flush_on_alert ? "ACTIVE": "INACTIVE");

    if (got_overlap_limit)
        LogMessage("    Packet Sequence Overlap Limit: %d\n", 
                   s4data.overlap_limit);

    if (got_inspect_limit)
        LogMessage("    Server Data Scan Threshold: %d\n", 
                   s4data.server_inspect_limit);

    if (got_max_sessions)
        LogMessage("    Session count max: %d sessions\n", (unsigned long)s4data.max_sessions);

    if (got_zero_flushed)
        LogMessage("    Zero out flushed packets: %s\n", 
               s4data.zero_flushed_packets ? "ACTIVE": "INACTIVE");

    if (got_enforce_state)
        LogMessage("    Enforce TCP State: %s\n",
            s4data.enforce_state ? "ACTIVE" : "INACTIVE",
            s4data.enforce_state & ENFORCE_STATE_DROP ? "and DROPPING" : " ");

    if (got_allow_session_blocking)
        LogMessage("    Allow Blocking of TCP Sessions in Inline: %s\n",
            s4data.allow_session_blocking ? "ACTIVE" : "INACTIVE");

#ifdef STREAM4_UDP
    if (got_udp_enable)
    {
        LogMessage("    UDP Tracking Enabled: %s\n",
                s4data.enable_udp_sessions ? "YES" : "NO");

        if (got_max_udp)
            LogMessage("    UDP Session count max: %d sessions\n",
                    (unsigned long)s4data.max_udp_sessions);

        if (got_udp_ignore_any)
            LogMessage("    UDP Ignore Traffic on port without port-specific rules: %s\n",
                s4data.udp_ignore_any ? "YES" : "NO");
    }
#endif
    
    mSplitFree(&toks, num_toks);
}

void Stream4InitReassembler(u_char *args)
{
    char buf[STD_BUF+1];
    char **toks = NULL;
    char **stoks = NULL;
    int num_toks = 0;
    int num_args;
    int i;
    int j = 0;
    char *index;
    char *value;

    if(s4data.stream4_active == 0)
    {
        FatalError("Please activate stream4 before trying to "
                   "activate stream4_reassemble\n");
    }

    s4data.reassembly_alerts = 1;
    s4data.reassemble_client = 1; 
    s4data.reassemble_server = 0;
    s4data.flush_on_alert = 0;
    s4data.assemble_ports[21] = 1;
    s4data.assemble_ports[23] = 1;
    s4data.assemble_ports[25] = 1;
    s4data.assemble_ports[42] = 1;
    s4data.assemble_ports[53] = 1;
    s4data.assemble_ports[80] = 1;
    s4data.assemble_ports[110] = 1;
    s4data.assemble_ports[111] = 1;
    s4data.assemble_ports[135] = 1;
    s4data.assemble_ports[136] = 1;
    s4data.assemble_ports[137] = 1;
    s4data.assemble_ports[139] = 1;
    s4data.assemble_ports[143] = 1;
    s4data.assemble_ports[445] = 1;
    s4data.assemble_ports[513] = 1;
    s4data.assemble_ports[1433] = 1;
    s4data.assemble_ports[1521] = 1;
    s4data.assemble_ports[3306] = 1;
    s4data.reassy_method = METHOD_FAVOR_OLD;

    /* setup for self preservaton... */
    s4data.emergency_ports[21] = 1;
    s4data.emergency_ports[23] = 1;
    s4data.emergency_ports[25] = 1;
    s4data.emergency_ports[42] = 1;
    s4data.emergency_ports[53] = 1;
    s4data.emergency_ports[80] = 1;
    s4data.emergency_ports[110] = 1;
    s4data.emergency_ports[111] = 1;
    s4data.emergency_ports[135] = 1;
    s4data.emergency_ports[136] = 1;
    s4data.emergency_ports[137] = 1;
    s4data.emergency_ports[139] = 1;
    s4data.emergency_ports[143] = 1;
    s4data.emergency_ports[445] = 1;
    s4data.emergency_ports[513] = 1;
    s4data.emergency_ports[1433] = 1;
    s4data.emergency_ports[1521] = 1;
    s4data.emergency_ports[3306] = 1;
   
    if (args != NULL) 
    {
        toks = mSplit(args, ",", 12, &num_toks, 0);
    }

    i=0;

    while(i < num_toks)
    {
        index = toks[i];
        while(isspace((int)*index)) index++;

        if(!strncasecmp(index, "clientonly", 10))
        {
            s4data.reassemble_client = 1;
            s4data.reassemble_server = 0;
        }
        else if(!strncasecmp(index, "serveronly", 10))
        {
            s4data.reassemble_server = 1;
            s4data.reassemble_client = 0;
        }
        else if(!strncasecmp(index, "both", 4))
        {
            s4data.reassemble_client = 1;
            s4data.reassemble_server = 1;
        }
        else if(!strncasecmp(index, "noalerts", 8))
        {
            s4data.reassembly_alerts = 0;
        }
        else if(!strncasecmp(index, "favor_old", 9))
        {
            s4data.reassy_method = METHOD_FAVOR_OLD;
        }
        else if(!strncasecmp(index, "favor_new", 9))
        {
            s4data.reassy_method = METHOD_FAVOR_NEW;
        }
        else if(!strncasecmp(index, "flush_on_alert", 9))
        {
            s4data.flush_on_alert = 1;
        }
        else if(!strncasecmp(index, "overlap_limit", 9))
        {
            stoks = mSplit(index, " ", 2, &num_args, 0);
            value = stoks[1];
            if((num_args == 2) && (isdigit((int)value[0])))
            {
                s4data.overlap_limit = atoi(value);
            }
            else
            {
                FatalError("%s(%d) => Bad overlap_limit value in "
                           "config file\n", file_name, file_line);
            }
            mSplitFree(&stoks, num_args);
        }
        else if(!strncasecmp(index, "flush_behavior", 14))
        {
            stoks = mSplit(index, " ", 2, &num_args, 0);
            value = stoks[1];
            if(num_args != 2)
            {
                FatalError("%s(%d) => Bad flush_behavior value in "
                           "config file\n", file_name, file_line);
            }
            if (!strncasecmp(value, "default", 7))
            {
                s4data.flush_behavior = FLUSH_BEHAVIOR_DEFAULT;
            }
            else if (!strncasecmp(value, "random", 6))
            {
                s4data.flush_behavior = FLUSH_BEHAVIOR_RANDOM;
            }
            else if (!strncasecmp(value, "large_window", 12))
            {
                s4data.flush_behavior = FLUSH_BEHAVIOR_LARGE;
            }
            else
            {
                FatalError("%s(%d) => Invalid flush_behavior value (%s) in "
                           "config file\n", file_name, file_line, value);
            }

            mSplitFree(&stoks, num_args);
        }
        else if(!strncasecmp(index, "flush_seed", 10))
        {
            stoks = mSplit(index, " ", 2, &num_args, 0);
            value = stoks[1];
            if((num_args == 2) && (isdigit((int)value[0])))
            {
                s4data.flush_seed = atoi(value) + time(NULL);
            }
            else
            {
                FatalError("%s(%d) => Unsupported flush_seed value in "
                           "config file\n", file_name, file_line);
            }
            mSplitFree(&stoks, num_args);
        }
        else if(!strncasecmp(index, "flush_base", 10))
        {
            stoks = mSplit(index, " ", 2, &num_args, 0);
            value = stoks[1];
            if((num_args == 2) && (isdigit((int)value[0])))
            {
                s4data.flush_base = atoi(value);
            }
            else
            {
                FatalError("%s(%d) => Bad flush_base value in "
                           "config file\n", file_name, file_line);
            }
            mSplitFree(&stoks, num_args);

            if((s4data.flush_base < 1) || (s4data.flush_base > 32768))
            {
                FatalError("%s(%d) => Unsupported flush_base value (%d bytes) in "
                           "config file\n", 
                           file_name, file_line, s4data.flush_base);
            }
        }
        else if(!strncasecmp(index, "flush_range", 11))
        {
            stoks = mSplit(index, " ", 2, &num_args, 0);
            value = stoks[1];
            if((num_args == 2) && (isdigit((int)value[0])))
            {
                s4data.flush_range = atoi(value);
            }
            else
            {
                FatalError("%s(%d) => Bad flush_range in config file\n",
                           file_name, file_line);
            }
            mSplitFree(&stoks, num_args);

            if((s4data.flush_range < 512) || (s4data.flush_range > 32767))
            {
                FatalError("%s(%d) => Unsupported flush_range value "
                           "(%d bytes) in config file\n",
                           file_name, file_line, s4data.flush_range);
            }
        }
        else if(!strncasecmp(index, "ports", 5))
        {
            char **ports;
            int num_ports;
            char *port;
            int j = 0;
            u_int32_t portnum;

            for(j = 0;j<65535;j++)
            {
                s4data.assemble_ports[j] = 0;
            }

            ports = mSplit(index, " ", 40, &num_ports, 0);

            j = 1;

            while(j < num_ports)
            {
                port = ports[j];

                if(isdigit((int)port[0]))
                {
                    portnum = atoi(port);

                    if(portnum > 65535)
                    {
                        FatalError("%s(%d) => Bad port list to "
                                   "reassembler\n", file_name, file_line);
                    }

                    s4data.assemble_ports[portnum] = 1;
                }
                else if(!strncasecmp(port, "all", 3))
                {
                    memset(&s4data.assemble_ports, 1, 65536);
                }
                else if(!strncasecmp(port, "default", 7))
                {
                    s4data.assemble_ports[21] = 1;
                    s4data.assemble_ports[23] = 1;
                    s4data.assemble_ports[25] = 1;
                    s4data.assemble_ports[42] = 1;
                    s4data.assemble_ports[53] = 1;
                    s4data.assemble_ports[80] = 1;
                    s4data.assemble_ports[110] = 1;
                    s4data.assemble_ports[111] = 1;
                    s4data.assemble_ports[135] = 1;
                    s4data.assemble_ports[136] = 1;
                    s4data.assemble_ports[137] = 1;
                    s4data.assemble_ports[139] = 1;
                    s4data.assemble_ports[143] = 1;
                    s4data.assemble_ports[445] = 1;
                    s4data.assemble_ports[513] = 1;
                    s4data.assemble_ports[1433] = 1;
                    s4data.assemble_ports[1521] = 1;
                    s4data.assemble_ports[3306] = 1;
                }

                j++;
            }

            mSplitFree(&ports, num_ports);
        }
        else if(!strncasecmp(index, "emergency_ports", 15))
        {
            char **ports;
            int num_ports;
            char *port;
            int j = 0;
            u_int32_t portnum;

            for(j = 0;j<65535;j++)
            {
                s4data.emergency_ports[j] = 0;
            }

            ports = mSplit(args, " ", 40, &num_ports, 0);

            j = 0;

            while(j < num_ports)
            {
                port = ports[j];

                if(isdigit((int)port[0]))
                {
                    portnum = atoi(port);

                    if(portnum > 65535)
                    {
                        FatalError("%s(%d) => Bad port list to "
                                   "reassembler\n", file_name, file_line);
                    }

                    s4data.emergency_ports[portnum] = 1;
                }
                else if(!strncasecmp(port, "all", 3))
                {
                    memset(&s4data.emergency_ports, 1, 65536);
                }
                else if(!strncasecmp(port, "default", 7))
                {
                    s4data.emergency_ports[21] = 1;
                    s4data.emergency_ports[23] = 1;
                    s4data.emergency_ports[25] = 1;
                    s4data.emergency_ports[42] = 1;
                    s4data.emergency_ports[53] = 1;
                    s4data.emergency_ports[80] = 1;
                    s4data.emergency_ports[110] = 1;
                    s4data.emergency_ports[111] = 1;
                    s4data.emergency_ports[135] = 1;
                    s4data.emergency_ports[136] = 1;
                    s4data.emergency_ports[137] = 1;
                    s4data.emergency_ports[139] = 1;
                    s4data.emergency_ports[143] = 1;
                    s4data.emergency_ports[445] = 1;
                    s4data.emergency_ports[513] = 1;
                    s4data.emergency_ports[1433] = 1;
                    s4data.emergency_ports[1521] = 1;
                    s4data.emergency_ports[3306] = 1;
                }

                j++;
            }

            mSplitFree(&ports, num_ports);
        }
        else if(!strcasecmp(index, "zero_flushed_packets"))
        {
            s4data.zero_flushed_packets = 1;
        }
        else if(!strncasecmp(index, "flush_data_diff_size", 
                    strlen("flush_data_diff_size")))
        {
            /* using strncasecmp since it will be flush_data_diff_size <int> */
            char *number_str;
            number_str = strrchr(index,' '); /* find the last ' ' */

            if(number_str && *number_str != '\0')
            {
                number_str++; 
            }

            if(number_str && *number_str != '\0' && (isdigit((int)*number_str)))
            {
                s4data.flush_data_diff_size = atoi(number_str);
                
                if(s4data.flush_data_diff_size < 0)
                {
                    FatalError("%s(%d) => Bad flush_data_diff_size in "
                            "config file\n", file_name, file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => Bad flush_data_diff_size in config file\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp(index, "large_packet_performance"))
        {
            s4data.large_packet_performance = 1;
        }
        else
        {
            FatalError("%s(%d) => Bad stream4_reassemble option "
                       "specified: \"%s\"\n", file_name, file_line, toks[i]);
        }

        i++;
    }

    if (num_toks)
        mSplitFree(&toks, num_toks);

    /* Setup flushpoints, per config */
    if ( s4data.flush_behavior == FLUSH_BEHAVIOR_LARGE )
    {
        /* Default, larger static flushpoints */
        int elm;
        for( elm = 0; elm < FCOUNT; elm += 1 )
        {
            flush_points[elm] = new_flush_points[elm];
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Setting new static "
                      "flush value of (%d bytes) at index %d\n",
                      flush_points[elm],elm););

        }
        LogMessage("WARNING %s(%d) => flush_behavior set in "
                   "config file, using new static flushpoints (%d)\n",
                   file_name, file_line, s4data.flush_behavior);

    }
    else if ( s4data.flush_behavior == FLUSH_BEHAVIOR_RANDOM )
    {
        /* set up random flush points */
        int elm;
        int rfp;
        srand(s4data.flush_seed);
        for( elm = 0; elm < FCOUNT; elm += 1 )
        {
            rfp = rand() % s4data.flush_range;
            flush_points[elm] = rfp + s4data.flush_base;
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Setting random "
                    "flush value of (%d bytes) at index %d\n",
                    flush_points[elm],elm););
        }
    }
    else
    {
        /* Use the old flushpoints -- default behavior */
        int elm;
        for( elm = 0; elm < FCOUNT; elm += 1 )
        {
            flush_points[elm] = old_flush_points[elm];
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Setting old static "
                       "flush value of %d bytes) at index %d\n",
                       flush_points[elm],elm););
        }
        LogMessage("WARNING %s(%d) => flush_behavior set in "
                   "config file, using old static flushpoints (%d)\n",
                   file_name, file_line, s4data.flush_behavior);
    }

    LogMessage("Stream4_reassemble config:\n");
    LogMessage("    Server reassembly: %s\n", 
               s4data.reassemble_server ? "ACTIVE": "INACTIVE");
    LogMessage("    Client reassembly: %s\n", 
               s4data.reassemble_client ? "ACTIVE": "INACTIVE");
    LogMessage("    Reassembler alerts: %s\n", 
               s4data.reassembly_alerts ? "ACTIVE": "INACTIVE");
    LogMessage("    Zero out flushed packets: %s\n", 
               s4data.zero_flushed_packets ? "ACTIVE": "INACTIVE");
    LogMessage("    Flush stream on alert: %s\n", 
               s4data.flush_on_alert ? "ACTIVE": "INACTIVE");
    LogMessage("    flush_data_diff_size: %d\n", 
               s4data.flush_data_diff_size);
    LogMessage("    Reassembler Packet Preferance : %s\n", 
               s4data.reassy_method == METHOD_FAVOR_NEW ?
               "Favor New" : "Favor Old");
    LogMessage("    Packet Sequence Overlap Limit: %d\n", 
               s4data.overlap_limit);
    LogMessage("    Flush behavior: %s\n", 
               s4data.flush_behavior == FLUSH_BEHAVIOR_DEFAULT ? "Small (<255 bytes)":
                (s4data.flush_behavior == FLUSH_BEHAVIOR_LARGE ? "Large (<2550 bytes)" :
                "random"));
    if (s4data.flush_behavior == FLUSH_BEHAVIOR_RANDOM)
    {
        LogMessage("    Flush base: %d\n", s4data.flush_base);
        LogMessage("    Flush seed: %d\n", s4data.flush_seed);
        LogMessage("    Flush range: %d\n", s4data.flush_range);
    }

    memset(buf, 0, STD_BUF+1);
    snprintf(buf, STD_BUF, "    Ports: ");       

    for(i=0;i<65536;i++)
    {
        if(s4data.assemble_ports[i])
        {
            sfsnprintfappend(buf, STD_BUF, "%d ", i);
            j++;
        }

        if(j > 20)
        { 
            LogMessage("%s...\n", buf);
            return;
        }
    }

    LogMessage("%s\n", buf);
    memset(buf, 0, STD_BUF+1);
    snprintf(buf, STD_BUF, "    Emergency Ports: "); 
    j=0;

    for(i=0;i<65536;i++)
    {
        if(s4data.emergency_ports[i])
        {
            sfsnprintfappend(buf, STD_BUF, "%d ", i);
            j++;
        }

        if(j > 20)
        { 
            LogMessage("%s...\n", buf);
            return;
        }
    }

    LogMessage("%s\n", buf);

    return;
}

/**
 * Check a FIN is valid within the window
 *
 * @param s stream to set the next_seq on 
 * @param direction direction of the packet
 * @param pkt_seq sequence number for the packet
 * @param p packet to grab the session from
 * 
 * @return 0 if everything went ok
 */
static INLINE int CheckFin(Stream *s, int direction, u_int32_t pkt_seq, Packet *p)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "CheckFin() called for %s\n",
                            direction ? "FROM_CLIENT":"FROM_SERVER"););

    /* If not tracking state ignore it */
    if( !s4data.stateful_inspection_flag )
        return 0;

    /*
     *  We want to make sure the FIN has the next valid sequence that 
     *  this side should be sending 
     *  If the pkt_seq < next_seq it's essentially a duplicate 
     *  sequence, and is probably going to be discarded, it certainly 
     *  should be. Also, the base sequence includes the SYN sequence count.
     *  If the packet seq is after the next seq than we should queue the 
     *  packet for later, in case an out of order packet arrives. We 
     *  should also honor the FIN-ACK requirements.
     *
     *  Ignoring a FIN implies we won't shutdown this session due to it.
     *  
     *  This is a standard TCP/IP stack 'in the window' check, but it's 
     *  not always the way stacks handle FIN's:
     *  
     *  if(SEQ_LT(pkt_seq,s->base_seq+s->bytes_tracked) || 
     *     SEQ_GEQ(pkt_seq,(s->last_ack+s->win_size))) 
     *  
     */
    if(SEQ_LT(pkt_seq,s->base_seq+s->bytes_tracked) || 
       SEQ_GEQ(pkt_seq,(s->last_ack+s->win_size))) 
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "Bad FIN packet, bad sequence!\n"
                    "pkt seq: 0x%X   last_ack: 0x%X  win: 0x%X\n",
                    pkt_seq, s->last_ack, s->win_size););

        /* we should probably alert here */
        if(s4data.evasion_alerts)
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_EVASIVE_FIN, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_EVASIVE_FIN_STR, /* msg string */
                    0);
        }
        return 1;
    }
    return 0;
}


/** 
 * Set that this side of the session has sent a fin.
 *
 * This overloads the next_seq variable to also be used to tell how
 * far forward we can acknowledge data.
 * 
 * @param s stream to set the next_seq on 
 * @param direction direction of the packet
 * @param pkt_seq sequence number for the packet
 * @param p packet to grab the session from
 * 
 * @return 0 if everything went ok
 */
static INLINE int SetFinSent(Session *ssn, int direction, u_int32_t pkt_seq, Packet *p)
{
    Stream *stream;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "SetFinSet() called for %s\n",
                            direction ? "FROM_CLIENT":"FROM_SERVER"););

    /* If not tracking state ignore it */
    if( !s4data.stateful_inspection_flag )
        return 0;

    if(direction == FROM_SERVER)
    {        
        stream = &ssn->server;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"--RST From Server!\n"););
    }
    else
    {        
        stream = &ssn->client;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"--RST From Client!\n"););
    }

    if (CheckFin(stream, direction, pkt_seq, p))
    {
        return 0;
    }

    if(direction == FROM_SERVER)
    {
        ssn->session_flags |= SSNFLAG_SERVER_FIN;
    }
    else
    {
        ssn->session_flags |= SSNFLAG_CLIENT_FIN;
    }
    
    stream->next_seq = ntohl(p->tcph->th_seq);

    return 0;
}

/** 
 * See if we can get ignore this packet
 *
 * The Emergency Status stuff is taken care of here.
 * 
 * @param p Packet
 * 
 * @return 1 if this packet isn't destined to be processeed, 0 otherwise
 */
static INLINE int NotForStream4(Packet *p)
{
    if(!p) 
    {
        return 1;
    }
    
    if(p->tcph == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "p->tcph is null, returning\n"););
        return 1;
    }
    
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "REBUILT_STREAM returning\n"););
        return 1;
    }

    if(s4_emergency.status != OPS_NORMAL)
    {
        /* Check to see if we should return to our non-emergency mode.
         * If we happen to stay in SUSPSEND mode, exit out
         */

        if(p->pkth->ts.tv_sec >= s4_emergency.end_time)
        {
            s4_emergency.status = OPS_NORMAL;
            s4_emergency.end_time = 0;
            s4_emergency.new_session_count = 0;
            s4data.reassembly_alerts = s4_emergency.old_reassembly_alerts;
            s4data.reassemble_client = s4_emergency.old_reassemble_client; 
            s4data.reassemble_server = s4_emergency.old_reassemble_server;
            pv.assurance_mode = s4_emergency.old_assurance_mode;
            pv.stateful = s4_emergency.old_stateful_mode;
        }

        if(s4_emergency.status == OPS_SUSPEND)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "OPS_SUSPEND returning\n"););
            return 1;
        }
    }
    
    /* don't accept packets w/ bad checksums */
    if(p->csum_flags & CSE_IP || p->csum_flags & CSE_TCP)
    {
        DEBUG_WRAP(
                   u_int8_t c1 = (p->csum_flags & CSE_IP);
                   u_int8_t c2 = (p->csum_flags & CSE_TCP);
                   DebugMessage(DEBUG_STREAM, "IP CHKSUM: %d, CSE_TCP: %d",
                                c1,c2);
                   DebugMessage(DEBUG_STREAM, "Bad checksum returning\n");
                   );
        
        p->packet_flags |= PKT_STREAM_UNEST_UNI;
        return 1;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Packet is for stream4...\n"););
    return 0;
}

/** 
 * Subtract from the byte counters for the stream session
 * 
 * @param stream Stream to adjust the byte counters on
 * @param sub amount to subtract from the byte_counters
 */
static INLINE void StreamSegmentSub(Stream *stream, u_int16_t sub)
{
    /* don't allow us to overflow */
#ifdef _DEBUG_SEGMENTS
    DebugMessage(DEBUG_STREAM, "[sss] %u -> %u (mem: %u)\n,",
            stream->bytes_tracked,
            stream->bytes_tracked - sub,
            stream4_memory_usage);
#endif /* DEBUG_SEGMENTS */

    if((stream->bytes_tracked - (u_int32_t)sub) > stream->bytes_tracked)
    {
        stream->bytes_tracked = 0;
    }
    else
    {
        stream->bytes_tracked -= (u_int32_t)sub;
    }

}


/** 
 * Add to the byte counters for the stream session
 * 
 * @param stream Stream to adjust the byte counters on
 * @param add amount to add to the byte_counters
 */
static INLINE void StreamSegmentAdd(Stream *stream, u_int16_t add)
{
    /* don't allow us to overflow */
#ifdef _DEBUG_SEGMENTS
    DebugMessage(DEBUG_STREAM, "[ssa] %u -> %u (mem: %u)\n,",
            stream->bytes_tracked,
            stream->bytes_tracked + add,
            stream4_memory_usage);
#endif /* _DEBUG_SEGMENTS */

    /* don't allow us to overflow */
    if((stream->bytes_tracked + (u_int32_t)add) < stream->bytes_tracked)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"[E] How'd we get this high?\n"););
        return;
    }
    else
    {
        stream->bytes_tracked += (u_int32_t)add;
        stream->bytes_sent += (u_int32_t)add;
        stream->pkts_sent++;
    }

}



/** 
 * Make sure that we do not log
 * 
 * @param p Packet to evaluate
 * @param stream Stream to compare against
 * 
 * @return 1 if we are within established limits, 0 otherwise.
 */
static INLINE int WithinSessionLimits(Packet *p, Stream *stream)
{
    u_int32_t limit; 

    return 1;
    /* use a different limit if the session was picked up midstream
     * rather than having a full 3whs */

    if(((Session *)(p->ssnptr))->session_flags & SSNFLAG_MIDSTREAM)
    {
        limit = 5000;
    }
    else
    {
        limit = (MAX_STREAM_SIZE + 5000);
    }

    if((stream->bytes_tracked + p->dsize) >= limit)
    {
        /* Go ahead and remove these statistics since we're not going to
         * store the packet
         */
        StreamSegmentSub(stream, p->dsize);
        return 0;
    }

    return 1;
}

/**
 * Prune The state machine if we need to
 *
 * Also updates all variables related to pruning that only have to
 * happen at initialization
 *
 * For want of packet time at plugin initialization. (It only happens once.)
 * It wood be nice to get the first packet and do a little extra before
 * getting into the main snort processing loop.
 *   -- cpw
 * 
 * @param p Packet ptr
 */
static INLINE void PruneCheck(Packet *p)
{
    PROFILE_VARS;

    if (!s4data.last_prune_time)
    {
        s4data.last_prune_time = p->pkth->ts.tv_sec;
        return;
    }

    if( (u_int)(p->pkth->ts.tv_sec) > s4data.last_prune_time + s4data.timeout)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Prune time quanta exceeded, pruning "
                    "stream cache\n"););

        sfPerf.sfBase.iStreamTimeouts++;

        PREPROC_PROFILE_START(stream4PrunePerfStats);

        PruneSessionCache(IPPROTO_TCP, p->pkth->ts.tv_sec, 0, NULL);
        PREPROC_PROFILE_END(stream4PrunePerfStats);
        s4data.last_prune_time = p->pkth->ts.tv_sec;

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Pruned for timeouts, %lu sessions "
                    "active, %lu bytes " "in use\n", 
                    (unsigned long int) GetSessionCount(p), stream4_memory_usage);
                DebugMessage(DEBUG_STREAM, "Stream4 memory cap hit %lu times\n", 
                    safe_alloc_faults););
    }
}

void enforceStateCheckNoSession(Packet *p)
{
        /*
        **  We treat IDS and IPS mode differently, because in IDS mode
        **  we are just monitoring so we pick up all legitimate traffic
        **  connections, which in this case (thanks to linux) is any
        **  flag combination (except RST) is valid as an initiator as
        **  long as the SYN flag is included.
        **
        **  In InlineMode, we WILL enforce the correct flag combinations
        **  or else we'll drop it.
        */
        if(!InlineMode())
        {
            if((p->tcph->th_flags & (TH_SYN|TH_RST)) != TH_SYN)
            {
                DisableDetect(p);

                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "No session, not a synner\n"););
                return;
            }
        }
        else
        {
            /*
            **  We're in inline mode
            */
            if((p->tcph->th_flags & (TH_SYN|TH_ACK|TH_PUSH|TH_FIN|TH_RST)) 
                    != TH_SYN)
            {
                DisableDetect(p);

                if (s4data.enforce_state & ENFORCE_STATE_DROP)
                {
                    InlineDrop(p);
            
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "No Session, not a synner, drop it\n"););
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "No Session, not a synner, pass it\n"););
                }

                return;
            }
        }
}

void enforceStateCheckSession(Session *ssn, Packet *p)
{
    /* If session isn't established... 
     * session_flags don't include ESTABLISHED AND
     * client and server states aren't set to ESTABLISHED
     */
    if (!(ssn->session_flags & SSNFLAG_ESTABLISHED) &&
         (ssn->client.state < ESTABLISHED) &&
         (ssn->server.state < ESTABLISHED))
    {
        /* ... and this isn't a SYN packet */
        if (!(p->tcph->th_flags & TH_SYN))
        {
            DisableDetect(p);

            if (InlineMode())
            {
                if (s4data.enforce_state & ENFORCE_STATE_DROP)
                {
                    InlineDrop(p);
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "Not established, not a synner, drop it\n"););
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "Not established, not a synner, pass it\n"););
                }
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "Not established, not a synner\n"););
            }
        }
    }

    return;
}

/*
 * Function: PreprocFunction(Packet *)
 *
 * Purpose: Perform the preprocessor's intended function.  This can be
 *          simple (statistics collection) or complex (IP defragmentation)
 *          as you like.  Try not to destroy the performance of the whole
 *          system by trying to do too much....
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 */
void ReassembleStream4(Packet *p, void *context)
{
    Session *ssn = NULL;
    int action;
    int reassemble = 0;
    u_int32_t pkt_seq;
    u_int32_t pkt_ack;
    int direction;
    static int alert_once_emerg   = 0;
    static int alert_once_suspend = 0;
    char ignore;
#ifdef DEBUG
    static int pcount = 0;
    char flagbuf[9];
#endif
    PROFILE_VARS;

#ifdef DEBUG
    pcount++;

    DebugMessage(DEBUG_STREAM, "pcount stream packet %d\n",pcount);
#endif

    if(NotForStream4(p))
    {
#ifdef STREAM4_UDP
        /* Process this is if its a UDP Packet -- since we now want
         * to handle those. */
        Stream4ProcessUdp(p);
#endif
        return;
    } 

    pc.tcp_stream_pkts++;

    reassemble = CheckPorts(p->sp, p->dp);

    /* if we're not doing stateful inspection... */
    if(s4data.stateful_inspection_flag == 0 && !reassemble)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "No stateful inspection on this port, returning"););
        return;
    }

    DEBUG_WRAP(
            CreateTCPFlagString(p, flagbuf);
            DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE), 
                "Got Packet 0x%X:%d ->  0x%X:%d %s\nseq: 0x%X   ack:0x%X\n",
                p->iph->ip_src.s_addr,
                p->sp,
                p->iph->ip_dst.s_addr,
                p->dp,
                flagbuf,
                ntohl(p->tcph->th_seq), ntohl(p->tcph->th_ack));
            );

    PREPROC_PROFILE_START(stream4PerfStats);

    pkt_seq = ntohl(p->tcph->th_seq);
    pkt_ack = ntohl(p->tcph->th_ack);

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"pkt_seq: %u, pkt_ack: %u\n", 
                pkt_seq, pkt_ack););

    /* see if we have a stream for this packet */
    ssn = GetSession(p);
    
    /*
    **  Let's leave this out for now until we figure out if we're going
    **  to make the rule language handle this type of policy (a.k.a
    **  not_established).
    */
    if(!ssn && s4data.enforce_state)
    {
        enforceStateCheckNoSession(p);
        if (do_detect_content == 0)
        {
            PREPROC_PROFILE_END(stream4PerfStats);
            return;
        }
    }

    if(ssn == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Calling CreateNewSession()\n"););

        p->packet_flags |= PKT_FROM_CLIENT;

        /*
         * If we are in "emergency mode", we become much more picky
         * about what we will accept as a session initiator.  Since
         * our goal is to regain 0 packet loss, we move to only accept
         * new sessions that begin with a SYN flag.  Note that we do
         * ignore the reserved bits on a session initiator as required
         * by ECN. --cmg
         */
        if((s4_emergency.status == OPS_NORMAL) ||
                ((p->tcph->th_flags & TH_NORESERVED) == TH_SYN))
        {
            ssn = CreateNewSession(p, pkt_seq, pkt_ack);

            if(ssn != NULL && ((p->tcph->th_flags & TH_NORESERVED) != TH_SYN))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "Picking up session midstream\n"););

                ssn->session_flags |= SSNFLAG_MIDSTREAM;
            }


            /* 
             * keep track of how many sessions per second we're creating 
             * vs. the number of data packets per second we get on 
             * those sessions
             */
            if(s4data.state_protection)
                ++s4_emergency.new_session_count;

            /* perfstats */
            if(ssn != NULL)
            {
                AddStreamSession(&sfPerf.sfBase);
            }
        } 
        else 
        {
            ssn = NULL;
        }

        if(s4data.state_protection)
        {
            if(s4_emergency.new_session_count >= s4data.suspend_threshold)
            {
                s4_emergency.status = OPS_SUSPEND;
                s4_emergency.end_time = p->pkth->ts.tv_sec + s4data.suspend_period;            
                pv.assurance_mode = ASSURE_ALL;
                pv.stateful = 0;

                if(alert_once_suspend == 0)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4,
                            STREAM4_SUSPEND,
                            1,
                            0,
                            3,
                            STREAM4_SUSPEND_STR,
                            0);

                    alert_once_suspend = 1;
                }
            }
            else if(s4_emergency.new_session_count >= s4data.sp_threshold)
            {
                s4_emergency.status = OPS_SELF_PRESERVATION;
                s4_emergency.end_time = p->pkth->ts.tv_sec + s4data.sp_period;
                s4_emergency.old_reassembly_alerts = s4data.reassembly_alerts;
                s4_emergency.old_reassemble_client = s4data.reassemble_client; 
                s4_emergency.old_reassemble_server = s4data.reassemble_server;
                s4_emergency.old_assurance_mode = pv.assurance_mode;
                s4_emergency.old_stateful_mode = pv.stateful;

                if(alert_once_emerg == 0)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4,
                            STREAM4_EMERGENCY,
                            1,
                            0,
                            3,
                            STREAM4_EMERGENCY_STR,
                            0);
                    
                    alert_once_emerg = 1;
                }
            }
        }

        p->packet_flags = PKT_STREAM_UNEST_UNI;

        if(ssn == NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"NULL SSN, maybe in emergency in "
                        "CreateNewSession, returning\n"););

            /*
             * Mark that this packet isn't worth doing IDS on.  This
             * is self preservation because either our system is under
             * session trashing attacks.  This will be the case under
             * super rapid tools like tcpisc that are generating
             * bogus TCP datagrams all the time  
             */
            if(s4_emergency.status != OPS_NORMAL)
            {
                DisableDetect(p);
            }

            PREPROC_PROFILE_END(stream4PerfStats);
            return;
        }           
    }    
    else
    {
        if(p->dsize != 0 && s4_emergency.status == OPS_NORMAL)
            s4_emergency.new_session_count = 0;
    }

    p->ssnptr = ssn;

    /* Check if stream is to be ignored per session flags */
    if (ssn && ssn->ignore_flag )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                "Nothing to do -- stream is set to be ignored.\n"););

        if (ssn->need_to_flush)
        {
            FlushStream(&ssn->client, p, NO_REVERSE);
            FlushStream(&ssn->server, p, NO_REVERSE);
            ssn->need_to_flush = 0;
        }

        SetIgnoreChannel(NULL, p, SSN_DIR_BOTH, -1, 0);

#ifdef DEBUG
        {
            /* Have to allocate & copy one of these since inet_ntoa
             * clobbers the info from the previous call. */
            struct in_addr tmpAddr;
            char srcAddr[17];
            tmpAddr.s_addr = p->iph->ip_src.s_addr;
            SnortStrncpy(srcAddr, inet_ntoa(tmpAddr), sizeof(srcAddr));
            tmpAddr.s_addr = p->iph->ip_dst.s_addr;

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                   "Ignoring channel %s:%d --> %s:%d\n",
                   srcAddr, p->sp,
                   inet_ntoa(tmpAddr), p->dp););
        }
#endif
        PREPROC_PROFILE_END(stream4PerfStats);
        return;
    }

    /* Check if this packet is one of the "to be ignored" channels.
     * If so, set flag, flush any data that may be buffered up on
     * the connection, and bail. */
    ignore = CheckIgnoreChannel(p);
    if (ignore)
    {
        SetIgnoreChannel(ssn, p, ignore, -1, 0);

        PREPROC_PROFILE_END(stream4PerfStats);
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                "[i] Tracked Bytes: (client: %d, server: %d)\n",
                ssn->client.bytes_tracked,
                ssn->server.bytes_tracked););

    /* update the stream window size */
    if((direction = GetDirection(ssn, p)) == FROM_SERVER)
    {
        p->packet_flags |= PKT_FROM_SERVER;
        ssn->client.win_size = ntohs(p->tcph->th_win);
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "server packet: %s\n", flagbuf););
    }
    else
    {
        p->packet_flags |= PKT_FROM_CLIENT;
        ssn->server.win_size = ntohs(p->tcph->th_win);
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "client packet: %s\n", flagbuf););
    }

    /* Check if stream is to be dropped in this direction */
    if (s4data.allow_session_blocking && ssn &&
        ssn->drop_traffic && InlineMode())
    {
        if (ssn->drop_traffic & direction)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                        "Blocking %s packet as session was blocked\n",
                        direction & FROM_SERVER ? "server" : "client"););
            DisableDetect(p);
            /* Still want to add this number of bytes to totals */
            SetPreprocBit(p, PP_PERFMONITOR);
            InlineDrop(p);
            return;
        }
    }

    if (p->dsize > 0)
    {
        if ((p->packet_flags & PKT_FROM_SERVER) &&
            (s4data.server_inspect_limit > 0))
        {
            /* Server packet, check if we should ignore the rest of the
             * server data until we see a client packet again.
             */

            /* A configurable threshold */
            if (ssn->server.bytes_inspected > s4data.server_inspect_limit)
            {
                p->bytes_to_inspect = -1;
            }
            else
            {
                if (p->dsize + ssn->server.bytes_inspected >
                                s4data.server_inspect_limit)
                {
                    /* We've already inspected some portion of the
                     * server stream and this packet puts us over the
                     * threshold.  Only inspect the difference.
                     */
                    /* Can't simply change dsize, since other preprocs,
                     * like change dsize based on their own configs
                     * (like HttpInspect FlowDepth).  We don't want
                     * to break that functionality.
                     */
        
                    p->bytes_to_inspect = s4data.server_inspect_limit -
                                           ssn->server.bytes_inspected;
                }
            }
            ssn->server.bytes_inspected += p->dsize;
        }
        else
        {
            ssn->server.bytes_inspected = 0;
        }
    }

    /* update the time for this session */
    ssn->last_session_time = p->pkth->ts.tv_sec;

    /* go into the FSM to maintain stream state for this packet */    
    if(s4data.asynchronous_link)
    {
        action = UpdateStateAsync(ssn, p, pkt_seq);
    }
    else
    {
        action = UpdateState2(ssn, p, pkt_seq);
    }

    if (s4data.enforce_state)
    {
        /* If enforce state, don't inspect this packet */
        enforceStateCheckSession(ssn, p);
        if (do_detect_content == 0)
        {
            /* In fact, just delete the session entirely since its
             * useless.  Performance hit now, saves time on the next
             * packet for this pseudo-session.
             */
            DeleteSession(ssn, p->pkth->ts.tv_sec);
            p->ssnptr = NULL;
            PREPROC_PROFILE_END(stream4PerfStats);
            return;
        }
    }

    /* if this packet has data, maybe we should store it */
    if(p->dsize && reassemble)
    {
        StoreStreamPkt2(ssn, p, pkt_seq);
    }
    else
    {
        /* Since we're not storing the packet on this session, let's
         * decrement the bytes tracked */
        if(direction == FROM_SERVER)
            StreamSegmentSub(&ssn->server, p->dsize);        
        else
            StreamSegmentSub(&ssn->client, p->dsize);
    }

    if ((s4data.overlap_limit > 0) &&
        (ssn->client.overlap_pkts > s4data.overlap_limit))
    {
        /* We reached the overlap limit.  Kill the session */
        /* But flush it first */
        action |= ACTION_FLUSH_CLIENT_STREAM;

        if(s4data.evasion_alerts)
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                STREAM4_OVERLAP_LIMIT, /* SID */
                1,                      /* Rev */
                0,                      /* classification */
                3,                      /* priority (low) */
                STREAM4_OVERLAP_LIMIT_STR, /* msg string */
                0);
        }
    }

    if ((s4data.overlap_limit > 0) &&
        (ssn->server.overlap_pkts > s4data.overlap_limit))
    {
        /* We reached the overlap limit.  Kill the session */
        /* But flush it first */
        action |= ACTION_FLUSH_SERVER_STREAM;

        if(s4data.evasion_alerts)
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                STREAM4_OVERLAP_LIMIT, /* SID */
                1,                      /* Rev */
                0,                      /* classification */
                3,                      /* priority (low) */
                STREAM4_OVERLAP_LIMIT_STR, /* msg string */
                0);
        }
    }

    /* 
     * resolve actions to be taken as indicated by state transitions or
     * normal traffic
     */
    if(s4data.asynchronous_link)
    {
        TcpActionAsync(ssn, p, action, direction, pkt_seq, pkt_ack);
    }
    else
    {
        TcpAction(ssn, p, action, direction, pkt_seq, pkt_ack);
    }

    /*
     * Kludge:  Sometime's we can drop a bad session
     *
     * Only try and mark the stream as established if we still have a
     * valid session AFTER the stream is done
     *
     * p->ssnptr == NULL when the action indicates we should have
     * dropped the session
     */
    if(p->ssnptr == ssn)  /* this is not true when the session is dropped */
    {
        /* mark this packet is part of an established stream if possible */
        if(((s4data.asynchronous_link == 0) &&
           (((ssn->session_flags & (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT))
              == (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT)) && 
           (ssn->server.state >= ESTABLISHED) && 
           (ssn->client.state >= ESTABLISHED))) ||
           ((s4data.asynchronous_link == 1) &&
           ((((ssn->session_flags & SSNFLAG_SEEN_CLIENT)) &&
           (ssn->client.state >= ESTABLISHED)) ||
           (((ssn->session_flags & SSNFLAG_SEEN_SERVER)) &&
           (ssn->server.state >= ESTABLISHED)))))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                        "Stream is established!,ssnflags = 0x%x\n",
                        ssn->session_flags););

            ssn->session_flags |= SSNFLAG_ESTABLISHED;
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Stream is not established!\n"););

            if((ssn->session_flags & (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT))
                    == (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT)) 
            {
                /*
                 * we've seen packets in this stream from both the client and 
                 * the server, but we haven't gotten through the three way
                 * handshake
                 */
                p->packet_flags |= PKT_STREAM_UNEST_BI;
            }
            else
            {
                /* 
                 * this is the first time we've seen a packet 
                 * from this stream
                 */
                p->packet_flags |= PKT_STREAM_UNEST_UNI;
            }
        }

        if(ssn->session_flags  & SSNFLAG_ESTABLISHED)
        {
            /* we know this stream is established, lets skip the other checks
             * otherwise we get into clobbering our flags in the check below
             */
            p->packet_flags |= PKT_STREAM_EST;

            if(p->packet_flags & PKT_STREAM_UNEST_UNI)
            {
                p->packet_flags ^= PKT_STREAM_UNEST_UNI;
            }

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                        "Marking stream as established\n"););
#ifdef DEBUG
            if(p->packet_flags & PKT_FROM_CLIENT)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "pkt is from client\n"););
            } 

            if(p->packet_flags & PKT_FROM_SERVER)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "pkt is from server\n"););
            } 
#endif /*DEBUG*/
        }
    }

    PrintSessionCache();

    /* see if we need to prune the session cache */
    PruneCheck(p);

    PREPROC_PROFILE_END(stream4PerfStats);
    return;
}



/**
 * Queues a state transition for UpdateState2
 * 
 * @param transition the state to transition to
 * @param sptr pointer to the stream to queue the transition for
 * @param expected_flags flag we need to see to accept the transition
 * @param seq_num sequence number of the packet initiating the transition
 * @param chk_seq flag to indicate if the seq number actually needs to be
 * checked
 *
 * @return void function
 */
void INLINE QueueState(u_int8_t transition, Stream *sptr, 
        u_int8_t expected_flags, u_int32_t seq_num, u_int8_t chk_seq)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "[^^] Queing transition to %s, flag 0x%X, seq: 0x%X\n", 
                state_names[transition], expected_flags, seq_num););

    sptr->state_queue = transition;
    sptr->expected_flags = expected_flags;
    sptr->stq_chk_seq = chk_seq;
    sptr->trans_seq = seq_num;
    return;
}

/**
 * Evaluate queued state transitions for completion criteria
 *
 * @param sptr pointer to the stream to be evaluated
 * @param flags flags of the current packet
 * @param ack ack number of the current packet
 *
 * @returns 1 on successful state transition, 0 on no transition
 */
int INLINE EvalStateQueue(Stream *sptr, u_int8_t flags, u_int32_t ack)
{
    if(sptr->expected_flags != 0)
    {
        if((flags & sptr->expected_flags) != 0)
        {
            if(sptr->stq_chk_seq && (SEQ_GEQ(ack, sptr->trans_seq)))
            {

                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "[^^] Accepting %s state transition\n", 
                            state_names[sptr->state_queue]););
                sptr->state = sptr->state_queue;
                sptr->expected_flags = 0;
                sptr->trans_seq = 0;
                return 1;
            }
            else if(!sptr->stq_chk_seq)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "[^^] Accepting %s state transition\n", 
                            state_names[sptr->state_queue]););
                sptr->state = sptr->state_queue;
                sptr->expected_flags = 0;
                sptr->trans_seq = 0;
                return 1;

            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "[!!] sptr->stq_chk_seq: %d  "
                            "[ack: 0x%X expected: 0x%X]\n", sptr->stq_chk_seq, 
                            ack, sptr->trans_seq););
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "[!!] flags: 0x%X  expected: 0x%X, bitwise: 0x%X\n", 
                        flags, sptr->expected_flags, 
                        (flags&sptr->expected_flags)););
        }
    }

    return 0;
}

int PurgeOnReSyn(Session *ssn, int direction, u_int32_t pkt_seq)
{
    Stream *s;
    StreamPacketData *spd;
    StreamPacketData *dump;
    int num_removed = 0;

    if(s4data.state_alerts)
    {
        SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                STREAM4_SYN_ON_ESTABLISHED, /* SID */
                1,                      /* Rev */
                0,                      /* classification */
                3,                      /* priority (low) */
                STREAM4_SYN_ON_ESTABLISHED_STR, /* msg string */
                0);
    }


    /* select the right stream */
    if(direction == FROM_CLIENT)
    {
        if(!ssn->reassemble_client)
        {
            return num_removed;
        }

        s = &ssn->client;
    }
    else
    {
        if(!ssn->reassemble_server)
        {
            return num_removed;
        }

        s = &ssn->server;
    }

    spd = s->seglist_tail;
    while (spd)
    {
        if (SEQ_GEQ(spd->seq_num, pkt_seq))
        {
            /* Remove this one entirely */
            dump = spd;
            spd = spd->prev;
            dump = RemoveSpd(s, dump);
            stream4_memory_usage -= dump->pkt_size;
            StreamSegmentSub(s, (u_int16_t)dump->pkt_size);
            free(dump->pktOrig);
            stream4_memory_usage -= sizeof(StreamPacketData);
            free(dump);
            num_removed++;
            continue;
        }

        if (SEQ_GEQ(spd->seq_num + spd->payload_size, pkt_seq))
        {
            /* Trim this one accordingly */
            u_int32_t overlap = pkt_seq - spd->seq_num;
            spd->seq_num = pkt_seq;
            spd->payload_size -= (u_int16_t)overlap;
            spd->payload += overlap;
            StreamSegmentSub(s, (u_int16_t)overlap);
            break; /* Should be the last one since they're in order */
        }

        if (SEQ_LT(spd->seq_num, pkt_seq))
        {
            /* Beyond the seq that was ReSYN'd */
            break;
        }

        spd = spd->prev;
    }

    return num_removed;
}

int UpdateState2(Session *ssn, Packet *p, u_int32_t pkt_seq)
{
    int direction;
    int retcode = 0;
    Stream *talker = NULL;
    Stream *listener = NULL;
#ifdef DEBUG
    char *t = NULL;
    char *l = NULL;
#endif
    PROFILE_VARS;

    PREPROC_PROFILE_START(stream4StatePerfStats);

    direction = GetDirection(ssn, p);

    if(direction == FROM_SERVER)
    {
        ssn->session_flags |= SSNFLAG_SEEN_SERVER;
        talker = &ssn->server;
        listener = &ssn->client;

        DEBUG_WRAP(
                t = strdup("Server");
                l = strdup("Client"););
    }
    else
    {
        ssn->session_flags |= SSNFLAG_SEEN_CLIENT;
        talker = &ssn->client;
        listener = &ssn->server;

        DEBUG_WRAP(
                t = strdup("Client");
                l = strdup("Server"););
    }

    EvalStateQueue(talker, p->tcph->th_flags, ntohl(p->tcph->th_ack));

    if(talker->state != ESTABLISHED)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "   %s [talker] state: %s\n", t, state_names[talker->state]););
    }
    if(listener->state != ESTABLISHED)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "   %s state: %s\n", l, state_names[listener->state]););
    }

    if(p->tcph->th_flags & TH_FIN)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "Marking that a fin was was sent %s\n",
                    (direction ? "FROM_CLIENT" : "FROM_SERVER")););

        SetFinSent(ssn, direction, pkt_seq, p);
    }

    StreamSegmentAdd(talker, p->dsize); 

    if(talker->state == ESTABLISHED)
    {
        listener->win_size = ntohs(p->tcph->th_win);
    }

    if(p->tcph->th_flags & TH_RST)
    {
        /* check to make sure the RST is in window */
        if(CheckRst(ssn, direction, pkt_seq, p))
        {
            int action = ACTION_FLUSH_CLIENT_STREAM | 
                         ACTION_FLUSH_SERVER_STREAM | 
                         ACTION_DROP_SESSION; 
            
            ssn->client.state = CLOSED;
            ssn->server.state = CLOSED;

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                        "   Client Transition: CLOSED\n");
                    DebugMessage(DEBUG_STREAM_STATE,  
                        "   Server Transision: CLOSED\n");
                    if(l) free(l);
                    if(t) free(t););

            if ( p->tcph->th_flags & TH_ACK )
            {
                if ( direction == FROM_SERVER )
                {
                    action |= ACTION_ACK_CLIENT_DATA;
                }
                else
                {
                    action |= ACTION_ACK_SERVER_DATA;
                }
            }

            PREPROC_PROFILE_END(stream4StatePerfStats);
            return action;
        }
    }

    switch(listener->state)
    {
        case LISTEN:
            /* only valid packet for this state is a SYN...
             *  or SYN + ECN crap.
             *
             * Revised: As long as it's got a SYN and not a
             * RST, Lets try to make the session start.  It
             * may just timeout -- cmg
             */
            if((p->tcph->th_flags & TH_SYN) &&
                    !(p->tcph->th_flags & TH_RST))
            {
                QueueState(SYN_RCVD, listener, TH_SYN| TH_ACK, 0, NO_CHK_SEQ);

                if(talker->state != SYN_SENT)
                {
                    talker->state = SYN_SENT;
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                                "   %s Transition: SYN_SENT\n", t););
                }
            }

            if(p->dsize != 0)
                retcode |= ACTION_DATA_ON_SYN;
            break;

        case SYN_SENT:
            if((p->tcph->th_flags & (TH_SYN|TH_ACK)) == (TH_SYN|TH_ACK))
            {
                if(talker->state != SYN_RCVD)
                {
                    talker->state = SYN_RCVD;

                    DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                                "   %s Transition: SYN_RCVD\n", t););
                }

                QueueState(ESTABLISHED, listener, TH_ACK, pkt_seq, CHK_SEQ);

                /* ECN response */
                if((p->tcph->th_flags & TH_RES2) && 
                        ssn->session_flags & SSNFLAG_ECN_CLIENT_QUERY)
                {
                    ssn->session_flags |= SSNFLAG_ECN_SERVER_REPLY;
                }

                retcode |= ACTION_SET_SERVER_ISN;
            }                    

            break;

        case SYN_RCVD:
            if(p->tcph->th_flags & TH_ACK)
            {
                listener->state = ESTABLISHED;
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: ESTABLISHED\n", l););
                retcode |= ACTION_COMPLETE_TWH;
            }

            break;

        case ESTABLISHED:
            if (p->tcph->th_flags & TH_SYN)
            {
                /* SYN on established... */
                /* purge data that is stored beyond the seq+1 of this SYN packet.
                 */
                PurgeOnReSyn(ssn, direction, pkt_seq + 1);
                talker->isn = pkt_seq;
                talker->last_ack = ntohl(p->tcph->th_ack);
                talker->base_seq = talker->last_ack;
            }
            if(p->tcph->th_flags & TH_ACK)
            {
                if(direction == FROM_CLIENT)
                    retcode |= ACTION_ACK_SERVER_DATA;
                else
                    retcode |= ACTION_ACK_CLIENT_DATA;
            }

            if((p->tcph->th_flags & TH_FIN) == TH_FIN)
            {
                if (!CheckFin(talker, direction, pkt_seq, p))
                {
                    talker->state = FIN_WAIT_1;
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                                "   %s Transition: FIN_WAIT_1\n", t););
                    QueueState(CLOSE_WAIT, listener, TH_ACK, pkt_seq, CHK_SEQ);
                }
            }

            break;

        case CLOSE_WAIT:
            QueueState(LAST_ACK, talker, TH_FIN, pkt_seq, NO_CHK_SEQ);

            if(p->tcph->th_flags == TH_ACK)
            {
                if(direction == FROM_CLIENT)
                    retcode |= ACTION_ACK_SERVER_DATA;
                else
                    retcode |= ACTION_ACK_CLIENT_DATA;
            }

            break;

        case LAST_ACK:
            if(p->tcph->th_flags & TH_ACK)
            {
                listener->state = CLOSED;
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: CLOSED\n", l););

                if(talker->state == TIME_WAIT)
                {
                    talker->state = CLOSED;
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                                "   %s Transition: CLOSED\n", t););
                }

                retcode |= (ACTION_FLUSH_CLIENT_STREAM | 
                        ACTION_FLUSH_SERVER_STREAM | 
                        ACTION_DROP_SESSION);
            }

            break;

        case FIN_WAIT_1:
            if((p->tcph->th_flags & (TH_ACK|TH_FIN)) == (TH_ACK|TH_FIN))
            {
                talker->state = LAST_ACK;
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: LAST_ACK\n", t););
                QueueState(TIME_WAIT, listener, TH_ACK, pkt_seq, CHK_SEQ);

                if(direction == FROM_CLIENT)
                    retcode |= ACTION_ACK_SERVER_DATA;
                else
                    retcode |= ACTION_ACK_CLIENT_DATA;
            }
            else if(p->tcph->th_flags == TH_ACK)
            {
                QueueState(LAST_ACK, talker, TH_FIN, pkt_seq, NO_CHK_SEQ);
                listener->state = FIN_WAIT_2;
                DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: FIN_WAIT_2\n", l););

                if(direction == FROM_CLIENT)
                    retcode |= ACTION_ACK_SERVER_DATA;
                else
                    retcode |= ACTION_ACK_CLIENT_DATA;
            }

            break;

        case FIN_WAIT_2:
            if(p->tcph->th_flags == (TH_FIN|TH_ACK))
            {
                talker->state = LAST_ACK;
                QueueState(TIME_WAIT, listener, TH_ACK, pkt_seq, CHK_SEQ);

                if(direction == FROM_CLIENT)
                    retcode |= ACTION_FLUSH_CLIENT_STREAM | ACTION_ACK_SERVER_DATA;
                else
                    retcode |= ACTION_FLUSH_SERVER_STREAM | ACTION_ACK_CLIENT_DATA;
            }
            else if(p->tcph->th_flags == TH_FIN)
            {
                talker->state = LAST_ACK;
                DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                            "   %s Transition: LAST_ACK\n", t););

                QueueState(TIME_WAIT, listener, TH_ACK, pkt_seq, CHK_SEQ);

                if(direction == FROM_CLIENT)
                    retcode |= ACTION_FLUSH_SERVER_STREAM;
                else
                    retcode |= ACTION_FLUSH_CLIENT_STREAM;
            }

            break;

        case TIME_WAIT:
        case CLOSED:    
            PREPROC_PROFILE_END(stream4StatePerfStats);
            return ACTION_FLUSH_CLIENT_STREAM | ACTION_DROP_SESSION;    
    }

    DEBUG_WRAP(
            if(l) free(l);
            if(t) free(t););

    PREPROC_PROFILE_END(stream4StatePerfStats);
    return retcode;
}


/* int UpdateStateAsync(Session *ssn, Packet *p, u_int32_t pkt_seq)
 * 
 * Purpose: Do the state transition table for packets based solely on
 * one-sided converstations
 *
 * Returns:  which ACTIONS need to be taken on this state
 */
 
int UpdateStateAsync(Session *ssn, Packet *p, u_int32_t pkt_seq)
{
    int direction;
    PROFILE_VARS;

    PREPROC_PROFILE_START(stream4StateAsyncPerfStats);

    direction = GetDirection(ssn, p);

    switch(direction)
    {
        case FROM_SERVER:  /* packet came from the server */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                        "Client State: SYN_SENT\n"););

            StreamSegmentAdd(&ssn->server, p->dsize); 

            ssn->session_flags |= SSNFLAG_SEEN_SERVER;

            switch(ssn->server.state)
            {
                case SYN_RCVD:
                    /* This is the first state the reassembler can stick in
                       in the Asynchronus state */

                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                "Server state: SYN_RCVD\n"););
                    if((p->tcph->th_flags & TH_NORESERVED) == (TH_SYN|TH_ACK))
                    {
                        ssn->server.state = ESTABLISHED;
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Server Transition: ESTABLISHED\n"););
                        PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
                        return ACTION_COMPLETE_TWH;
                    }
                    PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
                    return ACTION_NOTHING;

                case ESTABLISHED:
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Server state: ESTABLISHED\n"););
                    if(p->tcph->th_flags & TH_FIN)
                    {
                        ssn->server.state = CLOSED;
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Client Transition: FIN_WAIT_1\n"););

                        PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
                        return ACTION_FLUSH_SERVER_STREAM|ACTION_DROP_SESSION;
                    }
                    else if(p->tcph->th_flags & TH_RST)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                    "Got RST (0x%X)\n", 
                                    p->tcph->th_flags););
                        ssn->server.state = CLOSED;
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Server Transition: CLOSED\n"););

                        PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
                        return ACTION_FLUSH_SERVER_STREAM | ACTION_DROP_SESSION;
                    }

                    PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
                    return ACTION_NOTHING;
            }

        case FROM_CLIENT:

            StreamSegmentAdd(&ssn->client, p->dsize);

            ssn->session_flags |= SSNFLAG_SEEN_CLIENT;

            switch(ssn->client.state)
            {
                case SYN_SENT:
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Client State: SYN_SENT\n"););
                    if(p->tcph->th_flags & TH_RST)
                    {
                        ssn->client.state = CLOSED;

                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Client Transition: CLOSED -- RESET\n"););

                        PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
                        return ACTION_FLUSH_CLIENT_STREAM | ACTION_DROP_SESSION;
                    }
                    else if(p->tcph->th_flags & TH_ACK)
                    {
                        ssn->client.state = ESTABLISHED;

                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Client Transition: ESTABLISHED\n"););

                        PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
                        return ACTION_NOTHING;
                    }

                    PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
                    return ACTION_NOTHING;


                case ESTABLISHED:
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Client state: ESTABLISHED\n"););

                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Session State: ESTABLISHED\n"););
                    ssn->session_flags |= SSNFLAG_ESTABLISHED;


                    if(p->tcph->th_flags & TH_FIN)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                    "Got FIN (0x%X)\n", 
                                    p->tcph->th_flags););
                        ssn->client.state = CLOSED;
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Client Transition: CLOSEd\n"););

                        PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
                        return ACTION_FLUSH_CLIENT_STREAM|ACTION_DROP_SESSION;
                    }
                    else if(p->tcph->th_flags & TH_RST)
                    {
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                    "Got RST (0x%X)\n", 
                                    p->tcph->th_flags););
                        ssn->client.state = CLOSED;
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  
                                    "   Client Transition: Closed\n"););

                        PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
                        return ACTION_FLUSH_CLIENT_STREAM | ACTION_DROP_SESSION;
                    }
                    break;
            }
    }

    PREPROC_PROFILE_END(stream4StateAsyncPerfStats);
    return ACTION_NOTHING;
}

void NewSessionSetReassemble(Session *ssn)
{
    /* These are set "backwards" -- if reassemble_client is set that means
     * packets going FROM the client to the server port.  Similarly, if
     * reassemble_server is set that means packets going FROM the server
     * to the client port. */
    int reassemble = 0;
    switch (s4_emergency.status)
    {
    case OPS_NORMAL:
        reassemble = s4data.assemble_ports[ssn->server.port] |
                     s4data.assemble_ports[ssn->client.port];
        break;
    case OPS_SELF_PRESERVATION:
        reassemble = s4data.emergency_ports[ssn->server.port] |
                     s4data.emergency_ports[ssn->client.port];
        break;
    }
    if (s4data.reassemble_client)
        ssn->reassemble_client = reassemble;
    else
        ssn->reassemble_client = 0;

    if (s4data.reassemble_server)
        ssn->reassemble_server = reassemble;
    else
        ssn->reassemble_server = 0;
}

Session *CreateNewSession(Packet *p, u_int32_t pkt_seq, u_int32_t pkt_ack)
{
    Session *idx = NULL;
    static u_int8_t savedfpi; /* current flush point index */
    u_int8_t fpi;            /* flush point index */
    PROFILE_VARS;

    PREPROC_PROFILE_START(stream4NewSessPerfStats);
    /* assign a psuedo random flush point */
    savedfpi++;
    fpi = savedfpi % FCOUNT;    
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Using flush value of "
                "(%d bytes) at index %d\n", flush_points[fpi],fpi););
    /* This would be a lot better but could be a big performance hit
     * since the flush point values should be fully random at this
     * point it should be ok.
    srand(savedfpi + p->pkth->ts.tv_sec);
    fpi = rand() % FCOUNT;
    */

    switch(p->tcph->th_flags)
    {
        case TH_RES1|TH_RES2|TH_SYN: /* possible ECN traffic */
        case TH_RES1|TH_SYN: /* possible ECN traffic */
            if(p->iph->ip_tos == 0x02)
            {
                /* it is ECN traffic */
                p->packet_flags |= PKT_ECN;
            }

            /* fall through */

        case TH_SYN:  /* setup session on first packet of TWH */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[A] initializing new session "
                        "(%d bytes)\n", sizeof(Session)););

            idx = GetNewSession(p);

            idx->client.seglist = idx->client.seglist_tail = NULL;
            idx->server.seglist = idx->server.seglist_tail = NULL;

            idx->server.state = LISTEN;        
            idx->server.ip = p->iph->ip_dst.s_addr;
            idx->server.port = p->dp;

            idx->client.state = SYN_SENT;
            idx->client.ip = p->iph->ip_src.s_addr;
            idx->client.port = p->sp;
            idx->client.isn = pkt_seq;
            idx->server.win_size = ntohs(p->tcph->th_win);

            idx->start_time = p->pkth->ts.tv_sec;
            idx->last_session_time = p->pkth->ts.tv_sec;

            idx->session_flags |= SSNFLAG_SEEN_CLIENT;

            if(p->packet_flags & PKT_ECN)
            {
                idx->session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
            }

            idx->flush_point = flush_points[fpi];
            NewSessionSetReassemble(idx);
            break;

        case TH_RES2|TH_SYN|TH_ACK:
            if(p->iph->ip_tos == 0x02)
            {
                p->packet_flags |= PKT_ECN;
            }
            else
            {
                if(s4data.ps_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4,
                            STREAM4_STEALTH_ACTIVITY,
                            1,
                            0,
                            3,
                            STREAM4_STEALTH_ACTIVITY_STR,
                            0);

                    break;
                }

                PREPROC_PROFILE_END(stream4NewSessPerfStats);
                return NULL;
            }

            /* fall through */

        case TH_SYN|TH_ACK: /* maybe we missed the SYN packet... */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[A] initializing new session "
                        "(%d bytes)\n", sizeof(Session)););

            idx = GetNewSession(p);

            idx->client.seglist = idx->client.seglist_tail = NULL;
            idx->server.seglist = idx->server.seglist_tail = NULL;

            idx->server.state = SYN_RCVD;
            idx->client.state = SYN_SENT;

            idx->server.ip = p->iph->ip_src.s_addr;
            idx->server.port = p->sp;
            idx->server.isn = pkt_seq;
            idx->client.win_size = ntohs(p->tcph->th_win);

            idx->client.ip = p->iph->ip_dst.s_addr;
            idx->client.port = p->dp;
            idx->client.isn = pkt_ack-1;

            idx->start_time = p->pkth->ts.tv_sec;
            idx->last_session_time = p->pkth->ts.tv_sec;
            idx->session_flags = SSNFLAG_SEEN_SERVER;
            idx->flush_point = flush_points[fpi];
            NewSessionSetReassemble(idx);
            break;

        case TH_ACK: 
        case TH_ACK|TH_PUSH: 
        case TH_FIN|TH_ACK:
        case TH_ACK|TH_URG:
        case TH_ACK|TH_PUSH|TH_URG:
        case TH_FIN|TH_ACK|TH_URG:
        case TH_ACK|TH_PUSH|TH_FIN:
        case TH_ACK|TH_PUSH|TH_FIN|TH_URG:
            /* 
             * missed the TWH or just got the last packet of the 
             * TWH, or we're catching this session in the middle
             */

            /* 
             * this traffic could also be bogus SmartBits bullshit, in which case
             * the person testing this NIDS with the smartbits should be flogged
             * to death with a limp noodle
             */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[A] initializing new session "
                        "(%d bytes)\n", sizeof(Session)););

            idx = GetNewSession(p);

            idx->client.seglist = idx->client.seglist_tail = NULL;
            idx->server.seglist = idx->server.seglist_tail = NULL;

            idx->server.state = ESTABLISHED;
            idx->client.state = ESTABLISHED;

            if ( p->dp <= p->sp )  /* guess this is a client packet */
            {
                idx->server.ip = p->iph->ip_dst.s_addr;
                idx->server.port = p->dp;
                idx->server.isn = pkt_ack-1;
                idx->server.last_ack = pkt_ack;
                idx->server.base_seq = idx->server.last_ack;
                idx->server.win_size = ntohs(p->tcph->th_win);

                idx->client.ip = p->iph->ip_src.s_addr;
                idx->client.port = p->sp;
                idx->client.isn = pkt_seq-1;
                idx->client.last_ack = pkt_seq;
                idx->client.base_seq = idx->client.last_ack;
                idx->session_flags = SSNFLAG_SEEN_CLIENT;
            }
            else  /*  sp > dp, guess this is a server packet */
            {
                idx->client.ip = p->iph->ip_dst.s_addr;
                idx->client.port = p->dp;
                idx->client.isn = pkt_ack-1;
                idx->client.last_ack = pkt_ack;
                idx->client.base_seq = idx->client.last_ack;
                idx->client.win_size = ntohs(p->tcph->th_win);

                idx->server.ip = p->iph->ip_src.s_addr;
                idx->server.port = p->sp;
                idx->server.isn = pkt_seq-1;
                idx->server.last_ack = pkt_seq;
                idx->server.base_seq = idx->server.last_ack;
                idx->session_flags = SSNFLAG_SEEN_SERVER;
            }
            idx->start_time = p->pkth->ts.tv_sec;
            idx->last_session_time = p->pkth->ts.tv_sec;
            idx->flush_point = flush_points[fpi];
            NewSessionSetReassemble(idx);
            break;

        case TH_RES2|TH_SYN: /* nmap fingerprint packet */
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[A] initializing new session "
                        "(%d bytes)\n", sizeof(Session));
                    DebugMessage(DEBUG_STREAM,
                        "nmap fingerprint scan 2SYN packet!\n"););
            idx = GetNewSession(p);

            idx->client.seglist = idx->client.seglist_tail = NULL;
            idx->server.seglist = idx->server.seglist_tail = NULL;

            idx->server.state = NMAP_FINGERPRINT_2S;
            idx->client.state = NMAP_FINGERPRINT_2S;

            idx->server.ip = p->iph->ip_dst.s_addr;
            idx->server.port = p->dp;

            idx->client.ip = p->iph->ip_src.s_addr;
            idx->client.port = p->sp; /* cp incs by one for each packet */
            idx->client.port++;
            idx->client.isn = pkt_seq;
            idx->server.win_size = ntohs(p->tcph->th_win);

            idx->start_time = p->pkth->ts.tv_sec;
            idx->last_session_time = p->pkth->ts.tv_sec;

            idx->session_flags = SSNFLAG_SEEN_CLIENT|SSNFLAG_NMAP;
            idx->flush_point = flush_points[fpi];
            NewSessionSetReassemble(idx);

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"init nmap for sip: 0x%X sp: %d  "
                        "cip: 0x%X cp: %d\n", 
                        idx->server.ip, idx->server.port, 
                        idx->client.ip, idx->client.port););

            break;
        case TH_SYN|TH_RST|TH_ACK|TH_FIN|TH_PUSH|TH_URG:
            if(s4data.ps_alerts)
            {
                /* Full XMAS scan */
                SnortEventqAdd(GENERATOR_SPP_STREAM4,
                        STREAM4_STEALTH_FULL_XMAS,
                        1,
                        0,
                        3,
                        STREAM4_STEALTH_FULL_XMAS_STR,
                        0);
            }

            break;

        case TH_SYN|TH_ACK|TH_URG|TH_PUSH:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_SAPU, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_SAPU_STR, /* msg string */
                        0);
            }

            break;

        case TH_FIN:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_FIN_SCAN, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_FIN_SCAN_STR, /* msg string */
                        0);
            }

            break;

        case TH_SYN|TH_FIN:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_SYN_FIN_SCAN, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_SYN_FIN_SCAN_STR, /* msg string */
                        0);
            }

            break;

        case 0:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_NULL_SCAN, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_NULL_SCAN_STR, /* msg string */
                        0);
            }

            break;

        case TH_FIN|TH_PUSH|TH_URG:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_NMAP_XMAS_SCAN, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_NMAP_XMAS_SCAN_STR, /* msg string */
                        0);
            }

            break;

        case TH_URG:
        case TH_PUSH:
        case TH_FIN|TH_URG:
        case TH_PUSH|TH_FIN:
        case TH_URG|TH_PUSH:
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_VECNA_SCAN, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_VECNA_SCAN_STR, /* msg string */
                        0);
            }
            
            break;

        case TH_RST:
        case TH_RST|TH_ACK:
            break;

        default: /* 
                  * some kind of non-kosher activity occurred, drop the node 
                  * and flag a portscan
                  */
            if(s4data.ps_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_STEALTH_ACTIVITY, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_STEALTH_ACTIVITY_STR, /* msg string */
                        0);

                break;
            }
            PREPROC_PROFILE_END(stream4NewSessPerfStats);
            return NULL;
    }

    if(idx)
    {
        pc.tcp_streams++;
    }

    PREPROC_PROFILE_END(stream4NewSessPerfStats);
    return idx;
}



void DeleteSession(Session *ssn, u_int32_t time)
{
    struct in_addr foo;
    register int s;
    struct tm *lt;
    struct tm *et;
    Session *killme;
    char tcp_ssn = 1;

    if(ssn == NULL)
        return;
    
#ifdef STREAM4_UDP
    if (ssn->hashKey.proto == IPPROTO_UDP)
    {
        RemoveUDPSession(&sfPerf.sfBase);
        tcp_ssn = 0;
    }
    else
#endif
    RemoveStreamSession(&sfPerf.sfBase);
    
    if(s4data.track_stats_flag == STATS_HUMAN_READABLE)
    {
        lt = localtime((time_t *) &ssn->start_time);
        s = (ssn->start_time + thiszone) % 86400;

        fprintf(session_log, "[*] %s Session stats:\n   Start Time: ",
            tcp_ssn ? "TCP" : "UDP");
        fprintf(session_log, "%02d/%02d/%02d-%02d:%02d:%02d", lt->tm_mon+1,
                lt->tm_mday, lt->tm_year - 100, s/3600, (s%3600)/60, s%60);

        et = localtime((time_t *) &ssn->last_session_time);
        s = (ssn->last_session_time + thiszone) % 86400;
        fprintf(session_log, "   End Time: %02d/%02d/%02d-%02d:%02d:%02d\n", 
                et->tm_mon+1, et->tm_mday, et->tm_year - 100, s/3600, 
                (s%3600)/60, s%60);

        foo.s_addr = ssn->server.ip;
        fprintf(session_log, "   %s IP: %s  ", 
            tcp_ssn ? "Server" : "Responder", inet_ntoa(foo));
        fprintf(session_log, "port: %d  pkts: %u  bytes: %u\n", 
                ssn->server.port, ssn->server.pkts_sent, 
                ssn->server.bytes_sent);
        foo.s_addr = ssn->client.ip;
        fprintf(session_log, "   %s IP: %s  ", 
            tcp_ssn ? "Client" : "Sender", inet_ntoa(foo));
        fprintf(session_log, "port: %d  pkts: %u  bytes: %u\n", 
                ssn->client.port, ssn->client.pkts_sent, 
                ssn->client.bytes_sent);
        fflush(session_log);
    }
    else if(s4data.track_stats_flag == STATS_MACHINE_READABLE)
    {
        lt = localtime((time_t *) &ssn->start_time);
        s = (ssn->start_time + thiszone) % 86400;

        fprintf(session_log, "[*] %s Session => Start: ",
            tcp_ssn ? "TCP" : "UDP");
        fprintf(session_log, "%02d/%02d/%02d-%02d:%02d:%02d", lt->tm_mon+1,
                lt->tm_mday, lt->tm_year - 100, s/3600, (s%3600)/60, s%60);

        et = localtime((time_t *) &ssn->last_session_time);
        s = (ssn->last_session_time + thiszone) % 86400;
        fprintf(session_log, " End Time: %02d/%02d/%02d-%02d:%02d:%02d", 
                et->tm_mon+1, et->tm_mday, et->tm_year - 100, s/3600, 
                (s%3600)/60, s%60);

        foo.s_addr = ssn->server.ip;
        fprintf(session_log, "[%s IP: %s  ", 
            tcp_ssn ? "Server" : "Responder", inet_ntoa(foo));
        fprintf(session_log, "port: %d  pkts: %u  bytes: %u]", 
                ssn->server.port, ssn->server.pkts_sent, 
                ssn->server.bytes_sent);
        foo.s_addr = ssn->client.ip;
        fprintf(session_log, " [%s IP: %s  ", 
            tcp_ssn ? "Client" : "Sender", inet_ntoa(foo));
        fprintf(session_log, "port: %d  pkts: %u  bytes: %u]\n", 
                ssn->client.port, ssn->client.pkts_sent, 
                ssn->client.bytes_sent);
        fflush(session_log);
    }
    else if(s4data.track_stats_flag == STATS_BINARY)
    {
        BinStats bs;  /* lets generate some BS */

        bs.start_time = ssn->start_time;
        bs.end_time = ssn->last_session_time;
        bs.sip = ssn->server.ip;
        bs.cip = ssn->client.ip;
        bs.sport = ssn->server.port;
        bs.cport = ssn->client.port;
        bs.spackets = ssn->server.pkts_sent;
        bs.cpackets = ssn->client.pkts_sent;
        bs.sbytes = ssn->server.bytes_sent;
        bs.cbytes = ssn->client.bytes_sent;

        WriteSsnStats(&bs);
    }

    killme = RemoveSession(ssn);

    DropSession(killme);
}



/*
 * RST 
 *
 * Snort/IDS safe handling of TCP Resets
 *  
 * ignore rules
 *      if stream tracking is off, ignore resets.
 *      if stream reassembly is off in the direction of flow, ignore resets.
 *      if the rst sequence is a duplicate sequence number, ignore it.
 *      if the rst is on a flow where we have unack'd data, ignore it.
 *  if there is no ack with the reset, ignore it.
 *  if the sequence is > the next expected sequence but still within 
 *      the window , queue it, and ignore it for now.
 *  if the last ack we received is less than our next sequence, we have 
 *      outstanding acks - ignore the reset.
 *      
 *  ignoring a reset does the following:
 *      the session is not closed.
 *      if the session is closed by the receiver of the reset, the session will 
 *      time out.
 *      if the session is not closed by the receiver, than data will continue to 
 *      be tracked.
 * 
 * Includes Fix for bug 2161  
 * 9/2/2003
 *
 * 'go to the river called state, eat any of it's acks - but fear the 
 * reset, for it can be poisonous' - man
 * 
 * 
 */
int CheckRst(Session *ssn, int direction, u_int32_t pkt_seq, Packet *p)
{
    Stream *s;
    static StreamPacketData spd;
    spd.seq_num = pkt_seq;

    /* If not tracking state ignore it */
    if( !s4data.stateful_inspection_flag )
        return 0;

    if(direction == FROM_SERVER)
    {        
        s = &ssn->server;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"--RST From Server!\n"););
    }
    else
    {        
        s = &ssn->client;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"--RST From Client!\n"););
    }

    {
        DEBUG_WRAP(struct in_addr foo;);
        DEBUG_WRAP(foo.s_addr=s->ip; 
                DebugMessage(DEBUG_STREAM, 
                    "--RST packet from %s!\n",inet_ntoa(foo));
                DebugMessage(DEBUG_STREAM, 
                    "--pkt seq: %u   last_ack: %u base-seq: %u next-seq: %u "
                    "bytes-sent: %u bytes-tracked: %u win: %u \n",
                    pkt_seq,s->last_ack,s->base_seq,s->next_seq,s->bytes_sent,
                    s->bytes_tracked,s->win_size););
    }

    /*
     *  We want to make sure the RST has the next valid sequence that 
     *  this side should be sending 
     *  If the pkt_seq < next_seq it's essentially a duplicate 
     *  sequence, and is probably going to be discarded, it certainly 
     *  should be. Also, the base sequence includes the SYN sequence count.
     *  If the packet seq is after the next seq than we should queue the 
     *  packet for later, in case an out of order packet arrives. We 
     *  should also honor the RST-ACK requirements.. but I have to research 
     *  that more.
     *
     *  Ignoring a RST implies we won't shutdown this session due to it.
     *  
     *  This is a standard TCP/IP stack 'in the window' check, but it's 
     *  not always the way stacks handle RST's:
     *  
     *  if(SEQ_LT(pkt_seq,s->base_seq+s->bytes_tracked) || 
     *     SEQ_GEQ(pkt_seq,(s->last_ack+s->win_size))) 
     *  
     *  We use a tighter constraint...
     *
     *  Use bytes_tracked, which is the number of bytes currently queued
     *  for reassembly.  Don't use bytes_sent, which is the number of bytes
     *  seen on the session, including retransmissions, overlaps, etc.
     */
    if( !SEQ_EQ(pkt_seq,s->base_seq+s->bytes_tracked) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "Bad RST packet, bad sequence or no ack, no cookie!\n"
                    "pkt seq: 0x%X   last_ack: 0x%X   win: 0x%X\n",
                    pkt_seq, s->last_ack, s->win_size););

        /* we should probably alert here */
        if(s4data.evasion_alerts)
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_EVASIVE_RST, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_EVASIVE_RST_STR, /* msg string */
                    0);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "Ignoring a RST (1)...pkt_seq=%u\n",pkt_seq););
        return 0;
    }

    /* At this point if the reset seq + ack flags are ok, we still must not 
     * have any data waiting for an ack to honor the reset right now...
     *
     * 9/2/2003 -  bug 2161
     * 
     * Do not return 1 so fast. This RST might be a retransmission of
     * data that was not acked yet.  If it is, most hosts will reject
     * the RST. Future work should explore this futher.
     *
     * Shai Rubin <shai@cs.wisc.edu>
     */

    /* Find this packet seq within the packet store */
    if (SpdSeqExists(s, pkt_seq) &&
            SEQ_LT(s->last_ack,s->base_seq+s->bytes_tracked) )
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "Ignoring a RST (2)...pkt_seq=%u\n",pkt_seq););
        return 0;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                "Not Ignoring a RST...pkt_seq=%u\n",pkt_seq););

    return 1;
}

void PurgeFlushStream(Session *ssn, Stream *s)
{
    Packet p;
    StreamPacketData *spd;
    DecoderFlags decoder_flags;

    if (!s4_shutdown)
    {
        /* Turn off decoder alerts since we're decoding stored
         * packets that we already alerted on.
         */
        memcpy(&decoder_flags, &pv.decoder_flags, sizeof(DecoderFlags));
        memset(&pv.decoder_flags, 0, sizeof(DecoderFlags));
    }

    if (s)
    {
        spd = s->seglist;
        if (spd)
        {
            struct pcap_pkthdr pkth;
            unsigned char *pktOrig, *pkt;

            /* Uggh, hate to have do this, but we don't store the original
             * packet data.  Eth, IP & TCP headers are required for
             * rebuilding a stream.
             */
#ifdef GRE
            /* Hack so rebuilt/reinserted packet isn't counted toward GRE total 
             * Right now, this only works if the delivery protocol is IP
             */
            if (((IPHdr *)(spd->pktOrig + ETHERNET_HEADER_LEN))->ip_proto == IPPROTO_GRE)
            {
                pc.gre--;
            }
#endif
            pc.tcp--;
            memcpy(&pkth, &spd->pkth, sizeof(struct pcap_pkthdr));
            pktOrig = pkt = malloc(pkth.caplen + SPARC_TWIDDLE);
            memcpy(pktOrig, spd->pktOrig, pkth.caplen + SPARC_TWIDDLE);
            pkt += SPARC_TWIDDLE;
            (*grinder)(&p, (struct pcap_pkthdr *)&pkth, pkt);
            p.ssnptr = ssn;
            p.streamptr = s;
            FlushStream(s, &p, NO_REVERSE);
            free(pktOrig);
        }
    }
    if (!s4_shutdown)
    {
        /* And turn decoder alerts back on (or whatever they were set to) */
        memcpy(&pv.decoder_flags, &decoder_flags, sizeof(DecoderFlags));
    }
}

void FlushDeletedStream(Session *ssn, Stream *s)
{
    if (s && ssn)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
           "Dropping session... reassembling before purge\n"););

        PurgeFlushStream(ssn, s);
    }
}

void DropSession(Session *ssn)
{
    Stream *s;
    StreamApplicationData *application_data;
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,  "Dropping session %p\n", ssn););

    if(ssn == NULL)
        return;

    if (ssn->hashKey.proto == IPPROTO_TCP)
    {
        if (ssn->reassemble_server)
        {
            s = &ssn->server;
            FlushDeletedStream(ssn, s);
        }

        if (ssn->reassemble_client)
        {
            s = &ssn->client;
            FlushDeletedStream(ssn, s);
        }

        DeleteSpd(&ssn->server.seglist);
        DeleteSpd(&ssn->client.seglist);
        ssn->server.seglist_tail = NULL;
        ssn->server.pkt_count = 0;
        ssn->client.seglist_tail = NULL;
        ssn->client.pkt_count = 0;
    }

    application_data = ssn->application_data;
    while (application_data)
    {
        StreamApplicationData *tmp = application_data;
        application_data = application_data->next;
        if (tmp->preproc_free)
        {
            tmp->preproc_free(tmp->preproc_data);
            tmp->preproc_data = NULL;
            tmp->preproc_free = NULL;
        }
        free(tmp);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[F] Freeing %d byte session\n", 
                            sizeof(Session)););
   
}

void DeleteSpd(StreamPacketData **seglist)
{
    StreamPacketData *dump, *spd = *seglist;
    while (spd)
    {
        dump = spd;
        spd = spd->next;

        stream4_memory_usage -= dump->pkt_size;
        free(dump->pktOrig);
        stream4_memory_usage -= sizeof(StreamPacketData);
        free(dump);
    }

    *seglist = NULL;
}

int GetDirection(Session *ssn, Packet *p)
{
    if(p->iph->ip_src.s_addr == ssn->client.ip)
    {
        return FROM_CLIENT;
    }
    else if(((p->tcph->th_flags & TH_NORESERVED) == TH_SYN) &&
            !(ssn->session_flags & SSNFLAG_ESTABLISHED))
    {
        ssn->client.port = p->sp;
        ssn->client.ip   = p->iph->ip_src.s_addr;
        ssn->server.port = p->dp;
        ssn->server.ip   = p->iph->ip_dst.s_addr;
        return FROM_CLIENT;
    }
        
    return FROM_SERVER;
}

void Stream4ShutdownFunction(int signal, void *foo)
{
    DecoderFlags decoder_flags;

    /* Turn off decoder alerts since we're decoding stored
     * packets that we already alerted on.
     */
    memcpy(&decoder_flags, &pv.decoder_flags, sizeof(DecoderFlags));
    memset(&pv.decoder_flags, 0, sizeof(DecoderFlags));
    s4_shutdown = 1;

    PurgeSessionCache();

    /* And turn decoder alerts back on (or whatever they were set to) */
    memcpy(&pv.decoder_flags, &decoder_flags, sizeof(DecoderFlags));
    s4_shutdown = 0;
}

void Stream4CleanExitFunction(int signal, void *foo)
{
    if(s4data.track_stats_flag)
    {
        if(s4data.track_stats_flag != STATS_BINARY)
            fclose(session_log);
        else
            if(stats_log != NULL)
                fclose(stats_log->fp);
    }
}


void Stream4RestartFunction(int signal, void *foo)
{
    if(s4data.track_stats_flag)
    {
        if(s4data.track_stats_flag != STATS_BINARY)
            fclose(session_log);
        else
            if(stats_log != NULL)
                fclose(stats_log->fp);
    }
}


static u_int32_t GetTcpTimestamp(Packet *p, u_int32_t *ts)
{
    u_int32_t i = 0;
    
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "Getting timestamp...\n"););
    while(i < p->tcp_option_count && i < 40)
    {
        if(p->tcp_options[i].code == TCPOPT_TIMESTAMP)
        {
            *ts = EXTRACT_32BITS(p->tcp_options[i].data);
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Found timestamp %lu\n", *ts););
            return 1;
        }
        
        i++;
    }
    
    *ts = 0;
    
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "No timestamp...\n"););
    
    return 0;
}

static INLINE int Stream4PktFastTrack(StreamPacketData *tail,
        u_int32_t pkt_seq, u_int16_t size)
{
    if (!tail)
        return 1;

    if (SEQ_EQ(pkt_seq, tail->seq_num + tail->payload_size))
        return 1;

    return 0;
}

static StreamPacketData *SpdSeqExists(Stream *s, u_int32_t pkt_seq)
{
    int32_t dist_head;
    int32_t dist_tail;
    StreamPacketData *spd;

    if (!s->seglist)
        return NULL;

    dist_head = pkt_seq - s->seglist->seq_num;
    dist_tail = pkt_seq - s->seglist_tail->seq_num;

    if (dist_head <= dist_tail)
    {
        /* Start iterating at the head (left) */
        for (spd = s->seglist; spd; spd = spd->next)
        {
            if (SEQ_EQ(spd->seq_num, pkt_seq))
                return spd;

            if (SEQ_GEQ(spd->seq_num, pkt_seq))
                break;
        }
    }
    else
    {
        /* Start iterating at the tail (right) */
        for (spd = s->seglist_tail; spd; spd = spd->prev)
        {
            if (SEQ_EQ(spd->seq_num, pkt_seq))
                return spd;

            if (SEQ_LT(spd->seq_num, pkt_seq))
                break;
        }
    }
    return NULL;
}

static StreamPacketData *RemoveSpd(Stream *s, StreamPacketData *spd)
{
    if(s == NULL || spd == NULL)
        return 0;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Dropping packet data at seq %X, len %d\n",
                spd->seq_num, spd->payload_size););

    if(spd->prev)
        spd->prev->next = spd->next;
    else
        s->seglist = spd->next;

    if(spd->next)
        spd->next->prev = spd->prev;
    else
        s->seglist_tail = spd->prev;

    s->pkt_count--;

    return spd;
}

static void AddSpd(Stream *s, StreamPacketData *prev, StreamPacketData *new)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Adding packet data at seq %X, len %d\n",
                new->seq_num, new->payload_size););

    if(prev)
    {
        new->next = prev->next;
        new->prev = prev;
        prev->next = new;
        if (new->next)
            new->next->prev = new;
        else
            s->seglist_tail = new;
    }
    else
    {
        new->next = s->seglist;
        if(new->next)
            new->next->prev = new;
        else
            s->seglist_tail = new;
        s->seglist = new;
    }
    s->pkt_count++;

#ifdef DEBUG
    {
        StreamPacketData *spd = s->seglist;
        u_int32_t pkt_count = 0;
        while (spd)
        {
            spd = spd->next;
            pkt_count++;
        }

        if (pkt_count != s->pkt_count)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Packet_count mismatch\n"););
        }
    }
#endif
    pc.queued_segs++;
    return;
}

static int DupSpd(Packet *p, Stream *s, StreamPacketData *left, StreamPacketData **retSpd)
{
    StreamPacketData *spd = NULL;

    /*
     * get a new node
     */
    spd = (StreamPacketData *) SafeAlloc(sizeof(StreamPacketData),
                                p->pkth->ts.tv_sec, (Session *)p->ssnptr);

    spd->pktOrig = spd->pkt = (u_int8_t *) SafeAlloc(left->pkt_size,
                                p->pkth->ts.tv_sec, (Session *)p->ssnptr);

    memcpy(spd->pktOrig, left->pktOrig, left->pkth.caplen);
    memcpy(&spd->pkth, &left->pkth, sizeof(SnortPktHeader));

    spd->pkt_size = left->pkt_size;
    spd->pkt += SPARC_TWIDDLE;
    spd->data = spd->pkt + (left->data - left->pkt);

    /*
     * twiddle the values for overlaps
     */
    spd->payload = spd->data;
    spd->payload_size = left->payload_size;
    spd->seq_num = left->seq_num;
    spd->cksum = left->cksum;

    AddSpd(s, left, spd);
                                                                
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                 "added %d bytes on segment list @ seq: 0x%X, total %lu, "
                 "%d segments queued\n", spd->payload_size, spd->seq_num,
                 s->bytes_tracked, s->pkt_count););
                                                                
    *retSpd = spd;
    return 0;
}

static int InsertPkt(Stream *s, Packet *p, int16_t len, u_int32_t slide,
        u_int32_t trunc, u_int32_t seq, StreamPacketData *left,
        StreamPacketData **retSpd)
{
    StreamPacketData *spd = NULL;
    int32_t newSize = (int32_t)len - slide - trunc;
    if (newSize <= 0)
    {
        /*
         * zero size data because of trimming.  Don't
         * insert it
         */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "zero size TCP data after left & right trimming "
                    "(len: %d slide: %d trunc: %d)\n",
                    len, slide, trunc););
#ifdef DEBUG_STREAM
        {
            StreamPacketData *idx = s->seglist;
            unsigned long i = 0;
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Dumping Stream Data, %d segments\n", s->pkt_count););
            while (idx)
            {
                i++;
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "%d  ptr: %p  seq: 0x%X  size: %d nxt: %p prv: %p\n",
                        i, idx, idx->seq_num, idx->payload_size,
                        idx->next, idx->prev););
                        
                if(s->pkt_count < i)
                    FatalError("Circular list, WTF?\n");
                        
                idx = idx->next;
            }
        }
#endif
        return -1;
    }

    spd = (StreamPacketData *) SafeAlloc(sizeof(StreamPacketData),
                                    p->pkth->ts.tv_sec, (Session *)p->ssnptr);

    spd->pktOrig = spd->pkt = (u_int8_t *) SafeAlloc(p->pkth->caplen + SPARC_TWIDDLE,
                                    p->pkth->ts.tv_sec, (Session *)p->ssnptr);

    spd->pkt += SPARC_TWIDDLE;
    spd->pkt_size = p->pkth->caplen + SPARC_TWIDDLE;

    memcpy(spd->pkt, p->pkt, p->pkth->caplen);
    memcpy(&spd->pkth, p->pkth, sizeof(SnortPktHeader));

    spd->data = spd->pkt + (p->data - p->pkt);

    spd->payload = spd->data + slide;
    spd->payload_size = (u_int16_t)newSize;
    spd->seq_num = seq;
    spd->cksum = p->tcph->th_sum;

    AddSpd(s, left, spd);

    p->packet_flags |= PKT_STREAM_INSERT;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "added %d bytes on segment list @ seq: 0x%X, total %lu, "
                "%d segments queued\n", spd->payload_size, spd->seq_num,
                s->bytes_tracked, s->pkt_count););

    *retSpd = spd;
    return 0;
}

void StoreStreamPkt2(Session *ssn, Packet *p, u_int32_t pkt_seq)
{
    Stream *s;
    StreamPacketData *spd = NULL;
    StreamPacketData *left = NULL;
    StreamPacketData *right = NULL;
    StreamPacketData *dump = NULL;
    u_int32_t seq = pkt_seq;
    u_int32_t seq_end = pkt_seq + p->dsize;
    u_int16_t len = p->dsize;
    int trunc = 0;
    int overlap = 0;
    int slide = 0;
    int ret = 0;
    char done = 0;
    char addthis = 1;
    int32_t dist_head;
    int32_t dist_tail;

    int direction;
    PROFILE_VARS;

    PREPROC_PROFILE_START(stream4InsertPerfStats);

    direction = GetDirection(ssn, p);

    /* select the right stream */
    if(direction == FROM_CLIENT)
    {
        if(!ssn->reassemble_client)
        {
            PREPROC_PROFILE_END(stream4InsertPerfStats);
            return;
        }

        s = &ssn->client;

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Storing client packet (%d bytes)\n", 
                    p->pkth->caplen););

        /* Go ahead and detect ttl attacks if we already have one
           ttl from the stream

           since fragroute does this a lot, perhaps we should have a
           counter to avoid false positives.. -- cmg
         */

        if(s4data.ttl_limit)
        {
            if(ssn->ttl && p->iph->ip_ttl < 10)
            { /* have we already set a client ttl? */
                if(abs(ssn->ttl - p->iph->ip_ttl) >= s4data.ttl_limit) 
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_TTL_EVASION, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_TTL_EVASION_STR, /* msg string */
                            0);
                    PREPROC_PROFILE_END(stream4InsertPerfStats);
                    return;
                }
            } 
            else 
            {
                ssn->ttl = p->iph->ip_ttl; /* first packet we've seen,
                                              lets go ahead and set it. */
            }
        }
    }
    else
    {
        if(!ssn->reassemble_server)
        {
            PREPROC_PROFILE_END(stream4InsertPerfStats);
            return;
        }

        s = &ssn->server;

        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Storing server packet (%d bytes)\n", 
                                p->pkth->caplen););
    }

    if ((p->tcph->th_flags == 0) &&
        (ssn->session_flags & SSNFLAG_ESTABLISHED))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Dropping packet in established session "
                    "(%d bytes) without TCP Flags\n", p->pkth->caplen););

        if(s4data.evasion_alerts)
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_TCP_NO_ACK, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_TCP_NO_ACK_STR,/*msg string */
                    0);
        }

        PREPROC_PROFILE_END(stream4InsertPerfStats);
        return;
    }

    /* check for retransmissions of data that's already been ack'd */
    if(SEQ_LT(pkt_seq, s->last_ack) && (s->last_ack > 0) && 
       (direction == FROM_CLIENT))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"EVASIVE RETRANS: pkt seq: 0x%X "
                                "stream->last_ack: 0x%X\n", pkt_seq, s->last_ack););

        if(s4data.evasion_alerts)
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_EVASIVE_RETRANS, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_EVASIVE_RETRANS_STR, /* msg string */
                    0);
        }

        PREPROC_PROFILE_END(stream4InsertPerfStats);
        return;
    }

    /* check for people trying to write outside the window */
    if(((pkt_seq + p->dsize - s->last_ack) > s->win_size) && 
       (s->win_size > 0) && direction == FROM_CLIENT)
    {
        /*
         * got data out of the window, someone is FUCKING around or you've got
         * a really crappy IP stack implementaion (hello microsoft!)
         */
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "WINDOW VIOLATION: seq: 0x%X  "
                                "last_ack: 0x%X  dsize: %d  " "window: 0x%X\n", 
                                pkt_seq, s->last_ack, p->dsize, s->win_size););

        if(s4data.state_alerts)
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_WINDOW_VIOLATION, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_WINDOW_VIOLATION_STR, /* msg string */
                    0);
        }

        PREPROC_PROFILE_END(stream4InsertPerfStats);
        return;
    }

    if(!WithinSessionLimits(p, s))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[S4] Not within session limits!\n"););
        PREPROC_PROFILE_END(stream4InsertPerfStats);
        return;
    }

    /* check for timestamp of 0, ACK set (not SYN) in packet, and session
     * is established.  This should resolve problems with PAWs. */
    {
        u_int32_t timestamp;
        if (GetTcpTimestamp(p, &timestamp) == 1)
        {
            if ((timestamp == 0) &&
                (ssn->session_flags & SSNFLAG_ESTABLISHED) &&
                ((p->tcph->th_flags & (TH_SYN|TH_ACK)) == TH_ACK))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "Not inserting packet with 0 timestamp\n"););

                if(s4data.state_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_ZERO_TIMESTAMP, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_ZERO_TIMESTAMP_STR, /* msg string */
                            0);
                }

                PREPROC_PROFILE_END(stream4InsertPerfStats);
                return;
            }
        }
    }
    
    /* prepare a place to put the data */
    if(s->state < ESTABLISHED)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "WARNING: Data on unestablished "
                    "session state: %d)!\n", s->state););
        PREPROC_PROFILE_END(stream4InsertPerfStats);
        return;
    }

    /* PERFORMANCE */
    /* If packet is > 2x flush point and seglist is empty, don't insert */
    if (s4data.large_packet_performance &&
        !s->seglist && (p->dsize > (ssn->flush_point * 2)))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "WARNING: Data larger than "
                    "twice flushpoint.  It would result in an immediate "
                    "flush on receipt of the ACK.\n"
                    "Not inserting for reassembly: seq: %d, size %d!\n"
                    "This is a tradeoff of performance versus the remote "
                    "possibility of catching an exploit that spans two or "
                    "more consecuvitve large packets.\n",
                    pkt_seq, p->dsize););
        PREPROC_PROFILE_END(stream4InsertPerfStats);
        return;
    }

    /* Note, Packet will be fast-tracked if list is empty */
    if (Stream4PktFastTrack(s->seglist_tail, pkt_seq, len))
    {
        left = s->seglist_tail;
        right = NULL;
        ret = InsertPkt(s, p, len, 0 /* slide */, 0 /* trunc */,
                pkt_seq, left /* tail */, &spd);

        PREPROC_PROFILE_END(stream4InsertPerfStats);
        return;
    }

    /* Find the right place for this guy. */
    if (s->seglist && s->seglist_tail)
    {
        dist_head = pkt_seq - s->seglist->seq_num;
        dist_tail = pkt_seq - s->seglist_tail->seq_num;
    }
    else
    {
        dist_head = dist_tail = 0;
    }
    if (dist_head <= dist_tail)
    {
        /* Start iterating at the head (left) */
        for (spd = s->seglist; spd; spd = spd->next)
        {
            right = spd;
            if (SEQ_GEQ(right->seq_num, pkt_seq))
                break;

            left = right;
        }

        if (spd == NULL)
            right = NULL;

    }
    else
    {
        /* Start iterating at the tail (right) */
        for (spd = s->seglist_tail; spd; spd = spd->prev)
        {
            left = spd;
            if (SEQ_LT(left->seq_num, pkt_seq))
                break;

            right = left;
        }

        if (spd == NULL)
            left = NULL;
    }

    if (left)
    {
        overlap = (int)(left->seq_num + (u_int32_t)left->payload_size - pkt_seq);

        if (overlap > 0)
        {
            s->overlap_pkts++;
            /* Left overlap */
            if(s4data.evasion_alerts)
            {
                SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                        STREAM4_EVASIVE_RETRANS_DATA, /* SID */
                        1,                      /* Rev */
                        0,                      /* classification */
                        3,                      /* priority (low) */
                        STREAM4_EVASIVE_RETRANS_DATA_STR,/*msg string */
                        0);
            }

            switch (s4data.reassy_method )
            {
                case METHOD_FAVOR_OLD:
                    seq += overlap;
                    slide = overlap;
                    if (SEQ_LEQ(seq_end, seq))
                    {
                        /* 
                         * Nothing to do, new packet was wholly overlapped
                         */
                        PREPROC_PROFILE_END(stream4InsertPerfStats);
                        return;
                    }
                    break;
                case METHOD_FAVOR_NEW:
                    /* True "new" policy */
                    if ((left->seq_num < seq) && (left->seq_num + left->payload_size > (seq + len)))
                    {
                        /* New data is overlapped on both sides by existing
                         * data.  Existing data needs to be split and the
                         * new data inserted in the middle.
                         *
                         * Need to duplicate left.  Adjust that
                         * seq_num by + (seq_num + len) and 
                         * size by - (seqnum + len - left->seq_num)
                         */
                        ret = DupSpd(p, s, left, &right);
                        if (ret)
                        {
                            PREPROC_PROFILE_END(stream4InsertPerfStats);
                            return;
                        }
                        left->payload_size -= overlap;
                        StreamSegmentSub(s, (u_int16_t)overlap);
                    }
                    else
                    {
                        left->payload_size -= overlap;
                        StreamSegmentSub(s, (u_int16_t)overlap);
                    }
                    if (left->payload_size <= 0)
                    {
                        /* Left was wholly overlapped, blow it away */
                        dump = left;

                        left = left->prev;
                        dump = RemoveSpd(s, dump);
                        stream4_memory_usage -= dump->pkt_size;
                        free(dump->pktOrig);
                        stream4_memory_usage -= sizeof(StreamPacketData);
                        free(dump);
                    }
                    break;
            }

            if (SEQ_LEQ(seq_end, seq))
            {
                PREPROC_PROFILE_END(stream4InsertPerfStats);
                return;
            }
        }
        else
        {
            /* No left overlap */
        }
    }

    while (right && !done && SEQ_LT(right->seq_num, seq_end))
    {
        trunc = 0;
        overlap = (int)(seq_end - right->seq_num);

        if (overlap < right->payload_size)
        {
            s->overlap_pkts++;

            /* Partial right overlap */
            switch(s4data.reassy_method)
            {
                case METHOD_FAVOR_NEW:
                    right->seq_num += overlap;
                    right->payload += overlap;
                    right->payload_size -= overlap;
                    StreamSegmentSub(s, (u_int16_t)overlap);
                    if (right->payload_size <= 0)
                    {
                        /* Left was wholly overlapped, blow it away */
                        dump = right;

                        right = right->next;
                        dump = RemoveSpd(s, dump);
                        stream4_memory_usage -= dump->pkt_size;
                        free(dump->pktOrig);
                        stream4_memory_usage -= sizeof(StreamPacketData);
                        free(dump);
                    }
                    break;
                case METHOD_FAVOR_OLD:
                    trunc = overlap;
                    break;
            }
            done = 1;
        }
        else
        {
            s->overlap_pkts++;
            /* Whole right overlap */

            /* Look to see if this is a retransmit of the original */
            if ((right->seq_num == seq) && (right->cksum == p->tcph->th_sum))
            {
                /* RETRANSMISSION.  */
                /* Packet was analyized the first time.
                 * No need to continue looking at it.
                 */
                DisableDetect(p);

                /* Still want to add this number of bytes to totals */
                SetPreprocBit(p, PP_PERFMONITOR);

                if (InlineMode())
                {
                    /* We examined it previously. */
                    if (right->blocked == 1)
                    {
                        /* It was previously blocked.  Block it again */
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "Dropping retransmitted packet -- "
                            "blocked previously\n"););
                        InlineDrop(p);
                    }
                    else
                    {
                        /* It was previously not blocked.  Allow through */
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "Allowing retransmitted packet -- "
                            "not blocked previously\n"););
                    }
                }

                PREPROC_PROFILE_END(stream4InsertPerfStats);
                return;
            }
            else if ((right->seq_num == seq) &&
                     (right->payload_size >= p->dsize))
            {
                if(s4data.evasion_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_EVASIVE_RETRANS_DATA, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_EVASIVE_RETRANS_DATA_STR,/*msg string */
                            0);
                }
            }

            switch(s4data.reassy_method)
            {
                case METHOD_FAVOR_OLD:
                    if (right->seq_num == seq)
                    {
                        slide = (right->seq_num + right->payload_size - seq);
                        seq += slide;
                        left = right;
                        right = right->next;

                        if (right && (seq == right->seq_num))
                        {
                            /* same seq as next packet don't insert yet... keep
                             * going.
                             */
                            continue;
                        }
                    }
                    else
                    {
                        trunc += overlap;
                    }
                    if (seq_end - trunc <= seq)
                    {
                        PREPROC_PROFILE_END(stream4InsertPerfStats);
                        return;
                    }

                    ret = InsertPkt(s, p, len, slide, trunc, seq, left, &spd);
                    if (ret)
                    {
                        PREPROC_PROFILE_END(stream4InsertPerfStats);
                        return;
                    }

                    {
                        u_int32_t curr_end = spd->seq_num + spd->payload_size;

                        while (right &&
                               (curr_end <= right->seq_num) &&
                               (right->seq_num < seq_end))
                        {
                            curr_end = right->seq_num + right->payload_size;
                            left = right;
                            right = right->next;
                        }

                        if (right && (right->seq_num < seq_end))
                        {
                            /* Adjust seq to end of 'right' */
                            seq = right->seq_num + right->payload_size;

                            /* Not overlapping on the left any more */
                            slide = 0;

                            /* Set 'left' so the next insert goes after
                             * the current 'right' */
                            left = right;

                            /* Reset trunc, in case the next one kicks us
                             * out of the loop.  This packet will become
                             * the rightmost entry so far.  Don't
                             * truncate any further.
                             */
                            trunc = 0;

                            if (right->next)
                                continue;
                        }

                        if (curr_end < seq_end)
                        {
                            /* Insert this one into the proper sport,
                             * and adjust offset to the right-most
                             * endpoint so far.
                             */
                            slide = left->seq_num + left->payload_size - seq;
                            seq = curr_end;
                            trunc = 0;
                        }
                        else
                        {
                            addthis = 0;
                        }
                    }
                    break;
                case METHOD_FAVOR_NEW:
                    dump = right;
                    right = right->next;
                    StreamSegmentSub(s, dump->payload_size);
                    dump = RemoveSpd(s, dump);
                    stream4_memory_usage -= dump->pkt_size;
                    free(dump->pktOrig);
                    stream4_memory_usage -= sizeof(StreamPacketData);
                    free(dump);
                    break;
            }
        }
    }

    if (addthis)
    {
        ret = InsertPkt(s, p, len, slide, trunc, seq, left, &spd);
    }
    else
    {
        /* Fully trunc'd right overlap */
    }

    PREPROC_PROFILE_END(stream4InsertPerfStats);
    return;
}



void FlushStream(Stream *s, Packet *p, int direction)
{
    int stream_size;
    char gotevent = 0;
    char build_pkt = 1;
    char built_one = 0;
    PROFILE_VARS;

    PREPROC_PROFILE_START(stream4FlushPerfStats);

    sfPerf.sfBase.iStreamFlushes++;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "FlushStream Entered:"
                "last_ack(%u) base_seq(%u) pkt_count(%u)\ng",
                s->last_ack, s->base_seq, s->pkt_count););

    while (build_pkt && s->seglist)
    {
        stream_size = s->last_ack - s->base_seq;

        /* 
         ** FINs consume one byte, but they have no data.
         **
         ** NOTE:
         **   This already appears to be compensated for when we receive FINS,
         **   and this causes an off-by-one bug when implemented.
         */
        /*if(s->state == FIN_WAIT_2 || s->state == TIME_WAIT) stream_size--;*/

        if(stream_size >= MAX_STREAM_SIZE)
        {
#ifdef DEBUG        
            DebugMessage(DEBUG_STREAM,
                    "stream_size(%u) > MAX_STREAM_SIZE(%u)\n",
                    stream_size, MAX_STREAM_SIZE);

            DebugMessage(DEBUG_STREAM,
                    "Adjusting s->base_seq(%u) -> %u %u\n",
                    s->base_seq, s->last_ack - MAX_STREAM_SIZE,
                    s->last_ack - (MAX_STREAM_SIZE));

#endif /* DEBUG */
            stream_size = MAX_STREAM_SIZE - 1;
            s->base_seq = s->last_ack - stream_size;
        }

        if(stream_size > 0 && s->seglist)
        {
            /* put the stream together into a packet or something */
            if(BuildPacket(s, stream_size, p, direction))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Passing large packet "
                        "on 0 size stream cache\n"););
                build_pkt = 0;
                stream_pkt->dsize = 0;
            }

            /* If we aren't within session limits, we can try to build a
             * packet and end up with no data */
            if(stream_pkt->dsize > 0)
            {
                int tmp_do_detect, tmp_do_detect_content;
                PROFILE_VARS;
                /* Calc ticks to process the rebuild packet */
                PREPROC_PROFILE_START(stream4ProcessRebuiltPerfStats);

                /* Save off do_detect flags and reset them after Preprocess
                 * returns.  Since other preprocessors may turn off detection
                 * for other things with the rebuilt packet, we don't want that
                 * to affect this packet.
                 */
                tmp_do_detect = do_detect;
                tmp_do_detect_content = do_detect_content;
                gotevent = Preprocess(stream_pkt);
                do_detect = tmp_do_detect;
                do_detect_content = tmp_do_detect_content;
                PREPROC_PROFILE_END(stream4ProcessRebuiltPerfStats);

                if(s4data.zero_flushed_packets)
                    bzero(stream_pkt->data, stream_pkt->dsize);

                if ( p->ssnptr )
                {
                    /* Reset alert tracking after flushing rebuilt packet */
                    Session *ssn = p->ssnptr;

                    CleanSessionAlerts(ssn, stream_pkt);
                }

                if(gotevent)
                {
                    LogStream(s);
                }

                /* Built something, cleanup, try next seq */
                SegmentCleanTraverse(s);
                built_one = 1;
                if (s4data.seq_gap)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                                "Sequence Gap, SINGLE PACKET\n"););
                    if (s->seglist)
                    {
                        s->base_seq = s->seglist->seq_num;
                    }
                    else
                    {
                        s->base_seq = s->last_ack;
                    }
                    if (s->seglist && (s->seglist->chuck == SEG_PARTIAL))
                    {
                        /* only part of the 1st packet was used because it
                         * extended beyond the current ack.  Stop here. */
                        build_pkt = 0;
                    }
                    else
                    {
                        /* try to build the next reassembly after
                         * the gap.  */
                        build_pkt = 1;
                    }
                }
                else
                {
                    /* No gap, we're done with this rebuild */
                    build_pkt = 0;
                }
            }
            else
            {
                /* Zero sized packet */
                if (s4data.seq_gap)
                {
                    /* If zero sized packet is because of a gap,
                     * clean out the single packet, move base_seq,
                     * and try to build the next reassembly after gap.
                     */
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                                "Sequence Gap, SINGLE PACKET\n"););
                    SegmentCleanTraverse(s);
                    if (s->seglist)
                    {
                        s->base_seq = s->seglist->seq_num;
                    }
                    else
                    {
                        s->base_seq = s->last_ack;
                    }
                    if (s->pkt_count > 1)
                    {
                        /* zero sized packet because of gap. */

                        if (s->seglist && (s->seglist->chuck == SEG_PARTIAL))
                        {
                            /* only part of the 1st packet was used because it
                             * extended beyond the current ack.  Stop here. */
                            build_pkt = 0;
                        }
                        else
                        {
                            /* try to build the next reassembly after
                             * the gap.  */
                            build_pkt = 1;
                        }
                    }
                    else
                    {
                        /* No gap, zero sized packet (probably single),
                         * we're done with this rebuild */
                        build_pkt = 0;
                    }
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                                "Sequence Gap, SINGLE PACKET\n"););
                    SegmentCleanTraverse(s);
                    /* No gap, zero sized packet (probably single),
                     * we're done with this rebuild */
                    build_pkt = 0;
                }
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,"Passing large packet on "
                        "0 size stream cache\n"););
            /* Nothing to do */
            build_pkt = 0;
        }
    }

    if (built_one)
    {
        PREPROC_PROFILE_END(stream4FlushPerfStats);
        return;
    }

#if 0
    s->bytes_tracked = 0;
    s->overlap_pkts = 0;
    DeleteSpd(&s->seglist);
    s->seglist_tail = NULL;
    s->pkt_count = 0;
#endif

    PREPROC_PROFILE_END(stream4FlushPerfStats);
}



/**
 * Flush the side of the TCP stream that just caused an alert.
 *
 * This function is exported for the detection engine.
 *
 * This routine takes a packet, logs out the stream packets ( so that
 * we have original payloads around ), and then updates the stream
 * tracking sequence numbers so that
 * 
 * @param p Packet to flush the stream reassembler on
 * 
 * @return the number of packets that have been flushed from the stream reassembler
 */
int AlertFlushStream(Packet *p)
{
    Session *ssn;
    Stream *stream;
    int nodecount = 0;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Flushing stream due to an alert!\n"););

    if(NotForStream4(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Don't Flush a Rebuilt Stream\n"););
        return 0;
    }
    
    if (!p->ssnptr)
        return 0;

    ssn = p->ssnptr;

    if(!s4data.flush_on_alert)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Don't Flush a Rebuilt Stream on Alert from indviidual packet\n"););
        return 0;
    }

    if(ssn == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Nothing to Flush!\n"););
        return 0;
    }

    if(GetDirection(ssn, p) == FROM_SERVER)
    {
        stream = &ssn->server;

        if(ssn->reassemble_server)
        {
            FlushStream(stream, p, NO_REVERSE);
        }
        else
        { 
            /*
            **  We handle this part of deleting the stream, because
            **  FlushStream() didn't handle it for us.
            */
            DeleteSpd(&stream->seglist);
            stream->seglist_tail = NULL;
            stream->pkt_count = 0;
            stream->bytes_tracked = 0;
            stream->overlap_pkts = 0;
        }
    }
    else
    {
        stream = &ssn->client;

        if(ssn->reassemble_client)
        {
            FlushStream(stream, p, NO_REVERSE);
        }
        else
        { 
            /*
            **  We handle this part of deleting the stream, because
            **  FlushStream() didn't handle it for us.
            */
            DeleteSpd(&stream->seglist);
            stream->seglist_tail = NULL;
            stream->pkt_count = 0;
            stream->bytes_tracked = 0;
            stream->overlap_pkts = 0;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[AFS] Bytes Tracked: %u\n", 
                stream->bytes_tracked););
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[AFS] Bytes Tracked: %u\n", 
                stream->bytes_tracked););

    if(p->tcph)
    {
        stream->base_seq = ntohl(p->tcph->th_seq) + p->dsize;
        stream->last_ack = stream->base_seq;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Moved the base_seq to %u!\n",
                stream->base_seq););

    return nodecount;
}

/**
 * Force flusinging the client side of the TCP stream.
 *
 * This function is exported for the preprocessors.
 *
 * This routine takes a packet, logs out the stream packets ( so that
 * we have original payloads around ), and then updates the stream
 * tracking sequence numbers so that
 * 
 * @param p Packet to flush the stream reassembler on
 * 
 * @return the number of packets that have been flushed from the stream reassembler
 */
int ForceFlushStream(Packet *p)
{
    Session *ssn;
    Stream *stream;
    int nodecount = 0;
    u_int32_t count;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Flushing stream upon request!\n"););

    if(NotForStream4(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Don't Flush a Rebuilt Stream\n"););
        return 0;
    }

    if (!p->ssnptr)
        return 0;

    ssn = p->ssnptr;

    if(ssn == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Nothing to Flush!\n"););
        return 0;
    }

    /* Always flushing the client side */
    {
        stream = &ssn->client;
        count = stream->pkt_count;

        if(ssn->reassemble_client)
        {
            if (p->packet_flags & PKT_FROM_SERVER)
            {
                FlushStream(stream, p, REVERSE);
            }
            else
            {
                FlushStream(stream, p, NO_REVERSE);
            }
        }
        else
        { 
            /*
            **  We handle this part of deleting the stream, because
            **  FlushStream() didn't handle it for us.
            */
            DeleteSpd(&stream->seglist);
            stream->seglist_tail = NULL;
            stream->pkt_count = 0;
            stream->bytes_tracked = 0;
        }

        if (stream->pkt_count != count)
        {
            /* Only update if we reassembled and removed packets */
            ssn->client.base_seq = ssn->client.last_ack;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[AFS] Bytes Tracked: %u\n", 
                stream->bytes_tracked););

    return nodecount;
}


/** 
 * Log out the Stream if possible
 *
 * only works with pcap currently
 *
 * @todo make this work with a newer output subsystem
 * 
 * @param s stream to log the data from
 * 
 * @return number of nodes in the data
 */
int LogStream(Stream *s)
{
    int nodecount = 0;
   
    if((pv.log_bitmap & LOG_TCPDUMP) && s4data.log_flushed_streams)
    {
        nodecount = s->pkt_count;
        {
            StreamPacketData *spd = s->seglist;
            while (spd)
            {
                if (spd->chuck == SEG_UNASSEMBLED)
                    break;
                LogTraverse(spd, NULL);
                spd = spd->next;
            }
        }
    }

    return nodecount;
}

extern unsigned int num_preprocs;

void InitStream4Pkt()
{
    stream_pkt->pkth = calloc(sizeof(SnortPktHeader)+
                              ETHERNET_HEADER_LEN +
                              SPARC_TWIDDLE + IP_MAXPACKET,
                              sizeof(char));
    if (stream_pkt->pkth == NULL)
    {
        FatalError("InitStream4Pkt() => Failed to allocate memory\n");
    }

    stream_pkt->pkt = ((u_int8_t *)stream_pkt->pkth) + sizeof(SnortPktHeader);
    stream_pkt->eh = (EtherHdr *)((u_int8_t *)stream_pkt->pkt + SPARC_TWIDDLE);
    stream_pkt->iph =
        (IPHdr *)((u_int8_t *)stream_pkt->eh + ETHERNET_HEADER_LEN);
    stream_pkt->tcph = (TCPHdr *)((u_int8_t *)stream_pkt->iph + IP_HEADER_LEN);    

    stream_pkt->data = (u_int8_t *)stream_pkt->tcph + TCP_HEADER_LEN;

    /* stream_pkt->data is now pkt +
     *  IPMAX_PACKET - (IP_HEADER_LEN + TCP_HEADER_LEN + ETHERNET_HEADER_LEN)
     *  in size
     *
     * This is MAX_STREAM_SIZE
     */

    stream_pkt->eh->ether_type = htons(0x0800);
    SET_IP_VER(stream_pkt->iph, 0x4);
    SET_IP_HLEN(stream_pkt->iph, 0x5);
    stream_pkt->iph->ip_proto = IPPROTO_TCP;
    stream_pkt->iph->ip_ttl   = 0xF0;
    stream_pkt->iph->ip_len = 0x5;
    stream_pkt->iph->ip_tos = 0x10;

    SET_TCP_OFFSET(stream_pkt->tcph,0x5);
    stream_pkt->tcph->th_flags = TH_PUSH|TH_ACK;

    stream_pkt->preprocessor_bits = (BITOP *)SnortAlloc(sizeof(BITOP));
    boInitBITOP(stream_pkt->preprocessor_bits, num_preprocs + 1);
}



/** 
 * Build a new stream packet from 
 * 
 * @param s Stream storage variables
 * @param stream_size size of the newly assembled stream ( should be less than 2^16 - 41
 * @param p packet that caused us to flush
 * @param direction which are we flushing
 *
 * @returns 0 on success, -1 if we didn't get enough data to create the packet
 */
int BuildPacket(Stream *s, u_int32_t stream_size, Packet *p, int direction)
{
    BuildData bd;
    unsigned short zero_size = 1500;
    Session *ssn;
    u_int32_t ip_len; /* total length of the IP datagram */
    u_int32_t last_seq = 0;
    PROFILE_VARS;

    PREPROC_PROFILE_START(stream4BuildPerfStats);
    s4data.stop_traverse = 0;
    s4data.seq_gap = 0;

    bd.stream = s;
    bd.buf = stream_pkt->data;
    bd.total_size = 0;

    /* walk the packet tree (in order) and rebuild the app layer data */
    {
        StreamPacketData *spd = s->seglist;

        /* If first packet in the queue isn't the base sequence,
         * adjust the base so that we're starting at offset 0
         * when the data is copied.
         */
        if (spd->seq_num != s->base_seq)
        {
            s->base_seq = spd->seq_num;
        }
        stream_pkt->tcph->th_seq = htonl(s->base_seq);

        while (spd && !s4data.stop_traverse)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                    "Adding to rebuilt packet seq %d, %d bytes, %s\n",
                    (u_int32_t)spd->seq_num, spd->payload_size, spd->payload););
            /* If this is the first packet and there is a gap or nothing
             * following it, no point to reassembling the single packet. 
             * We already analyzed the data with the original packet.  Just
             * bail IF we're allowed to ignore single packets -- ignore
             * single packets is not set on a ForceFlush, (via the StreamAPI
             * called by preprocessors).  It is set as part of a regular
             * flush, because of ACKd data beyond the flushpoint.
            */
            if (bd.total_size == 0 && (s->flags & IGNORE_SINGLE_PKTS))
            {
                if (spd->next)
                {
                    /* PERFORMANCE */
                    /* If the next packet isn't the one immediately
                     * following, we have a missing packet.  Stop the
                     * reassembly here and process what we've got. */
                    if ((spd->seq_num + spd->payload_size)
                                != spd->next->seq_num)
                    {
                        s4data.seq_gap = 1;
                        /* Set these to recalculate the size of the
                         * Rebuilt packet */
                        s4data.stop_traverse = 1;
                        s4data.stop_seq = spd->seq_num + spd->payload_size;
                        stream_pkt->dsize = 0;

                        /* If this packet ends before the ACK we're
                         * using, mark it as used.
                         */
                        if (s4data.stop_seq <= s->last_ack)
                        {
                            spd->chuck = SEG_FULL;
                        }
                        else if (spd->seq_num < s->last_ack)
                        {
                            spd->chuck = SEG_PARTIAL;
                        }
                        PREPROC_PROFILE_END(stream4BuildPerfStats);
                        return 0;
                    }
                }
                else
                {
                    if (s->flags & FIRST_FLUSH_DONE)
                    {
                        /* PERFORMANCE */
                        /* No next packet...  */
                        s4data.seq_gap = 1;

                        /* Set these to recalculate the size of the
                         * Rebuilt packet */
                        s4data.stop_traverse = 1;
                        s4data.stop_seq = spd->seq_num + spd->payload_size;

                        stream_pkt->dsize = 0;
                        PREPROC_PROFILE_END(stream4BuildPerfStats);
                        return 0;
                    }
                }
            }

            TraverseFunc(spd, &bd);
            last_seq = spd->seq_num + spd->payload_size;
            s->flags |= FIRST_FLUSH_DONE;
            if (spd->next)
            {
                /* PERFORMANCE */
                /* If the next packet isn't the one immediately
                 * following, we have a missing packet.  Stop the
                 * reassembly here and process what we've got. */
                if ((spd->seq_num + spd->payload_size)
                                != spd->next->seq_num)
                {
                    s4data.seq_gap = 1;

                    /* Set these to recalculate the size of the
                     * Rebuilt packet */
                    s4data.stop_traverse = 1;
                    s4data.stop_seq = spd->seq_num + spd->payload_size;
                    break;
                }
            }
            spd = spd->next;
        }
    }

    /* Adjust the size of the rebuilt packet because of gaps */
    if(bd.total_size < stream_size)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "bd.total_size(%u) < stream_size(%u):"
                    "Incomplete segment -- packet loss or weird\n",
                    bd.total_size, stream_size););

        /* This is probably because we were past our session limits --
           there's nothing of value in this packet */
        if(bd.total_size == 0)
        {
            stream_pkt->dsize = 0;
            PREPROC_PROFILE_END(stream4BuildPerfStats);
            return -1;
        }

        if (bd.total_size == (last_seq - s->base_seq))
        {
            /* In this case... last_seq is the before we
             * stopped because of a missing packet. */
            stream_size = bd.total_size;

            /*
            **  Final sanity check for stream_size.  Make sure that the
            **  stream_size is not bigger than our buffer.
            */
            if(stream_size >= MAX_STREAM_SIZE)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                            "Truncating %d bytes from stream",
                            stream_size - MAX_STREAM_SIZE););

                stream_size = MAX_STREAM_SIZE - 1;
            }
        }
    }
    else if(bd.total_size > stream_size)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "stream_size(%u) < bd.total_size(%u):"
                    "Overlapping segments -- packet loss or weird\n",
                    stream_size, bd.total_size););
    }

    /* This is set in TraverseFunc when we reach a point that we
     * haven't ack'd to yet. Let's just go catch it next time.
     */
    if(s4data.stop_traverse && !s4data.seq_gap)
    {
        if(s4data.stop_seq < s->base_seq)
        {
            stream_size = s->base_seq - s4data.stop_seq;
        }
        else
        {
            stream_size = s4data.stop_seq - s->base_seq;
        }

        /*
        **  Final sanity check for stream_size.  Make sure that the
        **  stream_size is not bigger than our buffer.
        */
        if(stream_size >= MAX_STREAM_SIZE)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Truncating %d bytes from stream",
                        stream_size - MAX_STREAM_SIZE););

            stream_size = MAX_STREAM_SIZE - 1;
        }
    }
    else
    {
        //stream_pkt->dsize = (unsigned short)stream_size;
    }

    /* Setup the protocol header fields here.
     * If we have no data to reassemble, it saves on a
     * few instructions and memcpys
     */
    ip_len = stream_size + IP_HEADER_LEN + TCP_HEADER_LEN;

    stream_pkt->pkth->ts.tv_sec = s->seglist->pkth.ts.tv_sec;
    stream_pkt->pkth->ts.tv_usec = s->seglist->pkth.ts.tv_usec;

    stream_pkt->pkth->caplen = ip_len + ETHERNET_HEADER_LEN;
    stream_pkt->pkth->len    = stream_pkt->pkth->caplen;

    stream_pkt->iph->ip_len = htons((u_short) ip_len);
    stream_pkt->dsize = (unsigned short)stream_size;

    if(direction == REVERSE)
    {
        if(p->eh != NULL)
        {
            /* Set reassembled ethernet header since it may have been
             * removed earlier for different stream. */
            stream_pkt->eh = (EtherHdr *)((u_int8_t *)stream_pkt->pkt + SPARC_TWIDDLE);
            memcpy(stream_pkt->eh->ether_dst, p->eh->ether_src, 6);
            memcpy(stream_pkt->eh->ether_src, p->eh->ether_dst, 6);
        }
        else
        {
            /* No ether header in original packets, remove it from the
             * reassembled one. */
            stream_pkt->eh = NULL;
            stream_pkt->pkth->caplen -= ETHERNET_HEADER_LEN;
            stream_pkt->pkth->len -= ETHERNET_HEADER_LEN;
        }

        stream_pkt->tcph->th_sport = p->tcph->th_dport;
        stream_pkt->tcph->th_dport = p->tcph->th_sport;
        stream_pkt->iph->ip_src.s_addr = p->iph->ip_dst.s_addr;
        stream_pkt->iph->ip_dst.s_addr = p->iph->ip_src.s_addr;
        stream_pkt->sp = p->dp;
        stream_pkt->dp = p->sp;
        stream_pkt->tcph->th_ack = p->tcph->th_seq;
    }
    else
    {
        if(p->eh != NULL)
        {
            /* Set reassembled ethernet header since it may have been
             * removed earlier for different stream. */
            stream_pkt->eh = (EtherHdr *)((u_int8_t *)stream_pkt->pkt + SPARC_TWIDDLE);
            memcpy(stream_pkt->eh->ether_dst, p->eh->ether_dst, 6);
            memcpy(stream_pkt->eh->ether_src, p->eh->ether_src, 6);
        }
        else
        {
            /* No ether header in original packets, remove it from the
             * reassembled one. */
            stream_pkt->eh = NULL;
            stream_pkt->pkth->caplen -= ETHERNET_HEADER_LEN;
            stream_pkt->pkth->len -= ETHERNET_HEADER_LEN;
        }

        stream_pkt->tcph->th_sport = p->tcph->th_sport;
        stream_pkt->tcph->th_dport = p->tcph->th_dport;
        stream_pkt->iph->ip_src.s_addr = p->iph->ip_src.s_addr;
        stream_pkt->iph->ip_dst.s_addr = p->iph->ip_dst.s_addr;
        stream_pkt->sp = p->sp;
        stream_pkt->dp = p->dp;
        stream_pkt->tcph->th_ack = p->tcph->th_ack;
    }
    stream_pkt->tcph->th_win = p->tcph->th_win;

    /* A few other maintenance items -- set some flags, no TCP options */
    s4data.stop_traverse = 0;

    stream_pkt->tcp_option_count = 0;
    stream_pkt->tcp_lastopt_bad = 0;
    stream_pkt->packet_flags = (PKT_REBUILT_STREAM|PKT_STREAM_EST);

    ssn = p->ssnptr;
    stream_pkt->ssnptr = p->ssnptr;

    stream_pkt->streamptr = (void *) s;

    if(stream_pkt->sp == ssn->client.port)
    {
        stream_pkt->packet_flags |= PKT_FROM_CLIENT;
    }
    else
    {
        stream_pkt->packet_flags |= PKT_FROM_SERVER;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                "Built packet to %s from %x with %u byte payload, "
                "Direction: %s\n",
                inet_ntoa(stream_pkt->iph->ip_src),
                stream_pkt->iph->ip_dst,
                stream_pkt->dsize,
                (stream_pkt->packet_flags & PKT_FROM_SERVER)
                ? "from_server" : "from_client"););

    pc.rebuilt_tcp++;

#ifdef DEBUG
    if(stream_pkt->packet_flags & PKT_FROM_CLIENT)
    {
        DebugMessage(DEBUG_STREAM, "packet is from client!\n");
    }

    if(stream_pkt->packet_flags & PKT_FROM_SERVER)
    {
        DebugMessage(DEBUG_STREAM, "packet is from server!\n");
    }

    if (DEBUG_STREAM & GetDebugLevel())
    {
        //ClearDumpBuf();
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        PrintIPPkt(stdout, IPPROTO_TCP, stream_pkt);
        printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
        //ClearDumpBuf();
        /*printf("Printing app buffer at %p, size %d\n", 
          stream_pkt->data, stream_pkt->dsize);
          PrintNetData(stdout, stream_pkt->data, stream_pkt->dsize);
          ClearDumpBuf();*/
    }
#endif

    /* are we within our data loss limits? */
    if(abs(stream_pkt->dsize - bd.total_size) >= s4data.flush_data_diff_size)
    {
        /* leave a null packet if we tried to reassemble and failed */
        if(s4data.zero_flushed_packets)
        {
            /* stream_size is uint so can't be negative */
            if(stream_size && stream_size < zero_size)
            {
                zero_size = (unsigned short)stream_size;
            }

            if(zero_size > 0)
                bzero(stream_pkt->data, zero_size);
        }
    }
    PREPROC_PROFILE_END(stream4BuildPerfStats);

    return 0;
}


int CheckPorts(u_int16_t port1, u_int16_t port2)
{
    switch(s4_emergency.status)
    {
        case OPS_NORMAL:
            if(s4data.assemble_ports[port1] || s4data.assemble_ports[port2])
            {
                return 1;
            }
            break;

        case OPS_SELF_PRESERVATION:
            if(s4data.emergency_ports[port1] || s4data.emergency_ports[port2])
            {
                return 1;
            }
            break;
    }

    return 0;
}


void OpenStatsFile()
{
    time_t curr_time;      /* place to stick the clock data */
    char logdir[STD_BUF];
    int value;
    StatsLogHeader hdr;

    bzero(logdir, STD_BUF);
    curr_time = time(NULL);

    if(stats_log->filename[0] == '/')
        value = SnortSnprintf(logdir, STD_BUF, "%s.%lu", stats_log->filename, 
                         (unsigned long)curr_time);
    else
        value = SnortSnprintf(logdir, STD_BUF, "%s/%s.%lu", pv.log_dir, 
                         stats_log->filename, (unsigned long)curr_time);

    if(value != SNORT_SNPRINTF_SUCCESS)
    {
        FatalError("ERROR: log file logging path and file name are "
                   "too long, aborting!\n");
    }

    printf("stream4:OpenStatsFile() Opening %s\n", logdir);

    if((stats_log->fp=fopen(logdir, "w+")) == NULL)
    {
        FatalError("stream4:OpenStatsFile(%s): %s\n", logdir, strerror(errno));
    }

    hdr.magic = STATS_MAGIC;
    hdr.version_major = 1;
    hdr.version_minor = 81;
    hdr.timezone = 1;

    if(fwrite((char *)&hdr, sizeof(hdr), 1, stats_log->fp) != 1)
    {
        FatalError("stream4:OpenStatsFile(): %s\n", strerror(errno));
    }
        
    fflush(stats_log->fp);

    /* keep a copy of the filename for later reference */
    if(stats_log->filename != NULL)
    {
        free(stats_log->filename);

        stats_log->filename = strdup(logdir);
    }

    return;
}



void WriteSsnStats(BinStats *bs)
{
    fwrite(bs, sizeof(BinStats), 1, stats_log->fp);
    fflush(stats_log->fp);
    return;
}

static void TcpAction(Session *ssn, Packet *p, int action, int direction, 
                      u_int32_t pkt_seq, u_int32_t pkt_ack)
{
    u_int32_t count;
    PROFILE_VARS;

    PREPROC_PROFILE_START(stream4ActionPerfStats);
    if(action == ACTION_NOTHING)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "returning -- action nothing\n"););
        PREPROC_PROFILE_END(stream4ActionPerfStats);
        return;
    }
    else 
    {
        if((action & ACTION_SET_SERVER_ISN) &&
                (ssn->session_flags & SSNFLAG_MIDSTREAM))
        {
            /* Someone convinced us the session was going and then is
             * trying to convince us that we should be tracking this
             * session -- the server has the best chance of knowing
             * what it's really seeing.
             */

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                        "Midstream session SYN-ACK; setting seqs;" 
                        "removing midstream notification\n"););
            ssn->client.last_ack = pkt_ack;
            ssn->server.last_ack = pkt_seq;

            ssn->server.base_seq = ssn->server.last_ack;
            ssn->client.base_seq = ssn->client.last_ack;

            /* Once we reach here, the session is no longer a
               midstream session */

            //ssn->session_flags &= (SSNFLAG_ALL ^ SSNFLAG_MIDSTREAM);
        }      
        else if(action & ACTION_SET_SERVER_ISN)
        {
            ssn->server.isn = pkt_seq;
            ssn->client.win_size = ntohs(p->tcph->th_win);

            if(pkt_ack == (ssn->client.isn+1))
            {
                ssn->client.last_ack = ssn->client.isn+1;
            }
            else
            {
                /* we got a messed up response from the server */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "WARNING: Got unexpected SYN ACK from server!\n");
                        DebugMessage(DEBUG_STREAM, 
                            "expected: 0x%X   received: 0x%X\n"););
                ssn->client.last_ack = pkt_ack;
            }
        }

        /* complete a three way handshake */
        if(action & ACTION_COMPLETE_TWH)
        {
            /*
            **  Set a packet flag to say that the TWH has been
            **  completed.
            */
            p->packet_flags |= PKT_STREAM_TWH;

            /* this should be isn+1 */
            if(pkt_ack == ssn->server.isn+1)
            {
                ssn->server.last_ack = ssn->server.isn+1;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "WARNING: Fishy TWH from client "
                            "(0x%X:%d->0x%X:%d) (ack: 0x%X  isn: 0x%X)\n", 
                            p->iph->ip_src.s_addr, p->sp, p->iph->ip_dst.s_addr, 
                            p->dp, pkt_ack, ssn->server.isn););

                ssn->server.last_ack = pkt_ack;
            }

            ssn->server.base_seq = ssn->server.last_ack;
            ssn->client.base_seq = ssn->client.last_ack;
        }

        /* 
         * someone sent data in their SYN packet, classic sign of someone
         * doing bad things (or a bad ip stack/piece of equipment)
         */
        if(action & ACTION_DATA_ON_SYN)
        {
            if(p->tcph->th_flags & TH_SYN)
            {
                /* alert... */
                if(s4data.evasion_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_DATA_ON_SYN, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_DATA_ON_SYN_STR, /* msg string */
                            0);
                }

                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "WARNING: Data on SYN packet!\n"););
                PREPROC_PROFILE_END(stream4ActionPerfStats);
                return;
            }
        }

        if(action & ACTION_INC_PORT)
        {
            ssn->client.port++;
        }

        /* client sent some data */
        if(action & ACTION_ACK_CLIENT_DATA)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "client.base_seq(%u) client.last_ack(%u) offset(%u)\n",
                        ssn->client.base_seq,ssn->client.last_ack,
                        (ssn->client.last_ack - ssn->client.base_seq)););

            if((p->tcph->th_flags & TH_RST) && pkt_ack == 0)
            {
                /* Do not change where the side has seen upon a
                 * "nonestablished reset" */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[R] Reset Handled\n"););
            }
            /* Going way out of our way to avoid an off by 1. */
            else if((ssn->session_flags & SSNFLAG_CLIENT_FIN) && 
                    (ssn->client.next_seq + 1 == pkt_ack))
            {
                /* the fin consumes one byte of the sequence that
                 * really doesn't posses data */                
                ssn->client.last_ack = pkt_ack - 1;
            }
            else if(SEQ_LT(ssn->client.last_ack, pkt_ack))
            {
                /*
                 **   This assumes that the server is not malicious,
                 **   since it could fake large acks so we would ignore
                 **   data later on.
                 */
                ssn->client.last_ack = pkt_ack;
            }

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "client.base_seq(%u) "
                        "client.last_ack(%u) client.next_seq(%u)\n",
                        ssn->client.base_seq,ssn->client.last_ack, 
                        ssn->client.next_seq););

            if(ssn->session_flags & SSNFLAG_ESTABLISHED)
            {
                Stream *s;

                s = &ssn->client;
                
                count = s->pkt_count;
                if((ssn->client.last_ack - ssn->client.base_seq) > ssn->flush_point 
                        && (count > 1))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Flushing Client packet buffer "
                                "(%d bytes a: 0x%X b: 0x%X pkts: %d)\n",
                                (ssn->client.last_ack - ssn->client.base_seq), 
                                ssn->client.last_ack, ssn->client.base_seq,
                                count););

                    if(ssn->reassemble_client)
                    {
                        ssn->client.flags |= IGNORE_SINGLE_PKTS;
                        PREPROC_PROFILE_TMPEND(stream4ActionPerfStats);
                        FlushStream(&ssn->client, p, REVERSE);
                        PREPROC_PROFILE_TMPSTART(stream4ActionPerfStats);
                        ssn->client.flags &= ~IGNORE_SINGLE_PKTS;
                    }

                    if (s->pkt_count != count)
                    {
                        /* Only update if we reassembled and removed packets */
                        ssn->client.base_seq = ssn->client.last_ack;
                    }
                } 
                else 
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                                "%d (%d) bytes to go before we flush: "
                                "(%d) segments stored\n",
                                (ssn->flush_point-
                                    (ssn->client.last_ack - ssn->client.base_seq)),
                                (ssn->client.last_ack - ssn->client.base_seq),
                                count););
                }
            }
        }

        /* server sent some data */
        if(action & ACTION_ACK_SERVER_DATA)
        {
            if((p->tcph->th_flags & TH_RST) && pkt_ack == 0)
            {
                /* Do not change where the side has seen upon a
                 * "nonestablished reset" */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[R] Reset Handled\n"););
            }
            else if((ssn->session_flags & SSNFLAG_CLIENT_FIN) &&
                    (ssn->server.next_seq + 1 == pkt_ack))
            {
                /* Going way out of our way to avoid an off by 1. */
                ssn->server.last_ack = pkt_ack - 1;
            }
            else if(SEQ_LT(ssn->server.last_ack, pkt_ack))
            {
                ssn->server.last_ack = pkt_ack;
            }

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "server.base_seq(%u) "
                        "server.last_ack(%u) server.next_seq(%u)\n",
                        ssn->server.base_seq,ssn->server.last_ack, 
                        ssn->server.next_seq););

            if(ssn->session_flags & SSNFLAG_ESTABLISHED)
            {
                Stream *s;

                s = &ssn->server;

                count = s->pkt_count;
                if((ssn->server.last_ack - ssn->server.base_seq) > ssn->flush_point
                        && (count > 1))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                                "Flushing Server packet buffer "
                                "(%d bytes a: 0x%X b: 0x%X)\n",
                                (ssn->server.last_ack - ssn->server.base_seq),
                                ssn->server.last_ack, ssn->server.base_seq););

                    if(ssn->reassemble_server)
                    {
                        ssn->server.flags |= IGNORE_SINGLE_PKTS;
                        PREPROC_PROFILE_TMPEND(stream4ActionPerfStats);
                        FlushStream(&ssn->server, p, REVERSE);
                        PREPROC_PROFILE_TMPSTART(stream4ActionPerfStats);
                        ssn->server.flags &= ~IGNORE_SINGLE_PKTS;
                    }

                    if (s->pkt_count != count)
                    {
                        /* Only update if we reassembled and removed packets */
                        ssn->server.base_seq = ssn->server.last_ack;
                    }
                }
            }
        }

        if(s4data.ps_alerts && (action & ACTION_ALERT_NMAP_FINGERPRINT))
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_STEALTH_NMAP_FINGERPRINT, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_STEALTH_NMAP_FINGERPRINT_STR, /* msg string */
                    0);
            PREPROC_PROFILE_END(stream4ActionPerfStats);
            return;
        }

        if(action & ACTION_FLUSH_SERVER_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "flushing server stream, ending "
                        "session: %d\n", ssn->reassemble_server););

            if(ssn->reassemble_server)
            {
                PREPROC_PROFILE_TMPEND(stream4ActionPerfStats);
                if(direction == FROM_SERVER)
                {
                    ssn->server.flags |= IGNORE_SINGLE_PKTS;
                    FlushStream(&ssn->server, p, NO_REVERSE);
                    ssn->server.flags &= ~IGNORE_SINGLE_PKTS;
                }
                else
                {
                    ssn->server.flags |= IGNORE_SINGLE_PKTS;
                    FlushStream(&ssn->server, p, REVERSE);
                    ssn->server.flags &= ~IGNORE_SINGLE_PKTS;
                }
                PREPROC_PROFILE_TMPSTART(stream4ActionPerfStats);
            }

            p->packet_flags |= PKT_STREAM_EST;
        }

        if(action & ACTION_FLUSH_CLIENT_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "flushing client stream, ending "
                        "session\n"););

            if(ssn->reassemble_client)
            {
                PREPROC_PROFILE_TMPEND(stream4ActionPerfStats);
                if(direction == FROM_CLIENT)
                {
                    ssn->client.flags |= IGNORE_SINGLE_PKTS;
                    FlushStream(&ssn->client, p, NO_REVERSE);
                    ssn->client.flags &= ~IGNORE_SINGLE_PKTS;
                }
                else
                {
                    ssn->client.flags |= IGNORE_SINGLE_PKTS;
                    FlushStream(&ssn->client, p, REVERSE);
                    ssn->client.flags &= ~IGNORE_SINGLE_PKTS;
                }
                PREPROC_PROFILE_TMPSTART(stream4ActionPerfStats);
            }

            p->packet_flags |= PKT_STREAM_EST;
        }

        if(action & ACTION_DROP_SESSION)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Dumping session\n"););
            DeleteSession(ssn, p->pkth->ts.tv_sec);
            p->ssnptr = NULL;
        }
    }
    PREPROC_PROFILE_END(stream4ActionPerfStats);
}

static void TcpActionAsync(Session *ssn, Packet *p, int action, int direction, 
                           u_int32_t pkt_seq, u_int32_t pkt_ack)
{
    u_int32_t count;
    PROFILE_VARS;

    PREPROC_PROFILE_START(stream4ActionAsyncPerfStats);

    if(direction == FROM_CLIENT)
    {
        if(!ssn->client.isn)
        {
            ssn->client.isn = pkt_seq;
        }

        ssn->client.last_ack = pkt_seq;

    }
    else
    {
        if(!ssn->server.isn)
        {
            ssn->server.isn = pkt_seq;
        }

        ssn->server.last_ack = pkt_seq;
    }


    if(action == ACTION_NOTHING)
    {
        PREPROC_PROFILE_END(stream4ActionAsyncPerfStats);
        return;
    }
    else 
    {
        if(action & ACTION_SET_SERVER_ISN)
        {
            ssn->server.isn = pkt_seq;
            ssn->client.win_size = ntohs(p->tcph->th_win);

            if(pkt_ack == (ssn->client.isn+1))
            {
                ssn->client.last_ack = ssn->client.isn+1;
            }
            else
            {
                /* we got a messed up response from the server */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "WARNING: Got unexpected SYN ACK from server!\n");
                        DebugMessage(DEBUG_STREAM, 
                            "expected: 0x%X   received: 0x%X\n"););
                ssn->client.last_ack = pkt_ack;
            }
        }

        /* complete a three way handshake */
        if(action & ACTION_COMPLETE_TWH)
        {
            /*
            **  Set a packet flag to say that the TWH has been
            **  completed.
            */
            p->packet_flags |= PKT_STREAM_TWH;

            /* this should be isn+1 */
            if(pkt_ack == ssn->server.isn+1)
            {
                ssn->server.last_ack = ssn->server.isn+1;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "WARNING: Fishy TWH from client "
                            "(0x%X:%d->0x%X:%d) (ack: 0x%X  isn: 0x%X)\n", 
                            p->iph->ip_src.s_addr, p->sp, p->iph->ip_dst.s_addr, 
                            p->dp, pkt_ack, ssn->server.isn););

                ssn->server.last_ack = pkt_ack;
            }

            ssn->server.base_seq = ssn->server.last_ack;
            ssn->client.base_seq = ssn->client.last_ack;
        }

        /* 
         * someone sent data in their SYN packet, classic sign of someone
         * doing bad things (or a bad ip stack/piece of equipment)
         */
        if(action & ACTION_DATA_ON_SYN)
        {
            if(p->tcph->th_flags & TH_SYN)
            {
                /* alert... */
                if(s4data.evasion_alerts)
                {
                    SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                            STREAM4_DATA_ON_SYN, /* SID */
                            1,                      /* Rev */
                            0,                      /* classification */
                            3,                      /* priority (low) */
                            STREAM4_DATA_ON_SYN_STR, /* msg string */
                            0);
                }

                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "WARNING: Data on SYN packet!\n"););
                PREPROC_PROFILE_END(stream4ActionAsyncPerfStats);
                return;
            }
        }

        if(action & ACTION_INC_PORT)
        {
            ssn->client.port++;
        }

        /* client sent some data */
        if(action & ACTION_ACK_CLIENT_DATA)
        {
            Stream *s;

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "client.base_seq(%u) client.last_ack(%u)\n",
                        ssn->client.base_seq,ssn->client.last_ack););

            if((p->tcph->th_flags & TH_RST) && pkt_ack == 0)
            {
                /* Do not change where the side has seen upon a
                 * "nonestablished reset" */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[R] Reset Handled\n"););
            }
            /* Going way out of our way to avoid an off by 1. */
            else if((ssn->session_flags & SSNFLAG_CLIENT_FIN) && 
                    (ssn->client.next_seq + 1 == pkt_ack))
            {
                /* the fin consumes one byte of the sequence that
                 * really doesn't posses data */                
                ssn->client.last_ack = pkt_ack - 1;
            }
            else
            {
                ssn->client.last_ack = pkt_ack;
            }

            s = &ssn->client;
            count = s->pkt_count;
            if((ssn->client.last_ack - ssn->client.base_seq) > ssn->flush_point 
                    && (count > 1))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "Flushing Client packet buffer "
                            "(%d bytes a: 0x%X b: 0x%X pkts: %d)\n",
                            (ssn->client.last_ack - ssn->client.base_seq), 
                            ssn->client.last_ack, ssn->client.base_seq,
                            count););

                if(ssn->reassemble_client)
                {
                    ssn->client.flags |= IGNORE_SINGLE_PKTS;
                    PREPROC_PROFILE_TMPEND(stream4ActionAsyncPerfStats);
                    FlushStream(&ssn->client, p, REVERSE);
                    PREPROC_PROFILE_TMPSTART(stream4ActionAsyncPerfStats);
                    ssn->client.flags &= ~IGNORE_SINGLE_PKTS;
                }

                if (s->pkt_count != count)
                {
                    /* Only update if we reassembled and removed packets */
                    ssn->client.base_seq = ssn->client.last_ack;
                }
            }
        }

        /* server sent some data */
        if(action & ACTION_ACK_SERVER_DATA)
        {
            Stream *s;

            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                        "server.base_seq(%u) server.last_ack(%u)\n",
                        ssn->server.base_seq,ssn->server.last_ack););

            if((p->tcph->th_flags & TH_RST) && pkt_ack == 0)
            {
                /* Do not change where the side has seen upon a
                 * "nonestablished reset" */
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "[R] Reset Handled\n"););
            }
            else if((ssn->session_flags & SSNFLAG_CLIENT_FIN) &&
                    (ssn->server.next_seq + 1 == pkt_ack))
            {
                /* Going way out of our way to avoid an off by 1. */
                ssn->server.last_ack = pkt_ack - 1;
            }
            else
            {
                ssn->server.last_ack = pkt_ack;
            }


            s = &ssn->server;

            count = s->pkt_count;
            if((ssn->server.last_ack - ssn->server.base_seq) > ssn->flush_point
                    && (count > 1))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                            "Flushing Server packet buffer "
                            "(%d bytes a: 0x%X b: 0x%X)\n",
                            (ssn->server.last_ack - ssn->server.base_seq),
                            ssn->server.last_ack, ssn->server.base_seq););

                if(ssn->reassemble_server)
                {
                    ssn->server.flags |= IGNORE_SINGLE_PKTS;
                    PREPROC_PROFILE_TMPEND(stream4ActionAsyncPerfStats);
                    FlushStream(&ssn->server, p, REVERSE);
                    PREPROC_PROFILE_TMPSTART(stream4ActionAsyncPerfStats);
                    ssn->server.flags &= ~IGNORE_SINGLE_PKTS;
                }

                if (s->pkt_count != count)
                {
                    /* Only update if we reassembled and removed packets */
                    ssn->server.base_seq = ssn->server.last_ack;
                }
            }
        }

        if(s4data.ps_alerts && (action & ACTION_ALERT_NMAP_FINGERPRINT))
        {
            SnortEventqAdd(GENERATOR_SPP_STREAM4, /* GID */
                    STREAM4_STEALTH_NMAP_FINGERPRINT, /* SID */
                    1,                      /* Rev */
                    0,                      /* classification */
                    3,                      /* priority (low) */
                    STREAM4_STEALTH_NMAP_FINGERPRINT_STR, /* msg string */
                    0);
            PREPROC_PROFILE_END(stream4ActionAsyncPerfStats);
            return;
        }

        if(action & ACTION_FLUSH_SERVER_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "flushing server stream, ending "
                        "session: %d\n", ssn->reassemble_server););

            if(ssn->reassemble_server)
            {
                PREPROC_PROFILE_TMPEND(stream4ActionAsyncPerfStats);
                if(direction == FROM_SERVER)
                {
                    ssn->server.flags |= IGNORE_SINGLE_PKTS;
                    FlushStream(&ssn->server, p, NO_REVERSE);
                    ssn->server.flags &= ~IGNORE_SINGLE_PKTS;
                }
                else
                {
                    ssn->server.flags |= IGNORE_SINGLE_PKTS;
                    FlushStream(&ssn->server, p, REVERSE);
                    ssn->server.flags &= ~IGNORE_SINGLE_PKTS;
                }
                PREPROC_PROFILE_TMPSTART(stream4ActionAsyncPerfStats);
            }
        }

        if(action & ACTION_FLUSH_CLIENT_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "flushing client stream, ending "
                        "session\n"););

            if(ssn->reassemble_client)
            {
                PREPROC_PROFILE_TMPEND(stream4ActionAsyncPerfStats);
                if(direction == FROM_CLIENT)
                {
                    ssn->client.flags |= IGNORE_SINGLE_PKTS;
                    FlushStream(&ssn->client, p, NO_REVERSE);
                    ssn->client.flags &= ~IGNORE_SINGLE_PKTS;
                }
                else
                {
                    ssn->client.flags |= IGNORE_SINGLE_PKTS;
                    FlushStream(&ssn->client, p, REVERSE);
                    ssn->client.flags &= ~IGNORE_SINGLE_PKTS;
                }
                PREPROC_PROFILE_TMPSTART(stream4ActionAsyncPerfStats);
            }
        }

        if(action & ACTION_DROP_SESSION)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Dumping session\n"););
            DeleteSession(ssn, p->pkth->ts.tv_sec);
            p->ssnptr = NULL;
        }
    }
    PREPROC_PROFILE_END(stream4ActionAsyncPerfStats);
}

int Stream4IgnoreChannel(u_int32_t cliIP, u_int16_t cliPort,
                  u_int32_t srvIP, u_int16_t srvPort,
                  char protocol, char direction, char flags)
{
    return IgnoreChannel(cliIP, cliPort,
                         srvIP, srvPort,
                         protocol, direction,
                         flags, s4data.timeout);
}

void SetIgnoreChannel(void *ssnptr, Packet *p, char direction,
                int32_t bytes, int response_flag)
{
    Session *ssn = (Session *)ssnptr;

    if (!p)
        return;

    if (ssn)
    {
        ssn->ignore_flag = 1;

        if (ssn->hashKey.proto == IPPROTO_TCP)
        {
            /*
             * Flush both sides of the stream in case there was anything
             * buffered up... Should eliminate potential memory leak of
             * the saved packets from earlier in the stream.
             */
            if (p->packet_flags & PKT_REBUILT_STREAM)
            {
                ssn->need_to_flush = 1;
            }
            else
            {
                FlushStream(&ssn->client, p, NO_REVERSE);
                FlushStream(&ssn->server, p, NO_REVERSE);
            }
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
            "stream to be ignored.\n"););

    /*
     * Don't want to mess up PortScan by "dropping"
     * this packet.
     *
     * Also still want the perfmon to collect the stats.
     *
     * And don't want to do any detection with rules
     */
    DisableDetect(p);
    SetPreprocBit(p, PP_SFPORTSCAN);
    SetPreprocBit(p, PP_PERFMONITOR);
    otn_tmp = NULL;
}

static u_int32_t Stream4GetSessionFlags(void *ssnptr)
{
    Session *ssn;

    if(ssnptr)
    {
        ssn = (Session*)ssnptr;
        return ssn->session_flags;
    }
    return 0;
}

static u_int32_t Stream4SetSessionFlags(void *ssnptr, u_int32_t flags)
{
    Session *ssn;
    if(ssnptr)
    {
        ssn = (Session*)ssnptr;
        ssn->session_flags |= flags;
        return ssn->session_flags;
    }

    return 0;
}

static void * Stream4GetApplicationData(void *ssnptr, u_int32_t protocol)
{
    Session *ssn;
    StreamApplicationData *application_data;

    if(ssnptr)
    {
        ssn = (Session*)ssnptr;
        application_data = ssn->application_data;
        while (application_data)
        {
            if (application_data->preproc_proto == protocol)
                return application_data->preproc_data;
            application_data = application_data->next;
        }
    }
    return NULL;
}

static void Stream4SetApplicationData(void *ssnptr, 
                                      u_int32_t protocol,
                                      void *data,
                                      StreamAppDataFree free_func)
{
    Session *ssn;
    StreamApplicationData *application_data;
    if(ssnptr)
    {
        ssn = (Session*) ssnptr;
        application_data = ssn->application_data;

        while (application_data)
        {
            /* If same protocol */
            if (application_data->preproc_proto == protocol)
            {
                if ((application_data->preproc_free) &&
                    (application_data->preproc_data != data))
                {
                    /* Free the old data pointer if different */
                    application_data->preproc_free(application_data->preproc_data);
                }
                else
                {
                    break;
                }
                application_data->preproc_data = NULL;
                break;
            }
            application_data = application_data->next;
        }

        if (!application_data)
        {
            /* There isn't one for this protocol */
            application_data = SnortAlloc(sizeof(StreamApplicationData));
            application_data->next = ssn->application_data;
            ssn->application_data = application_data;
        }

        application_data->preproc_proto = (char)protocol;
        application_data->preproc_data = data;
        application_data->preproc_free = free_func;
    }
}

static int Stream4AddSessionAlert(void *ssnptr,
                                  Packet *p,
                                  u_int32_t gid,
                                  u_int32_t sid)
{
    Session *ssn = (Session *)ssnptr;
    Stream *stream = NULL;

    if (!ssn)
        return -1;

    if (p->packet_flags & PKT_FROM_SERVER)
    {
        stream = &ssn->server;
        /* If not reassembling on the server, don't bother */
        if (!ssn->reassemble_server)
            return -1;
    }
    else if (p->packet_flags & PKT_FROM_CLIENT)
    {
        stream = &ssn->client;

        /* If not reassembling on the client, don't bother */
        if (!ssn->reassemble_client)
            return -1;
    }
    else
    {
        /* Directionless packet, can't do much */
        return -1;
    }

    if (stream->alert_count >= MAX_SESSION_ALERTS)
        return -1;

    stream->alerts[stream->alert_count].gid = gid;
    stream->alerts[stream->alert_count].sid = sid;
    stream->alerts[stream->alert_count].seq = p->tcph->th_seq;
    stream->alert_count++;

    return 0;
}

void CleanSessionAlerts(Session *ssn, Packet *flushed_pkt)
{
    int i;
    int new_count = 0;
    Stream *stream;

    if (flushed_pkt->packet_flags & PKT_FROM_SERVER)
    {
        stream = &ssn->server;
    }
    else if (flushed_pkt->packet_flags & PKT_FROM_CLIENT)
    {
        stream = &ssn->client;
    }
    else
    {
        /* Huh?  We didn't set that flag in the rebuilt packet? */
        return;
    }

    for (i=0;i< stream->alert_count; i++)
    {
        u_int32_t alert_seq = ntohl(stream->alerts[i].seq);
        u_int32_t flushed_seq = ntohl(flushed_pkt->tcph->th_seq);
        if (alert_seq < flushed_seq + flushed_pkt->dsize)
        {
            /* Alert was covered by the flushed packet.  Zero it out. */
            stream->alerts[i].sid = 0;
            stream->alerts[i].gid = 0;
            stream->alerts[i].seq = 0;
        }
        else
        {
            /* Alert was for a later packet -- still in the
             * reassembly queue.  Keep it around. */
            if (new_count != i)
            {
                /* Move this one to an earlier position. */
                stream->alerts[new_count].sid = stream->alerts[i].sid;
                stream->alerts[new_count].gid = stream->alerts[i].gid;
                stream->alerts[new_count].seq = stream->alerts[i].seq;
            }
            new_count++;
        }
    }
        
    stream->alert_count = new_count;
}

static int Stream4CheckSessionAlert(void *ssnptr,
                                  Packet *p,
                                  u_int32_t gid,
                                  u_int32_t sid)
{
    Session *ssn = (Session *)ssnptr;
    Stream *stream;
    int      i;

    if (!ssn)
        return 0;

    /* If this is not a rebuilt packet, no need to check further */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return 0;

    if (p->packet_flags & PKT_FROM_SERVER)
    {
        stream = &ssn->server;
    }
    else if (p->packet_flags & PKT_FROM_CLIENT)
    {
        stream = &ssn->client;
    }
    else
    {
        /* Directionless packet, can't do much */
        return 0;
    }

    for ( i = 0; i < stream->alert_count; i++ )
    {
        /*  This is a rebuilt packet and if we've seen this alert before,
         *  return that we have previously alerted on a non-rebuilt packet.
         */
        if ( stream->alerts[i].gid == gid &&
             stream->alerts[i].sid == sid )
        {
            return -1;
        }
    }
    return 0;
}

typedef struct _TraverseReassemblyData
{
    PacketIterator callback;
    void *userdata;
    int packets;
} TraverseReassemblyData;

static void TraverseReassembly(StreamPacketData *NodePtr, void *foo)
{
    StreamPacketData *spd = (StreamPacketData *) NodePtr;
    TraverseReassemblyData *callbackData = (TraverseReassemblyData *)foo;

    /* packets that are part of the currently reassembled stream
     * should be marked with the chuck flag
     */
    if (spd->chuck != SEG_UNASSEMBLED)
    {
        callbackData->packets++;
        callbackData->callback(&spd->pkth, spd->pkt, callbackData->userdata);
    }
}

static int Stream4TraverseReassembly(Packet *p,
                                    PacketIterator callback,
                                    void *userdata)
{
    Stream *s;
    TraverseReassemblyData callbackData;
    callbackData.userdata = userdata;
    callbackData.callback = callback;
    callbackData.packets = 0;

    if (p)
    {
        s = (Stream *)p->streamptr;
        if (!s)
        {
            return 0;
        }

        {
            StreamPacketData *spd = s->seglist;
            while (spd)
            {
                if (spd->chuck == SEG_UNASSEMBLED)
                {
                    /* We hit a packet that hasn't been marked yet.
                     * Since packets are stored in order, we've hit
                     * all the ones that we need to include.  Done.
                     */
                    break;
                }
                TraverseReassembly(spd, &callbackData);
                spd = spd->next;
            }
        }
    }

    return callbackData.packets;
}

static void Stream4DropTraffic(
                    void *ssnptr,
                    char dir)
{
    Session *ssn = (Session *)ssnptr;

    if (!ssn)
        return;

    if (s4data.allow_session_blocking)
    {
#ifdef STREAM4_UDP
        if (ssn->hashKey.proto == IPPROTO_TCP)
#endif
        {
            ssn->drop_traffic |= dir; 
        }
    }

    /* XXX: Eventually, this will issue TCP resets or ICMP unreach
     * in each direction */
}

static void Stream4DropPacket(
                    Packet *p)
{
    Stream *s;
    Session *ssn;
    u_int32_t pkt_seq;

    /* Stream4 is not processing this... go away */
    if(NotForStream4(p))
        return;

    /* Ignore rebuilt packets */
    if (p->packet_flags & PKT_REBUILT_STREAM)
        return;

    /* No session?  Go away */
    ssn = (Session *)p->ssnptr;
    if (!ssn)
        return;

    pkt_seq = ntohl(p->tcph->th_seq);

    if(p->packet_flags & PKT_FROM_SERVER)
    {        
        s = &ssn->server;
    }
    else
    {        
        s = &ssn->client;
    }

    /* If this packet was inserted into a reassembly queue */
    if (p->packet_flags & PKT_STREAM_INSERT)
    {
        StreamPacketData *spd;
        /* Find this packet seq within the packet store */
        spd = SpdSeqExists(s, pkt_seq);
        if (spd)
        {
            spd->blocked = 1;
        }
    }
}

/* Uses the Flow preprocessor... */
static StreamFlowData *Stream4GetFlowData(Packet *p)
{
    FLOW *fp;
    FLOWDATA *flowdata;

    if (!p->flow)
    {
        return NULL;
    }

    fp = (FLOW *)p->flow;

    flowdata = &(fp->data);

    return (StreamFlowData *)flowdata;
}

static char Stream4GetReassemblyDirection(void *ssnptr)
{
    Session *ssn = (Session *)ssnptr;
    int retDir = 0;

    if (!ssn)
        return 0;

    retDir |= (ssn->reassemble_client ? SSN_DIR_CLIENT : 0);
    retDir |= (ssn->reassemble_server ? SSN_DIR_SERVER : 0);

    return retDir;
}

static char Stream4SetReassembly(void *ssnptr,
                                   u_int8_t flush_policy,
                                   char dir,
                                   char flags)
{
    Session *ssn = (Session *)ssnptr;
    /* Stream4 always uses STREAM_FLPOLICY_FOOTPRINT flush policy,
     * so ignore the flush_policy parameter */

    if (!ssn)
        return 0;

    if (flags & STREAM_FLPOLICY_SET_APPEND)
    {
        if (dir & SSN_DIR_CLIENT)
            ssn->reassemble_client = 1;

        if (dir & SSN_DIR_SERVER)
            ssn->reassemble_server = 1;
    }
    else if (flags & STREAM_FLPOLICY_SET_ABSOLUTE)
    {
        if (dir & SSN_DIR_CLIENT)
            ssn->reassemble_client = 1;
        else
        {
            if (ssn->reassemble_client)
            {
                /* Flush what's there since we're turning it off */
                PurgeFlushStream(ssn, &ssn->client);
            }
            ssn->reassemble_client = 0;
        }

        if (dir & SSN_DIR_SERVER)
            ssn->reassemble_server = 1;
        else
        {
            if (ssn->reassemble_server)
            {
                /* Flush what's there since we're turning it off */
                PurgeFlushStream(ssn, &ssn->server);
            }
            ssn->reassemble_server = 0;
        }
    }

    return Stream4GetReassemblyDirection(ssnptr);
}

static char Stream4GetReassemblyFlushPolicy(void *ssnptr, char dir)
{
    Session *ssn = (Session *)ssnptr;
    if (!ssn)
        return 0;

    if (dir & SSN_DIR_CLIENT)
    {
        if (ssn->reassemble_client)
        {
            return STREAM_FLPOLICY_FOOTPRINT;
        }
        else
        {
            return STREAM_FLPOLICY_NONE;
        }
    }

    if (dir & SSN_DIR_SERVER)
    {
        if (ssn->reassemble_server)
        {
            return STREAM_FLPOLICY_FOOTPRINT;
        }
        else
        {
            return STREAM_FLPOLICY_NONE;
        }
    }
    return STREAM_FLPOLICY_NONE;
}

static char Stream4IsStreamSequenced(void *ssnptr, char dir)
{
    Session *ssn = (Session *)ssnptr;
    if (!ssn)
        return 0;

    if (dir & SSN_DIR_CLIENT)
    {
        return !ssn->client.outoforder;
    }

    if (dir & SSN_DIR_SERVER)
    {
        return !ssn->server.outoforder;

    }

    return 0;
}
