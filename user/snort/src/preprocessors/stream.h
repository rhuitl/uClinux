#ifdef _STREAM4_INTERNAL_USAGE_ONLY_
/* The above #ifdef is added so that ONLY Stream4 includes this file */

#ifndef __STREAM_H__
#define __STREAM_H__

#include "snort_packet_header.h"

/* Only track a certain number of alerts per session */
#define MAX_SESSION_ALERTS  8

typedef struct _StreamPacketData
{
    struct _StreamPacketData *next;
    struct _StreamPacketData *prev;
    /* Pointer to orig packet data */
    u_int8_t *data;
    u_int8_t *pktOrig;
    u_int8_t *pkt;
    SnortPktHeader pkth;
    u_int16_t pkt_size;
    /* Pointer to trimmed payload */
    u_int8_t *payload;
    u_int16_t payload_size;
    u_int32_t seq_num;
    u_int32_t cksum;
    u_int8_t  chuck;   /* mark the spd for chucking if it's 
                        * been reassembled 
                        */
    u_int8_t  blocked;
} StreamPacketData;
#define FROM_SERVER     SSN_DIR_SERVER
#define FROM_CLIENT     SSN_DIR_CLIENT

typedef struct _StreamAlertInfo
{
    u_int32_t sid;
    u_int32_t gid;
    u_int32_t seq;
} StreamAlertInfo;

#define IGNORE_SINGLE_PKTS  0x01
#define FIRST_FLUSH_DONE    0x02

typedef struct _Stream
{
    u_int32_t ip;          /* IP addr */
    u_int16_t port;        /* port number */
    u_int8_t  state;       /* stream state */
    u_int32_t isn;         /* initial sequence number */
    u_int32_t base_seq;    /* base seq num for this packet set */
    u_int32_t last_ack;    /* last segment ack'd */
    u_int16_t win_size;    /* window size */
    u_int32_t next_seq;    /* next sequence we expect to see -- used on reassemble */
    u_int32_t pkts_sent;   /* track the number of packets in this stream */
    u_int32_t bytes_sent;  /* track the number of bytes in this stream */
    u_int32_t bytes_tracked; /* track the total number of bytes on this side */
    u_int8_t  state_queue;    /* queued state transition */
    u_int8_t  expected_flags; /* tcp flag needed to accept transition */
    u_int32_t trans_seq;      /* sequence number of transition packet */
    u_int8_t  stq_chk_seq;    /* flag to see if we need to check the seq 
                                 num of the state transition packet */
    u_int32_t overlap_pkts;  /* track the number of packets with duplicate seq #s */
    u_int32_t bytes_inspected; /* track the number of bytes seen since last
                                * data from other side */

    StreamPacketData *seglist;
    StreamPacketData *seglist_tail;
    u_int32_t pkt_count;
    char flags;

    StreamAlertInfo alerts[MAX_SESSION_ALERTS];
    u_int8_t  alert_count;   /* count alerts seen in a stream */

    u_int8_t  outoforder;    /* flag indicating stream is no longer in order */
} Stream;

typedef struct _SessionHashKey
{
    u_int32_t lowIP;
    u_int32_t highIP;
    u_int16_t port; /* If IPs are the same, this will be the lower of
                     * the two ports.  Otherwise, it will be the port
                     * corresponding to lowIP. */
#if defined(_LP64)
    u_int16_t pad1;
#endif
    u_int16_t port2;
#if defined(_LP64)
    u_int16_t pad2;
#endif
    u_int8_t  proto;
} SessionHashKey;

typedef struct _StreamApplicationData
{
    u_int8_t preproc_proto;
    void *preproc_data;    /* preprocessor layer data structure */
    void (*preproc_free)(void *); /* function to free preproc_data */
    struct _StreamApplicationData *next;
} StreamApplicationData;

typedef struct _Session
{
    Stream server;
    char reassemble_server;
    Stream client;
    char reassemble_client;
    
    time_t start_time;   /* unix second the session started */
    time_t last_session_time; /* last time this session got a packet */
    
    u_int32_t session_flags; /* special little flags we keep */

    u_int8_t drop_traffic; 
    u_int8_t ignore_flag;
    u_int8_t need_to_flush;

    u_int32_t  flush_point;
    u_int8_t  ttl; /* track the ttl of this current session ( only done on client side ) */

    StreamApplicationData *application_data;
    
    SessionHashKey hashKey;
} Session;

/* used for the StreamPacketData chuck field */
#define SEG_UNASSEMBLED 0x00
#define SEG_FULL        0x01
#define SEG_PARTIAL     0x02

typedef struct _Stream4Data
{
    char stream4_active;

    char stateful_inspection_flag;
    u_int32_t timeout;
    char state_alerts;
    char evasion_alerts;
    u_int32_t memcap;
    u_int32_t max_sessions;
    u_int32_t cache_clean_sessions;

    char log_flushed_streams;

    char ps_alerts;

    char track_stats_flag;
    char *stats_file;
    
    u_int32_t last_prune_time;

    char reassemble_client;
    char reassemble_server;
    char reassembly_alerts;
    char state_protection;
    char zero_flushed_packets;
    char flush_on_alert;
    u_int32_t overlap_limit;
    
    u_int8_t assemble_ports[65536];
    u_int8_t emergency_ports[65536];  /* alternate port set for self-preservation mode */

    u_int32_t sp_threshold;
    u_int32_t sp_period;

    u_int32_t suspend_threshold;
    u_int32_t suspend_period;
    
    
    u_int8_t  stop_traverse;
    u_int32_t stop_seq;
    u_int8_t seq_gap;
    char large_packet_performance;
    
    u_int8_t  min_ttl;   /* min TTL we'll accept to insert a packet */
    u_int8_t  ttl_limit; /* the largest difference we'll accept in the
                            course of a TTL conversation */
    u_int16_t path_mtu;  /* max segment size we'll accept */
    u_int8_t  reassy_method;
    u_int32_t ps_memcap;
    int flush_data_diff_size;
    

    char asynchronous_link; /* used when you can only see part of the conversation
                               it can't be anywhere NEAR as robust */
    char enforce_state;
    char ms_inline_alerts;
    char allow_session_blocking;

    u_int32_t server_inspect_limit;

    // Random flush points
    u_int32_t flush_base;
    u_int32_t flush_range;
    int32_t  flush_behavior;
    u_int32_t flush_seed;

#ifdef STREAM4_UDP
    // UDP Stuff
    u_int32_t max_udp_sessions;
    u_int8_t udp_ports[65536];
#define UDP_SESSION 0x1
#define UDP_INSPECT 0x2
    u_int8_t udp_ignore_any;
    char enable_udp_sessions;

    u_int32_t last_udp_prune_time;
#endif

} Stream4Data;

#endif  // __STREAM_H__

#else /*  _STREAM4_INTERNAL_USAGE_ONLY */
#error "Direct Use of stream.h not allowed.  Use stream_api.h instead."

#endif /*  _STREAM4_INTERNAL_USAGE_ONLY */

