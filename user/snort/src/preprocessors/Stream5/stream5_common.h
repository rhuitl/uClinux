#ifndef STREAM5_COMMON_H_
#define STREAM5_COMMON_H_

#include <sys/types.h>
#ifndef WIN32
#include <netinet/in.h>
#endif
#include "parser/IpAddrSet.h"

#include "stream_api.h"
#include "mempool.h"

/* Only track a maximum number of alerts per session */
#define MAX_SESSION_ALERTS 8

/* default limits */
#define S5_DEFAULT_SSN_TIMEOUT  30        /* seconds to timeout a session */
#define S5_DEFAULT_MIN_TTL       1        /* default for min TTL */
//#define S5_DEFAULT_TTL_LIMIT     5        /* default for TTL Limit */

/* target-based policy types */
#define STREAM_POLICY_FIRST     1
#define STREAM_POLICY_LINUX     2
#define STREAM_POLICY_BSD       3
#define STREAM_POLICY_OLD_LINUX 4
#define STREAM_POLICY_LAST      5
#define STREAM_POLICY_WINDOWS   6
#define STREAM_POLICY_SOLARIS   7
#define STREAM_POLICY_HPUX      8
#define STREAM_POLICY_IRIX      9
#define STREAM_POLICY_MACOS     10

#define STREAM5_CONFIG_STATEFUL_INSPECTION      0x00000001
#define STREAM5_CONFIG_ENABLE_ALERTS            0x00000002
#define STREAM5_CONFIG_LOG_STREAMS              0x00000004
#define STREAM5_CONFIG_REASS_CLIENT             0x00000008
#define STREAM5_CONFIG_REASS_SERVER             0x00000010
#define STREAM5_CONFIG_ASYNC                    0x00000020
#define STREAM5_CONFIG_SHOW_PACKETS             0x00000040
#define STREAM5_CONFIG_FLUSH_ON_ALERT           0x00000080
#define STREAM5_CONFIG_REQUIRE_3WHS             0x00000100
#define STREAM5_CONFIG_MIDSTREAM_DROP_NOALERT   0x00000200
#define STREAM5_CONFIG_IGNORE_ANY               0x00000400
#define STREAM5_CONFIG_PERFORMANCE              0x00000800
#define STREAM5_CONFIG_STATIC_FLUSHPOINTS       0x00001000

/* traffic direction identification */
#define FROM_SERVER     0
#define FROM_RESPONDER  0
#define FROM_CLIENT     1
#define FROM_SENDER     1

#define STREAM5_STATE_NONE                  0x0000
#define STREAM5_STATE_SYN                   0x0001
#define STREAM5_STATE_SYN_ACK               0x0002
#define STREAM5_STATE_ACK                   0x0004
#define STREAM5_STATE_ESTABLISHED           0x0008
#define STREAM5_STATE_DROP_CLIENT           0x0010
#define STREAM5_STATE_DROP_SERVER           0x0020
#define STREAM5_STATE_MIDSTREAM             0x0040
#define STREAM5_STATE_RESET                 0x0080
#define STREAM5_STATE_CLIENT_RESET          0x0100
#define STREAM5_STATE_SERVER_RESET          0x0200
#define STREAM5_STATE_TIMEDOUT              0x0400
#define STREAM5_STATE_UNREACH               0x0800
#define STREAM5_STATE_SENDER_SEEN           0x1000
#define STREAM5_STATE_RECEIVER_SEEN         0x2000
#define STREAM5_STATE_CLOSED                0x4000

#define TCP_HZ          100
#define TCP_TIMEOUT     TCP_HZ * 90
#define UDP_TIMEOUT     TCP_TIMEOUT

/*  D A T A   S T R U C T U R E S  **********************************/
typedef struct _SessionKey
{
    /* TODO: redo this using non-assuming IP structures */
    u_int32_t   ip_l; /* Low IP */
    u_int32_t   ip_h; /* High IP */
    u_int16_t   port_l; /* Low Port - 0 if ICMP */
    u_int16_t   port_h; /* High Port - 0 if ICMP */
    u_int16_t   vlan_tag;
    char        protocol;
    char        pad;
} SessionKey;

typedef struct _Stream5AppData
{
    u_int32_t   protocol;
    void        *dataPointer;
    struct _Stream5AppData *next;
    struct _Stream5AppData *prev;
    StreamAppDataFree freeFunc;
} Stream5AppData;

typedef struct _Stream5AlertInfo
{
    /* For storing alerts that have already been seen on the session */
    u_int32_t sid;
    u_int32_t gid;
    u_int32_t seq;
} Stream5AlertInfo;

typedef struct _Stream5LWSession
{
    SessionKey  key;

    u_int32_t   client_ip;
    u_int32_t   server_ip;
    u_int16_t   client_port;
    u_int16_t   server_port;
    char        protocol;

    u_int32_t   last_data_seen;
    u_int32_t   expire_time;
    char        direction;

    MemBucket   *proto_specific_data;
    u_int16_t   session_state;

    u_int32_t   session_flags;

    u_int32_t   application_protocols;
    u_int16_t   process_as_port1; /* client/sender port equivalency */
    u_int16_t   process_as_port2; /* server/responder port equivalency */

    Stream5AppData *appDataList;

    /* flag to ignore traffic on this session */
    char ignoreSessionClient;
    char ignoreSessionServer;

    /* add flowbits */
    MemBucket *flowdata;
} Stream5LWSession;

typedef struct _Stream5GlobalConfig
{
    char        track_tcp_sessions;
    u_int32_t   max_tcp_sessions;
    u_int32_t   tcp_packet_memcap;
    char        track_udp_sessions;
    u_int32_t   max_udp_sessions;
    char        track_icmp_sessions;
    u_int32_t   max_icmp_sessions;
    u_int32_t   memcap;
    u_int32_t   flags;
} Stream5GlobalConfig;

typedef struct _Stream5Stats
{
    u_int32_t   total_tcp_sessions;
    u_int32_t   total_udp_sessions;
    u_int32_t   total_icmp_sessions;
    u_int32_t   tcp_prunes;
    u_int32_t   udp_prunes;
    u_int32_t   icmp_prunes;
    u_int32_t   tcp_timeouts;
    u_int32_t   tcp_streamtrackers_created;
    u_int32_t   tcp_streamtrackers_released;
    u_int32_t   tcp_streamsegs_created;
    u_int32_t   tcp_streamsegs_released;
    u_int32_t   tcp_rebuilt_packets;
    u_int32_t   tcp_rebuilt_seqs_used;
    u_int32_t   tcp_overlaps;
    u_int32_t   tcp_discards;
    u_int32_t   udp_timeouts;
    u_int32_t   udp_sessions_created;
    u_int32_t   udp_sessions_released;
    u_int32_t   udp_discards;
    u_int32_t   icmp_timeouts;
    u_int32_t   icmp_sessions_created;
    u_int32_t   icmp_sessions_released;
    u_int32_t   events;
} Stream5Stats;

extern Stream5GlobalConfig s5_global_config;
extern Stream5Stats s5stats;
extern u_int32_t firstPacketTime;
extern MemPool s5FlowMempool;

void Stream5DisableInspection(Stream5LWSession *lwssn, Packet *p);

int Stream5Expire(Packet *p, Stream5LWSession *ssn);
void Stream5SetExpire(Packet *p, Stream5LWSession *ssn, u_int32_t timeout);
void MarkupPacketFlags(Packet *p, Stream5LWSession *ssn);

#endif /* STREAM5_COMMON_H_ */
