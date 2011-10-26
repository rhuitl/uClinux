/*
** Copyright (C) 1998-2005 Martin Roesch <roesch@sourcefire.com>
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

#ifndef __SNORT_H__
#define __SNORT_H__

#ifdef HAVE_CONFIG_H
    #include "config.h"
#endif

#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>

#include "decode.h"
#include "perf.h"

#ifdef GIDS
#include "inline.h"
#endif /* GIDS */

#ifdef INLINE_FAILOPEN
#include "pthread.h"
#endif

extern SFPERF sfPerf;

/* Mark this as a modern version of snort */
#define SNORT_20

/*  I N C L U D E S  **********************************************************/

/* This macro helps to simplify the differences between Win32 and
   non-Win32 code when printing out the name of the interface */
#ifndef WIN32
    #define PRINT_INTERFACE(i)  (i ? i : "NULL")
#else
    #define PRINT_INTERFACE(i)  print_interface(i)
#endif

/*  D E F I N E S  ************************************************************/
#define STD_BUF  1024

#define RF_ANY_SIP    0x01
#define RF_ANY_DIP    0x02
#define RF_ANY_SP     0x04
#define RF_ANY_DP     0x10
#define RF_ANY_FLAGS  0x20

#define MAX_PIDFILE_SUFFIX 11 /* uniqueness extension to PID file, see '-R' */

#ifndef _PATH_VARRUN
extern char _PATH_VARRUN[STD_BUF];
#endif

#ifndef WIN32
    #define DEFAULT_LOG_DIR            "/var/log/snort"
    #define DEFAULT_DAEMON_ALERT_FILE  "alert"
#else
    #define DEFAULT_LOG_DIR            "log"
    #define DEFAULT_DAEMON_ALERT_FILE  "log/alert.ids"
#endif  /* WIN32 */

/* you can redefine the user ID which is allowed to
 * initialize interfaces using pcap and read from them
 */
#ifndef SNIFFUSER
    #define SNIFFUSER 0
#endif


#ifdef ACCESSPERMS
    #define FILEACCESSBITS ACCESSPERMS
#else
    #ifdef  S_IAMB
        #define FILEACCESSBITS S_IAMB
    #else
        #define FILEACCESSBITS 0x1FF
    #endif
#endif    

#define TIMEBUF_SIZE    26


#define ASSURE_ALL    0  /* all TCP alerts fire regardless of stream state */
#define ASSURE_EST    1  /* only established TCP sessions fire alerts */

#define DO_IP_CHECKSUMS     0x00000001
#define DO_TCP_CHECKSUMS    0x00000002
#define DO_UDP_CHECKSUMS    0x00000004
#define DO_ICMP_CHECKSUMS   0x00000008

#define LOG_UNIFIED         0x00000001
#define LOG_TCPDUMP         0x00000002

#define SIGNAL_SNORT_ROTATE_STATS  28
#define SIGNAL_SNORT_CHILD_READY   29

/*  D A T A  S T R U C T U R E S  *********************************************/

#define MODE_PACKET_DUMP    1
#define MODE_PACKET_LOG     2
#define MODE_IDS            3
#define MODE_TEST           4
#define MODE_RULE_DUMP      5
#define MODE_VERSION        6

extern u_int8_t runMode;

typedef struct _Configuration
{
    char *logging_directory;

} Configuration;

typedef struct _Capabilities
{
    u_int8_t stateful_inspection;

} Capabilities;

typedef struct _runtime_config
{
    Configuration configuration;
    Capabilities capabilities;
} runtime_config;

#define LOG_ASCII   1
#define LOG_PCAP    2
#define LOG_NONE    3

#define ALERT_FULL     1
#define ALERT_FAST     2
#define ALERT_NONE     3
#define ALERT_UNSOCK   4
#define ALERT_STDOUT   5
#define ALERT_CMG      6
#define ALERT_SYSLOG   8

#define MAX_IFS        1

/* This feature allows us to change the state of a rule,
 * independent of it appearing in a rules file.
 */
#define RULE_STATE_DISABLED 0
#define RULE_STATE_ENABLED 1

typedef struct _RuleState
{
    int sid;
    int gid;
    int state;
    int action;
    struct _RuleState *next;
} RuleState;

#include "profiler.h"

/* GetoptLong Option numbers */
#define PID_PATH                  1
#ifdef DYNAMIC_PLUGIN
#define DYNAMIC_LIBRARY_DIRECTORY 2
#define DYNAMIC_LIBRARY_FILE      3
#define DYNAMIC_PREPROC_DIRECTORY 4
#define DYNAMIC_PREPROC_FILE      5
#define DYNAMIC_ENGINE_FILE       6
#define DYNAMIC_ENGINE_DIRECTORY  7
#define DUMP_DYNAMIC_RULES        8
#define DUMP_DYNAMIC_PREPROCS     9
#endif
#define ARG_RESTART               10
#define CREATE_PID_FILE           11
#define TREAT_DROP_AS_ALERT       12
#define PROCESS_ALL_EVENTS        13
#define ALERT_BEFORE_PASS         14
#define NOLOCK_PID_FILE           15
#define DISABLE_INLINE_INIT       16
#ifdef INLINE_FAILOPEN
#define DISABLE_INLINE_FAILOPEN   17
#endif

#ifdef DYNAMIC_PLUGIN
typedef struct _DynamicDetectionSpecifier
{
    int type;
    char *path;
} DynamicDetectionSpecifier;
#endif

/* struct to contain the program variables and command line args */
typedef struct _progvars
{
    int stateful;
    int line_buffer_flag;
    int checksums_mode;
    int checksums_drop;
    int assurance_mode;
    int max_pattern;
    int test_mode_flag;
    int alert_interface_flag;
    int verbose_bytedump_flag;
    int obfuscation_flag;
    int log_cmd_override;
    int alert_cmd_override;
    int char_data_flag;
    int data_flag;
    int verbose_flag;
    int readmode_flag;
    int show2hdr_flag;
    int showwifimgmt_flag;
    int inline_flag;
    char disable_inline_init_flag;
#ifdef INLINE_FAILOPEN
    char initialization_done_flag;
    char pass_thread_running_flag;
    pthread_t pass_thread_id;
    pid_t pass_thread_pid;
    int pass_thread_pktcount;
    char inline_failopen_disabled_flag;
#endif
#ifdef GIDS
#ifndef IPFW
    char layer2_resets;
    u_char enet_src[6];
#endif
#ifdef IPFW
    int divert_port;
#endif /* USE IPFW DIVERT socket instead of IPtables */
#endif /* GIDS */
#ifdef WIN32
    int syslog_remote_flag;
    char syslog_server[STD_BUF];
    int syslog_server_port;
#ifdef ENABLE_WIN32_SERVICE
    int terminate_service_flag;
    int pause_service_flag;
#endif  /* ENABLE_WIN32_SERVICE */
#endif  /* WIN32 */
    int promisc_flag;
    int rules_order_flag;
    int track_flag;
    int daemon_flag;
    int daemon_restart_flag;
    int logtosyslog_flag;
    int quiet_flag;
    int print_version;
    int pkt_cnt;
    int pkt_snaplen;
    u_long homenet;
    u_long netmask;
    u_int32_t obfuscation_net;
    u_int32_t obfuscation_mask;
    int alert_mode;
    int log_plugin_active;
    int alert_plugin_active;
    u_int32_t log_bitmap;
    char pid_filename[STD_BUF];
    char *config_file;
    char *config_dir;
    char *log_dir;
    char readfile[STD_BUF];
    char pid_path[STD_BUF];
    char *interface;
    char *pcap_cmd;
    char *alert_filename;
    char *binLogFile;
    int use_utc;
    int include_year;
    char *chroot_dir;
    u_int8_t min_ttl;
    u_int8_t log_mode;
    int num_rule_types;
    char pidfile_suffix[MAX_PIDFILE_SUFFIX+1]; /* room for a null */
    char create_pid_file;
    char nolock_pid_file;
    DecoderFlags decoder_flags; /* if decode.c alerts are going to be enabled */
    char ignore_ports[0x10000]; /* 65536, enough to hold ports */
    int rotate_perf_file;
    u_int32_t event_log_id;

#ifdef DYNAMIC_PLUGIN
#define MAX_DYNAMIC_ENGINES 16
    u_int32_t dynamicEngineCount;
    u_int8_t dynamicEngineCurrentDir;
    DynamicDetectionSpecifier *dynamicEngine[MAX_DYNAMIC_ENGINES];

#define MAX_DYNAMIC_DETECTION_LIBS 16
    u_int8_t dynamicLibraryCount;
    u_int8_t dynamicLibraryCurrentDir;
    DynamicDetectionSpecifier *dynamicDetection[MAX_DYNAMIC_DETECTION_LIBS];

    char dump_dynamic_rules_flag;
    char dynamic_rules_path[STD_BUF];

#define MAX_DYNAMIC_PREPROC_LIBS 16
    u_int8_t dynamicPreprocCount;
    u_int8_t dynamicPreprocCurrentDir;
    DynamicDetectionSpecifier *dynamicPreprocs[MAX_DYNAMIC_PREPROC_LIBS];

#endif

    int default_rule_state; /* Enabled */
    u_int32_t numRuleStates;
    RuleState *ruleStateList;

    int done_processing;

#if defined(ENABLE_RESPONSE2) && !defined(ENABLE_RESPONSE)
    int respond2_link;
    int respond2_rows;
    int respond2_memcap;
    u_int8_t respond2_attempts;
    char *respond2_ethdev;
#endif
    int usr_signal;
    int exit_signal;
    int restart_flag;
#ifdef PERF_PROFILING
    int profile_rules_flag;
    int profile_rules_sort;
    int profile_preprocs_flag;
    int profile_preprocs_sort;
#endif
    int tagged_packet_limit;
    int treat_drop_as_alert;
    int process_all_events;
    int alert_before_pass;
    /* XXX Move to IPv6 frag preprocessor once written */
    u_int32_t ipv6_frag_timeout;
    u_int32_t ipv6_max_frag_sessions;
} PV;

/* struct to collect packet statistics */
typedef struct _PacketCount
{
    u_long total;

    u_long other;
    u_long tcp;
    u_long udp;
    u_long icmp;
    u_long arp;
    u_long eapol;
    u_long ipv6;
    u_long ipx;
    u_long ethloopback;
#ifdef GRE
    u_long gre;
#endif
    u_long discards;
    u_long alert_pkts;
    u_long log_pkts;
    u_long pass_pkts;

    u_long frags;           /* number of frags that have come in */
    u_long frag_trackers;   /* number of tracking structures generated */
    u_long rebuilt_frags;   /* number of packets rebuilt */
    u_long frag_incomp;     /* number of frags cleared due to memory issues */
    u_long frag_timeout;    /* number of frags cleared due to timeout */
    u_long rebuild_element; /* frags that were element of rebuilt pkt */
    u_long frag_mem_faults; /* number of times the memory cap was hit */

    u_long tcp_stream_pkts; /* number of packets tcp reassembly touches */
    u_long rebuilt_tcp;     /* number of phoney tcp packets generated */
    u_long tcp_streams;     /* number of tcp streams created */
    u_long rebuilt_segs;    /* number of tcp segments used in rebuilt pkts */
    u_long queued_segs;     /* number of tcp segments stored for rebuilt pkts */
    u_long str_mem_faults;  /* number of times the stream memory cap was hit */

  /* wireless statistics */
    u_long wifi_mgmt;
    u_long wifi_data;
    u_long wifi_control; 
    u_long assoc_req;
    u_long assoc_resp;
    u_long reassoc_req;
    u_long reassoc_resp;
    u_long probe_req;
    u_long probe_resp;
    u_long beacon;
    u_long atim;
    u_long dissassoc;
    u_long auth;
    u_long deauth;
    u_long ps_poll;
    u_long rts;
    u_long cts;
    u_long ack;
    u_long cf_end;
    u_long cf_end_cf_ack;
    u_long data;
    u_long data_cf_ack;
    u_long data_cf_poll;
    u_long data_cf_ack_cf_poll;
    u_long cf_ack;
    u_long cf_poll;
    u_long cf_ack_cf_poll;
} PacketCount;

/*  G L O B A L S  ************************************************************/
extern PV pv;                 /* program vars (command line args) */
extern int datalink;          /* the datalink value */
extern char *progname;        /* name of the program (from argv[0]) */
extern char **progargs;
extern char *username;
extern char *groupname;
extern unsigned long userid;
extern unsigned long groupid;
extern struct passwd *pw;
extern struct group *gr;
extern char *pcap_cmd;        /* the BPF command string */
extern char *pktidx;          /* index ptr for the current packet */
extern pcap_t *pd; /* array of packet descriptors per interface */

/* backwards compatibility */
extern FILE *alert;           /* alert file ptr */
extern FILE *binlog_ptr;      /* binary log file ptr */
extern int flow;              /* flow var (probably obsolete) */
extern int thiszone;          /* time zone info */
extern PacketCount pc;        /* packet count information */
extern u_long netmasks[33];   /* precalculated netmask array */
extern struct pcap_pkthdr *g_pkthdr; /* packet header ptr */
extern u_char *g_pkt;         /* ptr to the packet data */
extern u_long g_caplen;       /* length of the current packet */
extern char *protocol_names[256];
extern u_int snaplen;


typedef void (*grinder_t)(Packet *, struct pcap_pkthdr *, u_char *);  /* ptr to the packet processor */

extern grinder_t grinder;

/* Snort run-time configuration struct*/
extern runtime_config snort_runtime;

/*  P R O T O T Y P E S  ******************************************************/
int SnortMain(int argc, char *argv[]);
int ParseCmdLine(int, char**);
void *InterfaceThread(void *);
void InitPcap( int );
int OpenPcap();
int SetPktProcessor();
void CleanExit(int);
void PcapProcessPacket(char *, struct pcap_pkthdr *, u_char *);
void ProcessPacket(char *, struct pcap_pkthdr *, u_char *, void *);
int ShowUsage(char *);
void SigCantHupHandler(int signal);


#endif  /* __SNORT_H__ */
