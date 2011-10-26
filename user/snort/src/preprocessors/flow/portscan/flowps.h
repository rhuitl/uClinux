#ifndef _FLOWPS_H
#define _FLOWPS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include "flow.h"
#include "unique_tracker.h"
#include "ipobj.h"

/* todo, move to scoreboard.h but I don't feel like fighting foward
 * declarations at the moment */
#define SDESC_SIZE 256  /**< size of the scoreboard description field */

#define ALERT_FIXED_TALKER    0x01
#define ALERT_SLIDING_TALKER  0x02
#define ALERT_FIXED_SCANNER   0x04
#define ALERT_SLIDING_SCANNER 0x08

/* hard coded "last node info" stuff */
#define FLOWPS_HOSTS_SIZE 5


typedef struct _SERVER_STATS
{
    IPSET   *ipv4_watch; /* network help "learn" */
    SFXHASH *ipv4_table;
} SERVER_STATS;

typedef enum {
    TRACKER_ACTIVE=1,
    TRACKER_SCANNER=2
} TRACKER_POSITION;

typedef struct _SCOREBOARD
{
    char description[SDESC_SIZE];
    TRACKER_POSITION kind;
    SFXHASH          *ipv4_table;
} SCOREBOARD;



typedef struct _PS_SCORE
{
    u_int32_t score; 
    time_t   start;
    time_t   ends;
} PS_SCORE;

typedef struct _CONN_ENTRY
{
    u_int32_t ip;
    u_int16_t port;
    u_int8_t  protocol;
    u_int8_t  cflags; /* usually the TCP header flags */
} CONN_ENTRY;

typedef struct _PS_SCORE_ENTRY
{
    TRACKER_POSITION position; /**< which table am I stored in */
    time_t           event_sec;  /**< time of original event */
    u_int32_t         event_id;   /**< event id of original event */    
    u_int32_t         flags;
    u_int32_t         last_idx; /* ring idx */
    u_int32_t         connections_seen;
    CONN_ENTRY       last_hosts[FLOWPS_HOSTS_SIZE]; /* array of most recent connections */
    PS_SCORE         fixed_talker;
    PS_SCORE         fixed_scanner;
    PS_SCORE         sliding_talker;
    PS_SCORE         sliding_scanner;
} SCORE_ENTRY;

typedef struct _SCORE_THRESHOLD
{
    int      fixed_size;  /* window sizes */
    int      sliding_size;
    u_int32_t sliding;     /* thresholds */
    u_int32_t fixed;
    float    window_scale; /* what to multipl"y the window size by each time */
} SCORE_THRESHOLD;

/** output mechanism for FLOWPS */
typedef enum {
    PKTKLUDGE,   /**< pktkludge + event */
    VARIABLEMSG  /**< variable length event message */
} FLOWPS_OUTPUT;

/**
 * Config structure to initialize the table
 */
typedef struct _PS_CONFIG
{    
    int tcp_penalties; /* give odd flag combinations more credence */
    int sb_memcap_total;  /**< scoreboard-memcap */
    int sb_memcap_talker;
    int sb_memcap_scanner;
    int sb_rows_talker;         /**< active row count */
    int sb_rows_scanner;        /**< scanner rowcount */

    
    int ut_memcap;              /**< uniqueness tracker memcap */
    int ut_rows;                /**< uniqueness tracker row count */

    int server_memcap;          /**< server watcher memcap */
    int server_rows;            /**< server watcher node count */
    int server_learning_time;   /**< how long should we wait until we have
                                  "deduced" all the servers on the network */
    u_int32_t server_ignore_limit; /**< how many times a service must
                                     be hit before it's ignored */
    u_int32_t server_scanner_limit; /**< how many times a service must
                                    *   be hit before it's considered active traffic
                                    */

    int base_score;          /**< default score for a new connection */
    int alert_once;         /**< alert only once per node */
    int dumpall;            /**< make all the subhashtables
                               dump their contents on exit */
    IPSET *server_watchnet_ipv4;
    IPSET *src_ignore_ipv4;  /**< ignore these sips */
    IPSET *dst_ignore_ipv4;  /**< ignore these dips */

    FLOWPS_OUTPUT output_mode;
    SCORE_THRESHOLD  limit_talker;  
    SCORE_THRESHOLD  limit_scanner;
} PS_CONFIG;

typedef struct _PS_TRACKER
{
    PS_CONFIG        config;         /* configuration options */
    SCOREBOARD       table_active;   /* active talkers */
    SCOREBOARD       table_scanner;  /* "policy violators" */
    UNIQUE_TRACKER   unique_tracker; /* table for determining "unique" connections */
    SERVER_STATS     server_stats;   /* table for allowing server learning */
} PS_TRACKER;


int flowps_init(PS_TRACKER *trackerp, PS_CONFIG *configp);
int flowps_destroy(PS_TRACKER *trackerp);

int flowps_mkconfig(PS_CONFIG *configp,
                    int sb_memcap_talker,
                    int sb_rows_talker,
                    int sb_memcap_scanner,
                    int sb_rows_scanner,
                    int ut_memcap,
                    int ut_rows,
                    int server_memcap,
                    int server_rows,
                    int server_learning_time,
                    int tcp_penalties,
                    u_int32_t server_ignore_limit,
                    u_int32_t server_scanner_limit,
                    int base_score,
                    int alert_once,
                    FLOWPS_OUTPUT output_mode);

int flowps_mkthreshold(SCORE_THRESHOLD *thr,
                       int fixed_size, 
                       u_int32_t fixed_limit,
                       int sliding_size,
                       u_int32_t sliding_limit,
                       float window_scale);

int flowps_is_ignored_ipv4(PS_TRACKER *pstp, u_int32_t *sip, u_int32_t *dip);

int flowps_add_entry(PS_TRACKER *trackerp, TRACKER_POSITION position,
                      u_int32_t *address, SCORE_ENTRY **sepp);
int flowps_find_entry(PS_TRACKER *trackerp, u_int32_t *address,
                      SCORE_ENTRY **sepp);
int flowps_score_entry(PS_TRACKER *pstp, SCORE_ENTRY *sep, int score,
                       TRACKER_POSITION tr_pos, int alert_once,
                       u_int32_t *alert_flags);

int flowps_entry_print(SCORE_ENTRY *entry, u_int32_t *address);     

int flowps_get_score(PS_TRACKER *pstp, FLOW *flowp, time_t cur,
                     u_int32_t flags, int *score, TRACKER_POSITION *type);

int flowps_sliding_winadj(PS_SCORE *pscp, time_t current_time,
                          SCORE_THRESHOLD *threshold);

int flowps_fixed_winadj(PS_SCORE *pscp, time_t current_time,
                        SCORE_THRESHOLD *threshold);

int flowps_set_last_address(SCORE_ENTRY *sep, FLOW *flowp, u_int8_t cflags);

int flowps_watch_servers(PS_TRACKER *trackerp);

int flowps_enabled(void);
int flowps_server_stats_enabled(PS_TRACKER *trackerp);


void flowps_stats(PS_TRACKER *pstp);
#endif /* _FLOWPS_H */
