#ifndef _CONNTRACKD_H_
#define _CONNTRACKD_H_

#include "mcast.h"
#include "local.h"

#include <stdio.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h> 
#include "cache.h"
#include "debug.h"
#include <signal.h>
#include "state_helper.h"
#include "linux_list.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

/* UNIX facilities */
#define FLUSH_MASTER	0	/* flush kernel conntrack table 	*/
#define RESYNC_MASTER	1	/* resync with kernel conntrack table 	*/
#define DUMP_INTERNAL 	16	/* dump internal cache 			*/
#define DUMP_EXTERNAL 	17	/* dump external cache 			*/
#define COMMIT		18	/* commit external cache		*/
#define FLUSH_CACHE	19	/* flush cache				*/
#define KILL		20	/* kill conntrackd			*/
#define STATS		21	/* dump statistics			*/
#define SEND_BULK	22	/* send a bulk				*/
#define REQUEST_DUMP	23	/* request dump 			*/
#define DUMP_INT_XML	24	/* dump internal cache in XML		*/
#define DUMP_EXT_XML	25	/* dump external cache in XML		*/

#define DEFAULT_CONFIGFILE	"/etc/conntrackd/conntrackd.conf"
#define DEFAULT_LOCKFILE	"/var/lock/conntrackd.lock"

enum {
	SYNC_MODE_PERSISTENT_BIT = 0,
	SYNC_MODE_PERSISTENT = (1 << SYNC_MODE_PERSISTENT_BIT),

	SYNC_MODE_NACK_BIT = 1,
	SYNC_MODE_NACK = (1 << SYNC_MODE_NACK_BIT),

	DONT_CHECKSUM_BIT = 2,
	DONT_CHECKSUM = (1 << DONT_CHECKSUM_BIT),
};

/* daemon/request modes */
#define NOT_SET         0
#define DAEMON		1
#define REQUEST		2

/* conntrackd modes */
#define SYNC_MODE	0
#define STATS_MODE      1

/* FILENAME_MAX is 4096 on my system, perhaps too much? */
#ifndef FILENAME_MAXLEN
#define FILENAME_MAXLEN 256
#endif

union inet_address {
	u_int32_t ipv4;
	u_int32_t ipv6[4];
	u_int32_t all[4];
};

#define CONFIG(x) conf.x

struct ct_conf {
	char logfile[FILENAME_MAXLEN];
	char lockfile[FILENAME_MAXLEN];
	int hashsize;			/* hashtable size */
	struct mcast_conf mcast;	/* multicast settings */
	struct local_conf local;	/* unix socket facilities */
	int limit;
	int refresh;
	int cache_timeout;		/* cache entries timeout */
	int commit_timeout;		/* committed entries timeout */
	unsigned int netlink_buffer_size;
	unsigned int netlink_buffer_size_max_grown;
	unsigned char ignore_protocol[IPPROTO_MAX];
	union inet_address *listen_to;
	unsigned int listen_to_len;
	unsigned int flags;
	int family;			/* protocol family */
	unsigned int resend_buffer_size;/* NACK protocol */
	unsigned int window_size;
};

#define STATE(x) st.x

struct ct_general_state {
	sigset_t 			block;
	FILE 				*log;
	int 				local;
	struct ct_mode 			*mode;
	struct ignore_pool		*ignore_pool;

	struct nfct_handle		*event;         /* event handler */
	struct nfct_handle		*dump;		/* dump handler */

	/* statistics */
	u_int64_t			malformed;
	u_int64_t 			bytes[NFCT_DIR_MAX];
	u_int64_t 			packets[NFCT_DIR_MAX];
};

#define STATE_SYNC(x) state.sync->x

struct ct_sync_state {
	struct cache *internal; 	/* internal events cache (netlink) */
	struct cache *external; 	/* external events cache (mcast) */

	struct mcast_sock *mcast_server;  /* multicast socket: incoming */
	struct mcast_sock *mcast_client;  /* multicast socket: outgoing  */

	struct sync_mode *sync;		/* sync mode */

	u_int32_t last_seq_sent;	/* last sequence number sent */
	u_int32_t last_seq_recv;	/* last sequence number recv */
	u_int64_t packets_replayed;	/* number of replayed packets */
	u_int64_t packets_lost;         /* lost packets: sequence tracking */
};

#define STATE_STATS(x) state.stats->x

struct ct_stats_state {
	struct cache *cache;            /* internal events cache (netlink) */
};

union ct_state {
	struct ct_sync_state *sync;
	struct ct_stats_state *stats;
};

extern struct ct_conf conf;
extern union ct_state state;
extern struct ct_general_state st;

#ifndef IPPROTO_VRRP
#define IPPROTO_VRRP 112
#endif

#define STEPS_PER_SECONDS	5

struct ct_mode {
	int (*init)(void);
	int (*add_fds_to_set)(fd_set *readfds);
	void (*run)(fd_set *readfds, int step);
	int (*local)(int fd, int type, void *data);
	void (*kill)(void);
	void (*dump)(struct nf_conntrack *ct);
	void (*overrun)(void);
	void (*event_new)(struct nf_conntrack *ct);
	void (*event_upd)(struct nf_conntrack *ct);
	int (*event_dst)(struct nf_conntrack *ct);
};

/* conntrackd modes */
extern struct ct_mode sync_mode;
extern struct ct_mode stats_mode;

#define MAX(x, y) x > y ? x : y

#endif
