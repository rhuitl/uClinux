/*
 * (C) 2005-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef _LIBNETFILTER_CONNTRACK_H_
#define _LIBNETFILTER_CONNTRACK_H_

#include <netinet/in.h>
#include <libnfnetlink/linux_nfnetlink.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/linux_nfnetlink_conntrack.h> 

#ifdef __cplusplus
extern "C" {
#endif

enum {
	CONNTRACK = NFNL_SUBSYS_CTNETLINK,
	EXPECT = NFNL_SUBSYS_CTNETLINK_EXP
};

/*
 * Subscribe to all possible conntrack event groups. Use this 
 * flag in case that you want to catch up all the possible 
 * events. Do not use this flag for dumping or any other
 * similar operation.
 */
#define NFCT_ALL_CT_GROUPS (NF_NETLINK_CONNTRACK_NEW|NF_NETLINK_CONNTRACK_UPDATE|NF_NETLINK_CONNTRACK_DESTROY)

struct nfct_handle;

/*
 * [Open|close] a conntrack handler
 */
extern struct nfct_handle *nfct_open(u_int8_t, unsigned);
extern struct nfct_handle *nfct_open_nfnl(struct nfnl_handle *nfnlh,
					  u_int8_t subsys_id,
					  unsigned int subscriptions);
extern int nfct_close(struct nfct_handle *cth);

extern int nfct_fd(struct nfct_handle *cth);
extern const struct nfnl_handle *nfct_nfnlh(struct nfct_handle *cth);

/* 
 * NEW libnetfilter_conntrack API 
 */

/* high level API */

#include <sys/types.h>

/* conntrack object */
struct nf_conntrack;

/* conntrack attributes */
enum nf_conntrack_attr {
	ATTR_ORIG_IPV4_SRC = 0,			/* u32 bits */
	ATTR_IPV4_SRC = ATTR_ORIG_IPV4_SRC,	/* alias */
	ATTR_ORIG_IPV4_DST,			/* u32 bits */
	ATTR_IPV4_DST = ATTR_ORIG_IPV4_DST,	/* alias */
	ATTR_REPL_IPV4_SRC,			/* u32 bits */
	ATTR_REPL_IPV4_DST,			/* u32 bits */
	ATTR_ORIG_IPV6_SRC = 4,			/* u128 bits */
	ATTR_IPV6_SRC = ATTR_ORIG_IPV6_SRC,	/* alias */
	ATTR_ORIG_IPV6_DST,			/* u128 bits */
	ATTR_IPV6_DST = ATTR_ORIG_IPV6_DST,	/* alias */
	ATTR_REPL_IPV6_SRC,			/* u128 bits */
	ATTR_REPL_IPV6_DST,			/* u128 bits */
	ATTR_ORIG_PORT_SRC = 8,			/* u16 bits */
	ATTR_PORT_SRC = ATTR_ORIG_PORT_SRC,	/* alias */
	ATTR_ORIG_PORT_DST,			/* u16 bits */
	ATTR_PORT_DST = ATTR_ORIG_PORT_DST,	/* alias */
	ATTR_REPL_PORT_SRC,			/* u16 bits */
	ATTR_REPL_PORT_DST,			/* u16 bits */
	ATTR_ICMP_TYPE = 12,			/* u8 bits */
	ATTR_ICMP_CODE,				/* u8 bits */
	ATTR_ICMP_ID,				/* u16 bits */
	ATTR_ORIG_L3PROTO,			/* u8 bits */
	ATTR_L3PROTO = ATTR_ORIG_L3PROTO,	/* alias */
	ATTR_REPL_L3PROTO = 16,			/* u8 bits */
	ATTR_ORIG_L4PROTO,			/* u8 bits */
	ATTR_L4PROTO = ATTR_ORIG_L4PROTO,	/* alias */
	ATTR_REPL_L4PROTO,			/* u8 bits */
	ATTR_TCP_STATE,				/* u8 bits */
	ATTR_SNAT_IPV4 = 20,			/* u32 bits */
	ATTR_DNAT_IPV4,				/* u32 bits */
	ATTR_SNAT_PORT,				/* u16 bits */
	ATTR_DNAT_PORT,				/* u16 bits */
	ATTR_TIMEOUT = 24,			/* u32 bits */
	ATTR_MARK,				/* u32 bits */
	ATTR_ORIG_COUNTER_PACKETS,		/* u64 bits */
	ATTR_REPL_COUNTER_PACKETS,		/* u64 bits */
	ATTR_ORIG_COUNTER_BYTES = 28,		/* u64 bits */
	ATTR_REPL_COUNTER_BYTES,		/* u64 bits */
	ATTR_USE,				/* u32 bits */
	ATTR_ID,				/* u32 bits */
	ATTR_STATUS = 32,			/* u32 bits  */
	ATTR_MAX
};

/* message type */
enum nf_conntrack_msg_type {
	NFCT_T_UNKNOWN = 0,

	NFCT_T_NEW_BIT = 0,
	NFCT_T_NEW = (1 << NFCT_T_NEW_BIT),

	NFCT_T_UPDATE_BIT = 1,
	NFCT_T_UPDATE = (1 << NFCT_T_UPDATE_BIT),

	NFCT_T_DESTROY_BIT = 2,
	NFCT_T_DESTROY = (1 << NFCT_T_DESTROY_BIT),

	NFCT_T_ALL = NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY,

	NFCT_T_ERROR_BIT = 31,
	NFCT_T_ERROR = (1 << NFCT_T_ERROR_BIT),
};

/* constructor / destructor */
extern struct nf_conntrack *nfct_new(void);
extern void nfct_destroy(struct nf_conntrack *ct);

/* clone */
struct nf_conntrack *nfct_clone(const struct nf_conntrack *ct);

/* object size */
extern size_t nfct_sizeof(const struct nf_conntrack *ct);

/* maximum object size */
extern size_t nfct_maxsize(void);

/* set option */
enum {
	NFCT_SOPT_UNDO_SNAT,
	NFCT_SOPT_UNDO_DNAT,
	NFCT_SOPT_UNDO_SPAT,
	NFCT_SOPT_UNDO_DPAT,
	NFCT_SOPT_SETUP_ORIGINAL,
	NFCT_SOPT_SETUP_REPLY,
	__NFCT_SOPT_MAX,
};
#define NFCT_SOPT_MAX (__NFCT_SOPT_MAX - 1)

/* get option */
enum {
	NFCT_GOPT_IS_SNAT,
	NFCT_GOPT_IS_DNAT,
	NFCT_GOPT_IS_SPAT,
	NFCT_GOPT_IS_DPAT,
	__NFCT_GOPT_MAX,
};
#define NFCT_GOPT_MAX (__NFCT_GOPT_MAX - 1)

extern int nfct_setobjopt(struct nf_conntrack *ct, unsigned int option);
extern int nfct_getobjopt(const struct nf_conntrack *ct, unsigned int option);

/* register / unregister callback */

extern int nfct_callback_register(struct nfct_handle *h,
				  enum nf_conntrack_msg_type type,
				  int (*cb)(enum nf_conntrack_msg_type type,
				  	    struct nf_conntrack *ct,
					    void *data),
				  void *data);

extern void nfct_callback_unregister(struct nfct_handle *h);

/* callback verdict */
enum {
	NFCT_CB_FAILURE = -1,   /* failure */
	NFCT_CB_STOP = 0,       /* stop the query */
	NFCT_CB_CONTINUE = 1,   /* keep iterating through data */
	NFCT_CB_STOLEN = 2,     /* like continue, but ct is not freed */
};

/* setter */
extern void nfct_set_attr(struct nf_conntrack *ct,
			  const enum nf_conntrack_attr type,
			  const void *value);

extern void nfct_set_attr_u8(struct nf_conntrack *ct,
			     const enum nf_conntrack_attr type,
			     u_int8_t value);

extern void nfct_set_attr_u16(struct nf_conntrack *ct,
			      const enum nf_conntrack_attr type,
			      u_int16_t value);

extern void nfct_set_attr_u32(struct nf_conntrack *ct,
			      const enum nf_conntrack_attr type,
			      u_int32_t value);

extern void nfct_set_attr_u64(struct nf_conntrack *ct,
			      const enum nf_conntrack_attr type,
			      u_int64_t value);

/* getter */
extern const void *nfct_get_attr(const struct nf_conntrack *ct,
				 const enum nf_conntrack_attr type);

extern u_int8_t nfct_get_attr_u8(const struct nf_conntrack *ct,
				 const enum nf_conntrack_attr type);

extern u_int16_t nfct_get_attr_u16(const struct nf_conntrack *ct,
				   const enum nf_conntrack_attr type);

extern u_int32_t nfct_get_attr_u32(const struct nf_conntrack *ct,
				   const enum nf_conntrack_attr type);

extern u_int64_t nfct_get_attr_u64(const struct nf_conntrack *ct,
				   const enum nf_conntrack_attr type);

/* checker */
extern int nfct_attr_is_set(const struct nf_conntrack *ct,
			    const enum nf_conntrack_attr type);

/* unsetter */
extern int nfct_attr_unset(struct nf_conntrack *ct,
			   const enum nf_conntrack_attr type);

/* print */

/* output type */
enum {
	NFCT_O_PLAIN,
	NFCT_O_DEFAULT = NFCT_O_PLAIN,
	NFCT_O_XML,
	NFCT_O_MAX
};

/* output flags */
enum {
	NFCT_OF_SHOW_LAYER3_BIT = 0,
	NFCT_OF_SHOW_LAYER3 = (1 << NFCT_OF_SHOW_LAYER3_BIT),
};

extern int nfct_snprintf(char *buf, 
			 unsigned int size,
			 const struct nf_conntrack *ct,
			 const unsigned int msg_type,
			 const unsigned int out_type,
			 const unsigned int out_flags);

extern int nfct_compare(const struct nf_conntrack *ct1,
			const struct nf_conntrack *ct2);

/* query */
enum nf_conntrack_query {
	NFCT_Q_CREATE,
	NFCT_Q_UPDATE,
	NFCT_Q_DESTROY,
	NFCT_Q_GET,
	NFCT_Q_FLUSH,
	NFCT_Q_DUMP,
	NFCT_Q_DUMP_RESET,
	NFCT_Q_CREATE_UPDATE,
};

extern int nfct_query(struct nfct_handle *h,
		      const enum nf_conntrack_query query,
		      const void *data);

extern int nfct_catch(struct nfct_handle *h);

/* low level API: netlink functions */

extern int nfct_build_conntrack(struct nfnl_subsys_handle *ssh,
				void *req,
				size_t size,
				u_int16_t type,
				u_int16_t flags,
				const struct nf_conntrack *ct);

extern int nfct_parse_conntrack(enum nf_conntrack_msg_type msg,
				const struct nlmsghdr *nlh, 
				struct nf_conntrack *ct);

extern int nfct_build_query(struct nfnl_subsys_handle *ssh,
			    const enum nf_conntrack_query query,
			    const void *data,
			    void *req,
			    unsigned int size);

/*
 * NEW expectation API
 */

/* expectation object */
struct nf_expect;

/* expect attributes */
enum nf_expect_attr {
	ATTR_EXP_MASTER = 0,	/* pointer to conntrack object */
	ATTR_EXP_EXPECTED,	/* pointer to conntrack object */
	ATTR_EXP_MASK,		/* pointer to conntrack object */
	ATTR_EXP_TIMEOUT,	/* u32 bits */
	ATTR_EXP_MAX
};

/* constructor / destructor */
extern struct nf_expect *nfexp_new(void);
extern void nfexp_destroy(struct nf_expect *exp);

/* clone */
extern struct nf_expect *nfexp_clone(const struct nf_expect *exp);

/* object size */
extern size_t nfexp_sizeof(const struct nf_expect *exp);

/* maximum object size */
extern size_t nfexp_maxsize(void);

/* register / unregister callback */

extern int nfexp_callback_register(struct nfct_handle *h,
				   enum nf_conntrack_msg_type type,
				   int (*cb)(enum nf_conntrack_msg_type type,
				  	     struct nf_expect *exp,
					     void *data),
				   void *data);

extern void nfexp_callback_unregister(struct nfct_handle *h);

/* setter */
extern void nfexp_set_attr(struct nf_expect *exp,
			   const enum nf_expect_attr type,
			   const void *value);

extern void nfexp_set_attr_u8(struct nf_expect *exp,
			      const enum nf_expect_attr type,
			      u_int8_t value);

extern void nfexp_set_attr_u16(struct nf_expect *exp,
			       const enum nf_expect_attr type,
			       u_int16_t value);

extern void nfexp_set_attr_u32(struct nf_expect *exp,
			       const enum nf_expect_attr type,
			       u_int32_t value);

/* getter */
extern const void *nfexp_get_attr(const struct nf_expect *exp,
				  const enum nf_expect_attr type);

extern u_int8_t nfexp_get_attr_u8(const struct nf_expect *exp,
				  const enum nf_expect_attr type);

extern u_int16_t nfexp_get_attr_u16(const struct nf_expect *exp,
				    const enum nf_expect_attr type);

extern u_int32_t nfexp_get_attr_u32(const struct nf_expect *exp,
				    const enum nf_expect_attr type);

/* checker */
extern int nfexp_attr_is_set(const struct nf_expect *exp,
			     const enum nf_expect_attr type);

/* unsetter */
extern int nfexp_attr_unset(struct nf_expect *exp,
			    const enum nf_expect_attr type);

/* query */
extern int nfexp_query(struct nfct_handle *h,
		       const enum nf_conntrack_query qt,
		       const void *data);

/* print */
extern int nfexp_snprintf(char *buf, 
			  unsigned int size,
			  const struct nf_expect *exp,
			  const unsigned int msg_type,
			  const unsigned int out_type,
			  const unsigned int out_flags);

extern int nfexp_catch(struct nfct_handle *h);

/* Bitset representing status of connection. Taken from ip_conntrack.h
 * 
 * Note: For backward compatibility this shouldn't ever change
 * 	 in kernel space.
 */
enum ip_conntrack_status {
	/* It's an expected connection: bit 0 set.  This bit never changed */
	IPS_EXPECTED_BIT = 0,
	IPS_EXPECTED = (1 << IPS_EXPECTED_BIT),

	/* We've seen packets both ways: bit 1 set.  Can be set, not unset. */
	IPS_SEEN_REPLY_BIT = 1,
	IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT),

	/* Conntrack should never be early-expired. */
	IPS_ASSURED_BIT = 2,
	IPS_ASSURED = (1 << IPS_ASSURED_BIT),

	/* Connection is confirmed: originating packet has left box */
	IPS_CONFIRMED_BIT = 3,
	IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),

	/* Connection needs src nat in orig dir.  This bit never changed. */
	IPS_SRC_NAT_BIT = 4,
	IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT),

	/* Connection needs dst nat in orig dir.  This bit never changed. */
	IPS_DST_NAT_BIT = 5,
	IPS_DST_NAT = (1 << IPS_DST_NAT_BIT),

	/* Both together. */
	IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT),

	/* Connection needs TCP sequence adjusted. */
	IPS_SEQ_ADJUST_BIT = 6,
	IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT),

	/* NAT initialization bits. */
	IPS_SRC_NAT_DONE_BIT = 7,
	IPS_SRC_NAT_DONE = (1 << IPS_SRC_NAT_DONE_BIT),

	IPS_DST_NAT_DONE_BIT = 8,
	IPS_DST_NAT_DONE = (1 << IPS_DST_NAT_DONE_BIT),

	/* Both together */
	IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE),

	/* Connection is dying (removed from lists), can not be unset. */
	IPS_DYING_BIT = 9,
	IPS_DYING = (1 << IPS_DYING_BIT),

    /* Connection has fixed timeout. */
	IPS_FIXED_TIMEOUT_BIT = 10,
	IPS_FIXED_TIMEOUT = (1 << IPS_FIXED_TIMEOUT_BIT),
};

/* 
 * Old deprecated API, its use for new applications is *strongly discouraged* 
 */

/*
 * In case that the user doesn't want to do some kind
 * of action against a conntrack based on its ID 
 */
#define NFCT_ANY_ID 0

union nfct_l4 {
	/* Add other protocols here. */
	u_int16_t all;
	struct {
		u_int16_t port;
	} tcp;
	struct {
		u_int16_t port;
	} udp;
	struct {
		u_int8_t type, code;
		u_int16_t id;
	} icmp;
	struct {
		u_int16_t port;
	} sctp;
};

union nfct_address {
	u_int32_t v4;
	u_int32_t v6[4];
};

struct nfct_tuple {
	union nfct_address src;
	union nfct_address dst;

	u_int8_t l3protonum;
	u_int8_t protonum;
	union nfct_l4 l4src;
	union nfct_l4 l4dst;
};

union nfct_protoinfo {
	struct {
		u_int8_t state;
	} tcp;
};

struct nfct_counters {
	u_int64_t packets;
	u_int64_t bytes;
};

struct nfct_nat {
	u_int32_t min_ip, max_ip;
	union nfct_l4 l4min, l4max;
};

#define NFCT_DIR_ORIGINAL 0
#define NFCT_DIR_REPLY 1
#define NFCT_DIR_MAX NFCT_DIR_REPLY+1

struct nfct_conntrack {
	struct nfct_tuple tuple[NFCT_DIR_MAX];
	
	u_int32_t 	timeout;
	u_int32_t	mark;
	u_int32_t 	status;
	u_int32_t	use;
	u_int32_t	id;

	union nfct_protoinfo protoinfo;
	struct nfct_counters counters[NFCT_DIR_MAX];
	struct nfct_nat nat;
};

struct nfct_expect {
	struct nfct_tuple master;
	struct nfct_tuple tuple;
	struct nfct_tuple mask;
	u_int32_t timeout;
	u_int32_t id;
	u_int16_t expectfn_queue_id;
};

struct nfct_conntrack_compare {
	struct nfct_conntrack *ct;
	unsigned int flags;
	unsigned int l3flags;
	unsigned int l4flags;
};

enum {
	NFCT_STATUS_BIT = 0,
	NFCT_STATUS = (1 << NFCT_STATUS_BIT),
	
	NFCT_PROTOINFO_BIT = 1,
	NFCT_PROTOINFO = (1 << NFCT_PROTOINFO_BIT),

	NFCT_TIMEOUT_BIT = 2,
	NFCT_TIMEOUT = (1 << NFCT_TIMEOUT_BIT),

	NFCT_MARK_BIT = 3,
	NFCT_MARK = (1 << NFCT_MARK_BIT),

	NFCT_COUNTERS_ORIG_BIT = 4,
	NFCT_COUNTERS_ORIG = (1 << NFCT_COUNTERS_ORIG_BIT),

	NFCT_COUNTERS_RPLY_BIT = 5,
	NFCT_COUNTERS_RPLY = (1 << NFCT_COUNTERS_RPLY_BIT),

	NFCT_USE_BIT = 6,
	NFCT_USE = (1 << NFCT_USE_BIT),

	NFCT_ID_BIT = 7,
	NFCT_ID = (1 << NFCT_ID_BIT)
};

enum {
	NFCT_MSG_UNKNOWN,
	NFCT_MSG_NEW,
	NFCT_MSG_UPDATE,
	NFCT_MSG_DESTROY
};

typedef int (*nfct_callback)(void *arg, unsigned int flags, int, void *data);

/*
 * [Allocate|free] a conntrack
 */
extern struct nfct_conntrack *
nfct_conntrack_alloc(struct nfct_tuple *orig, struct nfct_tuple *reply,
		     u_int32_t timeout, union nfct_protoinfo *proto,
		     u_int32_t status, u_int32_t mark,
		     u_int32_t id, struct nfct_nat *range);
extern void nfct_conntrack_free(struct nfct_conntrack *ct);

/*
 * [Allocate|free] an expectation
 */
extern struct nfct_expect *
nfct_expect_alloc(struct nfct_tuple *master, struct nfct_tuple *tuple,
		  struct nfct_tuple *mask, u_int32_t timeout, 
		  u_int32_t id);
extern void nfct_expect_free(struct nfct_expect *exp);


/*
 * [Register|unregister] callbacks
 */
extern void nfct_register_callback(struct nfct_handle *cth,
				   nfct_callback callback, void *data);
extern void nfct_unregister_callback(struct nfct_handle *cth);

/*
 * callback displayers
 */
extern int nfct_default_conntrack_display(void *, unsigned int, int, void *); 
extern int nfct_default_conntrack_display_id(void *, unsigned int, int, void *);
extern int nfct_default_expect_display(void *, unsigned int, int, void *);
extern int nfct_default_expect_display_id(void *, unsigned int, int, void *);
extern int nfct_default_conntrack_event_display(void *, unsigned int, int, 
						void *);

/*
 * [Create|update|get|destroy] conntracks
 */
extern int nfct_create_conntrack(struct nfct_handle *cth, 
				 struct nfct_conntrack *ct);
extern int nfct_update_conntrack(struct nfct_handle *cth,
				 struct nfct_conntrack *ct);
extern int nfct_delete_conntrack(struct nfct_handle *cth, 
				 struct nfct_tuple *tuple, int dir, 
				 u_int32_t id);
extern int nfct_get_conntrack(struct nfct_handle *cth, 
			      struct nfct_tuple *tuple, int dir,
			      u_int32_t id); 
/*
 * Conntrack table dumping & zeroing
 */
extern int nfct_dump_conntrack_table(struct nfct_handle *cth, int family);
extern int nfct_dump_conntrack_table_reset_counters(struct nfct_handle *cth, 
						    int family);

/*
 * Conntrack event notification
 */
extern int nfct_event_conntrack(struct nfct_handle *cth); 

/*
 * Conntrack printing functions
 */
extern int nfct_sprintf_conntrack(char *buf, struct nfct_conntrack *ct, 
				  unsigned int flags);
extern int nfct_sprintf_conntrack_id(char *buf, struct nfct_conntrack *ct,
				     unsigned int flags);
extern int nfct_sprintf_address(char *buf, struct nfct_tuple *t);
extern int nfct_sprintf_proto(char *buf, struct nfct_tuple *t);
extern int nfct_sprintf_protoinfo(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_timeout(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_protocol(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_status_assured(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_status_seen_reply(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_counters(char *buf, struct nfct_conntrack *ct, int dir);
extern int nfct_sprintf_mark(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_use(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_id(char *buf, u_int32_t id);

/*
 * Conntrack comparison
 */
extern int nfct_conntrack_compare(struct nfct_conntrack *ct1, 
				  struct nfct_conntrack *ct2,
				  struct nfct_conntrack_compare *cmp);

/* 
 * Expectations
 */
extern int nfct_dump_expect_list(struct nfct_handle *cth, int family);
extern int nfct_flush_conntrack_table(struct nfct_handle *cth, int family);
extern int nfct_get_expectation(struct nfct_handle *cth, 
				struct nfct_tuple *tuple,
				u_int32_t id);
extern int nfct_create_expectation(struct nfct_handle *cth, struct nfct_expect *);
extern int nfct_delete_expectation(struct nfct_handle *cth,
				   struct nfct_tuple *tuple, u_int32_t id);
extern int nfct_event_expectation(struct nfct_handle *cth);
extern int nfct_flush_expectation_table(struct nfct_handle *cth, int family);

/*
 * expectation printing functions
 */
extern int nfct_sprintf_expect(char *buf, struct nfct_expect *exp);
extern int nfct_sprintf_expect_id(char *buf, struct nfct_expect *exp);

/*
 * low-level functions for libnetfilter_cthelper
 */
extern void nfct_build_tuple(struct nfnlhdr *req, int size, 
			     struct nfct_tuple *t, int type);

#ifdef __cplusplus
}
#endif

#endif	/* _LIBNETFILTER_CONNTRACK_H_ */
