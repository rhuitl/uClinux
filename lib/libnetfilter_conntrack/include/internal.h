/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 * 
 * WARNING: Do *NOT* ever include this file, only for internal use!
 * 	    Use the set/get API in order to set/get the conntrack attributes
 */

#ifndef __LIBNETFILTER_CONNTRACK_INTERNAL__
#define __LIBNETFILTER_CONNTRACK_INTERNAL__

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>

#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

struct nfct_handle;

typedef void (*set_attr)(struct nf_conntrack *ct, const void *value);
typedef const void *(*get_attr)(const struct nf_conntrack *ct);

extern set_attr set_attr_array[];
extern get_attr get_attr_array[];

typedef int (*nfct_handler)(struct nfct_handle *cth, struct nlmsghdr *nlh,
			    void *arg);

struct nfct_handle {
	struct nfnl_handle *nfnlh;
	struct nfnl_subsys_handle *nfnlssh_ct;
	struct nfnl_subsys_handle *nfnlssh_exp;
	nfct_callback callback;		/* user callback */
	void *callback_data;		/* user data for callback */
	nfct_handler handler;		/* netlink handler */

	/* callback handler for the new API */
	struct nfnl_callback nfnl_cb;
	int(*cb)(enum nf_conntrack_msg_type type, 
		 struct nf_conntrack *ct,
		 void *data);
	int(*expect_cb)(enum nf_conntrack_msg_type type, 
			struct nf_expect *exp,
			void *data);
};

union __nfct_l4 {
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

union __nfct_address {
	u_int32_t v4;
	struct in6_addr v6;
};

struct __nfct_tuple {
	union __nfct_address src;
	union __nfct_address dst;

	u_int8_t l3protonum;
	u_int8_t protonum;
	union __nfct_l4 l4src;
	union __nfct_l4 l4dst;
};

union __nfct_protoinfo {
	struct {
		u_int8_t state;
	} tcp;
};

struct __nfct_counters {
	u_int64_t packets;
	u_int64_t bytes;
};

struct __nfct_nat {
	u_int32_t min_ip, max_ip;
	union __nfct_l4 l4min, l4max;
};

#define __DIR_ORIG 0
#define __DIR_REPL 1
#define __DIR_MAX __DIR_REPL+1

struct nf_conntrack {
	struct __nfct_tuple tuple[__DIR_MAX];
	
	u_int32_t 	timeout;
	u_int32_t	mark;
	u_int32_t 	status;
	u_int32_t	use;
	u_int32_t	id;

	union __nfct_protoinfo protoinfo;
	struct __nfct_counters counters[__DIR_MAX];
	struct __nfct_nat snat;
	struct __nfct_nat dnat;

	u_int32_t set[2];
};

struct nf_expect {
	struct nf_conntrack master;
	struct nf_conntrack expected;
	struct nf_conntrack mask;
	u_int32_t timeout;
	u_int32_t id;
	u_int16_t expectfn_queue_id;

	u_int32_t set[1];
};

/* container used to pass data to nfnl callbacks */
struct __data_container {
	struct nfct_handle *h;
	enum nf_conntrack_msg_type type;
	void *data;
};

static inline void set_bit(int nr, u_int32_t *addr)
{
	addr[nr >> 5] |= (1UL << (nr & 31));
}

static inline void unset_bit(int nr, u_int32_t *addr)
{
	addr[nr >> 5] &= ~(1UL << (nr & 31));
}

static inline int test_bit(int nr, const u_int32_t *addr)
{
	return ((1UL << (nr & 31)) & (addr[nr >> 5])) != 0;
}

#define BUFFER_SIZE(ret, size, len, offset)		\
	size += ret;					\
	if (ret > len)					\
		ret = len;				\
	offset += ret;					\
	len -= ret;

int __build_conntrack(struct nfnl_subsys_handle *ssh, struct nfnlhdr *req, size_t size, u_int16_t type, u_int16_t flags, const struct nf_conntrack *ct);
void __build_tuple(struct nfnlhdr *req, size_t size, const struct __nfct_tuple *t, const int type);
int __parse_message_type(const struct nlmsghdr *nlh);
void __parse_conntrack(const struct nlmsghdr *nlh, const struct nfattr *cda[], struct nf_conntrack *ct);
void __parse_tuple(const struct nfattr *attr, struct __nfct_tuple *tuple, int dir, u_int32_t *set);
int __snprintf_conntrack(char *buf, unsigned int len, const struct nf_conntrack *ct, unsigned int type, unsigned int msg_output, unsigned int flags);
int __snprintf_address(char *buf, unsigned int len, const struct __nfct_tuple *tuple);
int __snprintf_protocol(char *buf, unsigned int len, const struct nf_conntrack *ct);
int __snprintf_conntrack_default(char *buf, unsigned int len, const struct nf_conntrack *ct, const unsigned int msg_type, const unsigned int flags);
int __snprintf_conntrack_xml(char *buf, unsigned int len, const struct nf_conntrack *ct, const unsigned int msg_type, const unsigned int flags);


int __callback(struct nlmsghdr *nlh, struct nfattr *nfa[], void *data);

int __setobjopt(struct nf_conntrack *ct, unsigned int option);
int __getobjopt(const struct nf_conntrack *ct, unsigned int option);
int __compare(const struct nf_conntrack *ct1, const struct nf_conntrack *ct2);

typedef void (*set_exp_attr)(struct nf_expect *exp, const void *value);
typedef const void *(*get_exp_attr)(const struct nf_expect *exp);

extern set_exp_attr set_exp_attr_array[];
extern get_exp_attr get_exp_attr_array[];

int __build_expect(struct nfnl_subsys_handle *ssh, struct nfnlhdr *req, size_t size, u_int16_t type, u_int16_t flags, const struct nf_expect *exp);
int __parse_expect_message_type(const struct nlmsghdr *nlh);
void __parse_expect(const struct nlmsghdr *nlh, const struct nfattr *cda[], struct nf_expect *exp);
int __expect_callback(struct nlmsghdr *nlh, struct nfattr *nfa[], void *data);

#endif
