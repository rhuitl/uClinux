#ifndef _NETWORK_H_
#define _NETWORK_H_

#include <sys/types.h>

struct nethdr {
	u_int16_t flags;
	u_int16_t len;
	u_int32_t seq;
};
#define NETHDR_SIZ sizeof(struct nethdr)

#define NETHDR_DATA(x)							 \
	(struct netpld *)(((char *)x) + sizeof(struct nethdr))

struct nethdr_ack {
	u_int16_t flags; 
	u_int16_t len;
	u_int32_t seq;
	u_int32_t from;
	u_int32_t to;
};
#define NETHDR_ACK_SIZ sizeof(struct nethdr_ack)

enum {
	NET_F_HELLO_BIT = 0,
	NET_F_HELLO = (1 << NET_F_HELLO_BIT),

	NET_F_RESYNC_BIT = 1,
	NET_F_RESYNC = (1 << NET_F_RESYNC_BIT),

	NET_F_NACK_BIT = 2,
	NET_F_NACK = (1 << NET_F_NACK_BIT),

	NET_F_ACK_BIT = 3,
	NET_F_ACK = (1 << NET_F_ACK_BIT),

	NET_F_ALIVE_BIT = 4,
	NET_F_ALIVE = (1 << NET_F_ALIVE_BIT),
};

#define BUILD_NETMSG(ct, query)					\
({								\
	char __net[4096];					\
	memset(__net, 0, sizeof(__net));			\
	build_netmsg(ct, query, (struct nethdr *) __net);	\
	(struct nethdr *) __net;				\
})

struct us_conntrack;
struct mcast_sock;

void build_netmsg(struct nf_conntrack *ct, int query, struct nethdr *net);
int prepare_send_netmsg(struct mcast_sock *m, void *data);
int mcast_send_netmsg(struct mcast_sock *m, void *data);
int mcast_recv_netmsg(struct mcast_sock *m, void *data, int len);

struct mcast_conf;

int mcast_buffered_init(struct mcast_conf *conf);
void mcast_buffered_destroy();
int mcast_buffered_send_netmsg(struct mcast_sock *m, void *data, int len);
int mcast_buffered_pending_netmsg(struct mcast_sock *m);

#define IS_DATA(x)	((x->flags & ~NET_F_HELLO) == 0)
#define IS_ACK(x)	(x->flags & NET_F_ACK)
#define IS_NACK(x)	(x->flags & NET_F_NACK)
#define IS_RESYNC(x)	(x->flags & NET_F_RESYNC)
#define IS_ALIVE(x)	(x->flags & NET_F_ALIVE)
#define IS_CTL(x)	IS_ACK(x) || IS_NACK(x) || IS_RESYNC(x) || IS_ALIVE(x)
#define IS_HELLO(x)	(x->flags & NET_F_HELLO)

#define HDR_NETWORK2HOST(x)						\
({									\
	x->flags = ntohs(x->flags);					\
	x->len   = ntohs(x->len);					\
	x->seq   = ntohl(x->seq);					\
	if (IS_CTL(x)) {						\
		struct nethdr_ack *__ack = (struct nethdr_ack *) x;	\
		__ack->from = ntohl(__ack->from);			\
		__ack->to = ntohl(__ack->to);				\
	}								\
})

#define HDR_HOST2NETWORK(x)						\
({									\
	if (IS_CTL(x)) {						\
		struct nethdr_ack *__ack = (struct nethdr_ack *) x;	\
		__ack->from = htonl(__ack->from);			\
		__ack->to = htonl(__ack->to);				\
	}								\
	x->flags = htons(x->flags);					\
	x->len   = htons(x->len);					\
	x->seq   = htonl(x->seq);					\
})

/* extracted from net/tcp.h */

/*
 * The next routines deal with comparing 32 bit unsigned ints
 * and worry about wraparound (automatic with unsigned arithmetic).
 */

static inline int before(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq1-seq2) < 0;
}
#define after(seq2, seq1)       before(seq1, seq2)

/* is s2<=s1<=s3 ? */
static inline int between(__u32 seq1, __u32 seq2, __u32 seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

struct netpld {
	u_int16_t       len;
	u_int16_t       query;
};
#define NETPLD_SIZ		sizeof(struct netpld)

#define PLD_NETWORK2HOST(x)						 \
({									 \
	x->len = ntohs(x->len);						 \
	x->query = ntohs(x->query);					 \
})

#define PLD_HOST2NETWORK(x)						 \
({									 \
	x->len = htons(x->len);						 \
	x->query = htons(x->query);					 \
})

struct netattr {
	u_int16_t nta_len;
	u_int16_t nta_attr;
};

#define ATTR_NETWORK2HOST(x)						 \
({									 \
	x->nta_len = ntohs(x->nta_len);					 \
	x->nta_attr = ntohs(x->nta_attr);				 \
})

#define PLD_DATA(x)							 \
	(struct netattr *)(((char *)x) + sizeof(struct netpld))

#define PLD_TAIL(x)							 \
	(struct netattr *)(((char *)x) + sizeof(struct netpld) + x->len)

#define NTA_DATA(x)							 \
	(void *)(((char *)x) + sizeof(struct netattr))

#define NTA_NEXT(x, len)						      \
({									      \
	len -= NTA_ALIGN(NTA_LENGTH(x->nta_len));			      \
	(struct netattr *)(((char *)x) + NTA_ALIGN(NTA_LENGTH(x->nta_len)));  \
})

#define NTA_ALIGNTO	4
#define NTA_ALIGN(len)	(((len) + NTA_ALIGNTO - 1) & ~(NTA_ALIGNTO - 1))
#define NTA_LENGTH(len)	(NTA_ALIGN(sizeof(struct netattr)) + (len))

#endif
