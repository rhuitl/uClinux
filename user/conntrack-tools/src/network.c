/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "conntrackd.h"
#include "network.h"
#include "us-conntrack.h"
#include "sync.h"

static unsigned int seq_set, cur_seq;

static int __do_send(struct mcast_sock *m, void *data, int len)
{
	struct nethdr *net = data;

#undef _TEST_DROP
#ifdef _TEST_DROP
	static int drop = 0;

	if (++drop >= 10) {
		printf("drop sq: %u fl:%u len:%u\n",
			ntohl(net->seq), ntohs(net->flags),
			ntohs(net->len));
		drop = 0;
		return 0;
	}
#endif
	debug("send sq: %u fl:%u len:%u\n",
		ntohl(net->seq), ntohs(net->flags),
		ntohs(net->len));

	return mcast_send(m, net, len);
}

static int __do_prepare(struct mcast_sock *m, void *data, int len)
{
	struct nethdr *net = data;

	if (!seq_set) {
		seq_set = 1;
		cur_seq = time(NULL);
		net->flags |= NET_F_HELLO;
	}
	net->len = len;
	net->seq = cur_seq++;
	HDR_HOST2NETWORK(net);

	return len;
}

static int __prepare_ctl(struct mcast_sock *m, void *data)
{
	struct nethdr_ack *nack = (struct nethdr_ack *) data;

	return __do_prepare(m, data, NETHDR_ACK_SIZ);
}

static int __prepare_data(struct mcast_sock *m, void *data)
{
	struct nethdr *net = (struct nethdr *) data;
	struct netpld *pld = NETHDR_DATA(net);

	return __do_prepare(m, data, ntohs(pld->len) + NETPLD_SIZ + NETHDR_SIZ);
}

int prepare_send_netmsg(struct mcast_sock *m, void *data)
{
	int ret = 0;
	struct nethdr *net = (struct nethdr *) data;

	if (IS_DATA(net))
		ret = __prepare_data(m, data);
	else if (IS_CTL(net))
		ret = __prepare_ctl(m, data);

	return ret;
}

static int tx_buflenmax;
static int tx_buflen = 0;
static char *tx_buf;

#define HEADERSIZ 28 /* IP header (20 bytes) + UDP header 8 (bytes) */

int mcast_buffered_init(struct mcast_conf *conf)
{
	int mtu = conf->mtu - HEADERSIZ;

	/* default to Ethernet MTU 1500 bytes */
	if (conf->mtu == 0)
		mtu = 1500 - HEADERSIZ;

	tx_buf = malloc(mtu);
	if (tx_buf == NULL)
		return -1;

	tx_buflenmax = mtu;

	return 0;
}

void mcast_buffered_destroy(void)
{
	free(tx_buf);
}

/* return 0 if it is not sent, otherwise return 1 */
int mcast_buffered_send_netmsg(struct mcast_sock *m, void *data, int len)
{
	int ret = 0;
	struct nethdr *net = data;

retry:
	if (tx_buflen + len < tx_buflenmax) {
		memcpy(tx_buf + tx_buflen, net, len);
		tx_buflen += len;
	} else {
		__do_send(m, tx_buf, tx_buflen);
		ret = 1;
		tx_buflen = 0;
		goto retry;
	}

	return ret;
}

int mcast_buffered_pending_netmsg(struct mcast_sock *m)
{
	int ret;

	if (tx_buflen == 0)
		return 0;

	ret = __do_send(m, tx_buf, tx_buflen);
	tx_buflen = 0;

	return ret;
}

int mcast_send_netmsg(struct mcast_sock *m, void *data)
{
	int ret;
	int len = prepare_send_netmsg(m, data);

	ret = mcast_buffered_send_netmsg(m, data, len);
	mcast_buffered_pending_netmsg(m);

	return ret;
}

void build_netmsg(struct nf_conntrack *ct, int query, struct nethdr *net)
{
	struct netpld *pld = NETHDR_DATA(net);

	build_netpld(ct, pld, query);
}

int handle_netmsg(struct nethdr *net)
{
	int ret;
	struct netpld *pld = NETHDR_DATA(net);

	/* message too small: no room for the header */
	if (ntohs(net->len) < NETHDR_ACK_SIZ)
		return -1;

	HDR_NETWORK2HOST(net);

	if (IS_HELLO(net))
		STATE_SYNC(last_seq_recv) = net->seq - 1;

	if (IS_CTL(net))
		return 0;

	/* information received is too small */
	if (net->len < sizeof(struct netpld))
		return -1;

	/* size mismatch! */
	if (net->len < ntohs(pld->len) + NETHDR_SIZ)
		return -1;

	return 0;
}

int mcast_track_seq(u_int32_t seq, u_int32_t *exp_seq)
{
	static int seq_set = 0;
	int ret = 1;

	/* netlink sequence tracking initialization */
	if (!seq_set) {
		seq_set = 1;
		goto out;
	}

	/* fast path: we received the correct sequence */
	if (seq == STATE_SYNC(last_seq_recv)+1)
		goto out;

	/* out of sequence: some messages got lost */
	if (after(seq, STATE_SYNC(last_seq_recv)+1)) {
		STATE_SYNC(packets_lost) += seq-STATE_SYNC(last_seq_recv)+1;
		ret = 0;
		goto out;
	}

	/* out of sequence: replayed/delayed packet? */
	if (before(seq, STATE_SYNC(last_seq_recv)+1))
		dlog(STATE(log), "delayed packet? exp=%u rcv=%u",
				 STATE_SYNC(last_seq_recv)+1, seq);

out:
	*exp_seq = STATE_SYNC(last_seq_recv)+1;
	/* update expected sequence */
	STATE_SYNC(last_seq_recv) = seq;

	return ret;
}
