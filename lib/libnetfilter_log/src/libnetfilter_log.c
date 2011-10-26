/* libnfqnetlink.c: generic library for access to nf_queue
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <libnetfilter_log/linux_nfnetlink_log.h>

#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>

struct nflog_handle
{
	struct nfnl_handle *nfnlh;
	struct nfnl_subsys_handle *nfnlssh;
	struct nflog_g_handle *gh_list;
};

struct nflog_g_handle
{
	struct nflog_g_handle *next;
	struct nflog_handle *h;
	u_int16_t id;

	nflog_callback *cb;
	void *data;
};

struct nflog_data
{
	struct nfattr **nfa;
};

int nflog_errno;

/***********************************************************************
 * low level stuff 
 ***********************************************************************/

static void del_gh(struct nflog_g_handle *gh)
{
	struct nflog_g_handle *cur_gh, *prev_gh = NULL;

	for (cur_gh = gh->h->gh_list; cur_gh; cur_gh = cur_gh->next) {
		if (cur_gh == gh) {
			if (prev_gh)
				prev_gh->next = gh->next;
			else
				gh->h->gh_list = gh->next;
			return;
		}
		prev_gh = cur_gh;
	}
}

static void add_gh(struct nflog_g_handle *gh)
{
	gh->next = gh->h->gh_list;
	gh->h->gh_list = gh;
}

static struct nflog_g_handle *find_gh(struct nflog_handle *h, u_int16_t group)
{
	struct nflog_g_handle *gh;

	for (gh = h->gh_list; gh; gh = gh->next) {
		if (gh->id == group)
			return gh;
	}
	return NULL;
}

static int __nflog_rcv_cmd(struct nlmsghdr *nlh, struct nfattr *nfa[],
			    void *data)
{
	/* struct nflog_handle *h = data; */

	/* FIXME: implement this */
	return 0;
}

/* build a NFULNL_MSG_CONFIG message */
static int
__build_send_cfg_msg(struct nflog_handle *h, u_int8_t command,
		     u_int16_t queuenum, u_int8_t pf)
{
	char buf[NFNL_HEADER_LEN
		+NFA_LENGTH(sizeof(struct nfulnl_msg_config_cmd))];
	struct nfulnl_msg_config_cmd cmd;
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(h->nfnlssh, nmh, 0, pf, queuenum,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	cmd.command = command;
	nfnl_addattr_l(nmh, sizeof(buf), NFULA_CFG_CMD, &cmd, sizeof(cmd));

	return nfnl_talk(h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}

static int __nflog_rcv_pkt(struct nlmsghdr *nlh, struct nfattr *nfa[],
			    void *data)
{
	struct nfgenmsg *nfmsg = NLMSG_DATA(nlh);
	struct nflog_handle *h = data;
	u_int16_t group = ntohs(nfmsg->res_id);
	struct nflog_g_handle *gh = find_gh(h, group);
	struct nflog_data nfldata;

	if (!gh)
		return -ENODEV;

	if (!gh->cb)
		return -ENODEV;

	nfldata.nfa = nfa;
	return gh->cb(gh, nfmsg, &nfldata, gh->data);
}

static struct nfnl_callback cmd_cb = {
	.call 		= &__nflog_rcv_cmd,
	.attr_count 	= NFULA_CFG_MAX,
};

static struct nfnl_callback pkt_cb = {
	.call 		= &__nflog_rcv_pkt,
	.attr_count 	= NFULA_MAX,
};

/* public interface */

struct nfnl_handle *nflog_nfnlh(struct nflog_handle *h)
{
	return h->nfnlh;
}

int nflog_fd(struct nflog_handle *h)
{
	return nfnl_fd(nflog_nfnlh(h));
}

struct nflog_handle *nflog_open_nfnl(struct nfnl_handle *nfnlh)
{
	struct nflog_handle *h;
	int err;

	h = malloc(sizeof(*h));
	if (!h)
		return NULL;

	memset(h, 0, sizeof(*h));
	h->nfnlh = nfnlh;

	h->nfnlssh = nfnl_subsys_open(h->nfnlh, NFNL_SUBSYS_ULOG, 
				      NFULNL_MSG_MAX, 0);
	if (!h->nfnlssh) {
		/* FIXME: nflog_errno */
		goto out_free;
	}

	cmd_cb.data = h;
	err = nfnl_callback_register(h->nfnlssh, NFULNL_MSG_CONFIG, &cmd_cb);
	if (err < 0) {
		nflog_errno = err;
		goto out_close;
	}
	pkt_cb.data = h;
	err = nfnl_callback_register(h->nfnlssh, NFULNL_MSG_PACKET, &pkt_cb);
	if (err < 0) {
		nflog_errno = err;
		goto out_close;
	}

	return h;
out_close:
	nfnl_close(h->nfnlh);
out_free:
	free(h);
	return NULL;
}

struct nflog_handle *nflog_open(void)
{
	struct nfnl_handle *nfnlh;
	struct nflog_handle *lh;

	nfnlh = nfnl_open();
	if (!nfnlh) {
		/* FIXME: nflog_errno */
		return NULL;
	}

	lh = nflog_open_nfnl(nfnlh);
	if (!lh)
		nfnl_close(nfnlh);

	return lh;
}

int nflog_callback_register(struct nflog_g_handle *gh, nflog_callback *cb,
			     void *data)
{
	gh->data = data;
	gh->cb = cb;

	return 0;
}

int nflog_handle_packet(struct nflog_handle *h, char *buf, int len)
{
	return nfnl_handle_packet(h->nfnlh, buf, len);
}

int nflog_close(struct nflog_handle *h)
{
	return nfnl_close(h->nfnlh);
}

/* bind nf_queue from a specific protocol family */
int nflog_bind_pf(struct nflog_handle *h, u_int16_t pf)
{
	return __build_send_cfg_msg(h, NFULNL_CFG_CMD_PF_BIND, 0, pf);
}

/* unbind nf_queue from a specific protocol family */
int nflog_unbind_pf(struct nflog_handle *h, u_int16_t pf)
{
	return __build_send_cfg_msg(h, NFULNL_CFG_CMD_PF_UNBIND, 0, pf);
}

/* bind this socket to a specific queue number */
struct nflog_g_handle *
nflog_bind_group(struct nflog_handle *h, u_int16_t num)
{
	struct nflog_g_handle *gh;
	
	if (find_gh(h, num))
		return NULL;
	
	gh = malloc(sizeof(*gh));
	if (!gh)
		return NULL;

	memset(gh, 0, sizeof(*gh));
	gh->h = h;
	gh->id = num;

	if (__build_send_cfg_msg(h, NFULNL_CFG_CMD_BIND, num, 0) < 0) {
		free(gh);
		return NULL;
	}

	add_gh(gh);
	return gh;
}

/* unbind this socket from a specific queue number */
int nflog_unbind_group(struct nflog_g_handle *gh)
{
	int ret = __build_send_cfg_msg(gh->h, NFULNL_CFG_CMD_UNBIND, gh->id, 0);
	if (ret == 0) {
		del_gh(gh);
		free(gh);
	}

	return ret;
}

int nflog_set_mode(struct nflog_g_handle *gh,
		   u_int8_t mode, u_int32_t range)
{
	char buf[NFNL_HEADER_LEN
		+NFA_LENGTH(sizeof(struct nfulnl_msg_config_mode))];
	struct nfulnl_msg_config_mode params;
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(gh->h->nfnlssh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	params.copy_range = htonl(range);	/* copy_range is short */
	params.copy_mode = mode;
	nfnl_addattr_l(nmh, sizeof(buf), NFULA_CFG_MODE, &params,
		       sizeof(params));

	return nfnl_talk(gh->h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}

int nflog_set_timeout(struct nflog_g_handle *gh, u_int32_t timeout)
{
	char buf[NFNL_HEADER_LEN+NFA_LENGTH(sizeof(u_int32_t))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(gh->h->nfnlssh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr32(nmh, sizeof(buf), NFULA_CFG_TIMEOUT, htonl(timeout));

	return nfnl_talk(gh->h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}

int nflog_set_qthresh(struct nflog_g_handle *gh, u_int32_t qthresh)
{
	char buf[NFNL_HEADER_LEN+NFA_LENGTH(sizeof(u_int32_t))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(gh->h->nfnlssh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr32(nmh, sizeof(buf), NFULA_CFG_QTHRESH, htonl(qthresh));

	return nfnl_talk(gh->h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}

int nflog_set_nlbufsiz(struct nflog_g_handle *gh, u_int32_t nlbufsiz)
{
	char buf[NFNL_HEADER_LEN+NFA_LENGTH(sizeof(u_int32_t))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;
	int status;

	nfnl_fill_hdr(gh->h->nfnlssh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr32(nmh, sizeof(buf), NFULA_CFG_NLBUFSIZ, htonl(nlbufsiz));

	status = nfnl_talk(gh->h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);

	/* we try to have space for at least 10 messages in the socket buffer */
	if (status >= 0)
		nfnl_rcvbufsiz(gh->h->nfnlh, 10*nlbufsiz);

	return status;
}

int nflog_set_flags(struct nflog_g_handle *gh, u_int16_t flags)
{
	char buf[NFNL_HEADER_LEN+NFA_LENGTH(sizeof(u_int16_t))];
	struct nlmsghdr *nmh = (struct nlmsghdr *) buf;

	nfnl_fill_hdr(gh->h->nfnlssh, nmh, 0, AF_UNSPEC, gh->id,
		      NFULNL_MSG_CONFIG, NLM_F_REQUEST|NLM_F_ACK);

	nfnl_addattr16(nmh, sizeof(buf), NFULA_CFG_FLAGS, htons(flags));

	return nfnl_talk(gh->h->nfnlh, nmh, 0, 0, NULL, NULL, NULL);
}


struct nfulnl_msg_packet_hdr *nflog_get_msg_packet_hdr(struct nflog_data *nfad)
{
	return nfnl_get_pointer_to_data(nfad->nfa, NFULA_PACKET_HDR,
					 struct nfulnl_msg_packet_hdr);
}

u_int32_t nflog_get_nfmark(struct nflog_data *nfad)
{
	return ntohl(nfnl_get_data(nfad->nfa, NFULA_MARK, u_int32_t));
}

int nflog_get_timestamp(struct nflog_data *nfad, struct timeval *tv)
{
	struct nfulnl_msg_packet_timestamp *uts;

	uts = nfnl_get_pointer_to_data(nfad->nfa, NFULA_TIMESTAMP,
					struct nfulnl_msg_packet_timestamp);
	if (!uts)
		return -1;

	tv->tv_sec = __be64_to_cpu(uts->sec);
	tv->tv_usec = __be64_to_cpu(uts->usec);

	return 0;
}

u_int32_t nflog_get_indev(struct nflog_data *nfad)
{
	return ntohl(nfnl_get_data(nfad->nfa, NFULA_IFINDEX_INDEV, u_int32_t));
}

u_int32_t nflog_get_physindev(struct nflog_data *nfad)
{
	return ntohl(nfnl_get_data(nfad->nfa, NFULA_IFINDEX_PHYSINDEV, u_int32_t));
}

u_int32_t nflog_get_outdev(struct nflog_data *nfad)
{
	return ntohl(nfnl_get_data(nfad->nfa, NFULA_IFINDEX_OUTDEV, u_int32_t));
}

u_int32_t nflog_get_physoutdev(struct nflog_data *nfad)
{
	return ntohl(nfnl_get_data(nfad->nfa, NFULA_IFINDEX_PHYSOUTDEV, u_int32_t));
}

struct nfulnl_msg_packet_hw *nflog_get_packet_hw(struct nflog_data *nfad)
{
	return nfnl_get_pointer_to_data(nfad->nfa, NFULA_HWADDR,
					struct nfulnl_msg_packet_hw);
}

int nflog_get_payload(struct nflog_data *nfad, char **data)
{
	*data = nfnl_get_pointer_to_data(nfad->nfa, NFULA_PAYLOAD, char);
	if (*data)
		return NFA_PAYLOAD(nfad->nfa[NFULA_PAYLOAD-1]);

	return -1;
}

char *nflog_get_prefix(struct nflog_data *nfad)
{
	return nfnl_get_pointer_to_data(nfad->nfa, NFULA_PREFIX, char);
}

int nflog_get_uid(struct nflog_data *nfad, u_int32_t *uid)
{
	if (!nfnl_attr_present(nfad->nfa, NFULA_UID))
		return -1;

	*uid = ntohl(nfnl_get_data(nfad->nfa, NFULA_UID, u_int32_t));
	return 0;
}

int nflog_get_seq(struct nflog_data *nfad, u_int32_t *seq)
{
	if (!nfnl_attr_present(nfad->nfa, NFULA_SEQ))
		return -1;

	*seq = ntohl(nfnl_get_data(nfad->nfa, NFULA_SEQ, u_int32_t));
	return 0;
}

int nflog_get_seq_global(struct nflog_data *nfad, u_int32_t *seq)
{
	if (!nfnl_attr_present(nfad->nfa, NFULA_SEQ_GLOBAL))
		return -1;

	*seq = ntohl(nfnl_get_data(nfad->nfa, NFULA_SEQ_GLOBAL, u_int32_t));
	return 0;
}
