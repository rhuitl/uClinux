/* printpkt.c
 *
 * build something looking like a iptables LOG message
 *
 * (C) 2000-2003 by Harald Welte <laforge@gnumonks.org>
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
 *
 * $Id: printpkt.c 401 2003-10-16 13:00:51Z laforge $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifndef HOST_NAME_MAX
#warning this libc does not define HOST_NAME_MAX
#define HOST_NAME_MAX	(255+1)
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

struct intr_id {
	char* name;
	unsigned int id;		
};

static char hostname[HOST_NAME_MAX+1];

#define INTR_IDS 	35
static struct intr_id intr_ids[INTR_IDS] = {
	{ "oob.time.sec", 0 },
	{ "oob.prefix", 0 },
	{ "oob.in", 0 },
	{ "oob.out", 0 },
	{ "raw.mac", 0 },
	{ "ip.saddr", 0 },
	{ "ip.daddr", 0 },
	{ "ip.totlen", 0 },
	{ "ip.tos", 0 },
	{ "ip.ttl", 0 },
	{ "ip.id", 0 },
	{ "ip.fragoff", 0 },
	{ "ip.protocol", 0 },
	{ "tcp.sport", 0 },
	{ "tcp.dport", 0 },
	{ "tcp.seq", 0 },
	{ "tcp.ackseq", 0 },
	{ "tcp.window", 0 },
	{ "tcp.urg", 0 },
	{ "tcp.ack", 0 },
	{ "tcp.psh", 0 },
	{ "tcp.rst", 0 },
	{ "tcp.syn", 0 },
	{ "tcp.fin", 0 },
	{ "tcp.urgp", 0 },
	{ "udp.sport", 0 },
	{ "udp.dport", 0 },
	{ "udp.len", 0 },
	{ "icmp.type", 0 },
	{ "icmp.code", 0 },
	{ "icmp.echoid", 0 },
	{ "icmp.echoseq", 0 },
	{ "icmp.gateway", 0 },
	{ "icmp.fragmtu", 0 },
	{ "ahesp.spi", 0 },
};

#define GET_VALUE(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].value
#define GET_FLAGS(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].flags

int printpkt_print(ulog_iret_t *res, char *buf, int prefix)
{
	char *timestr;
	char *tmp;
	time_t now;

	char *buf_cur = buf;

	if (prefix) {
		now = (time_t) GET_VALUE(0).ui32;
		timestr = ctime(&now) + 4;

		/* truncate time */
		if ((tmp = strchr(timestr, '\n')))
			*tmp = '\0';

		/* truncate hostname */
		if ((tmp = strchr(hostname, '.')))
			*tmp = '\0';

		/* print time and hostname */
		buf_cur += sprintf(buf_cur, "%.15s %s", timestr, hostname);
	}

	if (*(char *) GET_VALUE(1).ptr)
		buf_cur += sprintf(buf_cur, " %s", (char *) GET_VALUE(1).ptr);

	buf_cur += sprintf(buf_cur," IN=%s OUT=%s ", 
			   (char *) GET_VALUE(2).ptr, 
			   (char *) GET_VALUE(3).ptr);

	/* FIXME: configurable */
	buf_cur += sprintf(buf_cur, "MAC=%s ", 
		(GET_FLAGS(4) & ULOGD_RETF_VALID) ? (char *) GET_VALUE(4).ptr : "");

	buf_cur += sprintf(buf_cur, "SRC=%s ", 
		       inet_ntoa((struct in_addr) {htonl(GET_VALUE(5).ui32)}));
	buf_cur += sprintf(buf_cur, "DST=%s ", 
		       inet_ntoa((struct in_addr) {htonl(GET_VALUE(6).ui32)}));

	buf_cur += sprintf(buf_cur,"LEN=%u TOS=%02X PREC=0x%02X TTL=%u ID=%u ", 
			GET_VALUE(7).ui16, GET_VALUE(8).ui8 & IPTOS_TOS_MASK, 
			GET_VALUE(8).ui8 & IPTOS_PREC_MASK, GET_VALUE(9).ui8,
			GET_VALUE(10).ui16);

	if (GET_VALUE(10).ui16 & IP_RF) 
		buf_cur += sprintf(buf_cur, "CE ");

	if (GET_VALUE(11).ui16 & IP_DF)
		buf_cur += sprintf(buf_cur, "DF ");

	if (GET_VALUE(11).ui16 & IP_MF)
		buf_cur += sprintf(buf_cur, "MF ");

	if (GET_VALUE(11).ui16 & IP_OFFMASK)
		buf_cur += sprintf(buf_cur, "FRAG:%u ", 
				GET_VALUE(11).ui16 & IP_OFFMASK);

	switch (GET_VALUE(12).ui8) {

	case IPPROTO_TCP:
		buf_cur += sprintf(buf_cur, "PROTO=TCP ");
		buf_cur += sprintf(buf_cur, "SPT=%u DPT=%u ",
				GET_VALUE(13).ui16, GET_VALUE(14).ui16);
		/* FIXME: config */
		buf_cur += sprintf(buf_cur, "SEQ=%u ACK=%u ", 
				GET_VALUE(15).ui32, GET_VALUE(16).ui32);

		buf_cur += sprintf(buf_cur, "WINDOW=%u ", GET_VALUE(17).ui16);

//		buf_cur += sprintf(buf_cur, "RES=0x%02x ", 
		
		if (GET_VALUE(18).b)
			buf_cur += sprintf(buf_cur, "URG ");

		if (GET_VALUE(19).b)
			buf_cur += sprintf(buf_cur, "ACK ");

		if (GET_VALUE(20).b)
			buf_cur += sprintf(buf_cur, "PSH ");

		if (GET_VALUE(21).b)
			buf_cur += sprintf(buf_cur, "RST ");

		if (GET_VALUE(22).b)
			buf_cur += sprintf(buf_cur, "SYN ");

		if (GET_VALUE(23).b)
			buf_cur += sprintf(buf_cur, "FIN ");

		buf_cur += sprintf(buf_cur, "URGP=%u ", GET_VALUE(24).ui16);

		break;
	case IPPROTO_UDP:

		buf_cur += sprintf(buf_cur, "PROTO=UDP ");

		buf_cur += sprintf(buf_cur, "SPT=%u DPT=%u LEN=%u ", 
				GET_VALUE(25).ui16, GET_VALUE(26).ui16, 
				GET_VALUE(27).ui16);
			break;
	case IPPROTO_ICMP:

		buf_cur += sprintf(buf_cur, "PROTO=ICMP ");

		buf_cur += sprintf(buf_cur, "TYPE=%u CODE=%u ",
				GET_VALUE(28).ui8, GET_VALUE(29).ui8);

		switch (GET_VALUE(28).ui8) {
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			buf_cur += sprintf(buf_cur, "ID=%u SEQ=%u ", 
					   GET_VALUE(30).ui16,
					   GET_VALUE(31).ui16);
			break;
		case ICMP_PARAMETERPROB:
			buf_cur += sprintf(buf_cur, "PARAMETER=%u ",
					   GET_VALUE(32).ui32 >> 24);
			break;
		case ICMP_REDIRECT:
			buf_cur += sprintf(buf_cur, "GATEWAY=%s ", inet_ntoa((struct in_addr) {htonl(GET_VALUE(32).ui32)}));
			break;
		case ICMP_DEST_UNREACH:
			if (GET_VALUE(29).ui8 == ICMP_FRAG_NEEDED)
				buf_cur += sprintf(buf_cur, "MTU=%u ", 
						   GET_VALUE(33).ui16);
			break;
		}
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		buf_cur += sprintf(buf_cur, "PROTO=%s ", GET_VALUE(12).ui8 == IPPROTO_ESP ? "ESP" : "AH");
		/* FIXME: "INCOMPLETE [%u bytes]" in case of short pkt */
		if (intr_ids[34].id > 0) {
			buf_cur += sprintf(buf_cur, "SPI=0x%x ", GET_VALUE(34).ui32);
		}
		break;
	default:

		buf_cur += sprintf(buf_cur, "PROTO=%u ", GET_VALUE(11).ui8);
	}
	strcat(buf_cur, "\n");

	return 0;
}

/* get all key id's for the keys we are intrested in */
static int get_ids(void)
{
	int i;
	struct intr_id *cur_id;

	for (i = 0; i < INTR_IDS; i++) {
		cur_id = &intr_ids[i];
		cur_id->id = keyh_getid(cur_id->name);
		if (!cur_id->id) {
			ulogd_log(ULOGD_ERROR, 
				"Cannot resolve keyhash id for %s\n", 
				cur_id->name);
			return 1;
		}
	}	
	return 0;
}

int printpkt_init(void)
{
	if (gethostname(hostname, sizeof(hostname)) < 0) {
		ulogd_log(ULOGD_FATAL, "can't gethostname(): %s\n",
			  strerror(errno));
		exit(2);
	}

	if (get_ids())
		return 1;

	return 0;
}
