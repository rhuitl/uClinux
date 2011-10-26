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
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/printpkt.h>

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

struct ulogd_key printpkt_keys[INTR_IDS] = {
	{ .name = "oob.time.sec", },
	{ .name = "oob.prefix", },
	{ .name = "oob.in", },
	{ .name = "oob.out", },
	{ .name = "raw.mac", },
	{ .name = "ip.saddr", },
	{ .name = "ip.daddr", },
	{ .name = "ip.totlen", },
	{ .name = "ip.tos", },
	{ .name = "ip.ttl", },
	{ .name = "ip.id", },
	{ .name = "ip.fragoff", },
	{ .name = "ip.protocol", },
	{ .name = "tcp.sport", },
	{ .name = "tcp.dport", },
	{ .name = "tcp.seq", },
	{ .name = "tcp.ackseq", },
	{ .name = "tcp.window", },
	{ .name = "tcp.urg", },
	{ .name = "tcp.ack", },
	{ .name = "tcp.psh", },
	{ .name = "tcp.rst", },
	{ .name = "tcp.syn", },
	{ .name = "tcp.fin", },
	{ .name = "tcp.urgp", },
	{ .name = "udp.sport", },
	{ .name = "udp.dport", },
	{ .name = "udp.len", },
	{ .name = "icmp.type", },
	{ .name = "icmp.code", },
	{ .name = "icmp.echoid", },
	{ .name = "icmp.echoseq", },
	{ .name = "icmp.gateway", },
	{ .name = "icmp.fragmtu", },
	{ .name = "ahesp.spi", },
};

#define GET_VALUE(res, x)	(res[x].u.source->u.value)
#define GET_FLAGS(res, x)	(res[x].u.source->flags)
#define pp_is_valid(res, x)	(GET_FLAGS(res, x) & ULOGD_RETF_VALID)

int printpkt_print(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;

	if (pp_is_valid(res, 1))
		buf_cur += sprintf(buf_cur, "%s", (char *) GET_VALUE(res, 1).ptr);

	if (pp_is_valid(res, 2) && pp_is_valid(res, 3)) {
		buf_cur += sprintf(buf_cur," IN=%s OUT=%s ", 
				   (char *) GET_VALUE(res, 2).ptr, 
				   (char *) GET_VALUE(res, 3).ptr);
	}

	/* FIXME: configurable */
	if (pp_is_valid(res, 4))
		buf_cur += sprintf(buf_cur, "MAC=%s ",
				   (char *) GET_VALUE(res, 4).ptr);
	else
		buf_cur += sprintf(buf_cur, "MAC= ");
	
	if (pp_is_valid(res, 5))
		buf_cur += sprintf(buf_cur, "SRC=%s ", inet_ntoa(
				(struct in_addr) {htonl(GET_VALUE(res, 5).ui32)}));

	if (pp_is_valid(res, 6))
		buf_cur += sprintf(buf_cur, "DST=%s ", inet_ntoa(
				(struct in_addr) {htonl(GET_VALUE(res, 6).ui32)}));

	/* FIXME: add pp_is_valid calls to remainder of file */
	buf_cur += sprintf(buf_cur,"LEN=%u TOS=%02X PREC=0x%02X TTL=%u ID=%u ", 
			GET_VALUE(res, 7).ui16, GET_VALUE(res, 8).ui8 & IPTOS_TOS_MASK, 
			GET_VALUE(res, 8).ui8 & IPTOS_PREC_MASK, GET_VALUE(res, 9).ui8,
			GET_VALUE(res, 10).ui16);

	if (GET_VALUE(res, 10).ui16 & IP_RF) 
		buf_cur += sprintf(buf_cur, "CE ");

	if (GET_VALUE(res, 11).ui16 & IP_DF)
		buf_cur += sprintf(buf_cur, "DF ");

	if (GET_VALUE(res, 11).ui16 & IP_MF)
		buf_cur += sprintf(buf_cur, "MF ");

	if (GET_VALUE(res, 11).ui16 & IP_OFFMASK)
		buf_cur += sprintf(buf_cur, "FRAG:%u ", 
				GET_VALUE(res, 11).ui16 & IP_OFFMASK);

	switch (GET_VALUE(res, 12).ui8) {

	case IPPROTO_TCP:
		buf_cur += sprintf(buf_cur, "PROTO=TCP ");
		buf_cur += sprintf(buf_cur, "SPT=%u DPT=%u ",
				GET_VALUE(res, 13).ui16, GET_VALUE(res, 14).ui16);
		/* FIXME: config */
		buf_cur += sprintf(buf_cur, "SEQ=%u ACK=%u ", 
				GET_VALUE(res, 15).ui32, GET_VALUE(res, 16).ui32);

		buf_cur += sprintf(buf_cur, "WINDOW=%u ", GET_VALUE(res, 17).ui16);

//		buf_cur += sprintf(buf_cur, "RES=0x%02x ", 
		
		if (GET_VALUE(res, 18).b)
			buf_cur += sprintf(buf_cur, "URG ");

		if (GET_VALUE(res, 19).b)
			buf_cur += sprintf(buf_cur, "ACK ");

		if (GET_VALUE(res, 20).b)
			buf_cur += sprintf(buf_cur, "PSH ");

		if (GET_VALUE(res, 21).b)
			buf_cur += sprintf(buf_cur, "RST ");

		if (GET_VALUE(res, 22).b)
			buf_cur += sprintf(buf_cur, "SYN ");

		if (GET_VALUE(res, 23).b)
			buf_cur += sprintf(buf_cur, "FIN ");

		buf_cur += sprintf(buf_cur, "URGP=%u ", GET_VALUE(res, 24).ui16);

		break;
	case IPPROTO_UDP:

		buf_cur += sprintf(buf_cur, "PROTO=UDP ");

		buf_cur += sprintf(buf_cur, "SPT=%u DPT=%u LEN=%u ", 
				GET_VALUE(res, 25).ui16, GET_VALUE(res, 26).ui16, 
				GET_VALUE(res, 27).ui16);
			break;
	case IPPROTO_ICMP:

		buf_cur += sprintf(buf_cur, "PROTO=ICMP ");

		buf_cur += sprintf(buf_cur, "TYPE=%u CODE=%u ",
				GET_VALUE(res, 28).ui8, GET_VALUE(res, 29).ui8);

		switch (GET_VALUE(res, 28).ui8) {
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			buf_cur += sprintf(buf_cur, "ID=%u SEQ=%u ", 
					   GET_VALUE(res, 30).ui16,
					   GET_VALUE(res, 31).ui16);
			break;
		case ICMP_PARAMETERPROB:
			buf_cur += sprintf(buf_cur, "PARAMETER=%u ",
					   GET_VALUE(res, 32).ui32 >> 24);
			break;
		case ICMP_REDIRECT:
			buf_cur += sprintf(buf_cur, "GATEWAY=%s ", inet_ntoa((struct in_addr) {htonl(GET_VALUE(res, 32).ui32)}));
			break;
		case ICMP_DEST_UNREACH:
			if (GET_VALUE(res, 29).ui8 == ICMP_FRAG_NEEDED)
				buf_cur += sprintf(buf_cur, "MTU=%u ", 
						   GET_VALUE(res, 33).ui16);
			break;
		}
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		buf_cur += sprintf(buf_cur, "PROTO=%s ", GET_VALUE(res, 12).ui8 == IPPROTO_ESP ? "ESP" : "AH");
		/* FIXME: "INCOMPLETE [%u bytes]" in case of short pkt */
		if (pp_is_valid(res, 34)) {
			buf_cur += sprintf(buf_cur, "SPI=0x%x ", GET_VALUE(res, 34).ui32);
		}
		break;
	default:

		buf_cur += sprintf(buf_cur, "PROTO=%u ", GET_VALUE(res, 11).ui8);
	}
	strcat(buf_cur, "\n");

	return 0;
}
