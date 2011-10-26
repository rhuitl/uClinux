/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "ferret.h"
#include "netframe.h"
#include "formats.h"

#include <ctype.h>
#include <string.h>

enum {
	TCP_FIN=1,
	TCP_SYN=2,
	TCP_RST=4,
	TCP_PSH=8,
	TCP_ACK=16,
	TCP_URG=32,
};

static void tcp_syn(struct Seaper *seap, struct NetFrame *frame)
{
	seap;frame;
}
static void tcp_synack(struct Seaper *seap, struct NetFrame *frame)
{
	seap;frame;
}
static void tcp_ack(struct Seaper *seap, struct NetFrame *frame)
{
	seap;frame;
}
static void tcp_fin(struct Seaper *seap, struct NetFrame *frame)
{
	seap;frame;
}


int smellslike_httprequest(const unsigned char *data, unsigned length)
{
	unsigned i;
	unsigned method;
	unsigned url;

	for (i=0; i<length && isspace(data[i]); i++)
		;
	method = i;
	while (i<length && !isspace(data[i]))
		i++;
	if (i>10)
		return 0;
	while (i<length && isspace(data[i]))
		i++;
	url = i;
	while (i<length && data[i] != '\n')
		i++;

	if (i>0 && data[i] == '\n') {
		i--;

		if (i>0 && data[i] == '\r')
			i--;

		if (i>10 && memicmp(&data[i-7], "HTTP/1.0", 8) == 0)
			return 1;
		if (i>10 && memicmp(&data[i-7], "HTTP/1.1", 8) == 0)
			return 1;
		if (i>10 && memicmp(&data[i-7], "HTTP/0.9", 8) == 0)
			return 1;
		
	}

	return 0;
}

int smellslike_msn_messenger(const unsigned char *data, unsigned length)
{
	unsigned i=0;
	unsigned method;
	unsigned method_length=0;
	unsigned parms;
	unsigned non_printable_count = 0;
	unsigned line_length;

	if (smellslike_httprequest(data, length))
		return 0;


	method = i;
	while (i<length && !isspace(data[i]))
		i++, method_length++;;
	while (i<length && data[i] != '\n' && isspace(data[i]))
		i++;
	parms = i;
	while (i<length && data[i] != '\n')
		i++;
	line_length = i;

	for (i=0; i<length; i++)
		if (!(isprint(data[i]) || isspace(data[i])))
			non_printable_count++;


	if (method_length == 3 && data[line_length] == '\n' && non_printable_count == 0)
		return 1;

	return 0;
}

static unsigned tcp_record_hash(struct TCPRECORD *rec)
{
	unsigned i;
	unsigned hash=0;

	for (i=0; i<16; i++) {
		hash += rec->ip_dst[i];
		hash += rec->ip_src[i] << 8;
	}
	hash += rec->tcp_dst;
	hash += rec->tcp_src << 8;

	return hash;
}
static unsigned tcp_record_equals(struct TCPRECORD *left, struct TCPRECORD *right)
{
	unsigned i;

	for (i=0; i<16; i++) {
		if (left->ip_src[i] != right->ip_src[i])
			return 0;
		if (left->ip_dst[i] != right->ip_dst[i])
			return 0;
	}
	if (left->ip_ver != right->ip_ver)
		return 0;
	if (left->tcp_dst != right->tcp_dst)
		return 0;
	if (left->tcp_src != right->tcp_src)
		return 0;

	return 1;
}
static void tcp_lookup_session(struct Seaper *seap, struct NetFrame *frame)
{
	struct TCPRECORD rec = {0};
	struct TCPRECORD *session;

	seap->session = 0;

	if (frame->ipver != 0) {
		return;
	}

	rec.ip_ver = frame->ipver;
	memcpy(rec.ip_dst, &frame->dst_ipv4, 4);
	memcpy(rec.ip_src, &frame->src_ipv4, 4);
	rec.tcp_dst = (unsigned short)frame->dst_port;
	rec.tcp_src = (unsigned short)frame->src_port;

	session = &seap->sessions[tcp_record_hash(&rec) % (sizeof(seap->sessions)/sizeof(seap->sessions[0]))];

	if (!tcp_record_equals(session, &rec)) {
		memcpy(session, &rec, sizeof(rec));
	}

	seap->session = session;
}

static void tcp_data(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	tcp_lookup_session(seap, frame);

	if (smellslike_httprequest(px, length))
		process_simple_http(seap, frame, px, length);

	if (frame->src_port == 1863 || frame->dst_port == 1863) {
		if (smellslike_msn_messenger(px, length)) {
			if (frame->src_port == 1863)
				process_simple_msnms_server_response(seap, frame, px, length);
			else
				process_simple_msnms_client_request(seap, frame, px, length);
		}
	}

	if (frame->src_port == 110)
		process_simple_pop3_response(seap, frame, px, length);
	else if (frame->dst_port == 110)
		process_simple_pop3_request(seap, frame, px, length);

	if (frame->src_port == 25)
		process_simple_smtp_response(seap, frame, px, length);
	else if (frame->dst_port == 25)
		process_simple_smtp_request(seap, frame, px, length);

	seap->session = 0;
}

void process_tcp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct {
		unsigned src_port;
		unsigned dst_port;
		unsigned seqno;
		unsigned ackno;
		unsigned header_length;
		unsigned flags;
		unsigned window;
		unsigned checksum;
		unsigned urgent;
	} tcp;

	if (length == 0) {
		FRAMERR(frame, "tcp: frame empty\n");
		return;
	}
	if (length < 20) {
		FRAMERR(frame, "tcp: frame too short\n");
		return;
	}

/*
	    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

	tcp.src_port = ex16be(px+0);
	tcp.dst_port = ex16be(px+2);
	tcp.seqno = ex32be(px+4);
	tcp.ackno = ex32be(px+8);
	tcp.header_length = px[12]>>2;
	tcp.flags = px[13];
	tcp.window = ex16be(px+14);
	tcp.checksum = ex16be(px+16);
	tcp.urgent = ex16be(px+18);

	frame->src_port = tcp.src_port;
	frame->dst_port = tcp.dst_port;

	if (tcp.header_length < 20) {
		FRAMERR(frame, "tcp: header too short, expected length=20, found length=%d\n", tcp.header_length);
		return;
	}
	if (tcp.header_length > length) {
		FRAMERR(frame, "tcp: header too short, expected length=%d, found length=%d\n", tcp.header_length, length);
		return;
	}
	if ((tcp.flags & 0x20) && tcp.urgent > 0) {
		FRAMERR(frame, "tcp: found %d bytes of urgent data\n", tcp.urgent);
		return;
	}

	if (tcp.header_length > 20) {
		unsigned o = 20;
		unsigned max = tcp.header_length;

		while (o < tcp.header_length) {
			unsigned tag = px[o++];
			unsigned len;

			if (tag == 0)
				break;
			if (tag == 1)
				continue;

			if (o >= max) {
				FRAMERR(frame, "tcp: options too long\n");
				break;
			}
			len = px[o++];

			if (len < 2) {
				FRAMERR(frame, "tcp: invalid length field\n");
				break;
			}
			if (o+len-2 > max) {
				FRAMERR(frame, "tcp: options too long\n");
				break;
			}

			switch (tag) {
			case 0x02: /* max seg size */
				if (len != 4)
					FRAMERR(frame, "tcp: unknown length: option=%d, length=%d\n", tag, len);
				break;
			case 0x04: /* SACK permitted */
				if (len != 2)
					FRAMERR(frame, "tcp: unknown length: option=%d, length=%d\n", tag, len);
				break;
			case 0x05: /* SACK */
				break;
			case 0x08: /*timestamp*/
				break;
			case 0x03: /*window scale*/
				break;
			default:
				FRAMERR(frame, "tcp: unknown option=%d, length=%d\n", tag, len);
			}

			o += len-2;
		}
	}


	switch (tcp.flags & 0x3F) {
	case TCP_SYN:
		tcp_syn(seap, frame);
		break;
	case TCP_SYN|TCP_ACK:
		tcp_synack(seap, frame);
		break;
	case TCP_FIN:
	case TCP_FIN|TCP_ACK:
	case TCP_FIN|TCP_ACK|TCP_PSH:
		tcp_fin(seap, frame);
		break;
	case TCP_ACK:
	case TCP_ACK|TCP_PSH:
		if (tcp.header_length >= length) {
			tcp_ack(seap, frame);
		} else
			tcp_data(seap, frame, px+tcp.header_length, length-tcp.header_length);
		break;
	case TCP_RST:
	case TCP_RST|TCP_ACK:
		break;
	case 0x40|TCP_ACK:
		break;
	case TCP_RST|TCP_ACK|TCP_FIN:
		break;
	default:
		FRAMERR(frame, "tcp: unexpected combo of flags: 0x%03x\n", tcp.flags);
	}
}

