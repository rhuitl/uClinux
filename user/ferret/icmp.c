/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "ferret.h"
#include "netframe.h"
#include "formats.h"


void process_icmp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned type = px[0];
	unsigned code = px[1];
	unsigned checksum = ex16be(px+2);

	length;frame;checksum;
	process_record(seap, 
		"TEST",REC_SZ,"icmp",-1,
		"type", REC_UNSIGNED, &type, sizeof(unsigned),
		"code", REC_UNSIGNED, &code, sizeof(code),
		0);
}

void process_icmpv6(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned type = px[0];
	unsigned code = px[1];
	unsigned checksum = ex16be(px+2);

	length;frame;checksum;
	process_record(seap, 
		"TEST",REC_SZ,"icmp",-1,
		"type", REC_UNSIGNED, &type, sizeof(unsigned),
		"code", REC_UNSIGNED, &code, sizeof(code),
		0);

	if (frame->dst_ipv6[0] == 0xFF)
	process_record(seap, 
		"ID-MAC",REC_MACADDR,frame->src_mac, 6,
		"ipv6",REC_IPv6,frame->src_ipv6, 16,
		0);
}


