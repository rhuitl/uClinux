/* Copyright (c) 2007 by Errata Security */
#ifndef __NETFRAME_H
#define __NETFRAME_H

struct NetFrame
{
	unsigned ipver;
	int protocol;
	int original_length;
	int captured_length;
	int time_secs;
	int time_usecs;
	int frame_number;
	const char *filename;
	const unsigned char *src_mac;
	const unsigned char *dst_mac;
	const unsigned char *bss_mac;
	const char *netbios_source;
	const char *netbios_destination;
	unsigned src_ipv4;
	unsigned dst_ipv4;
	unsigned src_port;
	unsigned dst_port;
	unsigned char src_ipv6[16];
	unsigned char dst_ipv6[16];
};

void FRAMERR(struct NetFrame *frame, const char *msg, ...);

#define FRAMERR_UNKNOWN_UNSIGNED(frame, name, value) FRAMERR(frame, "%s: unknown value: 0x%x (%d)\n", name, value, value);
#define FRAMERR_BADVAL(frame, name, value) FRAMERR(frame, "%s: unknown value: 0x%x (%d)\n", name, value, value);
#define FRAMERR_TRUNCATED(frame, name) FRAMERR(frame, "%s: truncated\n", name);

#endif /*__NETFRAME_H*/
