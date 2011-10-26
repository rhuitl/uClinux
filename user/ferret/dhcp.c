/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"
#include <string.h>

struct DHCP {
	unsigned op;
	unsigned hardware_type;
	unsigned hardware_address_length;
	unsigned hops;
	unsigned transaction_id;
	unsigned seconds_elapsed;
	unsigned flags;

	unsigned ciaddr;		/* client IP address (if client can respond to ARPs */
	unsigned yiaddr;		/* "your" (client) IP address */
	unsigned siaddr;		
	unsigned giaddr;		/* Relay agent IP address, used when router relays packets */ 
	unsigned char chaddr[20];	/* client hardware address */
	unsigned sname[68];		/* Optional server host name */
	unsigned char file[130];	/* Optional boot file name */

	unsigned msg;
	unsigned server_identifier;
	unsigned rfc2563_auto_configure;	/* 1=yes, 2=no*/

	unsigned overload_servername;
	unsigned overload_filename;
};

static void _dhcp_get_option(const unsigned char *px, unsigned length, unsigned offset, unsigned option_tag, const unsigned char **r_option, unsigned *r_option_length, unsigned *r_overload)
{

	while (offset < length) {
		unsigned tag;
		unsigned len;

		tag = px[offset++];
		if (tag == 0xFF)
			break; /*end of list*/
		if (tag == 0x00)
			continue; /*padding*/

		if (offset >= length)
			return;
		len = px[offset++];
		if (offset >= length)
			return;

		if (tag == option_tag)
		{
			*r_option = px+offset;
			*r_option_length = len;
		}

		if (tag == 52) {
			if (len != 1)
				;
			else if (r_overload) {
				*r_overload = px[offset];
			}
		}

		offset += len;
	}
}


static void dhcp_get_option(const unsigned char *px, unsigned length, unsigned option_tag, const unsigned char **r_option, unsigned *r_option_length)
{
	unsigned overload = 0;
	unsigned offset=0;

	*r_option = px;
	*r_option_length = 0;

	offset = 28+16+64+128;

	if (offset+4 > length)
		return;

	if (memcmp(px+offset, "\x63\x82\x53\x63", 4) != 0)
		return;
	offset += 4;

	_dhcp_get_option(px, length, offset, option_tag, r_option, r_option_length, &overload);
	if (overload & 1)
		_dhcp_get_option(px, 28+16+64+128, 28+16+64, option_tag, r_option, r_option_length, 0);
	if (overload & 2)
		_dhcp_get_option(px, 28+16+64, 28+16, option_tag, r_option, r_option_length, 0);
}

void process_dhcp_options(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct DHCP *dhcp)
{
	seap;
	while (offset < length) {
		unsigned tag;
		unsigned len;

		tag = px[offset++];
		if (tag == 0xFF)
			break; /*end of list*/
		if (tag == 0x00)
			continue; /*padding*/

		if (offset >= length) {
			FRAMERR(frame, "dhcp: option too short\n");
			break;
		}
		len = px[offset++];
		if (offset >= length) {
			FRAMERR(frame, "dhcp: option too short\n");
			break;
		}

		SAMPLE("DHCP", "tag",	REC_UNSIGNED, &tag,	sizeof(tag));

		switch (tag) {
		case 1: /*0x01 - Subnet tag */
			break;
		case 3: /*Router */
			if (len !=  4)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				unsigned ip = ex32be(px+offset);
				process_record(seap,
					"proto",	REC_SZ,			"DHCP",		-1,
					"server",	REC_FRAMESRC,	frame, -1, 
					"op",		REC_SZ,			"offer",-1,
					"router",	REC_IPv4,		&ip,	sizeof(ip),
					0);
			}
			break;
		case 6: /*DNS server*/
			{
				unsigned i;
				for (i=0; i<len; i+=4) {
					unsigned ip = ex32be(px+offset+i);
					process_record(seap,
						"proto",	REC_SZ,			"DHCP",		-1,
						"server",	REC_FRAMESRC,	frame, -1,
						"op",		REC_SZ,			"offer",-1,
						"dns-server",REC_IPv4,		&ip,	sizeof(ip),
						0);
				}
			}
			break;
		case 12: /*0x0c - Hostname */
			if (len ==  0)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else
				process_record(seap,
					"ID-MAC",	REC_MACADDR,	dhcp->chaddr,	6,
					"proto",	REC_SZ,			"DHCP",		-1,
					"op",		REC_SZ,			"Hostname",-1,
					"hostname",	REC_PRINTABLE,	px+offset,	len,
					0);
			break;
		case 15: /*0x0f - Domain Name */
			if (len ==  0)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else
				process_record(seap,
					"proto",	REC_SZ,			"DHCP",		-1,
					"server",	REC_FRAMESRC,	frame, -1,
					"op",		REC_SZ,			"offer",-1,
					"domainname",	REC_PRINTABLE,	px+offset,	len,
					0);
			break;
		case 31: /*perform router discovery*/
			{
				unsigned discovery=0;
				unsigned i;
				for (i=0; i<len; i++)
					discovery = discovery*10 + px[offset+i];
				process_record(seap,
					"proto",	REC_SZ,			"DHCP",		-1,
					"server",	REC_FRAMESRC,	frame, -1,
					"op",		REC_SZ,			"offer",-1,
					"discovery",REC_UNSIGNED,	&discovery,	sizeof(discovery),
					0);
			}
			break;
		case 53: /*0x35 - DHCP message type*/
			if (len != 1) {
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
				break;
			}
			dhcp->msg = px[offset];

			switch (dhcp->msg) {
			case 1: /*discover*/
			case 2: /*offer*/
			case 3: /*request*/
			case 5: /*ack*/
			case 6: /*nak*/
			case 7: /* release */
			case 8: /*inform*/
				SAMPLE("DHCP", "msg",	REC_UNSIGNED, &dhcp->msg,	sizeof(dhcp->msg));
				break;
			default:
				FRAMERR(frame, "dhcp: ungknown msg type %d\n", dhcp->msg);
			}
			break;
		case 55: /* 0x37 - Parameter Request List */
			if (len == 0)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			break;
		case 0x36: /* Server Identifier*/
			if (len != 4) {
				FRAMERR(frame, "dhcp: abnormal option length\n");
				break;
			}
			dhcp->server_identifier = ex32be(px+offset);
			break;
		case 43: /* vendor info*/
			if (len ==  0)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else
				process_record(seap,
					"ID-MAC",	REC_MACADDR,	dhcp->chaddr,	6,
					"proto",	REC_SZ,			"DHCP",		-1,
					"op",		REC_SZ,			"Vendor-Info",-1,
					"info",	REC_PRINTABLE,	px+offset,	len,
					0);
			break;
		case 60: /* 0x3c - Vendor class identifier */
			if (len ==  0)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else
				process_record(seap,
					"ID-MAC",	REC_MACADDR,	dhcp->chaddr,	6,
					"proto",	REC_SZ,			"DHCP",		-1,
					"op",		REC_SZ,			"Vendor-ID",-1,
					"vendor",	REC_PRINTABLE,	px+offset,	len,
					0);
			break;
		case 61: /* 0x3d - Client identifier */
			if (len < 2)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				const unsigned char *clientid = px+offset+1;
				switch (px[offset]) {
				case 0:
					break;
				case 1:
					if (len != 7)
						FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
					else {
						if (memcmp(dhcp->chaddr, "\0\0\0\0\0\0", 6) == 0) {
							FRAMERR(frame, "untested code path\n");
							memcpy(dhcp->chaddr, clientid, 6);
							dhcp->hardware_type = 1;
							dhcp->hardware_address_length = 6;
						}
						else if (memcmp(dhcp->chaddr, clientid, 6) != 0) {
							FRAMERR(frame, "untested code path\n");
							process_record(seap,
								"ID-MAC",	REC_MACADDR,	dhcp->chaddr,	6,
								"proto",	REC_SZ,			"DHCP",		-1,
								"op",		REC_SZ,			"Client-ID",-1,
								"new.mac",	REC_MACADDR,	clientid,	6,
								0);
						}
					}
				}
			}
			break;
		case 50: /* 0x32 - Request IP */
			if (len != 4)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				unsigned ip_address = ex32be(px+offset);
				process_record(seap,
					"ID-MAC",	REC_MACADDR,	dhcp->chaddr,	6,
					"proto",	REC_SZ,			"DHCP",		-1,
					"op",		REC_SZ,			"Request-IP",-1,
					"ip",		REC_IPv4,		&ip_address,	sizeof(ip_address),
					0);
			}
			break;
		case 51: /* IP address lease time */
			if (len !=  4)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				unsigned lease_time = ex32be(px+offset);
				process_record(seap,
					"proto",	REC_SZ,			"DHCP",		-1,
					"server",	REC_FRAMESRC,	frame, -1,
					"op",		REC_SZ,			"offer",-1,
					"leasetime",REC_UNSIGNED,	&lease_time,	sizeof(lease_time),
					0);
			}
			break;
		case 52: /* Option Overload */
			if (len != 1)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				if (px[offset] & 1)
					dhcp->overload_filename = 1;
				if (px[offset] & 2)
					dhcp->overload_servername = 1;
			}
			break;
		case 57: /* Mac DHCP message size, used by diskless clients to report 1500 so they don't have to reassemble?*/
			break;
		case 81:
			if (len < 4)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				const char *name = (const char*)px+offset+3;
				unsigned name_length = len-3;

				process_record(seap,
					"ID-MAC",	REC_MACADDR,	dhcp->chaddr,	6,
					"proto",	REC_SZ,			"DHCP",		-1,
					"op",		REC_SZ,			"FQDN", -1,
					"fqdn",		REC_PRINTABLE,	name, name_length,
					0);
				
				if (dhcp->op != 1)
					FRAMERR(frame, "implement this code path\n");
			}
			break;

		case 116: /*0x74 - Auto-configure */
			if (len != 1) {
				FRAMERR(frame, "dhcp: abnormal option length\n");
				break;
			}
			switch (px[offset]) {
			case 0: dhcp->rfc2563_auto_configure = 2; break;
			case 1: dhcp->rfc2563_auto_configure = 1; break;
			default:
				FRAMERR(frame, "dhcp: bad value, tag=%d, len=%d\n", tag, len);
			}
			break;
		case 44: /* netbios over tcp/ip server */
			break;
		default:
			FRAMERR(frame, "dhcp: tag: unknown %d (0x%02x)\n", tag, tag);
			break;
		}


		offset += len;
	}
}

static unsigned dhcp_number(const unsigned char *px, unsigned length, unsigned tag)
{
	unsigned i;
	unsigned result;
	const unsigned char *option;
	unsigned option_length;

	dhcp_get_option(px, length, tag, &option, &option_length);
	if (option_length == 0)
		return 0xFFFFFFFF;
	result = 0;
	for (i=0; i<option_length; i++)
		result = result * 256 + option[i];
	return result;
}


void process_dhcp(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct DHCP dhcp;

	memset(&dhcp, 0, sizeof(dhcp));
	if (length < 200) {
		FRAMERR(frame, "dhcp: frame too short\n");
		return;
	}

	dhcp.op = px[0];
	dhcp.hardware_type = px[1];
	dhcp.hardware_address_length = px[2];
	dhcp.hops = px[3];

	dhcp.transaction_id = ex32be(px+4);
	dhcp.seconds_elapsed = ex16be(px+8);
	dhcp.flags = ex16be(px+10);

	dhcp.ciaddr = ex32be(px+12);
	dhcp.yiaddr = ex32be(px+16);
	dhcp.siaddr = ex32be(px+20);
	dhcp.giaddr = ex32be(px+24);

	memcpy(dhcp.chaddr, px+28, 16);
	dhcp.chaddr[16] = '\0';

	memcpy(dhcp.sname, px+28+16, 64);
	dhcp.sname[64] = '\0';

	memcpy(dhcp.file, px+28+16+64, 128);
	dhcp.file[128] = '\0';

	offset = 28+16+64+128;

	if (offset+4 > length)
		return;

	if (memcmp(px+offset, "\x63\x82\x53\x63", 4) != 0)
		return;
	offset += 4;

	/* Process special options */
	dhcp.msg = dhcp_number(px, length, 53);
	switch (dhcp.msg) {
	case 8: /* inform */
		/* Process vendor specific information */
		{
			const unsigned char *spec;
			unsigned spec_length;
			const unsigned char *id;
			unsigned id_length;

			dhcp_get_option(px, length, 43, &spec, &spec_length);
			dhcp_get_option(px, length, 60, &id, &id_length);

			if (spec_length && id_length) {
				process_record(seap,
					"application",	REC_PRINTABLE, id, id_length,
					"info",			REC_PRINTABLE, spec, spec_length,
					0);
			}
		}
	}



	process_dhcp_options(seap, frame, px, length, offset, &dhcp);

	if (dhcp.overload_filename)
		process_dhcp_options(seap, frame, px, 28+16+64+128, 28+16+64, &dhcp);
	if (dhcp.overload_servername)
		process_dhcp_options(seap, frame, px, 28+16+64, 28+16, &dhcp);

	SAMPLE("BOOTP", "type",	REC_UNSIGNED, &dhcp.op,	sizeof(dhcp.op));
	switch (dhcp.op) {
	case 1: /*BOOTP request */
		break;
	case 2: /*BOOTP reply*/ 
		switch (dhcp.msg) {
		case 2:
			break;
		case 5: /*ack*/
			break;
		case 6: /*DHCP NACK*/
			{
				const unsigned char *dst_mac;
				unsigned src_ip;

				if (dhcp.hardware_address_length != 6) {
					FRAMERR(frame, "dhcp: expected hardware address length = 6, found length = %d\n", dhcp.hardware_address_length);
					break;
				}
				if (memcmp(dhcp.chaddr, "\0\0\0\0\0\0", 6) == 0) {
					FRAMERR(frame, "dhcp: expected hardware address, but found [00:00:00:00:00:00]\n");
					break;
				} else
					dst_mac = &dhcp.chaddr[0];

				if (dhcp.server_identifier)
					src_ip = dhcp.server_identifier;
				else if (dhcp.siaddr)
					src_ip = dhcp.siaddr;
				else
					src_ip = frame->src_ipv4;

				process_record(seap,
					"proto",	REC_SZ,			"DHCP",		-1,
					"op",		REC_SZ,			"NACK",		-1,
					"src.ip",	REC_IPv4,		&src_ip,	sizeof(src_ip),
					"dst.mac",	REC_MACADDR,	dst_mac,	6,
					0);
			}
			break;
		case 8:
			break;
		default:
			FRAMERR(frame, "dhcp: unknown dhcp msg type %d\n", dhcp.msg);
			break;
		}
		break;
	default:
			FRAMERR(frame, "dhcp: unknown bootp op code %d\n", dhcp.op);
		break;

	}

}

