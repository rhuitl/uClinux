/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "formats.h"
#include "netframe.h"
#include "ferret.h"
#include <string.h>
#include <stdio.h>

typedef unsigned char MACADDR[6];

struct	WIFI_MGMT {
	int frame_control;
	int duration;
	MACADDR destination;
	MACADDR source;
	MACADDR bss_id;
	int frag_number;
	int seq_number;

	unsigned char *ssid;
	unsigned ssid_length;

	unsigned maxrate;
	unsigned channel;
};

const char *oui_vendor(unsigned oui)
{
	switch (oui) {
	case 0x00601d: return "Agere";
	case 0x001018: return "Broadcom";
	case 0x000347: return "Intel";
	case 0x004096: return "Aironet";
	case 0x00037f: return "Atheros";
	case 0x0050f2: return "Microsoft";
	default: return "(unknown)";
	}
}
void process_wifi_fields(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct WIFI_MGMT *wifimgmt)
{
	while (offset < length) {
		unsigned tag, len;

		/* fix known bugs */
		if (offset == length-1 && px[offset] == 0x80 && memcmp(wifimgmt->source, "\x00\x02\x2d", 3) == 0)
			break;

		tag = px[offset++];
		if (offset >= length) {
			/* Fix Agere bug */
			FRAMERR(frame, "wifi parms: went past eof\n");
			break;
		}
		len = px[offset++];

		/* Fix bugs in well-known cards that cause us to go off the end */
		if (tag == 5 && memcmp(wifimgmt->source, "\x00\x02\x2d", 3) == 0 && offset+len > length)
			len = length-offset;
		if (tag == 0x80 && length-offset>3 && memcmp(px+offset, "\x00\x60\x1d", 3) == 0 && offset+len > length)
			len = length-offset;
		if (tag == 0xdd && length-offset>3 && memcmp(px+offset, "\x00\x03\x7f", 3) == 0 && offset+len > length)
			len = length-offset;

		if (offset + len > length) {
			; //FRAMERR(frame, "wifi parms: went past eof\n");
			break;
		}


		SAMPLE("IEEE802.11", "parm",REC_UNSIGNED, &tag, sizeof(tag));

		switch (tag) {
		case 0x00: /* SSID */
			wifimgmt->ssid = (unsigned char*)px+offset;
			wifimgmt->ssid_length = len;

			if (len == 0) {
				wifimgmt->ssid = (unsigned char*)"(broadcast)";
				wifimgmt->ssid_length = strlen((char*)wifimgmt->ssid);
			}
			break;
		case 1: /* SUPPORTED RATES */
		case 50: /* EXTENDED SUPPORTED RATES */
			{
				unsigned i;
				for (i=0; i<len; i++) {
					unsigned rate=0;

					rate = (px[offset+i]&0x7F) * 5;
					if (wifimgmt->maxrate < rate)
						wifimgmt->maxrate = rate;
				}
			}
			break;
		case 3: /* CHANNEL */
			if (len != 1)
				FRAMERR(frame, "wifi parms: bad channel length\n");
			if (len > 0)
				wifimgmt->channel = px[offset+len-1];
			break;
		case 5: /* TIM */
			/*TIM bug in Agere */
			if (offset + len > length)
				len = length-offset;
			break;
		case 0x06: /*IBSS */
		case 10: /*unknown*/
		case 0x0b: /* QBSS Load Element for 802.11e */
		case 150: /*unknown*/
		case 0x2a: /*ERP Information */
		case 0x2f: /*ERP infomration (why is this the same as 0x2a?) */
		case 0x2c: /*IEEE802.11e Traffic Classification (TCLAS) */
		case 0x30: /*RSN Information */
		case 0x85: /*Cisco proprietary */
			process_record(seap,
				"proto",			REC_SZ,			"WiFi",					-1,
				"op",				REC_SZ,			"unknownparm",			-1,
				"macaddr",			REC_MACADDR,	wifimgmt->source,		6,
				"wifi.tag",			REC_UNSIGNED,	&tag,					sizeof(tag),
				"wifi.value",		REC_PRINTABLE,	px+offset,				len,
				0);
			break;
		case 7: /* COUNTRY INFORMATION */
			if (tag < 3)
				FRAMERR(frame, "wifi parms: bad country info\n");
			else
			{
				char country[16];
				int country_len = len-3;
				int min_channel = px[offset+len-3];
				int max_channel = px[offset+len-2];
				int max_power = px[offset+len-1];
				char power[32];

				if (country_len > sizeof(country-1))
					country_len = sizeof(country-1);
				memcpy(country, px+offset, country_len);
				country[country_len] = '\0';

				_snprintf(power, sizeof(power), "%d-dBm", max_power);

				process_record(seap,
					"proto",			REC_SZ,			"WiFi",					-1,
					"op",				REC_SZ,			"countryinfo",			-1,
					"macaddr",			REC_MACADDR,	wifimgmt->source,		6,
					"wifi.country",		REC_SZ,			country,				-1,
					"wifi.minchannel",	REC_UNSIGNED,	&min_channel,			sizeof(min_channel),
					"wifi.maxchannel",	REC_UNSIGNED,	&max_channel,			sizeof(min_channel),
					"wifi.power",		REC_SZ,			power,					-1,
					0);
			}
			break;
		case 0x80:
		case 0xdd:
			if (len < 3) {
				FRAMERR(frame, "wifi vendor extension: too short\n");
			} else {
				unsigned oui = ex24be(px+offset);
				SAMPLE("IEEE802.11", "oui",REC_UNSIGNED, &oui, sizeof(oui));

				switch (oui) {
				case 0x00601d: /*agere*/
				case 0x001018: /*broadcom*/
				case 0x000347: /*intel*/
				case 0x004096: /*aironet*/
				case 0x00037f: /*Atheros*/
					process_record(seap,
						"proto",		REC_SZ,			"WiFi",				-1,
						"op",		REC_SZ,			"vendor",				-1,
						//"macaddr",	REC_MACADDR,	wifimgmt.source,		6,
						"vendor.name",		REC_SZ,			oui_vendor(oui),	-1,
						"vendor.oui",		REC_HEX24,		&oui,				sizeof(oui),
						"vendor.data",		REC_PRINTABLE,	px+offset+3,		len-3,
						0);
					break;
				case 0x0050f2: /*Microsoft*/
					offset += 3;
					len -= 3;
					if (len < 1) 
						FRAMERR(frame, "wifi vendor extension: too short\n");
					else {
						int tag2 = px[offset];
						offset++;
						len--;
						switch (tag2) {
						case 0x01: /* MS cypher suites */
						case 0x02:
							process_record(seap,
								"proto",		REC_SZ,				"WiFi",				-1,
								"op",			REC_SZ,				"vendor",			-1,
								//"macaddr",	REC_MACADDR,		wifimgmt.source,	6,
								"vendor.name",		REC_SZ,			oui_vendor(oui),	-1,
								"vendor.oui",		REC_HEX24,		&oui,				sizeof(oui),
								"vendor.data",		REC_PRINTABLE,	px+offset+3,		len-3,
								0);
							break;
						default:
							FRAMERR(frame, "wifi MS extension: unknown 0x%02x\n", tag2);
						}
					}
					break;
				case 0x00393: /* Apple */
					break;
				case 0x0af5: /* AirgoNet */
					break;
				default:
					FRAMERR(frame, "wifi vendor extension: unknown 0x%06x\n", oui);
				}
			}
			break;
		default:
			FRAMERR(frame, "wifi parms: unknown tag %d(0x%02x)\n", tag, tag);
		}


		offset += len;
	}

}

void process_wifi_probe(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct	WIFI_MGMT wifimgmt;
	memset(&wifimgmt, 0, sizeof(wifimgmt));

	if (length < 24) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	memcpy(wifimgmt.source, px+10, 6);

	/* Process variable tags */
	offset = 24;
	process_wifi_fields(seap, frame, px, length, offset, &wifimgmt);

	process_record(seap,
		"proto",	REC_SZ,			"WiFi",				-1,
		"op",		REC_SZ,			"probe",		-1,
		"macaddr",	REC_MACADDR,	wifimgmt.source,	6,
		"SSID",		REC_PRINTABLE,	wifimgmt.ssid,		wifimgmt.ssid_length,
		0);
}

void process_wifi_proberesponse(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;

	struct	WIFI_MGMT wifimgmt;
	memset(&wifimgmt, 0, sizeof(wifimgmt));

	if (length < 24) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	memcpy(wifimgmt.source, px+10, 6);

	/* Process variable tags */
	offset = 24;

	offset += 8; /* timestamp */

	offset += 2; /* beacon interval */

	offset += 2; /* capability information */

	process_wifi_fields(seap, frame, px, length, offset, &wifimgmt);

	{
		char maxrate[32];
		if (wifimgmt.maxrate%10)
			_snprintf(maxrate, sizeof(maxrate),"%d.%d-mbps", wifimgmt.maxrate/10, wifimgmt.maxrate%10);
		else
			_snprintf(maxrate, sizeof(maxrate),"%d-mbps", wifimgmt.maxrate/10);

		process_record(seap,
			"proto",	REC_SZ,			"WiFi",				-1,
			"op",		REC_SZ,			"probe-response",		-1,
			"macaddr",	REC_MACADDR,	wifimgmt.source,			6,
			"SSID",		REC_PRINTABLE,	wifimgmt.ssid,				wifimgmt.ssid_length,
			"maxrate",	REC_SZ,			maxrate,					-1,
			"channel",	REC_UNSIGNED,	&wifimgmt.channel,			sizeof(wifimgmt.channel),
			0);
	}
}

void process_wifi_associate_request(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct	WIFI_MGMT wifimgmt;
	memset(&wifimgmt, 0, sizeof(wifimgmt));

	if (length < 28) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	memcpy(wifimgmt.destination, px+4, 6);
	memcpy(wifimgmt.source, px+10, 6);
	memcpy(wifimgmt.bss_id, px+16, 6);


	process_wifi_fields(seap, frame, px, length, 28, &wifimgmt);

	{
		char maxrate[32];
		if (wifimgmt.maxrate%10)
			_snprintf(maxrate, sizeof(maxrate),"%d.%d-mbps", wifimgmt.maxrate/10, wifimgmt.maxrate%10);
		else
			_snprintf(maxrate, sizeof(maxrate),"%d-mbps", wifimgmt.maxrate/10);


		process_record(seap,
			"proto",	REC_SZ,			"WiFi",				-1,
			"op",		REC_SZ,			"associate",		-1,
			"macaddr",	REC_MACADDR,	wifimgmt.source,			6,
			"SSID",		REC_PRINTABLE,	wifimgmt.ssid,				wifimgmt.ssid_length,
			"BSS",		REC_MACADDR,	wifimgmt.bss_id,			6,
			"maxrate",	REC_SZ,			maxrate,					-1,
			0);
	}
}
void process_wifi_disassociate_request(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct	WIFI_MGMT wifimgmt;
	unsigned reason;
	memset(&wifimgmt, 0, sizeof(wifimgmt));

	if (length < 26) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	memcpy(wifimgmt.destination, px+4, 6);
	memcpy(wifimgmt.source, px+10, 6);
	memcpy(wifimgmt.bss_id, px+16, 6);
	reason = ex16le(px+24);

	process_record(seap,
		"proto",	REC_SZ,			"WiFi",				-1,
		"op",		REC_SZ,			"disassociate",		-1,
		"macaddr",	REC_MACADDR,	wifimgmt.source,			6,
		"BSS",		REC_MACADDR,	wifimgmt.bss_id,			6,
		"reason",	REC_UNSIGNED,	&reason, sizeof(reason),
		0);
}

void process_wifi_deauthentication(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct	WIFI_MGMT wifimgmt;
	unsigned reason;
	memset(&wifimgmt, 0, sizeof(wifimgmt));

	if (length < 26) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	memcpy(wifimgmt.destination, px+4, 6);
	memcpy(wifimgmt.source, px+10, 6);
	memcpy(wifimgmt.bss_id, px+16, 6);
	reason = ex16le(px+24);

	process_record(seap,
		"proto",	REC_SZ,			"WiFi",				-1,
		"op",		REC_SZ,			"deauthentication",		-1,
		"macaddr",	REC_MACADDR,	wifimgmt.source,			6,
		"BSS",		REC_MACADDR,	wifimgmt.bss_id,			6,
		"reason",	REC_UNSIGNED,	&reason, sizeof(reason),
		0);
}

void process_wifi_beacon(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;

	struct	WIFI_MGMT wifimgmt;
	memset(&wifimgmt, 0, sizeof(wifimgmt));

	if (length < 24) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	memcpy(wifimgmt.source, px+10, 6);

	/* Process variable tags */
	offset = 24;

	offset += 8; /* timestamp */

	offset += 2; /* beacon interval */

	offset += 2; /* capability information */

	process_wifi_fields(seap, frame, px, length, offset, &wifimgmt);

	{
		char maxrate[32];
		if (wifimgmt.maxrate%10)
			_snprintf(maxrate, sizeof(maxrate),"%d.%d-mbps", wifimgmt.maxrate/10, wifimgmt.maxrate%10);
		else
			_snprintf(maxrate, sizeof(maxrate),"%d-mbps", wifimgmt.maxrate/10);

		process_record(seap,
			"proto",	REC_SZ,			"WiFi",				-1,
			"op",		REC_SZ,			"beacon",		-1,
			"macaddr",	REC_MACADDR,	wifimgmt.source,			6,
			"SSID",		REC_PRINTABLE,	wifimgmt.ssid,				wifimgmt.ssid_length,
			"maxrate",	REC_SZ,			maxrate,					-1,
			"channel",	REC_UNSIGNED,	&wifimgmt.channel,			sizeof(wifimgmt.channel),
			0);
	}
}

void process_wifi_data(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	unsigned ethertype;
	unsigned oui;

	if (length <= 24) {
		; //FRAMERR(frame, "wifi.data: too short\n");
		return;
	}

	if (px[1] & 0x01) {
		frame->bss_mac = px+4;
		frame->src_mac = px+10;
		frame->dst_mac = px+16;
	} else {
		frame->dst_mac = px+4;
		frame->bss_mac = px+10;
		frame->src_mac = px+16;
	}

	/* Fragment control */
	{
		unsigned more_data = ((px[1] & 0x20)>0);
		unsigned fragment_number;

		more_data;fragment_number;
	}
	offset = 24;
	if (px[0] == 0x88)
		offset+=2;


	/* Look for SAP header */
	if (offset + 6 >= length) {
		FRAMERR(frame, "wifi.sap: too short\n");
		return;
	}

	if (memcmp(px+offset, "\xaa\xaa\x03", 3) != 0) {
		process_record(seap,
			"proto",	REC_SZ,			"WiFi",				-1,
			"op",		REC_SZ,			"data.unknown",		-1,
			"wifi.data",REC_PRINTABLE,	px+offset,				length-offset,
			0);
		return;
	}
	offset +=3 ;

	oui = ex24be(px+offset);
	SAMPLE("SAP", "ethertype", REC_UNSIGNED, &oui, sizeof(oui));

	/* Look for OUI code */
	switch (oui){
	case 0x000000:
		/* fall through below */
		break;
	case 0x004096: /* Cisco Wireless */
		return;
		break;
	case 0x00000c:
		offset +=3;
		if (offset < length)
		process_cisco00000c(seap, frame, px+offset, length-offset);
		return;
	case 0x080007:
		break; /*apple*/
	default:
		FRAMERR(frame, "Unknown SAP OUI: 0x%06x\n", oui);
		return;
	}
	offset +=3;

	/* EtherType */
	if (offset+2 >= length) {
		FRAMERR(frame, "ethertype: packet too short\n");
		return;
	}

	ethertype = ex16be(px+offset);
	offset += 2;

	switch (ethertype) {
	case 0x0800:
		process_ip(seap, frame, px+offset, length-offset);
		break;
	case 0x0806:
		process_arp(seap, frame, px+offset, length-offset);
		break;
	case 0x888e: /*802.11x authentication*/
		process_802_1x_auth(seap, frame, px+offset, length-offset);
		break;
	case 0x86dd: /* IPv6*/
		process_ipv6(seap, frame, px+offset, length-offset);
		break;
	case 0x809b:
		process_ipv6(seap, frame, px+offset, length-offset);
		break;
	case 0x872d: /* Cisco OWL */
		break;

	default:
		if (ethertype == length-offset && ex16be(px+offset) == 0xAAAA) {
			;
		}
		else
			FRAMERR_BADVAL(frame, "ethertype", ethertype);
	}
}

void process_wifi_frame(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	switch (px[0]) {
	case 0x00: /* association request */
		process_wifi_associate_request(seap, frame, px, length);
		break;
	case 0xa0:
		process_wifi_disassociate_request(seap, frame, px, length);
		break;
	case 0xc0:
		process_wifi_deauthentication(seap, frame, px, length);
		break;

	case 0x10: /*assocation response */
		break;
	case 0xD4: /*acknowledgement*/
		break;
	case 0x80: /*beacon*/
		process_wifi_beacon(seap, frame, px, length);
		break;
	case 0x40:
		process_wifi_probe(seap, frame, px, length);
		break;
	case 0x50:
		process_wifi_proberesponse(seap, frame, px, length);
		break;
	case 0x08: /*data*/
		if (px[1] & 0x40)
			break;
		process_wifi_data(seap, frame, px, length);
		break;
	case 0x88: /* QoS data */
		if (px[1] & 0x40)
			break;
		process_wifi_data(seap, frame, px, length);
		break;
	case 0x48: /*NULL function*/
		break;
	case 0xb0: /*authentication*/
		break;
	case 0xb4: /*request to send*/
		break;
	case 0xC4: /*clear to send */
		break;
	case 0x30: /*reassociation response*/
		break;
	case 0xc8: /*QoS Null function*/
		break;
	case 0xa4: /*Power Save Poll */
		break;
	case 0x20: /* Reassociation Request */
		break;
	default:
		FRAMERR(frame, "unknown wifi packet [0x%02x]\n", px[0]);

	}
}

