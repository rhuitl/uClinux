/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"
#include <string.h>
#include <ctype.h>

#ifndef MIN
#define MIN(a,b) ( (a)<(b) ? (a) : (b) )
#endif

struct DNSRECORD
{
	unsigned name_offset;
	unsigned type;
	unsigned clss;
	unsigned ttl;
	unsigned rdata_offset;
	unsigned rdata_length;
};
struct DNS {
	unsigned id;
	unsigned is_response;
	unsigned opcode;
	unsigned rcode;
	unsigned flags;
	unsigned question_count;
	unsigned answer_count;
	unsigned authority_count;
	unsigned additional_count;

	struct DNSRECORD records[256];
	unsigned record_count;

	struct DNSRECORD *questions;
	struct DNSRECORD *answers;
	struct DNSRECORD *authorities;
	struct DNSRECORD *additionals;
};

unsigned dns_extract_name(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, char *name, unsigned sizeof_name)
{
	int recurse_count = 0;
	unsigned name_offset = 0;

	name[0] = '\0';

	while (offset < length) {
		if (px[offset] == 0x00) {
			break;
		} else if (px[offset] & 0xC0) {
			if (recurse_count > 100) {
				FRAMERR(frame, "dns: name: recursion exceeded %d\n", recurse_count);
				break;
			}
			recurse_count++;
			if (offset+2 > length) {
				FRAMERR(frame, "dns: name: not enough bytes\n");
				strcpy(name, "(err)");
				return 5;
			}
			offset = ex16be(px+offset)&0x3FF;
		} else {
			unsigned len = px[offset++];
			if (offset >= length) {
				FRAMERR(frame, "dns: name: not enough bytes\n");
				strcpy(name, "(err)");
				return 5;
			}
			if (offset+len > length) {
				FRAMERR(frame, "dns: name: not enough bytes\n");
				strcpy(name, "(err)");
				return 5;
			}

			if (name_offset > 0) {
				if (name_offset+1 >= sizeof_name) {
					FRAMERR(frame, "dns: name: too long\n");
					strcpy(name, "(err)");
					return 5;
				}
				name[name_offset++] = '.';
			}
			if (name_offset+len+1 >= sizeof_name) {
				FRAMERR(frame, "dns: name: too long\n");
				strcpy(name, "(err)");
				return 5;
			}
			memcpy(name+name_offset, px+offset, len);
			name_offset += len;
			name[name_offset] = '\0';
			offset += len;
		}
	}

	return name_offset;
}

static unsigned dns_resolve_alias(struct NetFrame *frame, const unsigned char *px, unsigned length, struct DNS *dns, const char *alias, int depth)
{
	unsigned i;

	for (i=dns->question_count; i<dns->record_count; i++) {
		struct DNSRECORD *rec = &dns->records[i];
		char name[256];
		unsigned name_length;

		name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

		if ((rec->type != 1 && rec->type != 5)|| rec->clss != 1)
			continue;

		if (stricmp(alias, name) == 0) {
			switch (rec->type) {
			case 1:
				return ex32be(px+rec->rdata_offset);
			case 5:
				name_length = dns_extract_name(frame, px, length, rec->rdata_offset, name, sizeof(name));
				if (depth > 10)
					FRAMERR(frame, "dns: too much recursion, alias=\"%s\"\n", alias);
				else
					return dns_resolve_alias(frame, px, length, dns, name, depth+1);
			}
		}
	}

	//FRAMERR(frame, "dns: could not resolve IP for alias=\"%s\"\n", alias);

	return 0;
}

static void translate_netbios_name(struct NetFrame *frame, const char *name, char *netbios_name, unsigned sizeof_netbios_name)
{
	unsigned j;
	unsigned k;

	sizeof_netbios_name;

	k=0;
	for (j=0; name[j] && name[j] != '.'; j++) {
		if (name[j] < 'A' || name[j] > 'A'+15)
			FRAMERR(frame, "netbios: bad netbios name char %c (0x%02x) \n", name[j], name[j]);
		netbios_name[k] = (char)((name[j]-'A')<<4);
		j++;
		if (name[j] < 'A' || name[j] > 'A'+15)
			FRAMERR(frame, "netbios: bad netbios name char %c (0x%02x) \n", name[j], name[j]);

		if (name[j] && name[j] != '.')
			netbios_name[k++] |= (char)((name[j]-'A')&0x0F);
	}

	/* handle trailing byte */
	if (k && !isprint(netbios_name[k])) {
		unsigned code = netbios_name[k];
		k--;

		while (k && isspace(netbios_name[k-1]))
			k--;
		netbios_name[k++] = '<';
		netbios_name[k++] = "0123456789ABCDEF"[(code>>4)&0x0f];
		netbios_name[k++] = "0123456789ABCDEF"[(code>>0)&0x0f];
		netbios_name[k++] = '>';
	}


	while (name[j] && k<sizeof_netbios_name-1)
		netbios_name[k++] = name[j++];
	netbios_name[k] = '\0';
}

static void cleanse_netbios_name(struct NetFrame *frame, const char *name, char *netbios_name, unsigned sizeof_netbios_name)
{
	unsigned j;
	unsigned k;

	frame;sizeof_netbios_name;

	k=0;
	for (j=0; j<16; j++) {
		netbios_name[k++] = name[j];
	}
	netbios_name[k] = '\0';

	/* handle trailing byte */
	if (k && !isprint(netbios_name[k-1])) {
		unsigned code = netbios_name[k-1];
		k--;

		while (k && isspace(netbios_name[k-1]))
			k--;
		netbios_name[k++] = '<';
		netbios_name[k++] = "0123456789ABCDEF"[(code>>4)&0x0f];
		netbios_name[k++] = "0123456789ABCDEF"[(code>>0)&0x0f];
		netbios_name[k++] = '>';
	}

	netbios_name[k] = '\0';
}

static void process_request_update(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length, struct DNS *dns)
{
	unsigned i;

	if (dns->additional_count == 0)
		FRAMERR(frame, "dns: corrupt\n");

	for (i=0; i<dns->additional_count; i++) {
		char name[256];
		unsigned name_length;
		struct DNSRECORD *rec = &dns->additionals[i];

		name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

		switch (rec->type) {
		case 0x0020: /*NETBIOS */
			switch (rec->clss) {
			case 0x0001: /*INTERNET*/
				{
					unsigned ip_address = ex32be(px+rec->rdata_offset);
					char netbios_name[256];

					if (rec->rdata_length != 6)
						FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

					translate_netbios_name(frame, name, netbios_name, sizeof(netbios_name));

					process_record(seap,
						"proto",	REC_SZ,			"NETBIOS",						-1,
						"op",		REC_SZ,			"register",			-1,
						"ip.src",	REC_FRAMESRC,	frame, -1,
						"name",		REC_PRINTABLE,	netbios_name,				strlen(netbios_name),
						"address",	REC_IPv4,		&ip_address,				sizeof(ip_address),
						0);
				}
				break;
			default:
				FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
			}
			break;

		default:
			FRAMERR(frame, "dns: unknown type=%d (class=%d, name=%s)\n", rec->type, rec->clss, name);
		}
	}
}

static void dns_dynamic_update(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length, struct DNS *dns)
{
	unsigned i;


	for (i=0; i<dns->answer_count; i++) {
		char name[256];
		unsigned name_length;
		unsigned x;
		struct DNSRECORD *rec = &dns->answers[i];

		name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

		x = rec->clss<<16 | rec->type;
		
		SAMPLE("DynDNS", "Prereq", REC_UNSIGNED, &x, sizeof(x));

		switch (rec->type) {
		case 0x0001: /*A*/
			switch (rec->clss) {
			case 0x0001: /*INTERNET*/
				{
					unsigned ip_address = ex32be(px+rec->rdata_offset);

					if (rec->rdata_length != 4)
						FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);


					process_record(seap,
						"ID-IP",	REC_IPv4,		&ip_address,				sizeof(ip_address),
						"name",		REC_PRINTABLE,	name,				strlen(name),
						0);

					process_record(seap,
						"proto",	REC_SZ,			"NETBIOS",						-1,
						"op",		REC_SZ,			"register",			-1,
						"ip.src",	REC_FRAMESRC,	frame, -1,
						"name",		REC_PRINTABLE,	name,				strlen(name),
						"address",	REC_IPv4,		&ip_address,				sizeof(ip_address),
						0);
				}
				break;
			default:
				FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
			}
			break;

		}
	}
}

const unsigned char *find_mac(const unsigned char *px, unsigned length, unsigned offset, const unsigned char **r_name, unsigned *r_name_length)
{
	unsigned len;

	if (offset >= length)
		return 0;

	len = px[offset];
	if (len > 64)
		return 0;

	offset++;
	if (length > offset+len)
		length = offset+len;


	*r_name = px+offset;
	*r_name_length = 0;
	while (offset < length && px[offset] != '[') {
		(*r_name_length)++;
		offset++;
	}

	while (*r_name_length && isspace((*r_name)[(*r_name_length)-1]))
		(*r_name_length)--;

	if (offset +19  <= length && px[offset] == '[') {
		const unsigned char *result = px+offset;
		return result;
	}
	return 0;
}

static unsigned endsWith(const void *v_basestr, const void *v_pattern)
{
	const char *basestr = (const char *)v_basestr;
	const char *pattern = (const char *)v_pattern;
	unsigned base_length = strlen(basestr);
	unsigned pattern_length = strlen(pattern);

	if (base_length < pattern_length)
		return 0;
	return memcmp(basestr+base_length-pattern_length, pattern, pattern_length) == 0;

}

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define TYPECLASS(n,m) ((n)<<16|(m))

static void skip_name(const unsigned char *px, unsigned length, unsigned *r_offset)
{
	while (*r_offset < length) {
		if (0xC0 & px[*r_offset]) {
			(*r_offset) += 2;
			return;
		}
		if (0x00 == px[*r_offset]) {
			(*r_offset) += 1;
			return;
		}
		*r_offset += 1 + px[*r_offset];
	}
}
static void DECODEANSWER(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length, struct DNS *dns, struct DNSRECORD *rec, const char *opcode)
{
	unsigned ip_address;
	char name[256];
	unsigned name_length;
	char name2[256];
	unsigned name2_length;
	unsigned offset = rec->rdata_offset;
	unsigned offset_max = MIN(rec->rdata_offset+rec->rdata_length, length);


	/* Get the name */
	name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

	switch (rec->type<<16 | rec->clss) {
	case TYPECLASS(32,1): /*NetBIOS*/
		ip_address = ex32be(px+rec->rdata_offset+2);

		if (rec->rdata_length != 6)
			FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

		translate_netbios_name(frame, name, name2, sizeof(name2));

		process_record(seap,
			"proto",	REC_SZ,			"NETBIOS",						-1,
			opcode,		REC_SZ,			"registration",			-1,
			"name",		REC_PRINTABLE,	name2,				strlen(name2),
			"address",	REC_IPv4,		&ip_address,				sizeof(ip_address),
			"ip.src",	REC_FRAMESRC,	frame, -1,
			0);

		process_record(seap,
			"ID-IP",	REC_IPv4,		&ip_address,				sizeof(ip_address),
			"netbios",	REC_PRINTABLE,	name2,				strlen(name2),
			0);

		break;
	case TYPECLASS(6,1): /*SOA*/
		/*
		 * Authoritative Name Server
		 */
		name2_length = dns_extract_name(frame, px, length, offset, name2, sizeof(name2));
		process_record(seap,
			"proto",	REC_SZ,			"DNS",						-1,
			opcode,	REC_SZ,			"SOA",					-1,
			"domain",	REC_PRINTABLE,	name,						name_length,
			"NS",		REC_PRINTABLE,	name2,						name2_length,
			0);
		ip_address = dns_resolve_alias(frame, px, length, dns, name2, 0);
		if (ip_address)
		process_record(seap,
			"proto",	REC_SZ,			"DNS",						-1,
			opcode,	REC_SZ,			"SOA",					-1,
			"domain",	REC_PRINTABLE,	name,						name_length,
			"NS",		REC_IPv4,		&ip_address,				sizeof(ip_address),
			0);
		skip_name(px, length, &offset);

		/* Contact */
		if (offset < offset_max) {
			name2_length = dns_extract_name(frame, px, length, offset, name2, sizeof(name2));
			process_record(seap,
				"proto",	REC_SZ,			"DNS",						-1,
				opcode,	REC_SZ,			"SOA",					-1,
				"domain",	REC_PRINTABLE,	name,						name_length,
				"contact",	REC_PRINTABLE,	name2,						name2_length,
				0);
			skip_name(px, length, &offset);
		}

		break;
	case TYPECLASS(2,1): /* NS */
		dns_extract_name(frame, px, length, rec->rdata_offset, name2, sizeof(name2));
		ip_address = dns_resolve_alias(frame, px, length, dns, name2, 0);

		process_record(seap,
			"proto",	REC_SZ,			"DNS",						-1,
			opcode,	REC_SZ,			"NS",			-1,
			"domain",	REC_PRINTABLE,	name,						strlen(name),
			"NS",		REC_PRINTABLE,	name2,						strlen(name2),
			"sender",	REC_FRAMESRC,	frame, -1,
			0);
		process_record(seap,
			"proto",	REC_SZ,			"DNS",						-1,
			opcode,	REC_SZ,			"NS",			-1,
			"domain",	REC_PRINTABLE,	name,						strlen(name),
			"NS",		REC_IPv4,		&ip_address,				sizeof(ip_address),
			"sender",	REC_FRAMESRC,	frame, -1,
			0);
		break;
	default:
		FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
	}
}


void process_dns(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct DNS dns[1] = {0};
	unsigned record_count;
	unsigned total_records;
	unsigned i;

	memset(dns, 0, sizeof(dns[0]));

	if (length < 12) {
		FRAMERR(frame, "dns: frame too short\n");
		return;
	}

	dns->id = ex16be(px+0);
	dns->is_response = ((px[2]&0x80) != 0);
	dns->opcode = (px[2]>>3)&0x01F;
	dns->flags = ex16be(px+2)&0x7F0;
	dns->rcode = px[3]&0x0F;

	dns->question_count = ex16be(px+4);
	dns->answer_count = ex16be(px+6);
	dns->authority_count = ex16be(px+8);
	dns->additional_count = ex16be(px+10);

	total_records = dns->question_count + dns->answer_count + dns->authority_count + dns->additional_count;

	offset = 12;
	record_count = 0;

	/*
	 * After processing the header, now process all the records
	 */
	while (offset < length && record_count < 100) {
		struct DNSRECORD *rec = &dns->records[record_count];

		if (record_count >= total_records) {
			SAMPLE("dns", "too-many-records",	REC_UNSIGNED, &total_records,	sizeof(total_records));
			break;
		}

		rec->name_offset = offset;
		while (offset < length) {
			if (px[offset] == 0x00) {
				offset++;
				break;
			}
			if (px[offset] & 0xC0) {
				offset += 2;
				break;
			}
			offset += px[offset] + 1;

			if (offset > length) {
				FRAMERR(frame, "dns: past end of packet\n");
				return;
			}
		}

		if (offset + 4 > length) {
			FRAMERR(frame, "dns: past end of packet\n");
			return;
		}

		rec->type = ex16be(px+offset+0);
		rec->clss = ex16be(px+offset+2);
		offset += 4;
		
		record_count++;
		if (record_count <= dns->question_count)
			continue;
		
		
		if (offset + 6 > length) {
			FRAMERR(frame, "dns: past end of packet\n");
			return;
		}

		rec->ttl = ex32be(px+offset+0);
		rec->rdata_length = ex16be(px+offset+4);
		offset += 6;
		rec->rdata_offset = offset;
		offset += rec->rdata_length;

		if (offset > length) {
			FRAMERR(frame, "dns: past end of packet\n");
			return;
		}
	}
	dns->record_count = record_count;

	dns->questions = &dns->records[0];
	dns->answers = &dns->records[dns->question_count];
	dns->authorities = &dns->records[dns->question_count + dns->answer_count];
	dns->additionals = &dns->records[dns->question_count + dns->answer_count + dns->authority_count];

	switch (dns->opcode) {
	case 0x00: /*query request*/
		for (i=0; i<dns->question_count; i++) {
			char name[256];
			unsigned name_length;
			struct DNSRECORD *rec = &dns->questions[i];

			name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

			switch (rec->type) {
			case 0x0001: /*A = IPv4 address */
				switch (rec->clss) {
				case 0x0001: /*INTERNET*/
					process_record(seap,
						"proto",	REC_SZ,			"DNS",						-1,
						"query",		REC_SZ,			"A",					-1,
						"ip.src",	REC_FRAMESRC,	frame, -1,
						"name",		REC_PRINTABLE,	name,						strlen(name),
						0);
					break;
				default:
					FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
				}
				break;
			case 0x001c: /*AAAA = IPv6 address */
				switch (rec->clss) {
				case 0x0001: /*INTERNET*/
					process_record(seap,
						"proto",	REC_SZ,			"DNS",						-1,
						"query",		REC_SZ,		"AAAA",					-1,
						"ip.src",	REC_FRAMESRC,	frame, -1,
						"name",		REC_PRINTABLE,	name,						strlen(name),
						0);
					break;
				case 0x8001:
					process_record(seap,
						"proto",	REC_SZ,			"MDNS",						-1,
						"query",		REC_SZ,		"AAAA",					-1,
						"ip.src",	REC_FRAMESRC,	frame, -1,
						"flush",		REC_PRINTABLE,	name,						strlen(name),
						0);
					break;
				default:
					FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
				}
				break;
			case 0x0002: /*NS*/
				switch (rec->clss) {
				case 0x0001: /*INTERNET*/
					process_record(seap,
						"proto",	REC_SZ,			"DNS",						-1,
						"query",	REC_SZ,			"NS",					-1,
						"ip.src",	REC_FRAMESRC,	frame, -1,
						"name",		REC_PRINTABLE,	name,						strlen(name),
						0);
					break;
				default:
					FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
				}
				break;
			case 0x0006: /*SOA - Start of Authority */
				switch (rec->clss) {
				case 0x0001: /*INTERNET*/
					process_record(seap,
						"proto",	REC_SZ,			"DNS",						-1,
						"query",		REC_SZ,		"SOA",					-1,
						"ip.src",	REC_FRAMESRC,	frame, -1,
						"name",		REC_PRINTABLE,	name,						strlen(name),
						0);
					break;
				default:
					FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
				}
				break;
			case 0x0020: /*NETBIOS */
				switch (rec->clss) {
				case 0x0001: /*INTERNET*/
					{
						unsigned ip_address = ex32be(px+rec->rdata_offset);
						char netbios_name[300];
						
						translate_netbios_name(frame, name, netbios_name, sizeof(netbios_name));

						process_record(seap,
							"proto",	REC_SZ,			"NETBIOS",						-1,
							"query",	REC_SZ,			"netbios",			-1,
							"ip.src",	REC_FRAMESRC,	frame, -1,
							"name",		REC_PRINTABLE,	netbios_name,				strlen(netbios_name),
							"address",	REC_IPv4,		&ip_address,				sizeof(ip_address),
							0);
					}
					break;
				default:
					FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
				}
				break;
			case 0x0021: /*SRV (Service Location) */
				switch (rec->clss) {
				case 0x0001: /*INTERNET*/
					process_record(seap,
						"proto",	REC_SZ,			"DNS",						-1,
						"query",	REC_SZ,			"srv",					-1,
						"ip.src",	dns->is_response?REC_FRAMEDST:REC_FRAMESRC, frame, -1,
						"name",		REC_PRINTABLE,	name,						strlen(name),
						0);
					break;
				default:
					FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
				}
				break;
			case 12: /*PTR*/
				switch (rec->clss) {
				case 0x0001: /*INTERNET*/
					process_record(seap,
						"proto",	REC_SZ,			"DNS",						-1,
						"op",		REC_SZ,			"reverse",					-1,
						"ip.src",	dns->is_response?REC_FRAMEDST:REC_FRAMESRC, frame, -1,
						"name",		REC_PRINTABLE,	name,						strlen(name),
						0);
					break;
				case 0x8001: /*FLUSH*/
					break;
				default:
					FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
				}
				break;
			case 255: /*any*/
				switch (rec->clss) {
				case 0x8001: /*FLUSH*/
					process_record(seap,
						"proto",	REC_SZ,			"DNS",						-1,
						"op",		REC_SZ,			"flush",					-1,
						"ip.src",	dns->is_response?REC_FRAMEDST:REC_FRAMESRC, frame, -1,
						"name",		REC_PRINTABLE,	name,						strlen(name),
						0);
					if (endsWith(name, "._ipp._tcp.local")) {
						process_record(seap,
							"Bonjour",	dns->is_response?REC_FRAMEDST:REC_FRAMESRC, frame, -1,
							"Printer",		REC_PRINTABLE,	name,						strlen(name)-strlen("._ipp._tcp.local"),
							0);
					} else if (endsWith(name, ".local"))
						process_record(seap,
							"ID-IP",	dns->is_response?REC_FRAMEDST:REC_FRAMESRC, frame, -1,
							"name",		REC_PRINTABLE,	name,						strlen(name)-strlen(".local"),
							0);
					else
						FRAMERR(frame, "%s: unknown value: %s\n", "dns", name);

					break;
				case 1:
					break;
				default:
					FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
				}
				break;
			default:
				FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
			}
		}
		break;
	case 0x10: /*query response */
		switch (dns->rcode) {
		case 0:
			for (i=0; i<dns->answer_count; i++) {
				char name[256];
				unsigned name_length;
				struct DNSRECORD *rec = &dns->answers[i];

				if (rec->type == 0x8001)
					FRAMERR(frame, "test\n");

				name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

				switch (rec->type) {
				case 0x0001: /*A = IPv4 address */
					switch (rec->clss) {
					case 0x0001: /*INTERNET*/
						{
							unsigned ip_address = ex32be(px+rec->rdata_offset);
							if (rec->rdata_length != 4)
								FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

							process_record(seap,
								"proto",	REC_SZ,			"DNS",						-1,
								"op",		REC_SZ,			"lookup",			-1,
								"ip.src",	REC_FRAMESRC,	frame, -1,
								"name",		REC_PRINTABLE,	name,						strlen(name),
								"address",	REC_IPv4,		&ip_address,				sizeof(ip_address),
								0);
						}
						break;
					case 0x8001:
						{
							unsigned ip_address = ex32be(px+rec->rdata_offset);
							if (rec->rdata_length != 4)
								FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

							process_record(seap,
								"ID-IP",	REC_IPv4,		&ip_address,				sizeof(ip_address),
								"name",		REC_PRINTABLE,	name,						strlen(name),
								0);
						}
						break;
					default:
						FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
					}
					break;
				case 0x0002: /*NS*/
					DECODEANSWER(seap, frame, px, length, dns, rec, "answer");
					break;
				case 0x0006: /*SOA*/
					DECODEANSWER(seap, frame, px, length, dns, rec, "answer");
					break;
				case 0x001c: /*AAAA = IPv6 address */
					switch (rec->clss) {
					case 0x0001: /*INTERNET*/
						{
							const unsigned char *ip_address = px+rec->rdata_offset;
							if (rec->rdata_length != 16)
								FRAMERR(frame, "dns: data not 16-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

							process_record(seap,
								"proto",	REC_SZ,			"DNS",						-1,
								"op",		REC_SZ,			"lookup",			-1,
								"ip.src",	REC_FRAMESRC,	frame, -1,
								"name",		REC_PRINTABLE,	name,						strlen(name),
								"address",	REC_IPv6,		ip_address,				16,
								0);
						}
						break;
					case 0x8001:
						{
							const unsigned char *ip_address = px+rec->rdata_offset;
							if (rec->rdata_length != 16)
								FRAMERR(frame, "dns: data not 16-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

							process_record(seap,
								"ID-IP",	REC_IPv6,		ip_address,				16,
								"name",		REC_PRINTABLE,	name,						strlen(name),
								0);
						}
						break;
					default:
						FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
					}
					break;
				case 0x000d: /*HINFO*/
					switch (rec->clss) {
					case 0x8001:
						{
							unsigned j=0;
							const unsigned char *cpu;
							unsigned cpu_length;
							const unsigned char *os;
							unsigned os_length;

							j = rec->rdata_offset;

							cpu = px+j+1;
							cpu_length = px[j];
							j += cpu_length + 1;

							os = px+j+1;
							os_length = px[j];

							process_record(seap,
								"Bonjour",		REC_PRINTABLE,	name,						strlen(name),
								"OS", REC_PRINTABLE,	os,						os_length,
								0);
							process_record(seap,
								"Bonjour",		REC_PRINTABLE,	name,						strlen(name),
								"CPU", REC_PRINTABLE,	cpu,						cpu_length,
								0);
						}
						break;
					default:
						FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
					}
					break;
				case 0x0005: /*CNAME = aliased canonical name */
					{
						char alias[256];
						unsigned ip_address;

						dns_extract_name(frame, px, length, rec->rdata_offset, alias, sizeof(alias));

						ip_address = dns_resolve_alias(frame, px, length, dns, alias, 0);

						if (ip_address != 0)
						process_record(seap,
							"proto",	REC_SZ,			"DNS",						-1,
							"op",		REC_SZ,			"lookup",			-1,
							"ip.src",	REC_FRAMEDST,	frame, -1,
							"name",		REC_PRINTABLE,	name,						strlen(name),
							"address",	REC_IPv4,		&ip_address,				sizeof(ip_address),
							0);
					}
					break;
				case 12: /*PTR = pointer record*/
					switch (rec->clss) {
					case 0x0001: /*INTERNET*/
						if (name_length > 6 && memcmp(name+name_length-6, ".local", 6) == 0) {

							process_record(seap,
								"ID-IP",	REC_FRAMESRC,	frame, -1,
								"SERVICE",	REC_PRINTABLE,	name,						strlen(name),
								0);

							/* Extract MAC address */
							{
								const unsigned char *p_name;
								unsigned name_length;
								const unsigned char *p_mac = find_mac(px, MIN(length, rec->rdata_offset+rec->rdata_length), rec->rdata_offset, &p_name, &name_length);
								if (p_mac) {
									process_record(seap,
										"ID-IP",	REC_FRAMESRC,	frame, -1,
										"mac",		REC_PRINTABLE,	p_mac,						19,
										0);
									process_record(seap,
										"ID-IP",	REC_FRAMESRC,	frame, -1,
										"name",		REC_PRINTABLE,	p_name,						name_length,
										0);
								}
							}

						} else
							FRAMERR(frame, "dns: unknown PTR record\n");
						break;
					case 0x8001: /*FLUSH*/
						break;
					default:
						FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
					}
					break;
				case 0x0020: /*NETBIOS */
					DECODEANSWER(seap, frame, px, length, dns, rec, "netbios");
					break;
				case 0x0021: /*NBTSTAT*/
					switch (rec->clss) {
					case 0x0001: /*INTERNET*/
						{
							unsigned length2 = rec->rdata_offset + rec->rdata_length;
							unsigned number_of_names;
							unsigned j;


							offset = rec->rdata_offset;

							number_of_names = px[offset++];

							if (offset >= length || offset >= length2) {
								FRAMERR(frame, "dns: truncated\n");
								break;
							}


							/* Grab the names */
							for (j=0; j<number_of_names; j++) {
								char netbios_name[256];

								if (offset+18 > length || offset+18 > length2) {
									offset += 18;
									FRAMERR(frame, "dns: truncated\n");
									break;
								}
								
								cleanse_netbios_name(frame, (const char*)px+offset, netbios_name, sizeof(netbios_name));
								
								process_record(seap,
									"ID-IP",	REC_FRAMEDST,	frame, -1,
									"netbios",	REC_PRINTABLE,	netbios_name,			strlen(netbios_name),
									0);

								offset += 18;
							}

							if (offset+6 > length || offset+18 > length2) {
								FRAMERR(frame, "dns: truncated\n");
								break;
							}

							if (memicmp(px+offset, "\0\0\0\0\0\0", 6) != 0) {
								process_record(seap,
									"ID-IP",	REC_FRAMEDST,	frame, -1,
									"mac",		REC_MACADDR,	px+offset,				6,
									0);
							}
							offset += 6;
						}
						break;
					}
					break;
				case 0x0010: /* TXT Record */
					switch (rec->clss) {
					case 0x8001: /*FLUSH*/
						{
							unsigned offset = rec->rdata_offset;
							unsigned max = rec->rdata_offset + rec->rdata_length;
							unsigned b=0;
							const unsigned char *bonjour;
							unsigned bonjour_length;

							if (max > length)
								max = length;

							/* Grab the Bonjour name */
							for (b=0; b<name_length; b++) {
								if (name[b] == '.' && b+1<name_length && name[b+1] == '_') {
									b++;
									break;
								}
							}

							bonjour = (const unsigned char*)name+b;
							bonjour_length = name_length-b;

							/* For all the <name=value> pairs in the record */
							while (offset < max) {
								unsigned len = px[offset++];
								const unsigned char *tag;
								unsigned tag_length;
								const unsigned char *value;
								unsigned value_length;
								unsigned max2 = max;

								if (max2 > offset + len)
									max2 = offset + len;

								tag = px+offset;
								for (tag_length=0; offset+tag_length<max2 && tag[tag_length]!='='; tag_length++)
									;
								offset+=tag_length;
								if (offset < max2 && px[offset] == '=')
									offset++;
								while (offset < max2 && isspace(px[offset]))
									offset++;
								value = px+offset;
								value_length = (max2-offset);
								offset = max2;

								/* Process the name value pair */
								process_record(seap,
									"proto",	REC_SZ,			"Bonjour",				-1,
									"ip",		REC_FRAMESRC,	frame, -1,
									"service",	REC_PRINTABLE,	bonjour,				bonjour_length,
									"tag",		REC_PRINTABLE,	tag,					tag_length,
									"value",	REC_PRINTABLE,	value,					value_length,
									0);
							}
						}
						break;
					default:
						FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
					}
					break;
				default:
					FRAMERR(frame, "dns: unknown type=%d (class=%d, name=%s)\n", rec->type, rec->clss, name);
				}
			}
			break;
		case 3: /* No such name */
			SAMPLE("DNS", "rcode",	REC_UNSIGNED, &dns->rcode, sizeof(dns->rcode));
			break;
		default:
			FRAMERR(frame, "dns: unknown rcode=%d (opcode=%d)\n", dns->rcode, dns->opcode);
		}
		break;
	case 0x06: /*release*/
		switch (dns->rcode) {
		case 0:
			for (i=0; i<dns->additional_count; i++) {
				char name[256];
				unsigned name_length;
				struct DNSRECORD *rec = &dns->additionals[i];

				if (rec->type == 0x8001)
					FRAMERR(frame, "test\n");

				name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

				switch (rec->type) {
				case 0x0020: /*NETBIOS */
					switch (rec->clss) {
					case 0x0001: /*INTERNET*/
						{
							unsigned ip_address = ex32be(px+rec->rdata_offset+2);
							char netbios_name[256];

							if (rec->rdata_length != 6)
								FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

							translate_netbios_name(frame, name, netbios_name, sizeof(netbios_name));

							process_record(seap,
								"proto",	REC_SZ,			"NETBIOS",						-1,
								"op",		REC_SZ,			"release",			-1,
								"ip.src",	REC_FRAMEDST,	frame, -1,
								"name",		REC_PRINTABLE,	netbios_name,				strlen(netbios_name),
								"address",	REC_IPv4,		&ip_address,				sizeof(ip_address),
								0);

							process_record(seap,
								"ID-IP",	REC_IPv4,		&ip_address,				sizeof(ip_address),
								"netbios",	REC_PRINTABLE,	netbios_name,				strlen(netbios_name),
								0);

						}
						break;
					default:
						FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
					}
					break;
				default:
					FRAMERR(frame, "dns: unknown type=%d (class=%d, name=%s)\n", rec->type, rec->clss, name);
				}
			}
		}
		break;
	case 0x05: /*netbios registration request*/
		if (frame->dst_port == 53)
			dns_dynamic_update(seap, frame, px, length, dns);
		else
			process_request_update(seap, frame, px, length, dns);
		break;
	case 0x08:
		for (i=0; i<dns->additional_count; i++)
			DECODEANSWER(seap, frame, px, length, dns, &dns->additionals[i], "refresh");
		break;
	case 0x01: /*inverse query request*/
	case 0x11: /*inverse query reqsponse*/
	case 0x02: /*status request*/
	case 0x12: /*status response*/
	case 0x04: /*notify request*/
	case 0x14: /*notify response*/
	case 0x15: /*update response*/
	case 0x0f: /*multi-home registration*/
		for (i=0; i<dns->additional_count; i++)
			DECODEANSWER(seap, frame, px, length, dns, &dns->additionals[i], "multi-home");
		break;
	default:
		FRAMERR(frame, "dns: unknown opcode %d\n", dns->opcode);
	}
}

