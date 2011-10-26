/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "ferret.h"
#include "formats.h"
#include <string.h>

struct SRVLOC {
	unsigned version;
	unsigned function;
	unsigned packet_length;
	unsigned flags;
	unsigned next_extension_offset;
	unsigned transaction_id;
	const unsigned char *lang;
	unsigned lang_len;

	struct {
		struct {
			const unsigned char *prlist;
			unsigned prlist_length;
			const unsigned char *srvtype;
			unsigned srvtype_length;
			const unsigned char *scopes;
			unsigned scopes_length;
			const unsigned char *predicate;
			unsigned predicate_length;
			const unsigned char *slpspi;
			unsigned slpspi_length;
			
		} request;
	} pdu;
};

static void get_string(const unsigned  char *px, unsigned length, unsigned *r_offset, const unsigned char **r_str, unsigned *r_str_length)
{
	*r_str_length = 0;
	if ((*r_offset) + 4 > length)
		return;

	*r_str_length = ex16be(px+*r_offset);
	(*r_offset) += 2;
	*r_str = px + *r_offset;
	*r_offset += *r_str_length;
}
void process_srvloc(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct SRVLOC loc[1] = {0};

	unsigned offset = 0;
	
	if (offset+14>length) {
		FRAMERR_TRUNCATED(frame, "srvloc");
		return;
	}

	/*
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    Version    |  Function-ID  |            Length             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | Length, contd.|O|F|R|       reserved          |Next Ext Offset|
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Next Extension Offset, contd.|              XID              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Language Tag Length      |         Language Tag          \
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */


	loc->version = px[0];
	loc->function = px[1];
	loc->packet_length = ex24be(px+2);
	loc->flags = ex16be(px+5);
	loc->next_extension_offset = ex24be(px+7);
	loc->transaction_id = ex16be(px+10);
	loc->lang_len = ex16be(px+12);
	loc->lang = px+14;
	
	offset = 14+loc->lang_len;

	SAMPLE("SRVLOC", "version", REC_UNSIGNED, &loc->version, sizeof(loc->version));
	SAMPLE("SRVLOC", "function", REC_UNSIGNED, &loc->function, sizeof(loc->function));
	SAMPLE("SRVLOC", "language", REC_PRINTABLE, loc->lang, loc->lang_len);

	if (loc->version != 2) {
		FRAMERR_UNKNOWN_UNSIGNED(frame, "srvloc", loc->version);
		return;
	}
	 
	switch (loc->function) {
	case 1: /*service request*/
		get_string(px, length, &offset, &loc->pdu.request.prlist, &loc->pdu.request.prlist_length);
		get_string(px, length, &offset, &loc->pdu.request.srvtype, &loc->pdu.request.srvtype_length);
		get_string(px, length, &offset, &loc->pdu.request.scopes, &loc->pdu.request.scopes_length);
		get_string(px, length, &offset, &loc->pdu.request.predicate, &loc->pdu.request.predicate_length);
		get_string(px, length, &offset, &loc->pdu.request.slpspi, &loc->pdu.request.slpspi_length);

		SAMPLE("SRVLOC", "prlist", REC_PRINTABLE, loc->pdu.request.prlist, loc->pdu.request.prlist_length);
		SAMPLE("SRVLOC", "srvtype", REC_PRINTABLE, loc->pdu.request.srvtype, loc->pdu.request.srvtype_length);
		SAMPLE("SRVLOC", "scopes", REC_PRINTABLE, loc->pdu.request.scopes, loc->pdu.request.scopes_length);
		SAMPLE("SRVLOC", "predicate", REC_PRINTABLE, loc->pdu.request.predicate, loc->pdu.request.predicate_length);
		SAMPLE("SRVLOC", "slpspi", REC_PRINTABLE, loc->pdu.request.slpspi, loc->pdu.request.slpspi_length);

		JUICE(seap,
			RSZ("proto","srvloc"),
			RSZ("function", "request"),
			RPRINT("service", loc->pdu.request.srvtype, loc->pdu.request.srvtype_length),
			RPRINT("scope", loc->pdu.request.scopes, loc->pdu.request.scopes_length),
			0);

		break;
	default:
		FRAMERR_UNKNOWN_UNSIGNED(frame, "srvloc", loc->version);
	}


}

