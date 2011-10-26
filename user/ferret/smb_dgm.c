/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "netframe.h"
#include "formats.h"
#include "ferret.h"

#include <ctype.h>
#include <string.h>
#include <stdio.h>

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

struct SMBdgm_transact
{
	unsigned word_count;
	unsigned total_parm_count;
	unsigned total_data_count;
	unsigned max_parm_count;
	unsigned max_data_count;
	unsigned max_setup_count;
	unsigned flags;
	unsigned timeout;
	unsigned parm_count;
	unsigned parm_offset;
	unsigned data_count;
	unsigned data_offset;
	unsigned setup_count;
	unsigned byte_count;
	unsigned setup_offset;
	unsigned extra_offset;
	unsigned extra_length;
};
struct SMBdgm
{
	unsigned command;
	unsigned err;
	unsigned errcode;
	unsigned flags;
	unsigned flags2;
	unsigned process_id_high;
	unsigned process_id;
	unsigned char signature[8];
	unsigned tree_id;
	unsigned user_id;
	unsigned multiplex_id;

	union {
		struct SMBdgm_transact trans;
	} dgm;

	struct MailSlot {
		unsigned opcode;
		unsigned priority;
		unsigned clss;
		const unsigned char *name;
		unsigned name_length;
	} mailslot;

};

static unsigned get_byte(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result;
	unsigned offset = *r_offset;
	
	if (offset > length)
		return 0;
	if (offset == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	result = px[offset];
	
	(*r_offset)++;
	return result;
}
static unsigned get_word(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result;
	unsigned offset = *r_offset;
	
	if (offset > length)
		return 0;
	if (offset == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	if (offset+1 == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	result = ex16le(px+offset);
	
	(*r_offset) += 2;
	return result;
}
static unsigned get_dword(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result;
	unsigned offset = *r_offset;
	
	if (offset > length)
		return 0;
	if (offset == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	if (offset+1 == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	if (offset+2 == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	if (offset+3 == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	result = ex32le(px+offset);
	
	(*r_offset) += 4;
	return result;
}

static int path_equals(const unsigned char *name, unsigned name_length, const char *value)
{
	unsigned i;

	for (i=0; i<name_length && value[i]; i++)
		if (tolower(name[i]) != tolower(value[i]))
			return 0;
	if (i==name_length && value[i] == '\0')
		return 1;
	else 
		return 0;
}

static unsigned cleanse_netbios_name(const char *name)
{
	unsigned length = strlen(name);

	if (length>4 && name[length-1] == '>') {
		if (isdigit(name[length-2]) && isdigit(name[length-3]) && name[length-4] == '<')
			length-=4;
	}
	while (length && isspace(name[length-1]))
		length--;
	return length;
}
void process_BROWSE(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct SMBdgm *smb)
{
	unsigned cmd;

	smb;length;
	cmd = px[offset]; //get_byte(frame, px, length, &offset);

	switch (cmd) {
	case 15: /*Local Master Announcement*/
	case 9: /* Get Backup List Request*/
	case 8: /* Browser election Request */
	case 2: /* Request Announcement */
		break;
	case 12: /*0x0c - Domain/Workgroup Announcement */
		{
			const unsigned char *workgroup = px+offset+6;
			unsigned workgroup_length;
			const char *hostname = frame->netbios_source;
			unsigned hostname_length = cleanse_netbios_name(hostname);

			/* find nul terminator */
			for (workgroup_length=0; workgroup_length<16 && workgroup[workgroup_length]; workgroup_length++)
				;

			process_record(seap,
				"proto",	REC_SZ,			"MS-BROWSE",				-1,
				"op",		REC_SZ,			"domain",					-1,
				"domain",	REC_PRINTABLE,	workgroup,					workgroup_length,
				"hostname",	REC_PRINTABLE,	hostname,					hostname_length,
				"ip.src",	REC_FRAMESRC,	frame, -1,
				0);
		}
		break;
	case 1: /*0x01 - Host Announcement */
		{
			const unsigned char *netbios;
			unsigned netbios_length;
			unsigned major, minor;
			const unsigned char *comment;
			unsigned comment_length;
			char winver[32];

			if (offset + 22 > length) {
				FRAMERR(frame, "MS-BROWSE: truncated\n");
				break;
			}
			offset += 6;

			netbios = px+offset;

			/* find nul terminator */
			for (netbios_length=0; offset+netbios_length<length && netbios_length<16 && netbios[netbios_length]; netbios_length++)
				;


			process_record(seap,
				"ID-IP",	REC_FRAMESRC,	frame, -1,
				"netbios",	REC_PRINTABLE,	netbios,					netbios_length,
				0);

			offset += 16;

			if (offset + 2 > length) {
				FRAMERR(frame, "MS-BROWSE: truncated\n");
				break;
			}

			major = px[offset];
			minor = px[offset+1];
			_snprintf(winver, sizeof(winver), "%d.%d", major, minor);

			process_record(seap,
				"ID-IP",	REC_FRAMESRC,	frame, -1,
				"win-ver",	REC_SZ,		winver,					-1,
				0);

			offset += 10;


			comment = px+offset;
			for (comment_length=0; offset+comment_length<length && comment[comment_length]; comment_length++)
				;
			if (comment_length)
			process_record(seap,
				"ID-IP",	REC_FRAMESRC,	frame, -1,
				"comment",	REC_PRINTABLE,	comment,					comment_length,
				0);

		}
		break;
	default:
		FRAMERR(frame, "MSBROWSE: unknown command %d\n", cmd);
	}
}

void process_smb_mailslot(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct SMBdgm *smb)
{
	unsigned offset_max;
	unsigned i;

	offset = smb->dgm.trans.setup_offset;

	if (smb->dgm.trans.setup_count != 3)
		FRAMERR(frame, "smb: corrupt\n");
	smb->mailslot.opcode = get_word(frame, px, length, &offset);
	smb->mailslot.priority = get_word(frame, px, length, &offset);
	smb->mailslot.clss = get_word(frame, px, length, &offset);

	smb->mailslot.name = px+smb->dgm.trans.extra_offset;
	for (i=0; i<length; i++)
		if (smb->mailslot.name[i] == '\0')
			break;
	smb->mailslot.name_length = i;

	switch (smb->mailslot.opcode) {
	case 1: /* write mail slot */
		offset = smb->dgm.trans.data_offset;
		offset_max = smb->dgm.trans.data_count;
		if (path_equals(smb->mailslot.name, smb->mailslot.name_length, "\\MAILSLOT\\BROWSE"))
			process_BROWSE(seap, frame, px, MIN(length, offset+offset_max), offset, smb);
		else
			FRAMERR(frame, "smb: unknown mailslot=%.*s\n", smb->mailslot.name_length, smb->mailslot.name);
		break;
	default:
		FRAMERR(frame, "smb: corrupt\n");
	}

}

void process_smb_dgm_transaction(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct SMBdgm *smb)
{
	unsigned reserved;

	smb->dgm.trans.word_count		= get_byte(frame, px, length, &offset);
	smb->dgm.trans.total_parm_count = get_word(frame, px, length, &offset);
	smb->dgm.trans.total_data_count = get_word(frame, px, length, &offset);
	smb->dgm.trans.max_parm_count	= get_word(frame, px, length, &offset);
	smb->dgm.trans.max_data_count	= get_word(frame, px, length, &offset);
	smb->dgm.trans.max_setup_count	= get_byte(frame, px, length, &offset);
	reserved						= get_byte(frame, px, length, &offset);
	smb->dgm.trans.flags			= get_word(frame, px, length, &offset);
	smb->dgm.trans.timeout			= get_dword(frame, px, length, &offset);
	reserved						= get_word(frame, px, length, &offset);
	smb->dgm.trans.parm_count		= get_word(frame, px, length, &offset);
	smb->dgm.trans.parm_offset		= get_word(frame, px, length, &offset);
	smb->dgm.trans.data_count		= get_word(frame, px, length, &offset);
	smb->dgm.trans.data_offset		= get_word(frame, px, length, &offset);
	smb->dgm.trans.setup_count		= get_byte(frame, px, length, &offset);
	reserved						= get_byte(frame, px, length, &offset);
	smb->dgm.trans.setup_offset		= offset;
	offset += smb->dgm.trans.setup_count*2;
	smb->dgm.trans.byte_count		= get_word(frame, px, length, &offset);
	smb->dgm.trans.extra_offset			= offset;
	
	if (offset+10 < length && memicmp(px+offset, "\\MAILSLOT\\", 10)==0)
		process_smb_mailslot(seap, frame, px, length, offset, smb);
	else
		FRAMERR(frame, "smb: unknow transact command\n");

}

void process_smb_dgm(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct SMBdgm smb;
	unsigned reserved;

	if (length < 28) {
		FRAMERR(frame, "smb: truncated\n");
		return;
	}
	offset = 4;

	smb.command			= get_byte(frame, px, length, &offset);
	smb.err				= get_byte(frame, px, length, &offset);
	reserved			= get_byte(frame, px, length, &offset);
	smb.errcode			= get_word(frame, px, length, &offset);
	smb.flags			= get_byte(frame, px, length, &offset);
	smb.flags2			= get_word(frame, px, length, &offset);
	smb.process_id_high = get_word(frame, px, length, &offset);
	memcpy(smb.signature, px+offset, 8);
	offset += 8;
	reserved			= get_word(frame, px, length, &offset);
	smb.tree_id			= get_word(frame, px, length, &offset);
	smb.process_id		= get_word(frame, px, length, &offset);
	smb.user_id			= get_word(frame, px, length, &offset);
	smb.multiplex_id	= get_word(frame, px, length, &offset);

	switch (smb.command) {
	case 0x25: /* Transaction Request*/
		process_smb_dgm_transaction(seap, frame, px, length, offset, &smb);
		break;
	default:
		FRAMERR(frame, "smb: unknow dgm command\n");
	}

}

