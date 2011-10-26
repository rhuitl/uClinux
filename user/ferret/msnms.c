/* Copyright (c) 2007 by Errata Security */
#include "protos.h"
#include "formats.h"
#include "netframe.h"
#include "ferret.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/*
FROM SERVER commands
QNG
	Response from a PNG (ping) command that says how many seconds remain
	before the server expects another ping.

	Examples:
		QNG 42

		This example is a response to a ping where the server acknowledges the ping,
		and indicates that it wants another ping within 42 seconds.

*/

/* FROM CLIENT commands

VER
	The client notifies the server of which protocol it is using.

	The major versions are MSNP8, MSNP9, and MSNP10

	Examples:

		VER 1 MSNP8 CVR0

MSG
	This command sends a message
*/

#define CMD(str) ( (str[0]<<24) | (str[1]<<16) | (str[2]<<8) | (str[3]<<0) )

static void skip_whitespace(const unsigned char *px, unsigned length, unsigned *r_offset)
{
	while (*r_offset < length && px[*r_offset] != '\n' && isspace(px[*r_offset]))
		(*r_offset)++;
}
static unsigned get_parm(const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result=0;
	while ((*r_offset) < length && px[*r_offset] != '\n' && !isspace(px[*r_offset])) {
		(*r_offset)++;
		result++;
	}
	skip_whitespace(px, length, r_offset);
	return result;
}
static unsigned is_number(const unsigned char *px, unsigned length)
{
	unsigned i;
	for (i=0; i<length; i++)
		if (!isdigit(px[i]))
			return 0;
	if (length == 0)
		return 0;
	return 1;
}
static unsigned equals(const unsigned char *px, unsigned length, const char *sz)
{
	unsigned i;

	for (i=0; i<length && sz[i]; i++)
		if (px[i] != sz[i])
			return 0;
	if (i != length || sz[i] != '\0')
		return 0;
	return 1;
}
void process_simple_msnms_server_response(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned char cmd[16] = "";
	unsigned i;
	unsigned eol=0;

	/*Find out length of the command line */
	for (eol=0; eol<length && px[eol] != '\n'; eol++)
		;

	skip_whitespace(px, length, &offset);

	/* get command */
	i=0;
	while (offset < length && px[offset] != '\n' && !isspace(px[offset])) {
		if (i<sizeof(cmd)-1) {
			cmd[i++] = px[offset];
			cmd[i] = '\0';
		}
		offset++;
	}
	skip_whitespace(px, length, &offset);

	SAMPLE("MSN-MSGR", "command", REC_SZ, cmd, -1);

	switch (CMD(cmd)) {
    case 0x56455200: /* "VER" */
		while (offset < eol) {
			unsigned parm = offset;
			unsigned parm_length = get_parm(px, length, &offset);

			if (is_number(px+parm, parm_length))
				continue;

			if (equals(px+parm, parm_length, "CVR0"))
				continue;


			/* Syntax:
			 * VER <TrID> <protocol> <protocol> .... 
			 *
			 *	Indicates a list of protocols supported
			 *
			 *  Examples:
			 *		VER 0 MSNP8 CVR0
			 *		VER 0 MSNP8 MYPROTOCOL CVR0
			 */
			process_record(seap,
				"ID-IP",	REC_FRAMESRC,	frame, -1,
				"app",		REC_SZ,			"MSN-MSGR",		-1,
				"ver",		REC_PRINTABLE,	px+parm, parm_length,
				0);
		}				

		break;
    case 0x4e4c4e00: /* "NLN" */
		{
			unsigned state, state_length;
			unsigned handle, handle_length;
			unsigned friendly, friendly_length;

			state = offset;
			state_length = get_parm(px, length, &offset);

			handle = offset;
			handle_length = get_parm(px, length, &offset);

			friendly = offset;
			friendly_length = get_parm(px, length, &offset);

			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMEDST,	frame, -1,
				"friend",	REC_PRINTABLE,	px+handle, handle_length,
				"name",		REC_PRINTABLE,	px+friendly, friendly_length,
				"state",	REC_PRINTABLE,	px+state, state_length,
				0);
		}				
		break;
    case 0x514e4700: /* "QNG" */
			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMEDST,	frame, -1,
				0);
		break;
    case 0x43565200: /* "CVR" */
		break;
    case 0x55535200: /* "USR" */
		break;
    case 0x4d534700: /* "MSG" */
    case 0x58465200: /* "XFR" */
	default:
		FRAMERR(frame, "msn-ms: unknown commanded from client: %.*s\n", length, px);
	}


	
}
void process_simple_msnms_client_request(struct Seaper *seap, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned char cmd[16] = "";
	unsigned i;
	unsigned eol=0;

	/*Find out length of the command line */
	for (eol=0; eol<length && px[eol] != '\n'; eol++)
		;

	skip_whitespace(px, length, &offset);

	/* get command */
	i=0;
	while (offset < length && px[offset] != '\n' && !isspace(px[offset])) {
		if (i<sizeof(cmd)-1) {
			cmd[i++] = px[offset];
			cmd[i] = '\0';
		}
		offset++;
	}
	skip_whitespace(px, length, &offset);

	SAMPLE("MSN-MSGR", "command", REC_SZ, cmd, -1);

	switch (CMD(cmd)) {
    case 0x56455200: /* "VER" */
		while (offset < eol) {
			unsigned parm = offset;
			unsigned parm_length = get_parm(px, length, &offset);

			if (is_number(px+parm, parm_length))
				continue;

			if (equals(px+parm, parm_length, "CVR0"))
				continue;


			/* Syntax:
			 * VER <TrID> <protocol> <protocol> .... 
			 *
			 *	Indicates a list of protocols supported
			 *
			 *  Examples:
			 *		VER 0 MSNP8 CVR0
			 *		VER 0 MSNP8 MYPROTOCOL CVR0
			 */
			process_record(seap,
				"ID-IP",	REC_FRAMESRC,	frame, -1,
				"app",		REC_SZ,			"MSN-MSGR",		-1,
				"ver",		REC_PRINTABLE,	px+parm, parm_length,
				0);
		}				

		break;
    case 0x4e4c4e00: /* "NLN" */
		break;
    case 0x514e4700: /* "QNG" */
		break;
    case 0x43565200: /* "CVR" */
/*
    *  The first parameter is hexadecimal number specifying your locale ID (e.g. "0x0409" For U.S. English).
    * The second parameter is your OS type (e.g. "win" for Windows).
    * The third parameter is your OS version (e.g. "4.10" for Windows 98).
    * The fourth parameter is the architecture of your computer (e.g. "i386" for Intel-comaptible PCs of type 386 or above).
    * The fifth parameter is your client name (e.g. "MSMSGR" for the official MSN Messenger client).
    * The sixth parameter is your client version (e.g. "6.0.0602").
    * The seventh parameter is always "MSMSGS" in the official client. Your guess about what this means is as good as mine.
    * The eighth parameter is your passport.
*/
		{
			unsigned trid, trid_length;
			unsigned localid, localid_length;
			unsigned ostype, ostype_length;
			unsigned osver, osver_length;
			unsigned arch, arch_length;
			unsigned clientname, clientname_length;
			unsigned clientver, clientver_length;
			unsigned msmsgs, msmsgs_length;
			unsigned passport, passport_length;

			trid = offset;
			trid_length = get_parm(px, length, &offset);
			
			localid=offset;
			localid_length = get_parm(px, length, &offset);
			
			ostype=offset;
			ostype_length = get_parm(px, length, &offset);
			
			osver=offset;
			osver_length = get_parm(px, length, &offset);
			
			arch=offset;
			arch_length = get_parm(px, length, &offset);
			
			clientname=offset;
			clientname_length = get_parm(px, length, &offset);
			
			clientver=offset;
			clientver_length = get_parm(px, length, &offset);
			
			msmsgs=offset;
			msmsgs_length = get_parm(px, length, &offset);
			
			passport=offset;
			passport_length = get_parm(px, length, &offset);
			
			process_record(seap,
				"ID-IP",	REC_FRAMESRC,	frame, -1,
				"Passport",	REC_PRINTABLE,	px+passport, passport_length,
				0);

			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMESRC,	frame, -1,
				"localid",	REC_PRINTABLE, px+localid, localid_length,
				0);
			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMESRC,	frame, -1,
				"ostype",	REC_PRINTABLE, px+ostype, ostype_length,
				0);
			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMESRC,	frame, -1,
				"osver",	REC_PRINTABLE	, px+osver, osver_length,
				0);
			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMESRC,	frame, -1,
				"arch",		REC_PRINTABLE	, px+arch, arch_length,
				0);
			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMESRC,	frame, -1,
				"clientname",	REC_PRINTABLE, px+clientname, clientname_length,
				0);
			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMESRC,	frame, -1,
				"clientver",REC_PRINTABLE, px+clientver, clientver_length,
				0);
			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMESRC,	frame, -1,
				"msmsgs",	REC_PRINTABLE, px+msmsgs, msmsgs_length,
				0);
			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMESRC,	frame, -1,
				"passport",	REC_PRINTABLE, px+passport, passport_length,
				0);

		}				
		break;
    case 0x55535200: /* "USR" */
	/*After receiving the response to CVR, you must send the USR command. It has a TrID.
    * The first parameter is the authentication system (always TWN).
    * The second parameter is always the letter I (standing for initiating authentication).
    * The third parameter is the account name that you want to log on with.
	*/
		{
			unsigned trid, trid_length;
			unsigned twn, twn_length;
			unsigned ii, ii_length;
			unsigned username, username_length;

			trid = offset;
			trid_length = get_parm(px, length, &offset);
			
			twn = offset;
			twn_length = get_parm(px, length, &offset);

			ii = offset;
			ii_length = get_parm(px, length, &offset);

			username = offset;
			username_length = get_parm(px, length, &offset);

			process_record(seap,
				"proto",	REC_SZ,			"MSN-MSGR", -1,
				"ip",		REC_FRAMESRC,	frame, -1,
				"username",	REC_PRINTABLE, px+username, username_length,
				0);
			process_record(seap,
				"ID-IP",	REC_FRAMESRC,	frame, -1,
				"MSN-username",	REC_PRINTABLE,	px+username, username_length,
				0);
		}				
		break;
    case 0x4d534700: /* "MSG" */
    case 0x58465200: /* "XFR" */
	default:
		FRAMERR(frame, "msn-ms: unknown commanded from client: %.*s\n", length, px);
	}


	
}

