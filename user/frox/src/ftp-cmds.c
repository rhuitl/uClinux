/***************************************

    This is part of frox: A simple transparent FTP proxy
    Copyright (C) 2000 James Hollingshead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  ftp-cmds.c Parsing code for individual commands.
  
  ***************************************/

#include <fcntl.h>
#include "ftp-cmds.h"
#include "control.h"
#include "data.h"
#include "transdata.h"
#include "vscan.h"
#include "cache.h"
#include "os.h"

struct cmd_struct *ftp_cmds;

void save_pass(sstr * cmd, sstr * arg);
void pasv_parse(sstr * cmd, sstr * arg);
void port_parse(sstr * cmd, sstr * arg);
void abor_parse(sstr * cmd, sstr * arg);
void xfer_command(sstr * cmd, sstr * arg);
void cwd_command(sstr * cmd, sstr * arg);
void pasv_reply(sstr * msg);

void ftpcmds_init()
{
	static struct cmd_struct list[] = {	/*Pinched in part SUSE */
		{"PORT", port_parse},	/*proxy suite! */
		{"PASV", pasv_parse},
		{"ABOR", abor_parse},
		{"USER", user_munge},
		{"PASS", save_pass},
		{"ACCT", send_command},
		{"CWD", cwd_command},
		{"CDUP", cwd_command},
		{"SMNT", send_command},
		{"QUIT", send_command},
		{"REIN", send_command},
		{"TYPE", send_command},
		{"STRU", send_command},
		{"MODE", send_command},
		{"RETR", xfer_command},
		{"STOR", xfer_command},
		{"STOU", xfer_command},
		{"APPE", xfer_command},
		{"ALLO", send_command},
		{"REST", send_command},
		{"RNFR", send_command},
		{"RNTO", send_command},
		{"DELE", send_command},
		{"RMD", send_command},
		{"MKD", send_command},
		{"PWD", send_command},
		{"LIST", xfer_command},
		{"NLST", xfer_command},
		{"SITE", send_command},
		{"SYST", send_command},
		{"STAT", send_command},
		{"HELP", send_command},
		{"NOOP", send_command},
		{"SIZE", send_command},	/* Not found in RFC 959 */
		{"MDTM", send_command},
		{"MLFL", send_command},
		{"MAIL", send_command},
		{"MSND", send_command},
		{"MSOM", send_command},
		{"MSAM", send_command},
		{"MRSQ", send_command},
		{"MRCP", send_command},
		{"XCWD", send_command},
		{"XMKD", send_command},
		{"XRMD", send_command},
		{"XPWD", send_command},
		{"XCUP", send_command},
#if 0
		{"APSV", send_command},	/* As per RFC 1579      */
#endif
		{"", 0}
	};

	ftp_cmds = list;
}

/* NB this function can be called from other code which has already copied the
 * username into info->username and set info->anonymous. In this case arg will
 * be NULL */
void user_munge(sstr * cmd, sstr * arg)
{
	sstr *tmp;
	if(arg) {
		sstr_cpy(info->username, arg);
		if(sstr_casecmp2(info->username, "ftp")
		   && sstr_casecmp2(info->username, "anonymous"))
			info->anonymous = 0;
		else
			info->anonymous = 1;
	}

	cache_init();
	tmp = sstr_dup(info->username);
	if(config.ftpproxy.sin_addr.s_addr) {

		sstr_apprintf(tmp, "@%s",
			      inet_ntoa(info->final_server_address.sin_addr));
		if(!config.ftpproxynp ||
		   ntohs(info->final_server_address.sin_port) != 21)
			sstr_apprintf(tmp, ":%d",
				      ntohs(info->final_server_address.
					    sin_port));
	}
	send_command(cmd, tmp);
	sstr_free(tmp);
}

void save_pass(sstr * cmd, sstr * arg)
{
	sstr_cpy(info->passwd, arg);
	send_command(cmd, arg);
}

/* ------------------------------------------------------------- **
** Parse the PORT command in arg and store the client's data listening
** port. Either send out a PASV instead, or open a port of our own
** and send this to the server in a rewritten PORT command.
** ------------------------------------------------------------- */
void port_parse(sstr * cmd, sstr * arg)
{
	int code;
	sstr *msg;

	info->client_data.address = extract_address(arg);

	if(!config_portok(&info->client_data.address)) {
		send_cmessage(500, "Bad PORT command");
		return;
	}

	if(info->mode == PASSIVE && info->client_listen != -1)
		il_free();
	rclose(&info->server_listen);
	rclose(&info->client_listen);

	if(config.apconv) {
		info->mode = APCONV;
		write_log(VERBOSE, "Rewriting PORT command to PASV");

		send_ccommand("PASV", "");
		get_message(&code, &msg);

		info->server_data.address = extract_address(msg);
		if(!config_pasvok(&info->server_data.address)) {
			send_cmessage(500,
				      "Remote server error. PORT failed");
			return;
		} else {
			write_log(VERBOSE, "Rewriting 227 reply.");
			send_cmessage(200, "PORT command OK.");
			return;
		}
	} else {
		sstr *newbuf;
		int a1, a2, a3, a4, p1, p2;
		struct sockaddr_in listenaddr;
		socklen_t len;

		info->mode = ACTIVE;

		len = sizeof(listenaddr);
		getsockname(info->server_control.fd,
			    (struct sockaddr *) &listenaddr, &len);
		listenaddr.sin_family = AF_INET;
		info->server_listen =
			listen_on_socket(&listenaddr, config.actvports);

		if(info->server_listen == -1) {
			send_cmessage(451, "Proxy unable to comply.");
			return;
		}

		n2com(listenaddr, &a1, &a2, &a3, &a4, &p1, &p2);

		newbuf = sstr_init(40);
		sstr_apprintf(newbuf, "%d,%d,%d,%d,%d,%d", a1, a2, a3, a4,
			      p1, p2);

		write_log(VERBOSE, "  Rewritten PORT command:");

		send_command(cmd, newbuf);
		sstr_free(newbuf);
	}
}

/* ------------------------------------------------------------- **
** Intercepted a PASV command. 
**
** Parse the 227 reply message. Either: a) We are transparently
** proxying the data connection - send the 227 through unchanged, and
** do a intercept_listen() for when the client tries to connect. b) We
** aren't - listen on a port of our own and rewrite the 227 with that.
** c) For PAConv open a port for the client, open a port for the server,
** and send the server a PORT command.
** ------------------------------------------------------------- */
void pasv_parse(sstr * cmd, sstr * arg)
{
	int a1, a2, a3, a4, p1, p2;
	struct sockaddr_in tmp;
	int code;
	sstr *msg, *newbuf;

	write_log(VERBOSE, "  Intercepted a PASV command");

	info->mode = PASSIVE;
	rclose(&info->client_listen);
	rclose(&info->server_listen);
	rclose(&info->server_data.fd);
	rclose(&info->client_data.fd);

	if(config.paconv) {
		socklen_t len;
		newbuf = sstr_init(60);

		info->mode = PACONV;
		write_log(VERBOSE, "Rewriting PASV command to PORT");

		write_log(VERBOSE, "Start listening server-side socket");

		len = sizeof(tmp);
		getsockname(info->server_control.fd,
			    (struct sockaddr *) &tmp, &len);
		tmp.sin_family = AF_INET;
		info->server_listen =
			listen_on_socket(&tmp, config.actvports);

		n2com(tmp, &a1, &a2, &a3, &a4, &p1, &p2);
		sstr_apprintf(newbuf, "%d,%d,%d,%d,%d,%d",
			      a1, a2, a3, a4, p1, p2);
		send_ccommand("PORT", sstr_buf(newbuf));
		get_message(&code, NULL);
		if(code < 300) {
			write_log(VERBOSE,
				  "Start listening client-side socket");
			get_local_address(info->client_control.fd, &tmp);
			info->client_listen =
				listen_on_socket(&tmp, config.pasvports);

			n2com(tmp, &a1, &a2, &a3, &a4, &p1, &p2);
			sstr_cpy2(newbuf, "");
			sstr_apprintf(newbuf, "Entering Passive Mode"
				      "(%d,%d,%d,%d,%d,%d)",
				      a1, a2, a3, a4, p1, p2);
			send_message(227, newbuf);
		} else {
			send_cmessage(500, "Error in processing PASV");
		}

		sstr_free(newbuf);
		return;
	}

	send_command(cmd, arg);
	get_message(&code, &msg);

	info->server_data.address = extract_address(msg);
	if(!config_pasvok(&info->server_data.address)) {
		send_cmessage(500, "Bad passive command from server");
		return;
	}

	if(config.transdata) {
		get_local_address(info->client_control.fd, &tmp);
		info->client_listen =
			intercept_listen(info->server_data.address, tmp,
					 config.pasvports);
		if(info->client_listen != -1) {
			send_message(227, msg);
			info->mode = PASSIVE;
			return;
		}
		write_log(VERBOSE,
			  "Intercept_listen failed. Rewriting 227 reply instead");
	}

	get_local_address(info->client_control.fd, &tmp);
	info->client_listen = listen_on_socket(&tmp, config.pasvports);

	if(info->client_listen == -1) {
		send_cmessage(451, "Screwed up pasv command.");
		return;
	}

	n2com(tmp, &a1, &a2, &a3, &a4, &p1, &p2);

	newbuf = sstr_init(60);
	sstr_apprintf(newbuf, "Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
		      a1, a2, a3, a4, p1, p2);

	write_log(VERBOSE, "  Rewritten 227 reply:");

	send_message(227, newbuf);
	info->mode = PASSIVE;
	sstr_free(newbuf);
}

/* ------------------------------------------------------------- **
** Intercepted an ABOR -- we need to send telnet IPs etc.
** ------------------------------------------------------------- */
void abor_parse(sstr * cmd, sstr * arg)
{
	int code;
	rclose(&info->server_data.fd);
	rclose(&info->client_data.fd);
	info->state = NEITHER;
	vscan_abort();

	get_message(&code, NULL);
	send_cmessage(426, "Transfer aborted. Data connection closed.");
	send_cmessage(226, "Abort successful");
	return;
}

/* ------------------------------------------------------------- **
** Keep track of directory for logging (and ?caching) purposes.
** ------------------------------------------------------------- */
void cwd_command(sstr * cmd, sstr * arg)
{
	int code;
	sstr *msg;

	send_command(cmd, arg);

	get_message(&code, &msg);
	send_message(code, msg);

	if(code > 299)
		return;

	if(sstr_getchar(cmd, 1) == 'D')
		/*CDUP*/ sstr_ncat2(info->strictpath, "..", 2);
	else {
		 /*CWD*/ urlescape(arg, "%/ ;");
		sstr_cat(info->strictpath, arg);
	}
	sstr_ncat2(info->strictpath, "/", 1);
	write_log(VERBOSE, "Strictpath = \"%s\"", sstr_buf(info->strictpath));
}

/* ------------------------------------------------------------- **
** Commands that require a data stream.
** ------------------------------------------------------------- */
void xfer_command(sstr * cmd, sstr * arg)
{
	if(info->mode == APCONV) {
		write_log(VERBOSE,
			  "Connecting to both data streams for %s command",
			  sstr_buf(cmd));
		if(connect_client_data() == -1) {
			send_cmessage(425, "Can't open data connection");
			return;
		}

		if(connect_server_data() == -1) {
			send_cmessage(425, "Can't open data connection");
			return;
		}
	}

	if(sstr_casecmp2(cmd, "LIST") && sstr_casecmp2(cmd, "NLST")) {
		info->needs_logging = TRUE;
		info->virus = -1;
		info->cached = 0;
		sstr_cpy(info->filename, arg);
		urlescape(info->filename, "% ;/");
	}

	if(!sstr_casecmp2(cmd, "RETR") ||
	   !sstr_casecmp2(cmd, "LIST") || !sstr_casecmp2(cmd, "NLST"))
		info->state = DOWNLOAD;
	else
		info->state = UPLOAD;
	info->upload = info->state == UPLOAD;
	send_command(cmd, arg);

	if(!sstr_casecmp2(cmd, "RETR"))
		vscan_new(0);
}
