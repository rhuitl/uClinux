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

  control.c -- forward and parse the control stream.
  
  ***************************************/


#include <sys/ioctl.h>
#include <fcntl.h>
#include <ctype.h>

#include "control.h"
#include "common.h"
#include "ftp-cmds.h"
#include "data.h"
#include "ntp.h"
#include "ccp.h"
#include "vscan.h"
#include "cache.h"
#include "os.h"
#include "ssl.h"

int extract_clientcmd(sstr * buf, sstr ** cmd, sstr ** arg);
int extract_servercmd(sstr * buf, int *code, sstr ** msg);
static session_info *init_info(int fd, struct sockaddr_in source);
static void connect_to_server(void);

/* ------------------------------------------------------------- **
**  Sets up the control connection to the server and initialises
**  session info.
** ------------------------------------------------------------- */
void init_session(int fd, struct sockaddr_in source)
{
	info = init_info(fd, source);

	write_log(INFO, "Connect from %s",
		  sstr_buf(addr2name(info->client_control.address.sin_addr)));

	/*FIXME have a login function which deals with ntp and cache */
	ccp_changedest();
	ntp_changedest();
	info->final_server_address = info->server_control.address;

	write_log(INFO, "... to %s(%s)",
		  inet_ntoa(info->final_server_address.sin_addr),
		  sstr_buf(info->server_name));

#ifdef ENABLE_CHANGEPROC
	set_proc_title("frox: %s <-> %s",
		       inet_ntoa(info->client_control.address.sin_addr),
		       inet_ntoa(info->final_server_address.sin_addr));
#endif
	connect_to_server();

	ntp_senduser();

	run_proxy();
}

static void connect_to_server(void)
{
	/*Check for loops. Won't work if Listen undefined */
	if(info->server_control.address.sin_addr.s_addr
	   == config.listen_address.sin_addr.s_addr &&
	   info->server_control.address.sin_port
	   == config.listen_address.sin_port)
		die(ERROR, "Attempt to connect to self. "
		    "Do you need to set DoNTP to yes?",
		    421, "Proxy tried to loop. Closing connection", 0);
	if(info->server_control.address.sin_addr.s_addr == 0) {
		if(!config.ntp)
			die(ERROR,
			    "Frox unable to determine destination address. "
			    "Do you need to set DoNTP to yes?",
			    501, "Unable to contact server", 0);
		else if(config.ntpdest.sin_addr.s_addr)
			die(ERROR,
			    "Frox unable to determine destination address. "
			    "Try commenting out NTPAddress",
			    501, "Unable to contact server", 0);
		else
			die(ERROR,
			    "Frox unable to determine detination address. "
			    "See FAQ for troubleshooting.", 501,
			    "Unable to contact server", 0);
	}

	resolve_addr(&info->final_server_address.sin_addr, info->server_name);

	if(!config_connectionok(&info->client_control.address,
				&info->final_server_address,
				info->username ? sstr_buf(info->
							  username) : 0))
		die(ATTACK, "Denied by ACLs.", 501, "Connection denied. Bye",
		    0);

	if(config.ftpproxy.sin_addr.s_addr)
		info->server_control.address = config.ftpproxy;

	write_log(VERBOSE, "Connecting to server...");

	info->server_control.fd =
		connect_to_socket(&info->server_control.address,
				  &config.tcpoutaddr, config.contports);

	if(info->server_control.fd == -1)
		die(ERROR, "Connection closed -- unable to contact server",
		    501, "Proxy unable to contact ftp server", 0);

	write_log(VERBOSE, "     OK");

	if(config.loglevel >= VERBOSE) {	/*Save the overhead of DNS lookups */
		write_log(VERBOSE, "Apparent address = %s",
			  sstr_buf(addr2name
				   (info->apparent_server_address.sin_addr)));
		write_log(VERBOSE, "Real address = %s",
			  sstr_buf(addr2name
				   (info->final_server_address.sin_addr)));
		write_log(VERBOSE, "Proxy address = %s",
			  sstr_buf(addr2name
				   (info->server_control.address.sin_addr)));
	}
	ssl_init();
}

/* ------------------------------------------------------------- **
**  Allocate and initialise session_info structure. Also determine
**  destination address if possible.
**  ------------------------------------------------------------- */
static session_info *init_info(int fd, struct sockaddr_in source)
{
	session_info *i;
	i = (session_info *) malloc(sizeof(session_info));
	if(i == NULL)
		die(ERROR, "Malloc failed", 0, NULL, -1);
	memset(i, 0, sizeof(session_info));

	i->server_listen = i->client_listen = -1;
	i->client_data.fd = i->server_data.fd = -1;
	i->server_control.fd = -1;

	i->server_control.buf = sstr_init(BUF_LEN);
	i->client_control.buf = sstr_init(BUF_LEN);
	i->server_data.buf = sstr_init(DATA_BUF_LEN);
	i->client_data.buf = sstr_init(DATA_BUF_LEN);
	i->last_command = sstr_init(0);
	i->server_name = sstr_init(0);
	i->username = sstr_init(0);
	i->passwd = sstr_init(0);
	i->strictpath = sstr_init(0);
	i->cmd_arrays[CACHE_CMDS] = NULL;
	i->cmd_arrays[FTP_CMDS] = ftp_cmds;

	i->filename = sstr_init(0);

	if(config.apconv)
		i->mode = APCONV;
	else
		i->mode = ACTIVE;
	i->state = NEITHER;
	i->greeting = AWAITED;

	i->client_control.address = source;
	i->client_control.fd = fd;

	get_orig_dest(fd, &i->server_control.address);
	i->apparent_server_address = i->server_control.address;

	return i;
}

/* ------------------------------------------------------------- **
**  The main loop for each session.
** ------------------------------------------------------------- */
void run_proxy()
{
	int i;

	do {
		i = get_control_line(GET_BOTH);
		if(i & GET_CLNT)
			client_control_forward();
		if(i & GET_SRVR)
			server_control_forward();
	} while(TRUE);
}

/* ------------------------------------------------------------- **
** Forward buffered control stream data from client -> server.
** ------------------------------------------------------------- */
void client_control_forward()
{
	int i;
	sstr *cmd, *arg;

	while((i =
	       extract_clientcmd(info->client_control.buf, &cmd, &arg)) == 0)
		parse_client_cmd(cmd, arg);

	if(i < 0)
		die(ATTACK,
		    "Client is sending us a badly formed control stream.",
		    421, "You are sending me rubbish. Goodbye.", -1);
}

/* ------------------------------------------------------------- **
** Forward buffered control stream data from server -> client.
** ------------------------------------------------------------- */
void server_control_forward()
{
	int i, code;
	sstr *arg;

	while((i =
	       extract_servercmd(info->server_control.buf, &code, &arg)) == 0)
		if(!ssl_parsed_reply(code, arg) &&	/*Always returns 0 */
		   !cache_parsed_reply(code, arg) &&
		   !vscan_parsed_reply(code, arg))
			send_message(code, arg);

	if(i < 0)
		die(ATTACK,
		    "Server is sending us a badly formed control stream.",
		    421,
		    "FTP server is sending you rubbish! Closing connection.",
		    -1);
}

/* ------------------------------------------------------------- **
** Work through the arrays of commands to find a matching function.
** Currently there are only two arrays - one with specific functions 
** for during caching, and one with the defaults. An empty entry in
** the list should match all commands.
** ------------------------------------------------------------- */
void parse_client_cmd(sstr * cmd, sstr * arg)
{
	struct cmd_struct *p;
	int i;

	if(!ccp_allowcmd(cmd, arg))
		return;
	sstr_cpy(info->last_command, cmd);

	for(i = 0; i < NUM_CMD_ARRAYS; i++) {
		if(!info->cmd_arrays[i])
			continue;
		for(p = info->cmd_arrays[i]; p && p->cmd; p++) {
			if(!*p->name || !sstr_casecmp2(cmd, p->name)) {
				p->cmd(cmd, arg);
				return;
			}
		}
	}
	write_log(ERROR, "Command %s not implemented", sstr_buf(cmd));
	send_cmessage(502, "Command not implemented.");
}

/* ------------------------------------------------------------- **
** Get one command from client.
** ------------------------------------------------------------- */
void get_command(sstr ** cmd, sstr ** arg)
{
	int i;

	while((i =
	       extract_clientcmd(info->client_control.buf, cmd, arg)) == 1)
		if(get_control_line(GET_CLNT) <= 0)
			die(ERROR, "Arrrghh. Shouldn't be here", 0, NULL, -1);
}

/* ------------------------------------------------------------- **
** Get one reply from server. Ignore multi-line replies.
** ------------------------------------------------------------- */
void get_message(int *code, sstr ** msg)
{
	do {
		switch (extract_servercmd
			(info->server_control.buf, code, msg)) {
		case -1:
			die(ATTACK,
			    "Server is sending us a badly formed control stream.",
			    421, "FTP server is sending you rubbish!"
			    "Closing connection.", -1);
		case 0:
#ifdef DEBUG
			fprintf(stderr, "  s: \033[32m%d %s\033[37m\n",
				*code, msg ? sstr_buf(*msg) : "");
#endif
			if(*code > 0)
				return;
			continue;
		case 1:
			if(get_control_line(GET_SRVR) <= 0)
				die(ERROR, "Arrghh - shoudln't be here",
				    0, NULL, -1);
		}
	} while(TRUE);
}


void send_cmessage(int code, const char *msg)
{
	sstr *smsg;
	smsg = sstr_dup2(msg);

	send_message(code, smsg);

	sstr_free(smsg);
}

void send_ccommand(const char *cmd, const char *arg)
{
	sstr *scmd, *sarg;
	scmd = sstr_dup2(cmd);
	sarg = sstr_dup2(arg);

	send_command(scmd, sarg);

	sstr_free(scmd);
	sstr_free(sarg);
}

/* ------------------------------------------------------------- **
** Send command to server 
** ------------------------------------------------------------- */
void send_command(sstr * cmd, sstr * arg)
{
	sstr *buf;
	buf = sstr_init(MAX_LINE_LEN + 10);

	sstr_cat(buf, cmd);
	if(sstr_len(arg) != 0) {
		sstr_ncat2(buf, " ", 1);
		sstr_cat(buf, arg);
	}
	sstr_ncat2(buf, "\r\n", 2);

#ifdef DEBUG
	fprintf(stderr, "  C: \033[31m%s\033[37m", sstr_buf(buf));
#else
	write_log(VERBOSE, "  C: %s", sstr_buf(buf));
#endif
	if(info->ssl_sc)
		ssl_write(info->ssl_sc, buf);
	else
		sstr_write(info->server_control.fd, buf, 0);

	sstr_free(buf);
}

/* ------------------------------------------------------------- **
** Send message to client
** ------------------------------------------------------------- */
void send_message(int code, sstr * msg)
{
	sstr *buf;
	if(!ccp_allowmsg(&code, msg))
		return;

	buf = sstr_init(MAX_LINE_LEN + 10);

	if(code != 0)
		sstr_apprintf(buf, "%d%c", abs(code), code > 0 ? ' ' : '-');
	sstr_cat(buf, msg);
	sstr_ncat2(buf, "\r\n", 2);

#ifdef DEBUG
	fprintf(stderr, "  S: \033[34m%s\033[37m", sstr_buf(buf));
#else
	write_log(VERBOSE, "  S: %s", sstr_buf(buf));
#endif
	sstr_write(info->client_control.fd, buf, 0);
	sstr_free(buf);
}

int read_srvrctrl_data(void)
{
	if(info->ssl_sc)
		return ssl_append_read(info->ssl_sc,
				       info->server_control.buf, 0);
	else
		return sstr_append_read(info->server_control.fd,
					info->server_control.buf, 0);
}

/* ------------------------------------------------------------- **
** Central select bit. Deals with data connection
** forwarding/listening, and quits on ctrl connection close. Once
** there is a complete line read from one of the control connctions
** specified in "which" (GET_SRVR, GET_CTRL, or GET_SRVR|GET_CTRL) we
** return.
**
** The line read into the control connection buffer on function return
** contains a newline (\n), and is NULL terminated at some point
** beyond that. No other checking has been done on it.
**
** Return value is one of GET_SRVR, GET_CTRL or GET_SRVR|GET_CTRL.
** ------------------------------------------------------------- */
int get_control_line(int which)
{
	int ret = 0, i;
	fd_set reads, writes;

	do {
		i = setup_fds(&reads, &writes);
		alarm(config.timeout);
		if(select(i + 1, &reads, &writes, NULL, NULL) == -1) {
			if(errno == EINTR)
				continue;
			debug_perr("select");
			die(0, NULL, 0, NULL, -1);
		}

		do_dataforward(&reads, &writes);

		if(FD_ISSET(info->client_control.fd, &reads)) {
			i = sstr_append_read(info->client_control.fd,
					     info->client_control.buf, 0);
			if(i == 0)
				die(INFO, "Client closed connection",
				    0, NULL, 0);
			if(i < 0)
				die(ATTACK,
				    "Client flooding control connection", 421,
				    "You're sending rubbish. Goodbye", -1);
			if(sstr_hasline(info->client_control.buf))
				ret |= GET_CLNT;
		}

		if(info->server_control.fd != -1 &&
		   FD_ISSET(info->server_control.fd, &reads)) {
			i = read_srvrctrl_data();
			if(i == 0) {
				if(!cache_transferring())
					die(ERROR,
					    "Server closed the control connection",
					    0, NULL, 0);
				else {
					rclose(&info->server_control.fd);
					write_log(INFO,
						  "Server closed connection. Keeping going until cache done");
				}
			}
			if(i < 0)
				die(ATTACK,
				    "Server flooding the control connection",
				    421, "Server is sending rubbish."
				    "Closing connection", -1);
			if(sstr_hasline(info->server_control.buf))
				ret |= GET_SRVR;
		}

	} while(!(ret & which));
	return (ret);
}

/***************************************************************************
 *
 * Functions which read the raw control stream --- be careful
 *
 **************************************************************************/

/* ------------------------------------------------------------- **
** Removes one line of control stream from buf (up to '\r\n'). <= 5
** chars are returned in cmd (up to 4 + \0), and <= MAX_LINE_LEN in
** arg. Must accept any NULL terminated buf and give sane output.
**  
** returns 0 on success, 1 if there is not a complete line in
** buf, and -X on non-sane buf. contents of buf unchanged on
** return(1), undefined on return(-X)
** ------------------------------------------------------------- */
int extract_clientcmd(sstr * buf, sstr ** pcmd, sstr ** parg)
{
	static sstr *cmd = NULL, *arg = NULL;

	if(!cmd)
		cmd = sstr_init(4);
	if(!arg)
		arg = sstr_init(MAX_LINE_LEN);
	if(pcmd)
		*pcmd = cmd;
	if(parg)
		*parg = arg;

	if(!sstr_hasline(buf))
		return (1);
	switch (sstr_token(buf, cmd, " \t\n\r", 0)) {
	case -1:		/*Token doesn't fit in cmd */
		return (-1);
	case ' ':
	case '\t':
		sstr_token(buf, arg, "\r\n", 0);
		break;
	default:		/*end of line */
		sstr_empty(arg);
	}

	if(!config.nonasciiok)
		sstr_makeprintable(arg, '?');

	return (0);
}

/* ------------------------------------------------------------- **
** As extract_clientcmd, but returns the code as an int.
** If code==0 then we are in a multiline. code<0 means we are
** starting a multiline. 
** ------------------------------------------------------------- */
int extract_servercmd(sstr * buf, int *code, sstr ** pmsg)
{
	static int multiline = 0;
	static sstr *scode = NULL, *msg = NULL;

	if(!scode)
		scode = sstr_init(4);
	if(!msg)
		msg = sstr_init(MAX_LINE_LEN);
	if(pmsg)
		*pmsg = msg;

	if(!sstr_hasline(buf))
		return (1);

	if(sstr_token(buf, msg, "\r\n", 0) == -1)
		return (-1);

	if(!multiline ||
	   (sstr_atoi(msg) == multiline && sstr_getchar(msg, 3) == ' ')) {
		multiline = 0;

		if(sstr_split(msg, scode, 0, 4) == -1)
			return (-1);
		*code = sstr_atoi(scode);

		switch (sstr_getchar(scode, 3)) {
		case '-':
			multiline = *code;
			*code = -*code;
		case ' ':
			break;
		default:
			return (-1);
		}
	} else {
		*code = 0;
	}

	if(!config.nonasciiok)
		sstr_makeprintable(msg, '?');

	return (0);
}
