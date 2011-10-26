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

ntp.c -- non transparent proxying stuff

Overview: 

ntp_changedest gets called just before the proxy connects to the
remote server. If the connection is destined for a remote machine then
we assume that is the destination and that no ntp support is required. 
Otherwise we send a welcome to the client and read a reply of the form
"USER username[@host[:port]]". If necessary we then change the
destination (in the global "info" structure), save the hostname, and
return. We also call set config.transdata=FALSE to stop NAT on data
connections for this session.

We also need get called(ntp_senduser) when the remote server sends us
a 220 welcome message. If we have already welcomed the client we send
the login name we got then to the server and return TRUE. Otherwise we
return FALSE and the main proxy code will forward the welcome on to
the client.

config.fakentp is set where other code in frox wishes to know the
username before it makes a connection - normally because there are
ACLs or config file subsections based on the username. In this case
we use the ntp code to do this, but don't parse the username to do
an address change.
***************************************/

#include <sys/ioctl.h>
#include <netdb.h>

#include "common.h"
#include "cache.h"
#include "control.h"
#include "ntp.h"
#include "ccp.h"
#include "os.h"
#include "ftp-cmds.h"

void parseuser(sstr * arg);

static int working = FALSE;
static int faking = FALSE;

/* ------------------------------------------------------------- **
**  Called before the proxy connects to the server.
**  
**  Send client "220 Send Login", read and parse reply.
**  ------------------------------------------------------------- */
void ntp_changedest(void)
{
	sstr *cmd, *arg;
	struct sockaddr_in tmp;

	if(!config.ntp) {
		if(config.fakentp)
			faking = TRUE;
		else
			return;
	}

	if(config.ntpdest.sin_addr.s_addr) {
		/*Don't do ntp proxying unless the connection is to NTPDest. */
		get_orig_dest(info->client_control.fd, &tmp);
		if(tmp.sin_addr.s_addr != config.ntpdest.sin_addr.s_addr
		   || (config.ntpdest.sin_port &&
		       tmp.sin_port != config.ntpdest.sin_port))
			faking = TRUE;
	}

	if(faking && !config.fakentp)
		return;
	working = TRUE;

	send_cmessage(220, faking ? "Frox. Please login." :
		      "Frox transparent ftp proxy. Login with username[@host[:port]]");
	info->greeting = FAKED;
	do {
		get_command(&cmd, &arg);
		if(!sstr_casecmp2(cmd, "QUIT"))
			die(INFO, "Client closed connecton", 0, 0, 0);
		if(sstr_casecmp2(cmd, "USER"))
			send_cmessage(530, "Please login with USER first");
	} while(sstr_casecmp2(cmd, "USER"));

	if(!faking)
		parseuser(arg);
	else
		sstr_cpy(info->username, arg);

	if(sstr_casecmp2(info->username, "ftp")
	   && sstr_casecmp2(info->username, "anonymous"))
		info->anonymous = 0;
	else
		info->anonymous = 1;
}

/* ------------------------------------------------------------- **
**  If we have a username send it to the server.
**  ------------------------------------------------------------- */
void ntp_senduser(void)
{
	int i;
	sstr *msg, *tmp;

	if(!working)
		return;

	if(info->greeting != DONE) {
		get_message(&i, &msg);
		if(i != 220) {
			die(INFO, "Unable to contact server in ntp",
			    421, "Server Unable to accept connection", 0);
		}
	}
	info->greeting = DONE;

	working = FALSE;

	tmp = sstr_dup2("USER");
	user_munge(tmp, NULL);
	sstr_free(tmp);
}

/* ------------------------------------------------------------- **
**  Parse the user command, resolve the hostname if present, and do
**  security checks. If all ok alter info->server_control.address.
**  We check for @ from the far end to allow usernames with @s in
**  them.
**  ------------------------------------------------------------- */
void parseuser(sstr * arg)
{
	struct hostent *hostinfo;
	sstr *host = NULL;
	int sep, i, port = 0;
	sstr *tok;

	for(i = sstr_len(arg) - 1; i >= 0; i--)
		if(sstr_getchar(arg, i) == '@')
			break;

	if(i == -1) {
		sstr_cpy(info->username, arg);
		return;
	}

	sstr_split(arg, info->username, 0, i);
	sstr_split(arg, NULL, 0, 1);

	tok = sstr_init(MAX_LINE_LEN);
	sep = sstr_token(arg, tok, ":", 0);
	host = (sep == -1 ? arg : tok);

	if(sep == ':')
		port = sstr_atoi(arg);
	else
		port = 21;

	write_log(VERBOSE, "NTP:  Host=%s", sstr_buf(host));
	write_log(VERBOSE, "NTP:  Port=%d", port);

	/*Turn off data connection NAT for this connection! */
	config.transdata = FALSE;

	hostinfo = gethostbyname(sstr_buf(host));
	if(!hostinfo)
		die(INFO, "Unable to find NTP host",
		    501, "Can't find that host", 0);
	if(hostinfo->h_addrtype != AF_INET)
		die(INFO, "Invalid NTP host", 501, "Invalid host", 0);


	info->server_control.address.sin_addr =
		*((struct in_addr *) hostinfo->h_addr_list[0]);
	info->server_control.address.sin_port = htons(port);
	info->server_control.address.sin_family = AF_INET;

	/*We used to change apparent_server_address here, but I don't
	   think that is right. Makes no difference as we have turned
	   off TransparentData connections above and that is all it is
	   used for. */

	sstr_cpy(info->server_name, host);

	sstr_free(tok);
}
