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

  ccp.c -- ftp-proxy like command control program. This file is
           something of a mess now because it contains two completely
           different implementations plus wrappers to call one or the
           other depending on the "UseOldCCP" config file variable.
           The ccp_old_... functions will die in the next major
           release.

           Note that the interface here is low level. A badly written
           ccp script can cause the connection to hang. CCP scripts
           will also get relatively unsanitised data. Commands should
           fit ftp command syntax, and be less than MAX_LINE_LEN bytes
           long with all non printable characters purged, but that is
           all that is guaranteed.
  
  ***************************************/

#include <sys/wait.h>
#include <stdio.h>
#include "common.h"
#include "control.h"
#include "ccp.h"

#ifndef HAVE_SETENV
#define setenv(A, B, C)
#endif

static int exec_ccp_daemon(void);
static void check_serverok(void);
static int process_reply(sstr * cmd, sstr * arg);

static void ccp_new_changedest(void);
static int ccp_new_allowcmd(sstr * cmd, sstr * arg);
static int ccp_new_allowmsg(int *code, sstr * msg);
static void ccp_old_init(void);
static int ccp_old_allowcmd(sstr * cmd, sstr * arg);

static int stdin_fd;
static FILE *stdout_fp;

static int dont_reenter = 0;

void ccp_changedest(void)
{
	if(config.oldccp)
		ccp_old_init();
	else
		ccp_new_changedest();
}

int ccp_allowcmd(sstr * cmd, sstr * arg)
{
	if(config.oldccp)
		return ccp_old_allowcmd(cmd, arg);
	else
		return ccp_new_allowcmd(cmd, arg);
}

int ccp_allowmsg(int *code, sstr * msg)
{
	if(config.oldccp)
		return TRUE;
	else
		return ccp_new_allowmsg(code, msg);
}

/*************************
 **** New interface ******
 *************************/

static void ccp_new_changedest(void)
{
	if(!config.ccpcmd)
		return;

	exec_ccp_daemon();
	check_serverok();
}

static int exec_ccp_daemon(void)
{
	int stdin_fds[2], stdout_fds[2];
	static char *argv[2];

	argv[0] = config.ccpcmd;
	argv[1] = NULL;

	pipe(stdin_fds);
	pipe(stdout_fds);
	switch (fork()) {
	case 0:		/*Child */
		close(stdout_fds[0]);
		close(stdin_fds[1]);
		dup2(stdout_fds[1], 1);
		dup2(stdin_fds[0], 0);
		close(stdout_fds[1]);
		close(stdin_fds[0]);
		execvp(argv[0], argv);
		die(ERROR, "Failed to exec ccp prog", 0, NULL, -1);
	case -1:
		debug_err("Error");
		die(ERROR, "Unable to fork", 0, NULL, -1);
	default:
		break;
	}
	close(stdout_fds[1]);
	close(stdin_fds[0]);
	stdout_fp = fdopen(stdout_fds[0], "r");
	stdin_fd = stdin_fds[1];
	return 0;
}

static void check_serverok(void)
{
	sstr *buf;

	buf = sstr_init(MAX_LINE_LEN + 10);

	sstr_apprintf(buf, "I %s ",
		      inet_ntoa(info->client_control.address.sin_addr));
	sstr_apprintf(buf, "%s %s",
		      inet_ntoa(info->server_control.address.sin_addr),
		      sstr_len(info->server_name) ?
		      sstr_buf(info->server_name) : "X");
	sstr_apprintf(buf, " %d\n",
		      htons(info->server_control.address.sin_port));

	sstr_write(stdin_fd, buf, 0);

	sstr_free(buf);
	process_reply(NULL, NULL);
}

static int ccp_new_allowcmd(sstr * cmd, sstr * arg)
{
	sstr *buf;

	if(!config.ccpcmd)
		return TRUE;
	if(dont_reenter)
		return dont_reenter--;

	buf = sstr_init(MAX_LINE_LEN + 10);
	sstr_apprintf(buf, "C %s %s\n", sstr_buf(cmd), sstr_buf(arg));
	sstr_write(stdin_fd, buf, 0);

	sstr_free(buf);
	if(process_reply(cmd, arg) != 'C')
		return TRUE;

	dont_reenter = 1;
	send_message(sstr_atoi(cmd), arg);
	return FALSE;
}

static int ccp_new_allowmsg(int *code, sstr * msg)
{
	sstr *buf;

	if(!config.ccpcmd)
		return TRUE;
	if(dont_reenter)
		return dont_reenter--;

	buf = sstr_init(MAX_LINE_LEN + 10);
	sstr_apprintf(buf, "S %d %s\n", *code, sstr_buf(msg));
	sstr_write(stdin_fd, buf, 0);

	switch (process_reply(buf, msg)) {
	case 'S':
		dont_reenter = 1;
		parse_client_cmd(buf, msg);
		sstr_free(buf);
		return FALSE;
	case 'C':
		*code = sstr_atoi(buf);
		sstr_free(buf);
		return TRUE;
	default:
		return TRUE;
	}

}

static int process_reply(sstr * cmd, sstr * arg)
{
	sstr *buf;
	buf = sstr_init(MAX_LINE_LEN + 10);
	for(;;) {
		sstr_fgets(buf, stdout_fp);
		switch (sstr_getchar(buf, 0)) {
		case 'R':	/*Redirect */
			sstr_split(buf, NULL, 0, 2);
			sstr_split(buf, NULL, sstr_len(buf) - 1, 1);
			inet_aton(sstr_buf(buf),
				  &info->server_control.address.sin_addr);
			info->final_server_address =
				info->server_control.address;
			sstr_free(buf);
			return 0;
		case 'S':	/* A command to write to the server */
			sstr_split(buf, NULL, 0, 2);
			sstr_token(buf, cmd, " ", 0);
			sstr_token(buf, arg, "\r\n", 0);
			sstr_free(buf);
			return 'S';
		case 'C':	/* A message to write to the client */
			sstr_split(buf, NULL, 0, 2);
			sstr_token(buf, cmd, " ", 0);
			sstr_token(buf, arg, "\r\n", 0);
			sstr_free(buf);
			return 'C';
		case 'L':	/* A log message. Action to follow */
			sstr_split(buf, NULL, 0, 2);
			sstr_split(buf, NULL, sstr_len(buf) - 1, 1);
			write_log(IMPORT, sstr_buf(buf));
			break;
		case 'Q':	/* Close session */
			die(ERROR, "CCP requested exit. Closing session", 0,
			    NULL, 0);
			break;
		case 'X':	/* No change */
			sstr_free(buf);
			return 0;
		default:
			die(ERROR, "Unknown code from CCP progeam", 0, 0, 0);
			break;
		}
	}
}

/*************************
 **** Old interface ******
 *************************/
/*This will all go sometime soon. Maybe it will be replaced with a
  wrapper to ues around legacy ccps.*/

#define EPR "FROX_"

static int exec_old_ccp(void);

static void ccp_old_init(void)
{
	sstr *buf;

	if(!config.ccpcmd)
		return;

	buf = sstr_init(MAX_LINE_LEN);

	setenv(EPR "CLIENT",
	       inet_ntoa(info->client_control.address.sin_addr), 1);
	setenv(EPR "SERVER",
	       inet_ntoa(info->server_control.address.sin_addr), 1);
	setenv(EPR "SERVERNAME", sstr_buf(info->server_name), 1);
	sstr_apprintf(buf, "%lu-%u", time(NULL), getpid());
	setenv(EPR "SESSION", sstr_buf(buf), 1);

	setenv(EPR "COMMAND", "+NEW", 1);
	exec_old_ccp();

	sstr_free(buf);
}

static int ccp_old_allowcmd(sstr * cmd, sstr * arg)
{
	if(!config.ccpcmd)
		return TRUE;

	if(!sstr_cmp2(cmd, "USER")) {
		setenv(EPR "SERVER",
		       inet_ntoa(info->server_control.address.sin_addr), 1);
		setenv(EPR "SERVERNAME", sstr_buf(info->server_name), 1);
		setenv(EPR "USER", sstr_buf(arg), 1);
	}
	setenv(EPR "COMMAND", sstr_buf(cmd), 1);
	setenv(EPR "PARAMETER", sstr_buf(arg), 1);

	return (exec_old_ccp());
}

static int exec_old_ccp(void)
{
	int log_fds[2], message_fds[2], i;
	static char *argv[2];
	sstr *buf;

	argv[0] = config.ccpcmd;
	argv[1] = NULL;

	pipe(log_fds);
	pipe(message_fds);
	switch (fork()) {
	case 0:		/*Child */
		close(log_fds[0]);
		close(message_fds[0]);
		dup2(log_fds[1], 1);
		dup2(message_fds[1], 2);
		execvp(argv[0], argv);
		die(ERROR, "Failed to exec ccp prog", 0, NULL, 0);
	case -1:
		close(log_fds[1]);
		close(message_fds[1]);
		debug_err("Error");
		break;
	 /*FIXME*/ default:
		break;
	}
	wait(&i);
	if(!WIFEXITED(i)) {
		close(log_fds[0]);
		close(message_fds[0]);
		die(ERROR, "CCP program exited abnormally", 0, NULL, -1);
	}

	buf = sstr_init(MAX_LINE_LEN);
	sstr_append_read(log_fds[0], buf, MAX_LINE_LEN);
	if(sstr_len(buf) > 0)
		write_log(IMPORT, sstr_buf(buf));
	close(log_fds[0]);

	sstr_empty(buf);
	sstr_append_read(message_fds[0], buf, MAX_LINE_LEN);
	if(sstr_len(buf) > 0)
		sstr_write(info->client_control.fd, buf, 0);
	close(message_fds[0]);
	sstr_free(buf);

	switch (WEXITSTATUS(i)) {
	case 0:
		return TRUE;
	case 1:
		return FALSE;
	case 2:
		die(ERROR, "CCP requested exit. Closing session", 0, NULL, 0);
	}
	die(ERROR, "CCP exited with unknown exit code", 0, NULL, -1);
	return FALSE;
}
