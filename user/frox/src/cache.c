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

  cache.c -- Generic code for caching.

Overview:

   cache_init() redirects USER in ftp_cmds to come here. If user is
   anonymous we redirect all the other stuff we are going to need to
   parse or intercept for caching to come here too.

   We intercept RETR commands, and get all the info we need about the
   filename (size, last modification date, and uri).

   We call the specific cache code (in squidcache.c or localcache.c)
   with all this information, and it has the opportunity to return a
   file descriptor which will return the file.

   Specific cache code gets called with all incoming data in case it
   wishes to either alter it (ie. strip HTTP headers), or store it.

  Current Problems include: 
      o STAT does nothing useful.
      o If we start doing anything with USER or 220 cmds then we have
        the potential to interact with non-transparent proxying code.

  ***************************************/

#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "control.h"
#include "ftp-cmds.h"
#include "transdata.h"
#include "cache.h"

void cache_stat(sstr * cmd, sstr * arg);
void cache_abor(sstr * cmd, sstr * arg);
void cache_mode(sstr * cmd, sstr * arg);
void cache_stru(sstr * cmd, sstr * arg);
void cache_type(sstr * cmd, sstr * arg);
void cache_rest(sstr * cmd, sstr * arg);
void cache_retr(sstr * cmd, sstr * arg);
void cache_notallowed(sstr * cmd, sstr * arg);
int setup_fileinfo(sstr * filename);
void strip2bs(sstr * p);

extern void abor_parse(sstr * cmd, sstr * arg);
extern void xfer_command(sstr * cmd, sstr * arg);

static int nooping = FALSE;
static int working = FALSE;
static int type = 0;		/*Ascii or Binary */
static int noop = 0;		/*No of NOOPs sent */
static time_t last_noop;
static int offset = 0;

struct filedetails {
	sstr *host;
	sstr *path;
	sstr *filename;
	int size;
	sstr *mdtm;
};

struct filedetails fileinfo = { NULL, NULL, NULL, 0, NULL };

#define NOOP_INTERVAL 30	/*Seconds */

static struct cmd_struct cache_list[] = {
	{"MODE", cache_mode},
	{"STRU", cache_stru},
	{"TYPE", cache_type},
	{"REST", cache_rest},
	{"RETR", cache_retr},
	{"", NULL}
};

static struct cmd_struct xfer_list[] = {
	{"ABOR", cache_abor},
	{"STAT", cache_stat},
	{"", cache_notallowed},
	{"", NULL}
};

static int (*retr_start) (const sstr * host, const sstr * file,
			  const sstr * mdtm, int size, int offset, int type);
void (*inc_data) (sstr * inc);
static int (*retr_end) (void);
static void which_caches(struct options *c, int *local, int *http);

/* ------------------------------------------------------------- **
** Called at frox start. Fork the cache manager if it is needed.
** ------------------------------------------------------------- */
int cache_geninit(void)
{
	int need_local = 0, need_http = 0;

	which_caches(&config, &need_local, &need_http);

	if(need_local) {
#ifdef USE_LCACHE
		if(l_geninit() == -1)
			die(ERROR, "Unable to init local cache", 0, 0, -1);
#else
		die(ERROR, "Local caching not compiled in", 0, 0, -1);
#endif
	}
#ifndef USE_HCACHE
	if(need_http)
		die(ERROR, "HTTP caching not compiled in", 0, 0, -1);
#endif


	fileinfo.host = sstr_init(MAX_LINE_LEN);
	fileinfo.path = sstr_init(MAX_LINE_LEN);
	fileinfo.filename = sstr_init(MAX_LINE_LEN);
	fileinfo.mdtm = sstr_init(MAX_LINE_LEN);

	return 0;
}

/*
 * Check whether we need local and/or http caching in any of the config
 * file subsections.
 */
static void which_caches(struct options *c, int *local, int *http)
{
	int i;

	if(c->cachemod) {
		if(!strcasecmp(c->cachemod, "Local"))
			*local = 1;
		else if(!strcasecmp(c->cachemod, "HTTP"))
			*http = 1;
		else if(strcasecmp(c->cachemod, "None"))
			die(ERROR, "Unrecognised cache module", 0, 0, -1);
	}

	for(i = 0; i < c->subsecs.num; i++)
		which_caches(&c->subsecs.list[i].config, local, http);
}

/* ------------------------------------------------------------- **
** Setup the cache command list.
** ------------------------------------------------------------- */
void cache_init(void)
{
	if(!info->anonymous) {
		if(config.cacheall) {	/*Caching a non anonymous connection */
			config.strictcache = TRUE;
		} else {
			config.cachemod = NULL;
			return;
		}
	}

	if(!config.cachemod)
		return;
	if(!strcasecmp(config.cachemod, "None")) {
		config.cachemod = NULL;
		return;
	}

	info->cmd_arrays[CACHE_CMDS] = cache_list;
	if(!strcasecmp(config.cachemod, "Local")) {
		retr_start = l_retr_start;
		inc_data = l_inc_data;
		retr_end = l_retr_end;
	} else {
		retr_start = s_retr_start;
		inc_data = NULL;	/* s_retr_start() does all incoming data
					   processing before it returns. */
		retr_end = s_retr_end;
	}
}

/* ------------------------------------------------------------- **
** Commands to intercept at all times. TODO Consider moving stru and
** mode functions to ftp-cmds.c They are pretty much obsolete, and
** probably not used by anyone any more. 
** ------------------------------------------------------------- */
void cache_mode(sstr * cmd, sstr * arg)
{
	if(sstr_getchar(arg, 0) == 'S')
		send_cmessage(200, "Command okay");
	else
		send_cmessage(504, "Only stream mode implemented");
}

void cache_stru(sstr * cmd, sstr * arg)
{
	if(sstr_getchar(arg, 0) == 'F')
		send_cmessage(200, "Command okay");
	else
		send_cmessage(504, "Only file structure implemented");
}

void cache_type(sstr * cmd, sstr * arg)
{
	if(sstr_getchar(arg, 0) == 'I') {
		type = 1;
		send_command(cmd, arg);
	} else if(!sstr_casecmp2(arg, "AN")
		  || !sstr_casecmp2(arg, "A")) {
		type = 0;
		send_command(cmd, arg);
	} else
		send_cmessage(504, "Only types I and AN implemented");
}

void cache_rest(sstr * cmd, sstr * arg)
{

	write_log(VERBOSE, "cache.c intercepted REST");
	offset = sstr_atoi(arg);

	send_command(cmd, arg);
}

void cache_notallowed(sstr * cmd, sstr * arg)
{
	write_log(ERROR, "Command %s not allowed during cache xfer",
		  sstr_buf(cmd));
	send_cmessage(502, "Command not implemented.");
}

/* ------------------------------------------------------------- **
** Commands to intercept during transfer
** ------------------------------------------------------------- */
void cache_stat(sstr * cmd, sstr * arg)
{
	send_cmessage(213, "Retrieving file through cache");
}

void cache_abor(sstr * cmd, sstr * arg)
{
	int code;
	while(noop > 0) {
		get_message(&code, NULL);
		noop--;
	}
	nooping = FALSE;

	rclose(&info->client_data.fd);
	rclose(&info->server_data.fd);
	info->state = NEITHER;

	info->cmd_arrays[CACHE_CMDS] = cache_list;

	write_log(VERBOSE, "cache.c intercepted ABOR");
	send_cmessage(426, "transfer aborted");
	send_cmessage(226, "Closing data connection");
	working = FALSE;
	if(info->server_control.fd == -1)
		die(INFO, "Server timed out during cache transfer", 421,
		    "Sorry - timed out", 0);
}

/* ------------------------------------------------------------- **
** The important bit. Intercept RETR commands, find out all we need to
** about the file, and then pass all the info to the caching function. 
** ------------------------------------------------------------- */
void cache_retr(sstr * cmd, sstr * arg)
{
	int i = -1, code;
	sstr *msg;

	/* Clear these now. If cache code has stuff it needs sent it
	 * can put it into these buffers.*/
	sstr_empty(info->client_data.buf);
	sstr_empty(info->server_data.buf);

	if(setup_fileinfo(arg) == 0)
		i = retr_start(fileinfo.host, fileinfo.path, fileinfo.mdtm,
			       fileinfo.size, offset, type);

	if(i == -1) {		/*Cache can't return file for us. Do it ourselves. */
		sstr *tmp;
		tmp = sstr_init(10);
		nooping = FALSE;
		if(offset != 0) {	/*Send another REST since we sent loads
					 * of rubbish since the last one. */
			sstr_apprintf(tmp, "%d", offset);
			offset = 0;
			send_ccommand("REST", sstr_buf(tmp));
			get_message(&code, &msg);
			if(code != 350) {
				send_cmessage(503,
					      "Can't do REST after all!");
				sstr_free(tmp);
				return;
			}
		}
		sstr_cpy2(tmp, "RETR");
		xfer_command(tmp, arg);
		sstr_free(tmp);
		return;
	}

	/*Cache is retrieving the file - it will deal with REST, so
	   reset it to 0 just in case */
	if(offset != 0) {
		send_ccommand("REST", "0");
		get_message(&code, &msg);
		offset = 0;
	}
	info->needs_logging = TRUE;
	info->virus = -1;
	sstr_cpy(info->filename, arg);
	urlescape(info->filename, "% ;/");

	/*Set up everything as if this were a normal connection */
	rclose(&info->server_data.fd);
	info->server_data.fd = i;
	if(info->client_data.fd == -1 && info->mode != PASSIVE) {
		if(config.transdata) {
			struct sockaddr_in tmp =
				info->apparent_server_address;
			tmp.sin_port = htons(20);
			info->client_data.fd =
				transp_connect(info->client_data.address,
					       tmp);
		} else
			info->client_data.fd =
				connect_to_socket(&info->client_data.address,
						  &config.tcpoutaddr,
						  config.actvports);
		if(info->client_data.fd == -1) {
			write_log(ERROR,
				  "Unable to connect to client data port");
			cache_close_data();
			return;
		}
	}

	info->cmd_arrays[CACHE_CMDS] = xfer_list;

	nooping = TRUE;
	working = TRUE;
	time(&last_noop);
}

int setup_fileinfo(sstr * filename)
{
	int code;
	sstr *msg;

	if(!strcasecmp(config.cachemod, "Local") || !config.forcehttp) {
		send_ccommand("SIZE", sstr_buf(filename));
		get_message(&code, &msg);
		if(code / 100 != 2) {
			write_log(VERBOSE,
				  "SIZE not accepted - aborting caching");
			return (-1);
		}
		fileinfo.size = sstr_atoi(msg);
		write_log(VERBOSE, "Cache: Filesize is %d", fileinfo.size);

		send_ccommand("MDTM", sstr_buf(filename));
		get_message(&code, &msg);
		if(code / 100 != 2) {
			write_log(VERBOSE,
				  "MDTM not accepted - aborting caching");
			return (-1);
		}
		sstr_cpy(fileinfo.mdtm, msg);
		write_log(VERBOSE, "Cache: MDTM is %s",
			  sstr_buf(fileinfo.mdtm));
	}

	if(!config.strictcache) {
		if(sstr_getchar(filename, 0) != '/') {
			send_ccommand("PWD", "");
			get_message(&code, &msg);
			if(sstr_getchar(msg, 0) != '"')
				sstr_token(msg, NULL, "\"", 0);
			sstr_token(msg, fileinfo.path, "\"", 0);
			if(sstr_getchar(fileinfo.path,
					sstr_len(fileinfo.path) - 1) != '/')
				sstr_ncat2(fileinfo.path, "/", 1);
			urlescape(fileinfo.path, " %;");
		} else {	/* Absolute path given in filename */
			sstr_empty(fileinfo.path);
		}
	} else {
		sstr_ncpy2(fileinfo.path, "/", 1);
		sstr_cat(fileinfo.path, info->strictpath);
	}

	if(config.usefqdn && sstr_len(info->server_name))
		sstr_cpy(fileinfo.host, info->server_name);
	else
		sstr_cpy2(fileinfo.host,
			  inet_ntoa(info->final_server_address.sin_addr));

	if(ntohs(info->final_server_address.sin_port) != 21)
		sstr_apprintf(fileinfo.host, ":%d",
			      ntohs(info->final_server_address.sin_port));

	sstr_cpy(fileinfo.filename, filename);
	urlescape(fileinfo.filename, config.strictcache ? "% ;/" : "% ;");
	sstr_cat(fileinfo.path, fileinfo.filename);

	sstr_cpy(fileinfo.filename, filename);

	if(!config.strictcache)
		strip2bs(fileinfo.path);
	info->state = DOWNLOAD;

	return 0;
}

/* ------------------------------------------------------------- **
** Deal with server replies if we need to. 
** ------------------------------------------------------------- */
int cache_parsed_reply(int code, sstr * msg)
{
	if(!config.cachemod)
		return (FALSE);
	if(noop > 0) {
		if(code > 0)
			noop--;
		write_log(VERBOSE, "Got NOOP reply");
		return (TRUE);
	}
	if(working && code == 421) {
		write_log(VERBOSE,
			  "Discarding server close during cache retrieval");
		return TRUE;
	}
	return FALSE;
}

void cache_inc_data(sstr * buf)
{
	if(!config.cachemod)
		return;

	if(nooping && time(NULL) - last_noop > NOOP_INTERVAL &&
	   info->server_control.fd != -1) {
		write(info->server_control.fd, "NOOP\r\n", 6);
		noop++;
		time(&last_noop);
		write_log(VERBOSE, "Sent NOOP");
	}
	if(inc_data)
		inc_data(buf);
}

int cache_close_data(void)
{
	int code, i;
	sstr *msg;

	if(!config.cachemod)
		return (-1);

	while(noop > 0) {
		get_message(&code, &msg);
		noop--;
	}

	nooping = FALSE;
	info->cmd_arrays[CACHE_CMDS] = cache_list;

	i = retr_end();
	working = FALSE;
	if(info->server_control.fd == -1)
		die(INFO, "Server timed out during cache transfer", 421,
		    "Sorry - timed out", 0);
	return i;
}

int cache_transferring(void)
{
	return working;
}

/*Strip multiple "//" from string */
void strip2bs(sstr * p)
{
	int i;
	for(i = 0; i < sstr_len(p) - 1; i++) {
		while(sstr_getchar(p, i) == '/'
		      && sstr_getchar(p, i + 1) == '/')
			sstr_split(p, NULL, i, 1);
	}
}
