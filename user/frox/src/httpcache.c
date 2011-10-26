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

  httpcache.c -- Stuff for requesting files through an external cache 
                 (eg. squid)


  ***************************************/
#include <fcntl.h>
#include "common.h"
#include "cache.h"
#include "control.h"
#include "vscan.h"

static enum { STARTING, SUCCEEDING, SUCCESS, FAILURE, NONE } cache_status =
	NONE;
static int offset;
static int proxy_dl_ok(int fd);

/* ------------------------------------------------------------- **
** If we are to retrieve through squid then return a fd. If not, or on
** error, return -1. 
** ------------------------------------------------------------- */
int s_retr_start(const sstr * host, const sstr * file, const sstr * mdtm,
		 int size, int offst, int type)
{
	sstr *buf;
	int i, squidfd;

	offset = offst;
	if(config.mincachesize > size) {
		cache_status = NONE;
		write_log(VERBOSE,
			  "File too small for cache - retrieving directly");
		return (-1);
	}

	/*Set up the HTTP command */
	cache_status = STARTING;

	buf = sstr_init(0);
	i = sstr_apprintf(buf,
			  "GET ftp://%s%s%s%s%s%s%s HTTP/1.0\r\n"
			  "Host: %s\r\n"
			  "User-Agent: %s\r\n"
			  "X-Forwarded-For: %s\r\n",
			  info->anonymous ? "" : sstr_buf(info->username),
			  info->anonymous ? "" : ":",
			  info->anonymous ? "" : sstr_buf(info->passwd),
			  info->anonymous ? "" : "@",
			  sstr_buf(host), sstr_buf(file),
			  type == 1 ? (config.strictcache ? ";type=i" : "")
			  : ";type=an",
			  sstr_buf(host), "Frox/0.7",
			  inet_ntoa(info->client_control.address.sin_addr));
	if(offset > 0)
		sstr_apprintf(buf, "Range: bytes=%d-\r\n", offset);
	sstr_ncat2(buf, "\r\n", 2);

	if(i < 0 || i > BUF_LEN)
		die(ERROR, "Failure building HTTP string",
		    421, "Failure building HTTP string", -1);

	write_log(VERBOSE, "HTTP string = %s", sstr_buf(buf));

	if((squidfd = connect_to_socket(&config.httpproxy, NULL,
					config.pasvports)) == -1) {
		write_log(ERROR,
			  "Unable to contact HTTP proxy. Retrieving directly");
		cache_status = NONE;
		sstr_free(buf);
		return (-1);
	}

	/*Send the message to squid. We could block for a while here,
	 * but no-one should be sending us anything important...*/
/*	fcntl(squidfd, F_SETFL, O_NONBLOCK);*/
	sstr_write(squidfd, buf, 0);
	sstr_free(buf);

	/* Now wait for squid's answer. This is a nasty hack as it means
	 * more blocking.*/
	if(!proxy_dl_ok(squidfd))
		return -1;

	vscan_new(size);
	if(!vscan_parsed_reply(150, NULL))
		send_cmessage(150, "Starting transfer");

	/*And set everything up as if the connection was normal */

	return (squidfd);
}


/* Start downloading from proxy. If failure then close fd. If success
 * then wait until header is downloaded and return. All processing of
 * inc_data stream can be done from here.
 * 
 * Nasty hack. Proper solution involves changing cache.c and
 * control.c/data.c to allow deferring this decision to later. Then we
 * could use the central select loop rather than blocking here.*/
static int proxy_dl_ok(int fd)
{
	int i;
	sstr *buf = sstr_init(4096);

	do {
		fd_set readfds;

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		if(select(fd + 1, &readfds, NULL, NULL, NULL) == -1) {
			if(errno == EINTR)
				continue;
			debug_perr("select");
			die(0, NULL, 0, NULL, -1);
		}

		i = sstr_append_read(fd, buf, 4095);
		if(i == -1) {
			write_log(ERROR, "Error reading from http cache. "
				  "Aborting caching.");
			cache_status = NONE;
			close(fd);
			sstr_free(buf);
			return 0;
		}
		s_inc_data(buf);
	} while(cache_status == STARTING || cache_status == SUCCEEDING);
	switch (cache_status) {
	case SUCCESS:
		sstr_cat(info->client_data.buf, buf);
		sstr_free(buf);
		return 1;
	case FAILURE:
		close(fd);
		cache_status = NONE;
		write_log(ERROR, "Http cache unable to download file. "
			  "Aborting caching.");
		sstr_free(buf);
		return 0;
	default:
		die(ERROR, "Internal error, proxy_dl_ok()", 0, 0, -1);
		break;
	}
	return 0;
}

/* ------------------------------------------------------------- **
** Strip out HTTP lines from inc, and set cache_status according
** to whether the requests fails or not. Leave any message body
** in inc.
** ------------------------------------------------------------- */
void s_inc_data(sstr * inc)
{
	int i;
	sstr *buf = NULL;

	if(cache_status == NONE)
		return;
	if(cache_status == SUCCESS)
		return;
	if(cache_status == FAILURE) {	/*Discard message body */
		write_log(VERBOSE, "Discarding HTTP body after failure.");
		sstr_empty(inc);
		return;
	}

	/*Parse HTTP reply. FIXME - parse it properly! */
	do {
		i = sstr_chr(inc, '\n');
		if(i == -1)
			return;	/*Incomplete line */

		buf = sstr_init(MAX_LINE_LEN);
		sstr_split(inc, buf, 0, i + 1);
		write_log(VERBOSE, "HTTP: %s", sstr_buf(buf));
		if(!sstr_ncasecmp2(buf, "HTTP", 4)) {	/*Status Line */
			sstr_token(buf, NULL, " ", 0);
			i = sstr_atoi(buf);
			if((i / 100) == 2 && (offset == 0 || i == 206))
				cache_status = SUCCEEDING;
			else {	/*Failure - discard rest of message. */
				sstr_empty(inc);
				cache_status = FAILURE;
				sstr_free(buf);
				return;
			}
		} else if(sstr_getchar(buf, 0) == '\r')
			cache_status =
				(cache_status ==
				 SUCCEEDING) ? SUCCESS : FAILURE;

	} while(cache_status != SUCCESS && cache_status != FAILURE);

	sstr_free(buf);
	return;
}

int s_retr_end(void)
{
	if(cache_status == NONE)
		return (-1);
	if(cache_status == SUCCESS) {
		if(!vscan_parsed_reply(226, NULL))
			send_cmessage(226, "Transfer complete");
	} else {
		if(!vscan_parsed_reply(226, NULL))
			send_cmessage(426, "Unable to transfer file");
	}

	cache_status = NONE;
	return (-1);
}
