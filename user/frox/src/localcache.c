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

  localcache.c -- cache code if we are doing our own caching. This is
  experimental.

  ***************************************/
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include "common.h"
#include "cache.h"
#include "control.h"
#include "vscan.h"

extern sstr *cachemgr_init(char *cd, int cs);

int file_cached(const sstr * uri, const sstr * mdtm, int size, int offset);

static sstr *socket_file;

/*FIXME These two should really not be global*/
static int fd;
static enum { CACHED, CACHING, NONE } cache_status = NONE;

int l_geninit(void)
{
	socket_file = cachemgr_init(config.chroot, config.cachesize * 1024);
	if(!socket_file)
		return (-1);
	write_log(VERBOSE, "Cachemgr socket file == %s",
		  sstr_buf(socket_file));
	return (0);
}

/* ------------------------------------------------------------- ** 
** If we have the file return a fd to it. Otherwise return -1.
** ------------------------------------------------------------- */
int l_retr_start(const sstr * host, const sstr * file, const sstr * mdtm,
		 int size, int offset, int type)
{
	static sstr *uri = NULL;
	if(!uri)
		uri = sstr_init(512);

	if(sstr_len(mdtm) == 0) {
		write_log(VERBOSE, "Server didn't like MDTM. Can't cache :(");
		cache_status = NONE;
		return (-1);
	}

	sstr_cpy2(uri, "ftp://");
	if(!info->anonymous)
		sstr_apprintf(uri, "%s@", sstr_buf(info->username));
	sstr_cat(uri, host);
	sstr_cat(uri, file);
	if(type == 0)
		sstr_ncat2(uri, ";type=an", 8);

	if(!file_cached(uri, mdtm, size, offset)) {
		write_log(INFO, "Cache miss for %s", sstr_buf(uri));
		info->cached = 0;
		return (-1);
	}
	write_log(INFO, "Cache hit for %s.", sstr_buf(uri));
	info->cached = 1;

	vscan_new(size);
	if(!vscan_parsed_reply(150, NULL))
		send_cmessage(150, "Starting transfer");

	return (fd);
}

/* ------------------------------------------------------------- **
** Called whenever we get incoming data from server.
** Write data to cache.
** ------------------------------------------------------------- */
void l_inc_data(sstr * inc)
{
	if(cache_status == CACHING) {
		vscan_inc(inc);
		sstr_write(fd, inc, 0);
	}
}

int l_retr_end(void)
{
	if(cache_status == CACHED) {
		if(!vscan_parsed_reply(226, NULL))
			send_cmessage(226, "Transfer complete");
	}
	if(cache_status == CACHING) {
		vscan_end();
		close(fd);
	}
	cache_status = NONE;
	return (-1);
}

/* ------------------------------------------------------------- ** 
** Return TRUE if we have an up to date copy of the file. 
** Also set global variable fd to the file if we have it, or to where
** we should write the file if we don't.
**
** Each cache file has a header of "NNNN MDTM SIZE TYPE URI\n" where
** NNNN is the number of bytes in the header not including the "NNNN ".
** MDTM and SIZE are the returns from those functions, and TYPE is 0 
** for ascii, and 1 for binary.
**
** REST handling is fairly simplistic. If offset>0 and we have the
** portion of the file which is not requested then we seek to offset
** in it and overwrite with what we retrieve to complete our cached
** copy. Otherwise we give up. 
** ------------------------------------------------------------- */
int file_cached(const sstr * uri, const sstr * mdtm, int size, int offset)
{
	int type = 1;
	 /*FIXME*/ int cmgrfd;
	struct sockaddr_un addr;
	sstr *sbuf;

	sbuf = sstr_init(MAX_LINE_LEN * 2);
	sstr_apprintf(sbuf, "G %s %s %d %d %d\n", sstr_buf(uri),
		      sstr_buf(mdtm), size, type, offset);

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, sstr_buf(socket_file));
	if((cmgrfd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		debug_perr("socket");
		die(ERROR, "Error creating socket for caching", 0, NULL, -1);
	}
	if(connect(cmgrfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		debug_perr("Error connecting to cache manager");
		write_log(ERROR, "Unable to connect to cache manager."
			  "Abandoning caching");
		return FALSE;
	}

	write(cmgrfd, sstr_buf(sbuf), sstr_len(sbuf));
	switch (recv_fd(cmgrfd, &fd)) {
	case 0:
		debug_err("cache error");
		cache_status = NONE;
		close(cmgrfd);
		return FALSE;
	case 'A':
		write_log(VERBOSE, "Unable to use caching for this d/l.");
		cache_status = NONE;
		close(cmgrfd);
		return FALSE;
	case 'R':
		/*No need to set read lock. We are only here if the
		   complete file is cached. Cachemgr will never try and
		   overwrite part of a complete file -- it will unlink
		   it and create a new one (and we'll continue
		   accessing the old file) */
		cache_status = CACHED;
		close(cmgrfd);
		return TRUE;
	case 'W':
		set_write_lock(fd);
		cache_status = CACHING;
		close(cmgrfd);
		return FALSE;
	default:
		debug_err("Shouldn't get here");
		close(cmgrfd);
		die(0, NULL, 0, NULL, -1);
	}
	return (-1);
}
