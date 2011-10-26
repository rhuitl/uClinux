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
  
     data.c -- Code for handling the data connection and picking fds to select.

  ***************************************/


#include <sys/ioctl.h>
#include <fcntl.h>
#include <syslog.h>

#include "data.h"
#include "control.h"
#include "cache.h"
#include "vscan.h"
#include "transdata.h"
#include "ssl.h"

void client_data_connect(void);
void server_data_connect(void);

void writebuf2client(void);
void writebuf2server(void);
void forwarddata2client(void);
void forwarddata2server(void);

void closecd(void);
void closesd(void);

void bwlimit(int bytes, int rate);

/* ------------------------------------------------------------- **
** Setup fd sets for reading/writing. We always listen to the client's
** control stream, and other fds are selected on depending on state.
** ------------------------------------------------------------- */
int setup_fds(fd_set * reads, fd_set * writes)
{
	int n;

	FD_ZERO(reads);
	FD_ZERO(writes);

	FD_SET(info->client_control.fd, reads);
	n = info->client_control.fd;

	if(info->server_control.fd != -1) {
		FD_SET(info->server_control.fd, reads);
		if(info->server_control.fd > n)
			n = info->server_control.fd;
	}

	if(info->server_data.fd != -1) {
		if(sstr_len(info->client_data.buf) == 0)
			FD_SET(info->server_data.fd, reads);

		if(sstr_len(info->server_data.buf) != 0)
			FD_SET(info->server_data.fd, writes);
		if(info->server_data.fd > n)
			n = info->server_data.fd;
	}
	if(info->client_data.fd != -1) {
		if(sstr_len(info->server_data.buf) == 0)
			FD_SET(info->client_data.fd, reads);
		if(sstr_len(info->client_data.buf) != 0)
			FD_SET(info->client_data.fd, writes);
		if(info->client_data.fd > n)
			n = info->client_data.fd;
	}
	if(info->client_listen != -1) {
		FD_SET(info->client_listen, reads);
		if(info->client_listen > n)
			n = info->client_listen;
	}
	if(info->server_listen != -1) {
		FD_SET(info->server_listen, reads);
		if(info->server_listen > n)
			n = info->server_listen;
	}
	return (n);
}

/* ------------------------------------------------------------- **
** Check the fd_sets, and do data connection forwarding if any.
** ------------------------------------------------------------- */
void do_dataforward(fd_set * reads, fd_set * writes)
{
	if(info->client_listen != -1 && FD_ISSET(info->client_listen, reads))
		client_data_connect();
	if(info->server_listen != -1 && FD_ISSET(info->server_listen, reads))
		server_data_connect();

	if(info->server_data.fd != -1)
		if(FD_ISSET(info->server_data.fd, reads))
			forwarddata2client();
	if(info->server_data.fd != -1)
		if(FD_ISSET(info->server_data.fd, writes))
			writebuf2server();

	if(info->client_data.fd != -1)
		if(FD_ISSET(info->client_data.fd, reads))
			forwarddata2server();
	if(info->client_data.fd != -1)
		if(FD_ISSET(info->client_data.fd, writes))
			writebuf2client();

}

/* ------------------------------------------------------------- **
**  Client just connected to the data line
** ------------------------------------------------------------- */
void client_data_connect()
{
	int len = sizeof(info->client_data.address);

	write_log(VERBOSE, "  Client has connected to proxy data line");
	info->client_data.fd = accept(info->client_listen,
				      (struct sockaddr *) &info->
				      client_data.address, &len);

	if(config.sameaddress) {
		if(info->client_data.address.sin_addr.s_addr !=
		   info->client_control.address.sin_addr.s_addr) {
			write_log(ATTACK,
				  "Blocked %s from connecting to data line",
				  addr2name(info->client_data.address.
					    sin_addr));
			rclose(&info->client_data.fd);
			return;
		}
	}
	il_free();		/* Remove the ipchains entry for intercepting this
				 * data connection.*/

	sstr_empty(info->client_data.buf);

	if(info->mode == PACONV)
		return;
	/* Cache code could have already connected us. */
	if(info->server_data.fd == -1)
		connect_server_data();

}

/* ------------------------------------------------------------- **
**  Server just connected to the data line
** ------------------------------------------------------------- */
void server_data_connect()
{
	int len = sizeof(info->server_data.address);

	write_log(VERBOSE, "  Server has connected to proxy data line");
	info->server_data.fd = accept(info->server_listen,
				      (struct sockaddr *) &info->
				      server_data.address, &len);
	if(config.sameaddress) {
		if(info->server_data.address.sin_addr.s_addr !=
		   info->server_control.address.sin_addr.s_addr) {
			write_log(ATTACK,
				  "Blocked %s from connecting to data line",
				  addr2name(info->server_data.address.
					    sin_addr));
			ssl_shutdown(&info->ssl_sd);
			rclose(&info->server_data.fd);
			return;
		}
	}

	sstr_empty(info->server_data.buf);
	info->ssl_sd = ssl_initfd(info->server_data.fd, SSL_DATA);
	if(info->mode == PACONV)
		return;
	connect_client_data();
}

/*Connect to server data port. Initialise ssl on it if necessary*/
int connect_server_data()
{
	info->server_data.fd =
		connect_to_socket(&info->server_data.address,
				  &config.tcpoutaddr, config.pasvports);
	if(info->server_data.fd == -1) {
		write_log(ERROR, "Failed to contact server data port");
		rclose(&info->client_data.fd);
		return (-1);
	}
	sstr_empty(info->server_data.buf);

	/*This shouldn't need to be non blocking as data is only read
	 *when select says it is there. Non blocking makes ssl really
	 *tricky*/
	/*fcntl(info->server_data.fd, F_SETFL, O_NONBLOCK); */
	info->ssl_sd = ssl_initfd(info->server_data.fd, SSL_DATA);
	return (0);
}

int connect_client_data()
{
	/*FIXME should use server_data.address.sin_addr, but 20 as port */
	if(config.transdata)
		info->client_data.fd =
			transp_connect(info->client_data.address,
				       info->server_data.address);
	else {
		info->client_data.fd =
			connect_to_socket(&info->client_data.address,
					  config.listen.s_addr ? &config.
					  listen : NULL, config.actvports);
	}
	if(info->client_data.fd == -1) {
		write_log(ERROR, "Failed to contact client data port");
		ssl_shutdown(&info->ssl_sd);
		rclose(&info->server_data.fd);
		return (-1);
	}
	sstr_empty(info->client_data.buf);
	fcntl(info->client_data.fd, F_SETFL, O_NONBLOCK);
	return (0);
}

/* ------------------------------------------------------------- **
** Forward as much data as possible from client-->server, and store
** the rest in server_data.buf. If maxrate is set then read at most
** 1/4 of a second's worth.
** ------------------------------------------------------------- */
void forwarddata2server()
{
	int i;

	i = sstr_append_read(info->client_data.fd, info->server_data.buf,
			     config.maxulrate ? config.maxulrate / 4 : 0);
	if(i < 1) {		/*Socket close or error */
		closecd();
		return;
	}
	if(config.maxulrate)
		bwlimit(i, config.maxulrate);
	if(info->state != UPLOAD)
		sstr_empty(info->server_data.buf);

	if(info->server_data.fd != -1)
		writebuf2server();
}

/* ------------------------------------------------------------- **
** Forward as much data as possible from server-->client, and store
** the rest in client_data.buf. If maxrate is set then read at most
** 1/4 of a second's worth.
**
** The vscan_inc_data(), cache_inc_data() order is because http
** caching uses cache_inc_data to strip http headers which must be
** done before data reaches the virus scanner, while local caching
** uses it to write file data to file which musn't be done until the
** vscan code has emptied the buffer. Without caching cache_inc_data
** has no effect so it makes no difference. Ugly I know, but I could
** think of no better way...
** ------------------------------------------------------------- */
void forwarddata2client()
{
	int i, dlrate;
	dlrate = info->cached ? config.cachedlrate : config.maxdlrate;
	dlrate = dlrate ? dlrate / 4 : 0;
	if(info->ssl_sd)
		i = ssl_append_read(info->ssl_sd,
				    info->client_data.buf, dlrate);
	else
		i = sstr_append_read(info->server_data.fd,
				     info->client_data.buf, dlrate);

	if(i < 1) {		/*Socket close or error */
		if(!vscan_switchover())
			closesd();
		return;
	}
	if(dlrate)
		bwlimit(i, dlrate);
	if(info->state != DOWNLOAD)
		sstr_empty(info->client_data.buf);

	if(config.cachemod && *config.cachemod == 'h') {	/*http caching */
		cache_inc_data(info->client_data.buf);
		vscan_inc(info->client_data.buf);
	} else {		/*local caching */
		vscan_inc(info->client_data.buf);
		cache_inc_data(info->client_data.buf);
	}
	if(info->client_data.fd != -1)
		writebuf2client();
}

/* ------------------------------------------------------------- **
**  Flush as much buffer as we can
** ------------------------------------------------------------- */
void writebuf2client()
{
	int i;

	i = sstr_write(info->client_data.fd, info->client_data.buf, 0);
	if(i == -1) {
		if(errno == EAGAIN)
			return;
		if(errno != EPIPE)
			debug_perr("writebuf2client()");
		closecd();
		return;
	}
	sstr_split(info->client_data.buf, NULL, 0, i);

	if(sstr_len(info->client_data.buf) == 0 && info->server_data.fd == -1)
		closecd();
	debug(".");
}

/* ------------------------------------------------------------- **
**  Flush as much buffer as we can
** ------------------------------------------------------------- */
void writebuf2server()
{
	int i;

	if(info->ssl_sd)
		i = ssl_write(info->ssl_sd, info->server_data.buf);
	else
		i = sstr_write(info->server_data.fd, info->server_data.buf,
			       0);
	if(i == -1) {
		if(errno == EAGAIN)
			return;
		if(errno != EPIPE)
			debug_perr("writebuf2server()");
		closesd();
		return;
	}
	sstr_split(info->server_data.buf, NULL, 0, i);

	if(sstr_len(info->server_data.buf) == 0 && info->client_data.fd == -1)
		closesd();
	debug(".");
}

/* ------------------------------------------------------------- **
** Called for all data transfers. If more bytes transferred since the
** last call than permitted in the elapsed time then pause. The value
** of last doesn't get changed between transfers even if there's a big
** pause in between, but this only means that the first BUF_LEN bytes
** of the new transfer get passed through immediately. Shouldn't be a
** problem. Maybe I can even call it a feature -- fast transfer of
** small files. ;)
**
** We sleep only once there is ALLOW_DISCREPANCY seconds worth of
** sleeping to do. If this is too small we are really inaccurate in
** our transfer rate - nanosleep() may have a granularity of around
** 10ms. If it is too big then the transfer speed will wax and wane a
** bit but be more accurate in the long run. Not sure what the best
** value is.
**
** bytes is no. of bytes waiting to be transferred. rate is bytes/sec
** ------------------------------------------------------------- */
#define ALLOW_DISCREPANCY 0.5
void bwlimit(int bytes, int rate)
{
#ifdef HAVE_NANOSLEEP
	static struct timeval last = { 0, 0 };
	static int bytecnt = 0;
	struct timeval now;
	double actualtime, mintime;

	if(!last.tv_sec) {
		gettimeofday(&last, NULL);
		return;
	}
	bytecnt += bytes;
	gettimeofday(&now, NULL);

	actualtime = (now.tv_sec - last.tv_sec) +
		(double) (now.tv_usec - last.tv_usec) / (double) 1000000;
	mintime = (double) bytecnt / (double) rate;

	if(actualtime < mintime) {
		struct timespec ts;
		double sleep_time = mintime - actualtime;

		if(sleep_time < ALLOW_DISCREPANCY)
			return;

		ts.tv_sec = (time_t) sleep_time;
		ts.tv_nsec = (long) ((sleep_time - ts.tv_sec) *
				     (double) 1000000000);
		nanosleep(&ts, &ts);

		gettimeofday(&last, NULL);
		bytecnt = 0;
		debug("|");
	} else {
		gettimeofday(&last, NULL);
		bytecnt = 0;
	}
#endif
}

/* ------------------------------------------------------------- **
** Close client data socket, and if there is nothing left to flush
** close the other one too. With downloads we only come here if the
** client aborted - we need to abort virus scanning.
** ------------------------------------------------------------- */
void closecd(void)
{
	write_log(VERBOSE, "Closing client data connection");
	info->state = NEITHER;
	rclose(&info->client_data.fd);
	if(sstr_len(info->server_data.buf) == 0) {
		write_log(VERBOSE, "Closing server data connection");
		ssl_shutdown(&info->ssl_sd);
		rclose(&info->server_data.fd);
		vscan_abort();
		cache_close_data();
	}
	xfer_log();
}

/* ------------------------------------------------------------- **
** Close data socket, and if there is nothing left to flush close the
** other one too.
** ------------------------------------------------------------- */
void closesd(void)
{
	write_log(VERBOSE, "Closing server data connection");

	ssl_shutdown(&info->ssl_sd);
	rclose(&info->server_data.fd);
	info->state = NEITHER;

	vscan_end();
	cache_close_data();

	if(sstr_len(info->client_data.buf) == 0) {
		write_log(VERBOSE, "Closing client data connection");
		rclose(&info->client_data.fd);
	}
	xfer_log();
}
