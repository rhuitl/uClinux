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

  transdata.c -- System independent code for transparently proxying
                 data connections
  
  ***************************************/

#include <signal.h>
#include <sys/un.h>

#include "common.h"
#include "transdata.h"

static void serve_requests(int listen);
static int td_listenfd;
static int td_reqfd;


void transdata_newsocketpair()
{
	int fds[2];

	if(!config.transdata)
		return;
	if(config.inetd)
		write_log(IMPORT, "Transdata not recommended when running "
			  "out of inetd");
	if(socketpair(PF_UNIX, SOCK_STREAM, 0, fds) == -1) {
		config.transdata = FALSE;
		return;
	}
	td_reqfd = fds[0];
	send_fd(td_listenfd, fds[1], 'N');
	close(fds[1]);
}

/* ------------------------------------------------------------- **
**  Make a connection to dest which appears to have come from src. If
**  we can't then we just make the connection anyway.
**  ------------------------------------------------------------- */
int transp_connect(struct sockaddr_in dest, struct sockaddr_in src)
{
	struct fd_request req;
	int ret;

	write_log(VERBOSE, " TD: transp_connect(). Setting up req structure");
	req.type = CONNECT;
	req.local = src;
	req.remote = dest;
	req.ports[0] = config.actvports[0];
	req.ports[1] = config.actvports[1];

	write_log(VERBOSE, " TD: transp_connect(). Sending fd request.");
	send(td_reqfd, &req, sizeof(req), 0);
	recv_fd(td_reqfd, &ret);
	write_log(VERBOSE, " TD: transp_connect(). Received fd.");
	return ret;
}

/* ------------------------------------------------------------- **
**  Listen in order to intercept any connections that are headed for
**  realdest, on a port from the range specified by use. You must call
**  il_free at some point before exiting to remove the iptables rule
**  this function adds under 2.4. Current implementation of il_free
**  means you can only have one intercept_listening socket per
**  process.
**  ------------------------------------------------------------- */
int intercept_listen(struct sockaddr_in intercept,
		     struct sockaddr_in listen_on, int portrange[2])
{
	struct fd_request req;
	int ret;

	write_log(VERBOSE,
		  " TD: intercept_listen(). Setting up req structure");
	req.type = LISTEN;
	req.local = listen_on;
	req.remote = intercept;
	req.ports[0] = portrange[0];
	req.ports[1] = portrange[1];

	write_log(VERBOSE, " TD: intercept_listen(). Sending fd request.");
	send(td_reqfd, &req, sizeof(req), 0);
	recv_fd(td_reqfd, &ret);
	write_log(VERBOSE, " TD: intercept_listen(). Received fd.");

	return ret;
}

/* ------------------------------------------------------------- **
**  Call this to remove the iptables rule introduced by a previous
**  intercept_listen.
**  ------------------------------------------------------------- */
int il_free(void)
{
	struct fd_request req;

	if(!config.transdata)
		return 0;
	req.type = UNLISTEN;
	send(td_reqfd, &req, sizeof(req), 0);
	return 0;
}

void transdata_flush(void)
{
	if(!config.transdata)
		return;
	send(td_listenfd, "F", 1, 0);
}

/*******************************************************************
 *  Code below here runs as root in a separate process. It accepts
 *  connections from the socket, and then returns fds back across the
 *  connections as and when requested.
 ******************************************************************/

void transdata_setup()
{
	int fds[2];

	if(!config.transdata)
		return;
	if(kernel_transdata_setup() == -1) {
		write_log(ERROR, "Failed to setup transparent data. "
			  "Will not do it");
		config.transdata = FALSE;
		return;
	}
	if(socketpair(PF_UNIX, SOCK_STREAM, 0, fds) == -1) {
		config.transdata = FALSE;
		return;
	}

	switch ((tdatapid = fork())) {
	case -1:
		tdatapid = 0;
		config.transdata = FALSE;
		return;
	case 0:
		signal(SIGHUP, SIG_IGN);
		write_log(VERBOSE, "TDS: Running transdata server");
		break;
	default:
		close(fds[1]);
		td_listenfd = fds[0];
		return;
	}
	close(fds[0]);

	/*Drop privileges while we can */
	setgid(config.gid);
	setgid(config.gid);
	seteuid(config.uid);
	serve_requests(fds[1]);

	exit(0);
}

struct td_client {
	int fd;
	struct fd_request req;
	struct td_client *next;
};

void serve_client(struct td_client *p);
void purge_clients(void);

struct td_client *head = NULL;

static void serve_requests(int listen)
{
	int fd;
	struct td_client *p;

	do {
		fd_set reads;
		FD_ZERO(&reads);
		for(p = head; p != NULL; p = p->next)
			FD_SET(p->fd, &reads);
		FD_SET(listen, &reads);

		select(FD_SETSIZE, &reads, NULL, NULL, NULL);
		if(FD_ISSET(listen, &reads)) {
			switch (recv_fd(listen, &fd)) {
			case 0:
				write_log(IMPORT, "Transdata exiting");
				exit(0);
			case 'F':
				kernel_td_flush();
				break;
			case 'N':
				write_log(VERBOSE,
					  "TDS: Accepted new client with fd=%d",
					  fd);
				p = malloc(sizeof(struct td_client));
				p->next = head;
				p->fd = fd;
				p->req.type = NONE;
				head = p;
				break;
			}
		}
		for(p = head; p != NULL; p = p->next) {
			if(FD_ISSET(p->fd, &reads)) {
				if(p->req.type == LISTEN) {
					kernel_td_unlisten(p->req);
					p->req.type = NONE;
				}
				if(recv(fd, &p->req, sizeof(p->req),
					MSG_WAITALL) <= 1) {
					write_log(VERBOSE,
						  "TDS: Closing fd %d",
						  p->fd);
					close(p->fd);
					p->fd = -1;
					continue;
				}
				serve_client(p);
			}
		}
		purge_clients();
	} while(TRUE);
}

void serve_client(struct td_client *p)
{
	int ret;
	switch (p->req.type) {
	case CONNECT:
		ret = kernel_td_connect(p->req);
		break;
	case LISTEN:
		ret = kernel_td_listen(p->req);
		break;
	case UNLISTEN:
		/*Don't need to do anything - kernel_td_unlisten()
		   already called from serve_requests before dealing
		   with this one. */
		return;
	default:
		return;
	}
	write_log(VERBOSE, "TDS: Sending fd %d", ret);
	if(ret == -1)
		write(p->fd, "X", 1);
	else
		send_fd(p->fd, ret, 'x');
	close(ret);
}

void purge_clients(void)
{
	struct td_client *p, *pp;

	while(head && head->fd == -1) {
		pp = head;
		head = pp->next;
		free(pp);
	}
	for(p = head; p && p->next; p = p->next) {
		if(p->next->fd == -1) {
			pp = p->next;
			p->next = p->next->next;
			free(pp);
		}
	}
}
