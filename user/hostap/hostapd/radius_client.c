/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / RADIUS client
 * Copyright (c) 2002-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include "hostapd.h"
#include "radius.h"
#include "radius_client.h"
#include "eloop.h"

/* Defaults for RADIUS retransmit values (exponential backoff) */
#define RADIUS_CLIENT_FIRST_WAIT 1 /* seconds */
#define RADIUS_CLIENT_MAX_WAIT 120 /* seconds */
#define RADIUS_CLIENT_MAX_RETRIES 10 /* maximum number of retransmit attempts
				      * before entry is removed from retransmit
				      * list */
#define RADIUS_CLIENT_MAX_ENTRIES 30 /* maximum number of entries in retransmit
				      * list (oldest will be removed, if this
				      * limit is exceeded) */
#define RADIUS_CLIENT_NUM_FAILOVER 4 /* try to change RADIUS server after this
				      * many failed retry attempts */



static int
radius_change_server(hostapd *hapd, struct hostapd_radius_server *nserv,
		     struct hostapd_radius_server *oserv,
		     int sock, int auth);
static int radius_client_init_acct(hostapd *hapd);
static int radius_client_init_auth(hostapd *hapd);


static void radius_client_msg_free(struct radius_msg_list *req)
{
	radius_msg_free(req->msg);
	free(req->msg);
	free(req);
}


int radius_client_register(hostapd *hapd, RadiusType msg_type,
			   RadiusRxResult (*handler)(hostapd *hapd,
						     struct radius_msg *msg,
						     struct radius_msg *req,
						     u8 *shared_secret,
						     size_t shared_secret_len,
						     void *data),
			   void *data)
{
	struct radius_rx_handler **handlers, *newh;
	size_t *num;

	if (msg_type == RADIUS_ACCT) {
		handlers = &hapd->radius->acct_handlers;
		num = &hapd->radius->num_acct_handlers;
	} else {
		handlers = &hapd->radius->auth_handlers;
		num = &hapd->radius->num_auth_handlers;
	}

	newh = (struct radius_rx_handler *)
		realloc(*handlers,
			(*num + 1) * sizeof(struct radius_rx_handler));
	if (newh == NULL)
		return -1;

	newh[*num].handler = handler;
	newh[*num].data = data;
	(*num)++;
	*handlers = newh;

	return 0;
}


static void radius_client_handle_send_error(struct hostapd_data *hapd, int s,
					    RadiusType msg_type)
{
	int _errno = errno;
	perror("send[RADIUS]");
	if (_errno == ENOTCONN || _errno == EDESTADDRREQ || _errno == EINVAL) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_INFO,
			       "Send failed - maybe interface status changed -"
			       " try to connect again");
		eloop_unregister_read_sock(s);
		close(s);
		if (msg_type == RADIUS_ACCT || msg_type == RADIUS_ACCT_INTERIM)
			radius_client_init_acct(hapd);
		else
			radius_client_init_auth(hapd);
	}
}


static int radius_client_retransmit(hostapd *hapd,
				    struct radius_msg_list *entry, time_t now)
{
	int s;

	if (entry->msg_type == RADIUS_ACCT ||
	    entry->msg_type == RADIUS_ACCT_INTERIM)
		s = hapd->radius->acct_serv_sock;
	else
		s = hapd->radius->auth_serv_sock;

	/* retransmit; remove entry if too many attempts */
	entry->attempts++;
	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL, "Resending RADIUS message (id=%d)"
		      "\n", entry->msg->hdr->identifier);

	if (send(s, entry->msg->buf, entry->msg->buf_used, 0) < 0)
		radius_client_handle_send_error(hapd, s, entry->msg_type);

	entry->next_try = now + entry->next_wait;
	entry->next_wait *= 2;
	if (entry->next_wait > RADIUS_CLIENT_MAX_WAIT)
		entry->next_wait = RADIUS_CLIENT_MAX_WAIT;
	if (entry->attempts >= RADIUS_CLIENT_MAX_RETRIES) {
		printf("Removing un-ACKed RADIUS message due to too many "
		       "failed retransmit attempts\n");
		return 1;
	}

	return 0;
}


static void radius_client_timer(void *eloop_ctx, void *timeout_ctx)
{
	hostapd *hapd = eloop_ctx;
	time_t now, first;
	struct radius_msg_list *entry, *prev, *tmp;
	int auth_failover = 0, acct_failover = 0;

	entry = hapd->radius->msgs;
	if (!entry)
		return;

	time(&now);
	first = 0;

	prev = NULL;
	while (entry) {
		if (now >= entry->next_try &&
		    radius_client_retransmit(hapd, entry, now)) {
			if (prev)
				prev->next = entry->next;
			else
				hapd->radius->msgs = entry->next;

			tmp = entry;
			entry = entry->next;
			radius_client_msg_free(tmp);
			hapd->radius->num_msgs--;
			continue;
		}

		if (entry->attempts > RADIUS_CLIENT_NUM_FAILOVER) {
			if (entry->msg_type == RADIUS_ACCT ||
			    entry->msg_type == RADIUS_ACCT_INTERIM)
				acct_failover++;
			else
				auth_failover++;
		}

		if (first == 0 || entry->next_try < first)
			first = entry->next_try;

		prev = entry;
		entry = entry->next;
	}

	if (hapd->radius->msgs) {
		if (first < now)
			first = now;
		eloop_register_timeout(first - now, 0,
				       radius_client_timer, hapd, NULL);
	}

	if (auth_failover && hapd->conf->num_auth_servers > 1) {
		struct hostapd_radius_server *next, *old;
		old = hapd->conf->auth_server;
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_NOTICE,
			       "No response from Authentication server "
			       "%s:%d - failover",
			       inet_ntoa(old->addr), old->port);

		next = old + 1;
		if (next > &(hapd->conf->auth_servers
			     [hapd->conf->num_auth_servers - 1]))
			next = hapd->conf->auth_servers;
		hapd->conf->auth_server = next;
		radius_change_server(hapd, next, old,
				     hapd->radius->auth_serv_sock, 1);
	}

	if (acct_failover && hapd->conf->num_acct_servers > 1) {
		struct hostapd_radius_server *next, *old;
		old = hapd->conf->acct_server;
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_NOTICE,
			       "No response from Accounting server "
			       "%s:%d - failover",
			       inet_ntoa(old->addr), old->port);
		next = old + 1;
		if (next > &hapd->conf->acct_servers
		    [hapd->conf->num_acct_servers - 1])
			next = hapd->conf->acct_servers;
		hapd->conf->acct_server = next;
		radius_change_server(hapd, next, old,
				     hapd->radius->acct_serv_sock, 0);
	}
}


static void radius_client_list_add(hostapd *hapd, struct radius_msg *msg,
				   RadiusType msg_type, u8 *shared_secret,
				   size_t shared_secret_len, u8 *addr)
{
	struct radius_msg_list *entry, *prev;

	if (eloop_terminated()) {
		/* No point in adding entries to retransmit queue since event
		 * loop has already been terminated. */
		radius_msg_free(msg);
		free(msg);
		return;
	}

	entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		printf("Failed to add RADIUS packet into retransmit list\n");
		radius_msg_free(msg);
		free(msg);
		return;
	}

	memset(entry, 0, sizeof(*entry));
	if (addr)
		memcpy(entry->addr, addr, ETH_ALEN);
	entry->msg = msg;
	entry->msg_type = msg_type;
	entry->shared_secret = shared_secret;
	entry->shared_secret_len = shared_secret_len;
	time(&entry->first_try);
	entry->next_try = entry->first_try + RADIUS_CLIENT_FIRST_WAIT;
	entry->attempts = 1;
	entry->next_wait = RADIUS_CLIENT_FIRST_WAIT * 2;

	if (!hapd->radius->msgs)
		eloop_register_timeout(RADIUS_CLIENT_FIRST_WAIT, 0,
				       radius_client_timer, hapd, NULL);

	entry->next = hapd->radius->msgs;
	hapd->radius->msgs = entry;

	if (hapd->radius->num_msgs >= RADIUS_CLIENT_MAX_ENTRIES) {
		printf("Removing the oldest un-ACKed RADIUS packet due to "
		       "retransmit list limits.\n");
		prev = NULL;
		while (entry->next) {
			prev = entry;
			entry = entry->next;
		}
		if (prev) {
			prev->next = NULL;
			radius_client_msg_free(entry);
		}
	} else
		hapd->radius->num_msgs++;
}


static void radius_client_list_del(struct hostapd_data *hapd,
				   RadiusType msg_type, u8 *addr)
{
	struct radius_msg_list *entry, *prev, *tmp;

	if (addr == NULL)
		return;

	entry = hapd->radius->msgs;
	prev = NULL;
	while (entry) {
		if (entry->msg_type == msg_type &&
		    memcmp(entry->addr, addr, ETH_ALEN) == 0) {
			if (prev)
				prev->next = entry->next;
			else
				hapd->radius->msgs = entry->next;
			tmp = entry;
			entry = entry->next;
			HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
				      "Removing matching RADIUS message for "
				      MACSTR "\n", MAC2STR(addr));
			radius_client_msg_free(tmp);
			hapd->radius->num_msgs--;
			continue;
		}
		prev = entry;
		entry = entry->next;
	}
}


int radius_client_send(hostapd *hapd, struct radius_msg *msg,
		       RadiusType msg_type, u8 *addr)
{
	u8 *shared_secret;
	size_t shared_secret_len;
	char *name;
	int s, res;

	if (msg_type == RADIUS_ACCT_INTERIM) {
		/* Remove any pending interim acct update for the same STA. */
		radius_client_list_del(hapd, msg_type, addr);
	}

	if (msg_type == RADIUS_ACCT || msg_type == RADIUS_ACCT_INTERIM) {
		shared_secret = hapd->conf->acct_server->shared_secret;
		shared_secret_len = hapd->conf->acct_server->shared_secret_len;
		radius_msg_finish_acct(msg, shared_secret, shared_secret_len);
		name = "accounting";
		s = hapd->radius->acct_serv_sock;
	} else {
		shared_secret = hapd->conf->auth_server->shared_secret;
		shared_secret_len = hapd->conf->auth_server->shared_secret_len;
		radius_msg_finish(msg, shared_secret, shared_secret_len);
		name = "authentication";
		s = hapd->radius->auth_serv_sock;
	}

	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
		      "Sending RADIUS message to %s server\n", name);
	if (HOSTAPD_DEBUG_COND(HOSTAPD_DEBUG_MSGDUMPS))
		radius_msg_dump(msg);

	res = send(s, msg->buf, msg->buf_used, 0);
	if (res < 0)
		radius_client_handle_send_error(hapd, s, msg_type);

	radius_client_list_add(hapd, msg, msg_type, shared_secret,
			       shared_secret_len, addr);

	return res;
}


static void radius_client_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	hostapd *hapd = (hostapd *) eloop_ctx;
	RadiusType msg_type = (RadiusType) sock_ctx;
	int len, i;
	unsigned char buf[3000];
	struct radius_msg *msg;
	struct radius_rx_handler *handlers;
	size_t num_handlers;
	struct radius_msg_list *req, *prev_req;

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("recv[RADIUS]");
		return;
	}
	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
		      "Received %d bytes from RADIUS server\n", len);
	if (len == sizeof(buf)) {
		printf("Possibly too long UDP frame for our buffer - "
		       "dropping it\n");
		return;
	}

	msg = radius_msg_parse(buf, len);
	if (msg == NULL) {
		printf("Parsing incoming RADIUS frame failed\n");
		return;
	}

	HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
		      "Received RADIUS message\n");
	if (HOSTAPD_DEBUG_COND(HOSTAPD_DEBUG_MSGDUMPS))
		radius_msg_dump(msg);

	if (msg_type == RADIUS_ACCT) {
		handlers = hapd->radius->acct_handlers;
		num_handlers = hapd->radius->num_acct_handlers;
	} else {
		handlers = hapd->radius->auth_handlers;
		num_handlers = hapd->radius->num_auth_handlers;
	}

	prev_req = NULL;
	req = hapd->radius->msgs;
	while (req) {
		/* TODO: also match by src addr:port of the packet when using
		 * alternative RADIUS servers (?) */
		if ((req->msg_type == msg_type ||
		     (req->msg_type == RADIUS_ACCT_INTERIM &&
		      msg_type == RADIUS_ACCT)) &&
		    req->msg->hdr->identifier == msg->hdr->identifier)
			break;

		prev_req = req;
		req = req->next;
	}

	if (req == NULL) {
		HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
			      "No matching RADIUS request found (type=%d "
			      "id=%d) - dropping packet\n",
			      msg_type, msg->hdr->identifier);
		goto fail;
	}

	/* Remove ACKed RADIUS packet from retransmit list */
	if (prev_req)
		prev_req->next = req->next;
	else
		hapd->radius->msgs = req->next;
	hapd->radius->num_msgs--;

	for (i = 0; i < num_handlers; i++) {
		RadiusRxResult res;
		res = handlers[i].handler(hapd, msg, req->msg,
					  req->shared_secret,
					  req->shared_secret_len,
					  handlers[i].data);
		switch (res) {
		case RADIUS_RX_PROCESSED:
			radius_msg_free(msg);
			free(msg);
			/* continue */
		case RADIUS_RX_QUEUED:
			radius_client_msg_free(req);
			return;
		case RADIUS_RX_UNKNOWN:
			/* continue with next handler */
			break;
		}
	}

	printf("No RADIUS RX handler found (type=%d code=%d id=%d) - dropping "
	       "packet\n", msg_type, msg->hdr->code, msg->hdr->identifier);
	radius_client_msg_free(req);

 fail:
	radius_msg_free(msg);
	free(msg);
}


u8 radius_client_get_id(hostapd *hapd)
{
	struct radius_msg_list *entry, *prev, *remove;
	u8 id = hapd->radius->next_radius_identifier++;

	/* remove entries with matching id from retransmit list to avoid
	 * using new reply from the RADIUS server with an old request */
	entry = hapd->radius->msgs;
	prev = NULL;
	while (entry) {
		if (entry->msg->hdr->identifier == id) {
			HOSTAPD_DEBUG(HOSTAPD_DEBUG_MINIMAL,
				      "Removing pending RADIUS message, since "
				      "its id (%d) is reused\n", id);
			if (prev)
				prev->next = entry->next;
			else
				hapd->radius->msgs = entry->next;
			remove = entry;
		} else
			remove = NULL;
		prev = entry;
		entry = entry->next;

		if (remove)
			radius_client_msg_free(remove);
	}

	return id;
}


void radius_client_flush(hostapd *hapd)
{
	struct radius_msg_list *entry, *prev;

	if (!hapd->radius)
		return;

	eloop_cancel_timeout(radius_client_timer, hapd, NULL);

	entry = hapd->radius->msgs;
	hapd->radius->msgs = NULL;
	hapd->radius->num_msgs = 0;
	while (entry) {
		prev = entry;
		entry = entry->next;
		radius_client_msg_free(prev);
	}
}


static int
radius_change_server(hostapd *hapd, struct hostapd_radius_server *nserv,
		     struct hostapd_radius_server *oserv,
		     int sock, int auth)
{
	struct sockaddr_in serv;

	hostapd_logger(hapd, NULL, HOSTAPD_MODULE_RADIUS, HOSTAPD_LEVEL_INFO,
		       "%s server %s:%d",
		       auth ? "Authentication" : "Accounting",
		       inet_ntoa(nserv->addr), nserv->port);

	if (!oserv || nserv->shared_secret_len != oserv->shared_secret_len ||
	    memcmp(nserv->shared_secret, oserv->shared_secret,
		   nserv->shared_secret_len) != 0) {
		/* Pending RADIUS packets used different shared
		 * secret, so they would need to be modified. Could
		 * update all message authenticators and
		 * User-Passwords, etc. and retry with new server. For
		 * now, just drop all pending packets. */
		radius_client_flush(hapd);
	} else {
		/* Reset retry counters for the new server */
		struct radius_msg_list *entry;
		entry = hapd->radius->msgs;
		while (entry) {
			entry->next_try = entry->first_try +
				RADIUS_CLIENT_FIRST_WAIT;
			entry->attempts = 0;
			entry->next_wait = RADIUS_CLIENT_FIRST_WAIT * 2;
			entry = entry->next;
		}
		if (hapd->radius->msgs) {
			eloop_cancel_timeout(radius_client_timer, hapd, NULL);
			eloop_register_timeout(RADIUS_CLIENT_FIRST_WAIT, 0,
					       radius_client_timer, hapd,
					       NULL);
		}
	}

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = nserv->addr.s_addr;
	serv.sin_port = htons(nserv->port);

	if (connect(sock, (struct sockaddr *) &serv, sizeof(serv)) < 0) {
		perror("connect[radius]");
		return -1;
	}

	return 0;
}


static void radius_retry_primary_timer(void *eloop_ctx, void *timeout_ctx)
{
	hostapd *hapd = eloop_ctx;
	struct hostapd_radius_server *oserv;

	if (hapd->radius->auth_serv_sock >= 0 && hapd->conf->auth_servers &&
	    hapd->conf->auth_server != hapd->conf->auth_servers) {
		oserv = hapd->conf->auth_server;
		hapd->conf->auth_server = hapd->conf->auth_servers;
		radius_change_server(hapd, hapd->conf->auth_server, oserv,
				     hapd->radius->auth_serv_sock, 1);
	}

	if (hapd->radius->acct_serv_sock >= 0 && hapd->conf->acct_servers &&
	    hapd->conf->acct_server != hapd->conf->acct_servers) {
		oserv = hapd->conf->acct_server;
		hapd->conf->acct_server = hapd->conf->acct_servers;
		radius_change_server(hapd, hapd->conf->acct_server, oserv,
				     hapd->radius->acct_serv_sock, 0);
	}

	if (hapd->conf->radius_retry_primary_interval)
		eloop_register_timeout(hapd->conf->
				       radius_retry_primary_interval, 0,
				       radius_retry_primary_timer, hapd, NULL);
}


static int radius_client_init_auth(hostapd *hapd)
{
	hapd->radius->auth_serv_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (hapd->radius->auth_serv_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	radius_change_server(hapd, hapd->conf->auth_server, NULL,
			     hapd->radius->auth_serv_sock, 1);

	if (eloop_register_read_sock(hapd->radius->auth_serv_sock,
				     radius_client_receive, hapd,
				     (void *) RADIUS_AUTH)) {
		printf("Could not register read socket for authentication "
		       "server\n");
		return -1;
	}

	return 0;
}


static int radius_client_init_acct(hostapd *hapd)
{
	hapd->radius->acct_serv_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (hapd->radius->acct_serv_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		return -1;
	}

	radius_change_server(hapd, hapd->conf->acct_server, NULL,
			     hapd->radius->acct_serv_sock, 0);

	if (eloop_register_read_sock(hapd->radius->acct_serv_sock,
				     radius_client_receive, hapd,
				     (void *) RADIUS_ACCT)) {
		printf("Could not register read socket for accounting "
		       "server\n");
		return -1;
	}

	return 0;
}


int radius_client_init(hostapd *hapd)
{
	hapd->radius = malloc(sizeof(struct radius_client_data));
	if (hapd->radius == NULL)
		return -1;

	memset(hapd->radius, 0, sizeof(struct radius_client_data));
	hapd->radius->auth_serv_sock = hapd->radius->acct_serv_sock = -1;

	if (hapd->conf->auth_server && radius_client_init_auth(hapd))
		return -1;

	if (hapd->conf->acct_server && radius_client_init_acct(hapd))
		return -1;

	if (hapd->conf->radius_retry_primary_interval)
		eloop_register_timeout(hapd->conf->
				       radius_retry_primary_interval, 0,
				       radius_retry_primary_timer, hapd, NULL);

	return 0;
}


void radius_client_deinit(hostapd *hapd)
{
	if (!hapd->radius)
		return;

	eloop_cancel_timeout(radius_retry_primary_timer, hapd, NULL);

	radius_client_flush(hapd);
	free(hapd->radius->auth_handlers);
	free(hapd->radius->acct_handlers);
	free(hapd->radius);
	hapd->radius = NULL;
}


void radius_client_flush_auth(struct hostapd_data *hapd, u8 *addr)
{
	struct radius_msg_list *entry, *prev, *tmp;

	prev = NULL;
	entry = hapd->radius->msgs;
	while (entry) {
		if (entry->msg_type == RADIUS_AUTH &&
		    memcmp(entry->addr, addr, ETH_ALEN) == 0) {
			hostapd_logger(hapd, addr, HOSTAPD_MODULE_RADIUS,
				       HOSTAPD_LEVEL_DEBUG,
				       "Removing pending RADIUS authentication"
				       " message for removed client");

			if (prev)
				prev->next = entry->next;
			else
				hapd->radius->msgs = entry->next;

			tmp = entry;
			entry = entry->next;
			radius_client_msg_free(tmp);
			hapd->radius->num_msgs--;
			continue;
		}

		prev = entry;
		entry = entry->next;
	}
}
