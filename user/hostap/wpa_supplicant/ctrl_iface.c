/*
 * WPA Supplicant / UNIX domain socket -based control interface
 * Copyright (c) 2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>

#include "common.h"
#include "eloop.h"
#include "wpa.h"
#include "wpa_supplicant.h"
#include "config.h"
#include "eapol_sm.h"
#include "wpa_supplicant_i.h"
#include "ctrl_iface.h"
#include "l2_packet.h"


struct wpa_ctrl_dst {
	struct wpa_ctrl_dst *next;
	struct sockaddr_un addr;
	socklen_t addrlen;
	int debug_level;
	int errors;
};


static const char * wpa_cipher_txt(int cipher)
{
	switch (cipher) {
	case WPA_CIPHER_NONE:
		return "NONE";
	case WPA_CIPHER_WEP40:
		return "WEP-40";
	case WPA_CIPHER_WEP104:
		return "WEP-104";
	case WPA_CIPHER_TKIP:
		return "TKIP";
	case WPA_CIPHER_CCMP:
		return "CCMP";
	default:
		return "UNKNOWN";
	}
}


static const char * wpa_key_mgmt_txt(int key_mgmt)
{
	switch (key_mgmt) {
	case WPA_KEY_MGMT_IEEE8021X:
		return "WPA/IEEE 802.1X/EAP";
	case WPA_KEY_MGMT_PSK:
		return "WPA-PSK";
	case WPA_KEY_MGMT_NONE:
		return "NONE";
	case WPA_KEY_MGMT_IEEE8021X_NO_WPA:
		return "IEEE 802.1X (no WPA)";
	default:
		return "UNKNOWN";
	}
}


static const char * wpa_state_txt(int state)
{
	switch (state) {
	case WPA_DISCONNECTED:
		return "DISCONNECTED";
	case WPA_SCANNING:
		return "SCANNING";
	case WPA_ASSOCIATING:
		return "ASSOCIATING";
	case WPA_ASSOCIATED:
		return "ASSOCIATED";
	case WPA_4WAY_HANDSHAKE:
		return "4WAY_HANDSHAKE";
	case WPA_GROUP_HANDSHAKE:
		return "GROUP_HANDSHAKE";
	case WPA_COMPLETED:
		return "COMPLETED";
	default:
		return "UNKNOWN";
	}
}


static int wpa_supplicant_ctrl_iface_set(struct wpa_supplicant *wpa_s,
					 char *cmd)
{
	char *value;

	value = strchr(cmd, ' ');
	if (value == NULL)
		return -1;
	*value++ = '\0';

	wpa_printf(MSG_DEBUG, "CTRL_IFACE SET '%s'='%s'", cmd, value);
	if (strcasecmp(cmd, "EAPOL::heldPeriod") == 0) {
		eapol_sm_configure(wpa_s->eapol,
				   atoi(value), -1, -1, -1);
	} else if (strcasecmp(cmd, "EAPOL::authPeriod") == 0) {
		eapol_sm_configure(wpa_s->eapol,
				   -1, atoi(value), -1, -1);
	} else if (strcasecmp(cmd, "EAPOL::startPeriod") == 0) {
		eapol_sm_configure(wpa_s->eapol,
				   -1, -1, atoi(value), -1);
	} else if (strcasecmp(cmd, "EAPOL::maxStart") == 0) {
		eapol_sm_configure(wpa_s->eapol,
				   -1, -1, -1, atoi(value));
	} else
		return -1;
	return 0;
}


static int wpa_supplicant_ctrl_iface_preauth(struct wpa_supplicant *wpa_s,
					     char *addr)
{
	u8 bssid[ETH_ALEN];

	if (hwaddr_aton(addr, bssid)) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE PREAUTH: invalid address "
			   "'%s'", addr);
		return -1;
	}

	wpa_printf(MSG_DEBUG, "CTRL_IFACE PREAUTH " MACSTR, MAC2STR(bssid));
	rsn_preauth_deinit(wpa_s);
	if (rsn_preauth_init(wpa_s, bssid))
		return -1;

	return 0;
}


static int wpa_supplicant_ctrl_iface_attach(struct wpa_supplicant *wpa_s,
					    struct sockaddr_un *from,
					    socklen_t fromlen)
{
	struct wpa_ctrl_dst *dst;

	dst = malloc(sizeof(*dst));
	if (dst == NULL)
		return -1;
	memset(dst, 0, sizeof(*dst));
	memcpy(&dst->addr, from, sizeof(struct sockaddr_un));
	dst->addrlen = fromlen;
	dst->debug_level = MSG_INFO;
	dst->next = wpa_s->ctrl_dst;
	wpa_s->ctrl_dst = dst;
	wpa_hexdump(MSG_DEBUG, "CTRL_IFACE monitor attached",
		    from->sun_path, fromlen);
	return 0;
}


static int wpa_supplicant_ctrl_iface_detach(struct wpa_supplicant *wpa_s,
					    struct sockaddr_un *from,
					    socklen_t fromlen)
{
	struct wpa_ctrl_dst *dst, *prev = NULL;

	dst = wpa_s->ctrl_dst;
	while (dst) {
		if (fromlen == dst->addrlen &&
		    memcmp(from->sun_path, dst->addr.sun_path, fromlen) == 0) {
			if (prev == NULL)
				wpa_s->ctrl_dst = dst->next;
			else
				prev->next = dst->next;
			free(dst);
			wpa_hexdump(MSG_DEBUG, "CTRL_IFACE monitor detached",
				    from->sun_path, fromlen);
			return 0;
		}
		prev = dst;
		dst = dst->next;
	}
	return -1;
}


static int wpa_supplicant_ctrl_iface_level(struct wpa_supplicant *wpa_s,
					   struct sockaddr_un *from,
					   socklen_t fromlen,
					   char *level)
{
	struct wpa_ctrl_dst *dst;

	wpa_printf(MSG_DEBUG, "CTRL_IFACE LEVEL %s", level);

	dst = wpa_s->ctrl_dst;
	while (dst) {
		if (fromlen == dst->addrlen &&
		    memcmp(from->sun_path, dst->addr.sun_path, fromlen) == 0) {
			wpa_hexdump(MSG_DEBUG, "CTRL_IFACE changed monitor "
				    "level", from->sun_path, fromlen);
			dst->debug_level = atoi(level);
			return 0;
		}
		dst = dst->next;
	}

	return -1;
}


static int wpa_supplicant_ctrl_iface_ctrl_rsp(struct wpa_supplicant *wpa_s,
					      char *rsp)
{
	char *pos, *id_pos;
	int id;
	struct wpa_ssid *ssid;

	pos = strchr(rsp, '-');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';
	id_pos = pos;
	pos = strchr(pos, ':');
	if (pos == NULL)
		return -1;
	*pos++ = '\0';
	id = atoi(id_pos);
	wpa_printf(MSG_DEBUG, "CTRL_IFACE: field=%s id=%d value='%s'",
		   rsp, id, pos);

	ssid = wpa_s->conf->ssid;
	while (ssid) {
		if (id == ssid->id)
			break;
		ssid = ssid->next;
	}

	if (ssid == NULL) {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Could not find SSID id=%d "
			   "to update", id);
		return -1;
	}

	if (strcmp(rsp, "IDENTITY") == 0) {
		free(ssid->identity);
		ssid->identity = strdup(pos);
		ssid->identity_len = strlen(pos);
		ssid->pending_req_identity = 0;
		if (ssid == wpa_s->current_ssid)
			wpa_s->reassociate = 1;
	} else if (strcmp(rsp, "PASSWORD") == 0) {
		free(ssid->password);
		ssid->password = strdup(pos);
		ssid->password_len = strlen(pos);
		ssid->pending_req_password = 0;
		if (ssid == wpa_s->current_ssid)
			wpa_s->reassociate = 1;
	} else if (strcmp(rsp, "OTP") == 0) {
		free(ssid->otp);
		ssid->otp = strdup(pos);
		ssid->otp_len = strlen(pos);
		free(ssid->pending_req_otp);
		ssid->pending_req_otp = NULL;
		ssid->pending_req_otp_len = 0;
	} else {
		wpa_printf(MSG_DEBUG, "CTRL_IFACE: Unknown field '%s'", rsp);
		return -1;
	}

	return 0;
}


void wpa_supplicant_ctrl_iface_receive(int sock, void *eloop_ctx,
				       void *sock_ctx)
{
	struct wpa_supplicant *wpa_s = eloop_ctx;
	u8 buf[256];
	int res;
	struct sockaddr_un from;
	socklen_t fromlen = sizeof(from);
	char *reply, *pos, *end;
	const int reply_size = 2048;
	int reply_len;
	int new_attached = 0, ctrl_rsp = 0;

	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
		       (struct sockaddr *) &from, &fromlen);
	if (res < 0) {
		perror("recvfrom(ctrl_iface)");
		return;
	}
	buf[res] = '\0';
	wpa_hexdump_ascii(MSG_DEBUG, "RX ctrl_iface", buf, res);

	reply = malloc(reply_size);
	if (reply == NULL) {
		sendto(sock, "FAIL\n", 5, 0, (struct sockaddr *) &from,
		       fromlen);
		return;
	}

	memcpy(reply, "OK\n", 3);
	reply_len = 3;

	if (strcmp(buf, "PING") == 0) {
		memcpy(reply, "PONG\n", 5);
		reply_len = 5;
	} else if (strcmp(buf, "MIB") == 0) {
		reply_len = wpa_get_mib(wpa_s, reply, reply_size);
		if (reply_len >= 0) {
			res = eapol_sm_get_mib(wpa_s->eapol, reply + reply_len,
					       reply_size - reply_len);
			if (res < 0)
				reply_len = -1;
			else
				reply_len += res;
		}
	} else if (strcmp(buf, "STATUS") == 0) {
		pos = reply;
		end = reply + reply_size;
		pos += snprintf(pos, end - pos, "bssid=" MACSTR "\n",
				MAC2STR(wpa_s->bssid));
		if (wpa_s->current_ssid) {
			pos += snprintf(
				pos, end - pos, "ssid=%s\n",
				wpa_ssid_txt(wpa_s->current_ssid->ssid,
					     wpa_s->current_ssid->ssid_len));
		}
		pos += snprintf(pos, end - pos,
				"pairwise_cipher=%s\n"
				"group_cipher=%s\n"
				"key_mgmt=%s\n"
				"wpa_state=%s\n",
				wpa_cipher_txt(wpa_s->pairwise_cipher),
				wpa_cipher_txt(wpa_s->group_cipher),
				wpa_key_mgmt_txt(wpa_s->key_mgmt),
				wpa_state_txt(wpa_s->wpa_state));

		res = eapol_sm_get_status(wpa_s->eapol, pos, end - pos);
		if (res < 0)
			reply_len = -1;
		else
			pos += res;

		if (wpa_s->preauth_eapol) {
			pos += snprintf(pos, end - pos, "Pre-authentication "
					"EAPOL state machines:\n");
			res = eapol_sm_get_status(wpa_s->preauth_eapol,
						  pos, end - pos);
			if (res < 0)
				reply_len = -1;
			else
				pos += res;
		}

		if (reply_len >= 0)
			reply_len = pos - reply;
	} else if (strcmp(buf, "PMKSA") == 0) {
		reply_len = pmksa_cache_list(wpa_s, reply, reply_size);
	} else if (strncmp(buf, "SET ", 4) == 0) {
		if (wpa_supplicant_ctrl_iface_set(wpa_s, buf + 4))
			reply_len = -1;
	} else if (strcmp(buf, "LOGON") == 0) {
		eapol_sm_notify_logoff(wpa_s->eapol, FALSE);
	} else if (strcmp(buf, "LOGOFF") == 0) {
		eapol_sm_notify_logoff(wpa_s->eapol, TRUE);
	} else if (strcmp(buf, "REASSOCIATE") == 0) {
		wpa_s->reassociate = 1;
		wpa_supplicant_req_scan(wpa_s, 0, 0);
	} else if (strncmp(buf, "PREAUTH ", 8) == 0) {
		if (wpa_supplicant_ctrl_iface_preauth(wpa_s, buf + 8))
			reply_len = -1;
	} else if (strcmp(buf, "ATTACH") == 0) {
		if (wpa_supplicant_ctrl_iface_attach(wpa_s, &from, fromlen))
			reply_len = -1;
		else
			new_attached = 1;
	} else if (strcmp(buf, "DETACH") == 0) {
		if (wpa_supplicant_ctrl_iface_detach(wpa_s, &from, fromlen))
			reply_len = -1;
	} else if (strncmp(buf, "LEVEL ", 6) == 0) {
		if (wpa_supplicant_ctrl_iface_level(wpa_s, &from, fromlen,
						    buf + 6))
			reply_len = -1;
	} else if (strncmp(buf, "CTRL-RSP-", 9) == 0) {
		if (wpa_supplicant_ctrl_iface_ctrl_rsp(wpa_s, buf + 9))
			reply_len = -1;
		else
			ctrl_rsp = 1;
	} else if (strcmp(buf, "RECONFIGURE") == 0) {
		if (wpa_supplicant_reload_configuration(wpa_s))
			reply_len = -1;
	} else {
		memcpy(reply, "UNKNOWN COMMAND\n", 16);
		reply_len = 16;
	}

	if (reply_len < 0) {
		memcpy(reply, "FAIL\n", 5);
		reply_len = 5;
	}
	sendto(sock, reply, reply_len, 0, (struct sockaddr *) &from, fromlen);
	free(reply);

	if (new_attached)
		eapol_sm_notify_ctrl_attached(wpa_s->eapol);
	if (ctrl_rsp)
		eapol_sm_notify_ctrl_response(wpa_s->eapol);
}


static char * wpa_supplicant_ctrl_iface_path(struct wpa_supplicant *wpa_s)
{
	char *buf;
	size_t len;

	if (wpa_s->conf->ctrl_interface == NULL)
		return NULL;

	len = strlen(wpa_s->conf->ctrl_interface) + strlen(wpa_s->ifname) + 2;
	buf = malloc(len);
	if (buf == NULL)
		return NULL;

	snprintf(buf, len, "%s/%s",
		 wpa_s->conf->ctrl_interface, wpa_s->ifname);
	return buf;
}


int wpa_supplicant_ctrl_iface_init(struct wpa_supplicant *wpa_s)
{
	struct sockaddr_un addr;
	int s = -1;
	char *fname = NULL;

	wpa_s->ctrl_sock = -1;

	if (wpa_s->conf->ctrl_interface == NULL)
		return 0;

	if (mkdir(wpa_s->conf->ctrl_interface, S_IRWXU | S_IRWXG) < 0) {
		if (errno == EEXIST) {
			wpa_printf(MSG_DEBUG, "Using existing control "
				   "interface directory.");
		} else {
			perror("mkdir[ctrl_interface]");
			goto fail;
		}
	}

	if (chown(wpa_s->conf->ctrl_interface, 0,
		  wpa_s->conf->ctrl_interface_gid) < 0) {
		perror("chown[ctrl_interface]");
		return -1;
	}

	if (strlen(wpa_s->conf->ctrl_interface) + 1 + strlen(wpa_s->ifname) >=
	    sizeof(addr.sun_path))
		goto fail;

	s = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket(PF_UNIX)");
		goto fail;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	fname = wpa_supplicant_ctrl_iface_path(wpa_s);
	if (fname == NULL)
		goto fail;
	strncpy(addr.sun_path, fname, sizeof(addr.sun_path));
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind(PF_UNIX)");
		goto fail;
	}

	if (chown(fname, 0, wpa_s->conf->ctrl_interface_gid) < 0) {
		perror("chown[ctrl_interface/ifname]");
		goto fail;
	}

	if (chmod(fname, S_IRWXU | S_IRWXG) < 0) {
		perror("chmod[ctrl_interface/ifname]");
		goto fail;
	}
	free(fname);

	wpa_s->ctrl_sock = s;
	eloop_register_read_sock(s, wpa_supplicant_ctrl_iface_receive, wpa_s,
				 NULL);

	return 0;

fail:
	if (s >= 0)
		close(s);
	if (fname) {
		unlink(fname);
		free(fname);
	}
	return -1;
}


void wpa_supplicant_ctrl_iface_deinit(struct wpa_supplicant *wpa_s)
{
	struct wpa_ctrl_dst *dst, *prev;

	if (wpa_s->ctrl_sock > -1) {
		char *fname;
		eloop_unregister_read_sock(wpa_s->ctrl_sock);
		close(wpa_s->ctrl_sock);
		wpa_s->ctrl_sock = -1;
		fname = wpa_supplicant_ctrl_iface_path(wpa_s);
		if (fname)
			unlink(fname);
		free(fname);

		if (rmdir(wpa_s->conf->ctrl_interface) < 0) {
			if (errno == ENOTEMPTY) {
				wpa_printf(MSG_DEBUG, "Control interface "
					   "directory not empty - leaving it "
					   "behind");
			} else {
				perror("rmdir[ctrl_interface]");
			}
		}
	}

	dst = wpa_s->ctrl_dst;
	while (dst) {
		prev = dst;
		dst = dst->next;
		free(prev);
	}
}


void wpa_supplicant_ctrl_iface_send(struct wpa_supplicant *wpa_s, int level,
				    char *buf, size_t len)
{
	struct wpa_ctrl_dst *dst, *next;
	struct msghdr msg;
	int idx;
	struct iovec io[2];
	char levelstr[10];

	dst = wpa_s->ctrl_dst;
	if (wpa_s->ctrl_sock < 0 || dst == NULL)
		return;

	snprintf(levelstr, sizeof(levelstr), "<%d>", level);
	io[0].iov_base = levelstr;
	io[0].iov_len = strlen(levelstr);
	io[1].iov_base = buf;
	io[1].iov_len = len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = io;
	msg.msg_iovlen = 2;

	idx = 0;
	while (dst) {
		next = dst->next;
		if (level >= dst->debug_level) {
			wpa_hexdump(MSG_DEBUG, "CTRL_IFACE monitor send",
				    dst->addr.sun_path, dst->addrlen);
			msg.msg_name = &dst->addr;
			msg.msg_namelen = dst->addrlen;
			if (sendmsg(wpa_s->ctrl_sock, &msg, 0) < 0) {
				fprintf(stderr, "CTRL_IFACE monitor[%d]: ",
					idx);
				perror("sendmsg");
				dst->errors++;
				if (dst->errors > 10) {
					wpa_supplicant_ctrl_iface_detach(
						wpa_s, &dst->addr,
						dst->addrlen);
				}
			} else
				dst->errors = 0;
		}
		idx++;
		dst = next;
	}
}
