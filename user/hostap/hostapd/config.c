/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver / Configuration file
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
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
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "hostapd.h"
#include "sha1.h"


static struct hostapd_config *hostapd_config_defaults(void)
{
	struct hostapd_config *conf;

	conf = malloc(sizeof(*conf));
	if (conf == NULL) {
		printf("Failed to allocate memory for configuration data.\n");
		return NULL;
	}
	memset(conf, 0, sizeof(*conf));

	conf->ssid_len = 4;
	memcpy(conf->ssid, "test", 4);
	conf->wep_rekeying_period = 300;

	conf->logger_syslog_level = HOSTAPD_LEVEL_INFO;
	conf->logger_stdout_level = HOSTAPD_LEVEL_INFO;
	conf->logger_syslog = (unsigned int) -1;
	conf->logger_stdout = (unsigned int) -1;

	conf->auth_algs = HOSTAPD_AUTH_OPEN | HOSTAPD_AUTH_SHARED_KEY;

	conf->wpa_group_rekey = 600;
	conf->wpa_gmk_rekey = 86400;
	conf->wpa_key_mgmt = WPA_KEY_MGMT_PSK;
	conf->wpa_pairwise = WPA_CIPHER_TKIP;
	conf->wpa_group = WPA_CIPHER_TKIP;

	return conf;
}


static int mac_comp(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(macaddr));
}


static int hostapd_config_read_maclist(const char *fname, macaddr **acl,
				       int *num)
{
	FILE *f;
	char buf[128], *pos;
	int line = 0;
	u8 addr[ETH_ALEN];
	macaddr *newacl;

	if (!fname)
		return 0;

	f = fopen(fname, "r");
	if (!f) {
		printf("MAC list file '%s' not found.\n", fname);
		return -1;
	}

	while (fgets(buf, sizeof(buf), f)) {
		line++;

		if (buf[0] == '#')
			continue;
		pos = buf;
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}
		if (buf[0] == '\0')
			continue;

		if (hwaddr_aton(buf, addr)) {
			printf("Invalid MAC address '%s' at line %d in '%s'\n",
			       buf, line, fname);
			fclose(f);
			return -1;
		}

		newacl = (macaddr *) realloc(*acl, (*num + 1) * ETH_ALEN);
		if (newacl == NULL) {
			printf("MAC list reallocation failed\n");
			fclose(f);
			return -1;
		}

		*acl = newacl;
		memcpy((*acl)[*num], addr, ETH_ALEN);
		(*num)++;
	}

	fclose(f);

	qsort(*acl, *num, sizeof(macaddr), mac_comp);

	return 0;
}


static int
hostapd_config_read_radius_addr(struct hostapd_radius_server **server,
				int *num_server, const char *val, int def_port,
				struct hostapd_radius_server **curr_serv)
{
	struct hostapd_radius_server *nserv;
	int ret;

	nserv = realloc(*server, (*num_server + 1) * sizeof(*nserv));
	if (nserv == NULL)
		return -1;

	*server = nserv;
	nserv = &nserv[*num_server];
	(*num_server)++;
	(*curr_serv) = nserv;

	memset(nserv, 0, sizeof(*nserv));
	nserv->port = def_port;
	ret = !inet_aton(val, &nserv->addr);

	return ret;
}


static int hostapd_config_parse_key_mgmt(int line, const char *value)
{
	int val = 0, last;
	char *start, *end, *buf;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (strcmp(start, "WPA-PSK") == 0)
			val |= WPA_KEY_MGMT_PSK;
		else if (strcmp(start, "WPA-EAP") == 0)
			val |= WPA_KEY_MGMT_IEEE8021X;
		else {
			printf("Line %d: invalid key_mgmt '%s'", line, start);
			free(buf);
			return -1;
		}

		if (last)
			break;
		start = end + 1;
	}

	free(buf);
	if (val == 0) {
		printf("Line %d: no key_mgmt values configured.", line);
		return -1;
	}

	return val;
}


static int hostapd_config_parse_cipher(int line, const char *value)
{
	int val = 0, last;
	char *start, *end, *buf;

	buf = strdup(value);
	if (buf == NULL)
		return -1;
	start = buf;

	while (start != '\0') {
		while (*start == ' ' || *start == '\t')
			start++;
		if (*start == '\0')
			break;
		end = start;
		while (*end != ' ' && *end != '\t' && *end != '\0')
			end++;
		last = *end == '\0';
		*end = '\0';
		if (strcmp(start, "CCMP") == 0)
			val |= WPA_CIPHER_CCMP;
		else if (strcmp(start, "TKIP") == 0)
			val |= WPA_CIPHER_TKIP;
		else if (strcmp(start, "WEP104") == 0)
			val |= WPA_CIPHER_WEP104;
		else if (strcmp(start, "WEP40") == 0)
			val |= WPA_CIPHER_WEP40;
		else if (strcmp(start, "NONE") == 0)
			val |= WPA_CIPHER_NONE;
		else {
			printf("Line %d: invalid cipher '%s'.", line, start);
			free(buf);
			return -1;
		}

		if (last)
			break;
		start = end + 1;
	}
	free(buf);

	if (val == 0) {
		printf("Line %d: no cipher values configured.", line);
		return -1;
	}
	return val;
}


static int hostapd_config_check(struct hostapd_config *conf)
{
	if (conf->ieee802_1x && !conf->minimal_eap && !conf->auth_servers) {
		printf("Invalid IEEE 802.1X configuration.\n");
		return -1;
	}

	if (conf->ieee802_1x && conf->minimal_eap &&
	    (conf->default_wep_key_len || conf->individual_wep_key_len)) {
		printf("Minimal EAP server cannot be used for dynamic WEP "
		       "keying.\n");
		return -1;
	}

	if (conf->wpa && (conf->wpa_key_mgmt & WPA_KEY_MGMT_PSK) &&
	    conf->wpa_psk == NULL) {
		printf("WPA-PSK enabled, but PSK or passphrase is not "
		       "configured.\n");
		return -1;
	}

	return 0;
}


struct hostapd_config * hostapd_config_read(const char *fname)
{
	struct hostapd_config *conf;
	FILE *f;
	char buf[256], *pos;
	int line = 0;
	int errors = 0;
	char *accept_mac_file = NULL, *deny_mac_file = NULL;

	f = fopen(fname, "r");
	if (f == NULL) {
		printf("Could not open configuration file '%s' for reading.\n",
		       fname);
		return NULL;
	}

	conf = hostapd_config_defaults();
	if (conf == NULL) {
		fclose(f);
		return NULL;
	}

	while (fgets(buf, sizeof(buf), f)) {
		line++;

		if (buf[0] == '#')
			continue;
		pos = buf;
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}
		if (buf[0] == '\0')
			continue;

		pos = strchr(buf, '=');
		if (pos == NULL) {
			printf("Line %d: invalid line '%s'\n", line, buf);
			errors++;
			continue;
		}
		*pos = '\0';
		pos++;

		if (strcmp(buf, "interface") == 0) {
			snprintf(conf->iface, sizeof(conf->iface), "%s", pos);
		} else if (strcmp(buf, "debug") == 0) {
			conf->debug = atoi(pos);
		} else if (strcmp(buf, "logger_syslog_level") == 0) {
			conf->logger_syslog_level = atoi(pos);
		} else if (strcmp(buf, "logger_stdout_level") == 0) {
			conf->logger_stdout_level = atoi(pos);
		} else if (strcmp(buf, "logger_syslog") == 0) {
			conf->logger_syslog = atoi(pos);
		} else if (strcmp(buf, "logger_stdout") == 0) {
			conf->logger_stdout = atoi(pos);
		} else if (strcmp(buf, "dump_file") == 0) {
			conf->dump_log_name = strdup(pos);
		} else if (strcmp(buf, "daemonize") == 0) {
			conf->daemonize = atoi(pos);
		} else if (strcmp(buf, "ssid") == 0) {
			conf->ssid_len = strlen(pos);
			if (conf->ssid_len >= HOSTAPD_SSID_LEN ||
			    conf->ssid_len < 1) {
				printf("Line %d: invalid SSID '%s'\n", line,
				       pos);
				errors++;
			}
			memcpy(conf->ssid, pos, conf->ssid_len);
			conf->ssid[conf->ssid_len] = '\0';
		} else if (strcmp(buf, "macaddr_acl") == 0) {
			conf->macaddr_acl = atoi(pos);
			if (conf->macaddr_acl != ACCEPT_UNLESS_DENIED &&
			    conf->macaddr_acl != DENY_UNLESS_ACCEPTED &&
			    conf->macaddr_acl != USE_EXTERNAL_RADIUS_AUTH) {
				printf("Line %d: unknown macaddr_acl %d\n",
				       line, conf->macaddr_acl);
			}
		} else if (strcmp(buf, "accept_mac_file") == 0) {
			accept_mac_file = strdup(pos);
			if (!accept_mac_file) {
				printf("Line %d: allocation failed\n", line);
				errors++;
			}
		} else if (strcmp(buf, "deny_mac_file") == 0) {
			deny_mac_file = strdup(pos);
			if (!deny_mac_file) {
				printf("Line %d: allocation failed\n", line);
				errors++;
			}
		} else if (strcmp(buf, "assoc_ap_addr") == 0) {
			if (hwaddr_aton(pos, conf->assoc_ap_addr)) {
				printf("Line %d: invalid MAC address '%s'\n",
				       line, pos);
				errors++;
			}
			conf->assoc_ap = 1;
		} else if (strcmp(buf, "ieee8021x") == 0) {
			conf->ieee802_1x = atoi(pos);
		} else if (strcmp(buf, "minimal_eap") == 0) {
			conf->minimal_eap = atoi(pos);
		} else if (strcmp(buf, "eap_message") == 0) {
			conf->eap_req_id_text = strdup(pos);
		} else if (strcmp(buf, "wep_key_len_broadcast") == 0) {
			conf->default_wep_key_len = atoi(pos);
			if (conf->default_wep_key_len > 13) {
				printf("Line %d: invalid WEP key len %d "
				       "(= %d bits)\n", line,
				       conf->default_wep_key_len,
				       conf->default_wep_key_len * 8);
				errors++;
			}
		} else if (strcmp(buf, "wep_key_len_unicast") == 0) {
			conf->individual_wep_key_len = atoi(pos);
			if (conf->individual_wep_key_len < 0 ||
			    conf->individual_wep_key_len > 13) {
				printf("Line %d: invalid WEP key len %d "
				       "(= %d bits)\n", line,
				       conf->individual_wep_key_len,
				       conf->individual_wep_key_len * 8);
				errors++;
			}
		} else if (strcmp(buf, "wep_rekey_period") == 0) {
			conf->wep_rekeying_period = atoi(pos);
			if (conf->wep_rekeying_period < 0) {
				printf("Line %d: invalid period %d\n",
				       line, conf->wep_rekeying_period);
				errors++;
			}
		} else if (strcmp(buf, "eapol_key_index_workaround") == 0) {
			conf->eapol_key_index_workaround = atoi(pos);
		} else if (strcmp(buf, "iapp_interface") == 0) {
			conf->ieee802_11f = 1;
			snprintf(conf->iapp_iface, sizeof(conf->iapp_iface),
				 "%s", pos);
		} else if (strcmp(buf, "own_ip_addr") == 0) {
			if (!inet_aton(pos, &conf->own_ip_addr)) {
				printf("Line %d: invalid IP address '%s'\n",
				       line, pos);
				errors++;
			}
		} else if (strcmp(buf, "nas_identifier") == 0) {
			conf->nas_identifier = strdup(pos);
		} else if (strcmp(buf, "auth_server_addr") == 0) {
			if (hostapd_config_read_radius_addr(
				    &conf->auth_servers,
				    &conf->num_auth_servers, pos, 1812,
				    &conf->auth_server)) {
				printf("Line %d: invalid IP address '%s'\n",
				       line, pos);
				errors++;
			}
		} else if (conf->auth_server &&
			   strcmp(buf, "auth_server_port") == 0) {
			conf->auth_server->port = atoi(pos);
		} else if (conf->auth_server &&
			   strcmp(buf, "auth_server_shared_secret") == 0) {
			int len = strlen(pos);
			if (len == 0) {
				/* RFC 2865, Ch. 3 */
				printf("Line %d: empty shared secret is not "
				       "allowed.\n", line);
				errors++;
			}
			conf->auth_server->shared_secret = strdup(pos);
			conf->auth_server->shared_secret_len = len;
		} else if (strcmp(buf, "acct_server_addr") == 0) {
			if (hostapd_config_read_radius_addr(
				    &conf->acct_servers,
				    &conf->num_acct_servers, pos, 1813,
				    &conf->acct_server)) {
				printf("Line %d: invalid IP address '%s'\n",
				       line, pos);
				errors++;
			}
		} else if (conf->acct_server &&
			   strcmp(buf, "acct_server_port") == 0) {
			conf->acct_server->port = atoi(pos);
		} else if (conf->acct_server &&
			   strcmp(buf, "acct_server_shared_secret") == 0) {
			int len = strlen(pos);
			if (len == 0) {
				/* RFC 2865, Ch. 3 */
				printf("Line %d: empty shared secret is not "
				       "allowed.\n", line);
				errors++;
			}
			conf->acct_server->shared_secret = strdup(pos);
			conf->acct_server->shared_secret_len = len;
		} else if (strcmp(buf, "radius_retry_primary_interval") == 0) {
			conf->radius_retry_primary_interval = atoi(pos);
		} else if (strcmp(buf, "radius_acct_interim_interval") == 0) {
			conf->radius_acct_interim_interval = atoi(pos);
		} else if (strcmp(buf, "auth_algs") == 0) {
			conf->auth_algs = atoi(pos);
			if (conf->auth_algs == 0) {
				printf("Line %d: no authentication algorithms "
				       "allowed\n",
				       line);
				errors++;
			}
		} else if (strcmp(buf, "wpa") == 0) {
			conf->wpa = atoi(pos);
		} else if (strcmp(buf, "wpa_group_rekey") == 0) {
			conf->wpa_group_rekey = atoi(pos);
		} else if (strcmp(buf, "wpa_gmk_rekey") == 0) {
			conf->wpa_gmk_rekey = atoi(pos);
		} else if (strcmp(buf, "wpa_passphrase") == 0) {
			int len = strlen(pos);
			if (len < 8 || len > 63) {
				printf("Line %d: invalid WPA passphrase length"
				       " %d (expected 8..63)\n", line, len);
				errors++;
			} else
				conf->wpa_passphrase = strdup(pos);
		} else if (strcmp(buf, "wpa_psk") == 0) {
			free(conf->wpa_psk);
			conf->wpa_psk = malloc(PMK_LEN);
			if (conf->wpa_psk == NULL)
				errors++;
			else if (hexstr2bin(pos, conf->wpa_psk, PMK_LEN) ||
				 pos[PMK_LEN * 2] != '\0') {
				printf("Line %d: Invalid PSK '%s'.\n", line,
				       pos);
				errors++;
			}
		} else if (strcmp(buf, "wpa_key_mgmt") == 0) {
			conf->wpa_key_mgmt =
				hostapd_config_parse_key_mgmt(line, pos);
			if (conf->wpa_key_mgmt == -1)
				errors++;
		} else if (strcmp(buf, "wpa_pairwise") == 0) {
			conf->wpa_pairwise =
				hostapd_config_parse_cipher(line, pos);
			if (conf->wpa_pairwise == -1 ||
			    conf->wpa_pairwise == 0)
				errors++;
			else if (conf->wpa_pairwise &
				 (WPA_CIPHER_NONE | WPA_CIPHER_WEP40 |
				  WPA_CIPHER_WEP104)) {
				printf("Line %d: unsupported pairwise "
				       "cipher suite '%s'\n",
				       conf->wpa_pairwise, pos);
				errors++;
			} else {
				if (conf->wpa_pairwise & WPA_CIPHER_TKIP)
					conf->wpa_group = WPA_CIPHER_TKIP;
				else
					conf->wpa_group = WPA_CIPHER_CCMP;
			}
		} else if (strcmp(buf, "rsn_preauth") == 0) {
			conf->rsn_preauth = atoi(pos);
		} else if (strcmp(buf, "rsn_preauth_interfaces") == 0) {
			conf->rsn_preauth_interfaces = strdup(pos);
		} else {
			printf("Line %d: unknown configuration item '%s'\n",
			       line, buf);
			errors++;
		}
	}

	fclose(f);

	if (conf->wpa_passphrase) {
		if (conf->wpa_psk) {
			printf("Warning: both WPA PSK and passphrase set. "
			       "Using passphrase.\n");
			free(conf->wpa_psk);
		}
		conf->wpa_psk = malloc(PMK_LEN);
		if (conf->wpa_psk == NULL)
			errors++;
		else {
			pbkdf2_sha1(conf->wpa_passphrase,
				    conf->ssid, conf->ssid_len,
				    4096, conf->wpa_psk, PMK_LEN);
		}
	}

	if (hostapd_config_read_maclist(accept_mac_file, &conf->accept_mac,
					&conf->num_accept_mac))
		errors++;
	free(accept_mac_file);
	if (hostapd_config_read_maclist(deny_mac_file, &conf->deny_mac,
					&conf->num_deny_mac))
		errors++;
	free(deny_mac_file);

	conf->auth_server = conf->auth_servers;
	conf->acct_server = conf->acct_servers;

	if (hostapd_config_check(conf))
		errors++;

	if (errors) {
		printf("%d errors found in configuration file '%s'\n",
		       errors, fname);
		hostapd_config_free(conf);
		conf = NULL;
	}

	return conf;
}


static void hostapd_config_free_radius(struct hostapd_radius_server *servers,
				       int num_servers)
{
	int i;

	for (i = 0; i < num_servers; i++) {
		free(servers[i].shared_secret);
	}
	free(servers);
}


void hostapd_config_free(struct hostapd_config *conf)
{
	if (conf == NULL)
		return;

	free(conf->dump_log_name);
	free(conf->eap_req_id_text);
	free(conf->accept_mac);
	free(conf->deny_mac);
	free(conf->nas_identifier);
	hostapd_config_free_radius(conf->auth_servers, conf->num_auth_servers);
	hostapd_config_free_radius(conf->acct_servers, conf->num_acct_servers);
	free(conf->wpa_psk);
	free(conf->wpa_passphrase);
	free(conf->rsn_preauth_interfaces);
	free(conf);
}


/* Perform a binary search for given MAC address from a pre-sorted list.
 * Returns 1 if address is in the list or 0 if not. */
int hostapd_maclist_found(macaddr *list, int num_entries, u8 *addr)
{
	int start, end, middle, res;

	start = 0;
	end = num_entries - 1;

	while (start <= end) {
		middle = (start + end) / 2;
		res = memcmp(list[middle], addr, ETH_ALEN);
		if (res == 0)
			return 1;
		if (res < 0)
			start = middle + 1;
		else
			end = middle - 1;
	}

	return 0;
}
