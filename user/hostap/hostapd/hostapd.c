/*
 * Host AP (software wireless LAN access point) user space daemon for
 * Host AP kernel driver
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
#include <signal.h>
#include <time.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "eloop.h"
#include "hostapd.h"
#include "ieee802_1x.h"
#include "ieee802_11.h"
#include "accounting.h"
#include "eapol_sm.h"
#include "iapp.h"
#include "ap.h"
#include "ieee802_11_auth.h"
#include "sta_info.h"
#include "driver.h"
#include "radius_client.h"
#include "wpa.h"


struct hapd_interfaces {
	int count;
	hostapd **hapd;
};

unsigned char rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };


void hostapd_logger(hostapd *hapd, u8 *addr, unsigned int module, int level,
		    char *fmt, ...)
{
	char *format, *module_str;
	int maxlen;
	va_list ap;
	int conf_syslog_level, conf_stdout_level;
	unsigned int conf_syslog, conf_stdout;

	maxlen = strlen(fmt) + 100;
	format = malloc(maxlen);
	if (!format)
		return;

	va_start(ap, fmt);

	if (hapd && hapd->conf) {
		conf_syslog_level = hapd->conf->logger_syslog_level;
		conf_stdout_level = hapd->conf->logger_stdout_level;
		conf_syslog = hapd->conf->logger_syslog;
		conf_stdout = hapd->conf->logger_stdout;
	} else {
		conf_syslog_level = conf_stdout_level = 0;
		conf_syslog = conf_stdout = (unsigned int) -1;
	}

	switch (module) {
	case HOSTAPD_MODULE_IEEE80211:
		module_str = "IEEE 802.11";
		break;
	case HOSTAPD_MODULE_IEEE8021X:
		module_str = "IEEE 802.1X";
		break;
	case HOSTAPD_MODULE_RADIUS:
		module_str = "RADIUS";
		break;
	case HOSTAPD_MODULE_WPA:
		module_str = "WPA";
		break;
	default:
		module_str = NULL;
		break;
	}

	if (hapd && hapd->conf && addr)
		snprintf(format, maxlen, "%s: STA " MACSTR "%s%s: %s",
			 hapd->conf->iface, MAC2STR(addr),
			 module_str ? " " : "", module_str, fmt);
	else if (hapd && hapd->conf)
		snprintf(format, maxlen, "%s:%s%s %s",
			 hapd->conf->iface, module_str ? " " : "",
			 module_str, fmt);
	else if (addr)
		snprintf(format, maxlen, "STA " MACSTR "%s%s: %s",
			 MAC2STR(addr), module_str ? " " : "",
			 module_str, fmt);
	else
		snprintf(format, maxlen, "%s%s%s",
			 module_str, module_str ? ": " : "", fmt);

	if ((conf_stdout & module) && level >= conf_stdout_level) {
		vprintf(format, ap);
		printf("\n");
	}

	if ((conf_syslog & module) && level >= conf_syslog_level) {
		int priority;
		switch (level) {
		case HOSTAPD_LEVEL_DEBUG_VERBOSE:
		case HOSTAPD_LEVEL_DEBUG:
			priority = LOG_DEBUG;
			break;
		case HOSTAPD_LEVEL_INFO:
			priority = LOG_INFO;
			break;
		case HOSTAPD_LEVEL_NOTICE:
			priority = LOG_NOTICE;
			break;
		case HOSTAPD_LEVEL_WARNING:
			priority = LOG_WARNING;
			break;
		default:
			priority = LOG_INFO;
			break;
		}
		vsyslog(priority, format, ap);
	}

	free(format);

	va_end(ap);
}


static void hostapd_deauth_all_stas(hostapd *hapd)
{
	u8 addr[ETH_ALEN];

	memset(addr, 0xff, ETH_ALEN);
	ieee802_11_send_deauth(hapd, addr, WLAN_REASON_PREV_AUTH_NOT_VALID);
}


/* This function will be called whenever a station associates with the AP */
void hostapd_new_assoc_sta(hostapd *hapd, struct sta_info *sta)
{
	/* IEEE 802.11f (IAPP) */
	if (hapd->conf->ieee802_11f)
		iapp_new_station(hapd, sta);

	/* Start accounting here, if IEEE 802.1X is not used. IEEE 802.1X code
	 * will start accounting after the station has been authorized. */
	if (!hapd->conf->ieee802_1x)
		accounting_sta_start(hapd, sta);

	/* Start IEEE 802.1x authentication process for new stations */
	ieee802_1x_new_station(hapd, sta);
	wpa_new_station(hapd, sta);
}


static void handle_term(int sig, void *eloop_ctx, void *signal_ctx)
{
	printf("Signal %d received - terminating\n", sig);
	eloop_terminate();
}


static void handle_reload(int sig, void *eloop_ctx, void *signal_ctx)
{
	struct hapd_interfaces *hapds = (struct hapd_interfaces *) eloop_ctx;
	struct hostapd_config *newconf;
	int i;

	printf("Signal %d received - reloading configuration\n", sig);

	for (i = 0; i < hapds->count; i++) {
		hostapd *hapd = hapds->hapd[i];
		newconf = hostapd_config_read(hapd->config_fname);
		if (newconf == NULL) {
			printf("Failed to read new configuration file - "
			       "continuing with old.\n");
			continue;
		}
		/* TODO: update dynamic data based on changed configuration
		 * items (e.g., open/close sockets, remove stations added to
		 * deny list, etc.) */
		radius_client_flush(hapd);
		hostapd_config_free(hapd->conf);
		hapd->conf = newconf;
	}
}


#ifdef HOSTAPD_DUMP_STATE
static void hostapd_dump_state(hostapd *hapd)
{
	FILE *f;
	time_t now;
	struct sta_info *sta;
	int i;

	if (!hapd->conf->dump_log_name) {
		printf("Dump file not defined - ignoring dump request\n");
		return;
	}

	printf("Dumping hostapd state to '%s'\n", hapd->conf->dump_log_name);
	f = fopen(hapd->conf->dump_log_name, "w");
	if (f == NULL) {
		printf("Could not open dump file '%s' for writing.\n",
		       hapd->conf->dump_log_name);
		return;
	}

	time(&now);
	fprintf(f, "hostapd state dump - %s", ctime(&now));

	for (sta = hapd->sta_list; sta != NULL; sta = sta->next) {
		fprintf(f, "\nSTA=" MACSTR "\n", MAC2STR(sta->addr));

		fprintf(f,
			"  AID=%d flags=0x%x %s%s%s%s%s%s\n"
			"  capability=0x%x listen_interval=%d\n",
			sta->aid,
			sta->flags,
			(sta->flags & WLAN_STA_AUTH ? "[AUTH]" : ""),
			(sta->flags & WLAN_STA_ASSOC ? "[ASSOC]" : ""),
			(sta->flags & WLAN_STA_PS ? "[PS]" : ""),
			(sta->flags & WLAN_STA_TIM ? "[TIM]" : ""),
			(sta->flags & WLAN_STA_PERM ? "[PERM]" : ""),
			(sta->flags & WLAN_STA_AUTHORIZED ? "[AUTHORIZED]" :
			 ""),
			sta->capability,
			sta->listen_interval);

		fprintf(f, "  supported_rates=");
		for (i = 0; i < sizeof(sta->supported_rates); i++)
			if (sta->supported_rates[i] != 0)
				fprintf(f, "%02x ", sta->supported_rates[i]);
		fprintf(f, "%s%s%s%s\n",
			(sta->tx_supp_rates & WLAN_RATE_1M ? "[1M]" : ""),
			(sta->tx_supp_rates & WLAN_RATE_2M ? "[2M]" : ""),
			(sta->tx_supp_rates & WLAN_RATE_5M5 ? "[5.5M]" : ""),
			(sta->tx_supp_rates & WLAN_RATE_11M ? "[11M]" : ""));

		fprintf(f,
			"  timeout_next=%s\n",
			(sta->timeout_next == STA_NULLFUNC ? "NULLFUNC POLL" :
			 (sta->timeout_next == STA_DISASSOC ? "DISASSOC" :
			  "DEAUTH")));

		ieee802_1x_dump_state(f, "  ", sta);
	}

	fclose(f);
}
#endif /* HOSTAPD_DUMP_STATE */


static void handle_dump_state(int sig, void *eloop_ctx, void *signal_ctx)
{
#ifdef HOSTAPD_DUMP_STATE
	struct hapd_interfaces *hapds = (struct hapd_interfaces *) eloop_ctx;
	int i;

	for (i = 0; i < hapds->count; i++) {
		hostapd *hapd = hapds->hapd[i];
		hostapd_dump_state(hapd);
	}
#endif /* HOSTAPD_DUMP_STATE */
}


static void hostapd_set_broadcast_wep(hostapd *hapd)
{
	if (hapd->conf->default_wep_key_len < 1)
		return;

	hapd->default_wep_key = malloc(hapd->conf->default_wep_key_len);
	if (hapd->default_wep_key == NULL ||
	    hostapd_get_rand(hapd->default_wep_key,
			     hapd->conf->default_wep_key_len)) {
		printf("Could not generate random WEP key.\n");
		free(hapd->default_wep_key);
		exit(1);
	}
}


/* The rekeying function: generate a new broadcast WEP key, rotate
 * the key index, and direct Key Transmit State Machines of all of the
 * authenticators to send a new key to the authenticated stations.
 */
static void hostapd_rotate_wep(void *eloop_ctx, void *timeout_ctx)
{
	struct sta_info *s;
	hostapd *hapd = eloop_ctx;

	if (hapd->default_wep_key)
		free(hapd->default_wep_key);

	if (hapd->default_wep_key_idx >= 3)
		hapd->default_wep_key_idx =
			hapd->conf->individual_wep_key_len > 0 ? 1 : 0;
	else
		hapd->default_wep_key_idx++;

	hostapd_set_broadcast_wep(hapd);

	for (s = hapd->sta_list; s != NULL; s = s->next)
		ieee802_1x_notify_key_available(s->eapol_sm, 1);

	if (HOSTAPD_DEBUG_COND(HOSTAPD_DEBUG_MINIMAL)) {
		hostapd_hexdump("New WEP key generated",
				hapd->default_wep_key,
				hapd->conf->default_wep_key_len);
	}

	/* TODO: Could setup key for RX here, but change default TX keyid only
	 * after new broadcast key has been sent to all stations. */
	if (hostapd_set_encryption(hapd->driver.data, "WEP", NULL,
				   hapd->default_wep_key_idx,
				   hapd->default_wep_key,
				   hapd->conf->default_wep_key_len)) {
		printf("Could not set WEP encryption.\n");
	}

	if (hapd->conf->wep_rekeying_period > 0)
		eloop_register_timeout(hapd->conf->wep_rekeying_period, 0,
				       hostapd_rotate_wep, hapd, NULL);
}


static void hostapd_cleanup(hostapd *hapd)
{
	free(hapd->default_wep_key);
	if (hapd->conf->ieee802_11f)
		iapp_deinit(hapd);
	accounting_deinit(hapd);
	wpa_deinit(hapd);
	ieee802_1x_deinit(hapd);
	hostapd_acl_deinit(hapd);
	radius_client_deinit(hapd);

	hostapd_wireless_event_deinit(hapd->driver.data);

	hostapd_driver_deinit(hapd);

	hostapd_config_free(hapd->conf);
	hapd->conf = NULL;

	free(hapd->config_fname);
}


static int hostapd_flush_old_stations(hostapd *hapd)
{
	int ret = 0;

	printf("Flushing old station entries\n");
	if (hostapd_flush(hapd->driver.data)) {
		printf("Could not connect to kernel driver.\n");
		ret = -1;
	}
	printf("Deauthenticate all stations\n");
	hostapd_deauth_all_stas(hapd);

	return ret;
}


static int hostapd_setup_encryption(hostapd *hapd)
{
	if (HOSTAPD_DEBUG_COND(HOSTAPD_DEBUG_MINIMAL))
		hostapd_hexdump("Default WEP key", hapd->default_wep_key,
				hapd->conf->default_wep_key_len);

	hostapd_set_encryption(hapd->driver.data, "none", NULL, 0, NULL, 0);

	if (hostapd_set_encryption(hapd->driver.data, "WEP", NULL,
				   hapd->default_wep_key_idx,
				   hapd->default_wep_key,
				   hapd->conf->default_wep_key_len)) {
		printf("Could not set WEP encryption.\n");
		return -1;
	}

	/* Setup rekeying timer. */
	if (hapd->conf->wep_rekeying_period > 0 &&
	    (hapd->default_wep_key || hapd->conf->individual_wep_key_len > 0)
	    && eloop_register_timeout(hapd->conf->wep_rekeying_period, 0,
				      hostapd_rotate_wep, hapd, NULL)) {
		printf("Couldn't set rekeying timer.\n");
		return -1;
	}

	return 0;
}


static int hostapd_setup_interface(hostapd *hapd)
{
    if (hostapd_driver_init(hapd)) {
		printf("Host AP driver initialization failed.\n");
		return -1;
	}

	printf("Using interface %sap with hwaddr " MACSTR " and ssid '%s'\n",
	       hapd->conf->iface, MAC2STR(hapd->own_addr), hapd->conf->ssid);

	/* Set SSID for the kernel driver (to be used in beacon and probe
	 * response frames) */
	if (hostap_ioctl_setiwessid(hapd->driver.data, hapd->conf->ssid,
				    hapd->conf->ssid_len)) {
		printf("Could not set SSID for kernel driver\n");
		return -1;
	}

	if (radius_client_init(hapd)) {
		printf("RADIUS client initialization failed.\n");
		return -1;
	}

	if (hostapd_acl_init(hapd)) {
		printf("ACL initialization failed.\n");
		return -1;
	}

	if (ieee802_1x_init(hapd)) {
		printf("IEEE 802.1X initialization failed.\n");
		return -1;
	}

	if (hapd->conf->wpa && wpa_init(hapd)) {
		printf("WPA initialization failed.\n");
		return -1;
	}

	if (accounting_init(hapd)) {
		printf("Accounting initialization failed.\n");
		return -1;
	}

	if (hapd->conf->ieee802_11f && iapp_init(hapd)) {
		printf("IEEE 802.11f (IAPP) initialization failed.\n");
		return -1;
	}

	if (hostapd_wireless_event_init(hapd->driver.data) < 0)
		return -1;

	if (hapd->default_wep_key && hostapd_setup_encryption(hapd))
		return -1;

	if (hostapd_flush_old_stations(hapd))
		return -1;

	return 0;
}


static void usage(void)
{
	fprintf(stderr,
		"Host AP user space daemon for management functionality of "
		"Host AP kernel driver\n"
		"Copyright (c) 2002-2004, Jouni Malinen <jkmaline@cc.hut.fi>\n"
		"\n"
		"usage: hostapd [-hdB] <configuration file(s)>\n"
		"\n"
		"options:\n"
		"   -h   show this usage\n"
		"   -d   show more debug messages (-dd for even more)\n"
		"   -B   run daemon in the background\n");

	exit(1);
}


static hostapd * hostapd_init(const char *config_file)
{
	hostapd *hapd;

	hapd = malloc(sizeof(*hapd));
	if (hapd == NULL) {
		printf("Could not allocate memory for hostapd data\n");
		exit(1);
	}
	memset(hapd, 0, sizeof(*hapd));

	hapd->config_fname = strdup(config_file);
	if (hapd->config_fname == NULL) {
		printf("Could not allocate memory for config_fname\n");
		exit(1);
	}

	hapd->conf = hostapd_config_read(hapd->config_fname);
	if (hapd->conf == NULL) {
		free(hapd->config_fname);
		exit(1);
	}

	if (hapd->conf->individual_wep_key_len > 0) {
		/* use key0 in individual key and key1 in broadcast key */
		hapd->default_wep_key_idx = 1;
	}

	if (hapd->conf->assoc_ap)
		hapd->assoc_ap_state = WAIT_BEACON;

	return hapd;
}


int main(int argc, char *argv[])
{
	struct hapd_interfaces interfaces;
	int ret = 1, i, j;
	int c, debug = 0, daemonize = 0;

	for (;;) {
		c = getopt(argc, argv, "Bdh");
		if (c < 0)
			break;
		switch (c) {
		case 'h':
			usage();
			break;
		case 'd':
			debug++;
			break;
		case 'B':
			daemonize++;
			break;

		default:
			usage();
			break;
		}
	}

	if (optind == argc)
		usage();

	interfaces.count = argc - optind;

	interfaces.hapd = malloc(interfaces.count * sizeof(hostapd *));
	if (interfaces.hapd == NULL) {
		printf("malloc failed\n");
		exit(1);
	}

	eloop_init(&interfaces);
	eloop_register_signal(SIGHUP, handle_reload, NULL);
	eloop_register_signal(SIGINT, handle_term, NULL);
	eloop_register_signal(SIGTERM, handle_term, NULL);
	eloop_register_signal(SIGUSR1, handle_dump_state, NULL);

	for (i = 0; i < interfaces.count; i++) {
		printf("Configuration file: %s\n", argv[optind + i]);
		interfaces.hapd[i] = hostapd_init(argv[optind + i]);
		if (!interfaces.hapd[i])
			goto out;
		for (j = 0; j < debug; j++) {
			if (interfaces.hapd[i]->conf->logger_stdout_level > 0)
				interfaces.hapd[i]->conf->
					logger_stdout_level--;
			interfaces.hapd[i]->conf->debug++;
		}
		hostapd_set_broadcast_wep(interfaces.hapd[i]);
		if (hostapd_setup_interface(interfaces.hapd[i]))
			goto out;
	}

	if (daemonize && daemon(0, 0)) {
		perror("daemon");
		goto out;
	}

	openlog("hostapd", 0, LOG_DAEMON);

	eloop_run();

	for (i = 0; i < interfaces.count; i++) {
		hostapd_free_stas(interfaces.hapd[i]);
		hostapd_flush_old_stations(interfaces.hapd[i]);
	}

	ret = 0;

 out:
	for (i = 0; i < interfaces.count; i++) {
		if (!interfaces.hapd[i])
			continue;

		hostapd_cleanup(interfaces.hapd[i]);
		free(interfaces.hapd[i]);
	}
	free(interfaces.hapd);

	eloop_destroy();

	closelog();

	return ret;
}
