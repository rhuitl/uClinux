/*
 * Host AP crypto configuration tool for Host AP kernel driver
 * Copyright (c) 2002, Jouni Malinen <jkmaline@cc.hut.fi>
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
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>

#include <sys/socket.h>
#include "util.h"
#include "wireless_copy.h"

#define DEFAULT_KEYS "ff:ff:ff:ff:ff:ff"


static inline int hex2int(char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	if (c >= 'A' && c <= 'F')
		return (c - 'A' + 10);
	return -1;
}


static int macstr2addr(const char *macstr, u8 *addr)
{
	int i, val, val2;
	const char *pos = macstr;

	for (i = 0; i < 6; i++) {
		val = hex2int(*pos++);
		if (val < 0)
			return -1;
		val2 = hex2int(*pos++);
		if (val2 < 0)
			return -1;
		addr[i] = (val * 16 + val2) & 0xff;

		if (i < 5 && *pos++ != ':')
			return -1;
	}

	if (*pos != '\0')
		return -1;

	return 0;
}


static void usage(void)
{
	printf("Usage: hostap_crypt_conf [-123456789tpl] <device> [addr] "
	       "[alg] [key]\n"
	       "Options:\n"
	       "  -1 .. -9   key index (for WEP); only one index per command\n"
	       "  -t         set TX key index (given with -1 .. -9)\n"
	       "  -p         permanent station configuration (do not expire "
	       "data)\n"
	       "  -l         list configured keys (do not use addr or alg)\n"
	       "  device     wlan#\n"
	       "  addr       station hwaddr or " DEFAULT_KEYS " for default/"
	       "broadcast key\n"
	       "  alg        crypt algorithm (WEP, NULL, none)\n"
	       "  key        key data (in hex, e.g. '0011223344', or s:string)"
	       "\n\n"
	       "Algorithms:\n"
	       "  WEP        40 or 104 bit WEP\n"
	       "  NULL       NULL encryption (i.e., do not encrypt/decrypt);\n"
	       "             used to configure no encryption for given\n"
	       "             station when using default encryption\n"
	       "  none       disable encryption\n");

	exit(1);
}


static void parse_key_string(struct prism2_hostapd_param *param,
			     const char *key)
{
	param->u.crypt.key_len = strlen(key);
	if (param->u.crypt.key_len > 1024 - sizeof(*param)) {
		fprintf(stderr, "Too long key.\n");
		exit(1);
	}

	memcpy(param->u.crypt.key, key, param->u.crypt.key_len);
}


static void parse_key_hex(struct prism2_hostapd_param *param,
			  const char *key)
{
	int len = strlen(key);
	const char *ipos;
	char *opos;

	if (len & 1) {
		fprintf(stderr, "Invalid hex string '%s' (odd length)\n", key);
		exit(1);
	}
	param->u.crypt.key_len = len / 2;
	if (param->u.crypt.key_len > 1024 - sizeof(*param)) {
		fprintf(stderr, "Too long key.\n");
		exit(1);
	}

	ipos = key;
	opos = param->u.crypt.key;
	while (len > 0) {
		int val1, val2;
		val1 = hex2int(*ipos++);
		val2 = hex2int(*ipos++);
		if (val1 < 0 || val2 < 0) {
			fprintf(stderr, "Invalid hex string '%s' (could not "
				"parse '%c%c')\n", key,
				*(ipos - 2), *(ipos - 1));
			exit(1);
		}
		*opos++ = (val1 << 4) + val2;
		len -= 2;
	}
}


static void show_error(struct prism2_hostapd_param *param)
{
	switch (param->u.crypt.err) {
	case HOSTAP_CRYPT_ERR_UNKNOWN_ALG:
		printf("Unknown algorithm '%s'.\n"
		       "You may need to load kernel module to register that "
		       "algorithm.\n"
		       "E.g., 'modprobe hostap_crypt_wep' for WEP.\n",
		       param->u.crypt.alg);
		break;
	case HOSTAP_CRYPT_ERR_UNKNOWN_ADDR:
		printf("Unknown address " MACSTR ".\n",
		       MAC2STR(param->sta_addr));
		if (!(param->u.crypt.flags & HOSTAP_CRYPT_FLAG_PERMANENT))
			printf("You can use -p flag to add permanent entry "
			       "for not yet associated station.\n");
		break;
	case HOSTAP_CRYPT_ERR_CRYPT_INIT_FAILED:
		printf("Crypt algorithm initialization failed.\n");
		break;
	case HOSTAP_CRYPT_ERR_KEY_SET_FAILED:
		printf("Key setting failed.\n");
		break;
	case HOSTAP_CRYPT_ERR_TX_KEY_SET_FAILED:
		printf("TX key index setting failed.\n");
		break;
	case HOSTAP_CRYPT_ERR_CARD_CONF_FAILED:
		printf("Card configuration failed.\n");
		break;
	}
}


static int do_ioctl(const char *dev, struct prism2_hostapd_param *param,
		    int show_err)
{
	int s;
	struct iwreq iwr;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, dev, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) param;
	iwr.u.data.length = (int) ((char *) param->u.crypt.key -
				   (char *) param) +
		param->u.crypt.key_len;

	if (ioctl(s, PRISM2_IOCTL_HOSTAPD, &iwr) < 0) {
		if (show_err) {
			perror("ioctl[PRISM2_IOCTL_HOSTAPD]");
			show_error(param);
		}
		return -1;
	}

	return 0;
}


static int show_key(const char *dev, char *addr, int forced_show)
{
	char buf[1024];
	struct prism2_hostapd_param *param;
	int idx, i, max_key_len;

	max_key_len = sizeof(buf) -
		(int) ((char *) param->u.crypt.key - (char *) param);

	memset(buf, 0, sizeof(buf));
	param = (struct prism2_hostapd_param *) buf;
	param->cmd = PRISM2_GET_ENCRYPTION;

	if (macstr2addr(addr, param->sta_addr))
		return -1;
	param->u.crypt.idx = 0xff;
	param->u.crypt.key_len = max_key_len;
	if (do_ioctl(dev, param, forced_show))
		return -1;

	if (!forced_show && strcmp(param->u.crypt.alg, "none") == 0)
		return 0;

	if (strcmp(addr, DEFAULT_KEYS) == 0)
		printf("Default keys\n");
	else
		printf("\nKeys for %s\n", addr);
	printf("  algorithm: %s\n", param->u.crypt.alg);
	if (strcmp(param->u.crypt.alg, "none") == 0)
		return 0;

	if (param->u.crypt.idx != 0xff)
		printf("  TX key idx: %d\n", param->u.crypt.idx + 1);

	for (idx = 0; idx < 4; idx++) {
		param->u.crypt.idx = idx;
		param->u.crypt.key_len = max_key_len;
		if (do_ioctl(dev, param, forced_show) == 0) {
			printf("  key %d:", idx + 1);
			if (param->u.crypt.key_len > max_key_len)
				printf(" invalid key_len %d",
				       param->u.crypt.key_len);
			else
				for (i = 0; i < param->u.crypt.key_len; i++)
					printf(" %02x", param->u.crypt.key[i]);
			printf("\n");
		}
	}

	return 0;
}

static int show_key_list(const char *dev)
{
	char dirname[128];
	DIR *procdir;
	struct dirent *entry;

	if (show_key(dev, DEFAULT_KEYS, 1))
		return -1;

	snprintf(dirname, sizeof(dirname), "/proc/net/hostap/%s", dev);
	procdir = opendir(dirname);
	if (!procdir) {
		printf("Could not open directory '%s'\n", dirname);
		perror("opendir");
		return -1;
	}

	while ((entry = readdir(procdir)) != NULL) {
		if (strlen(entry->d_name) == 17 && entry->d_name[2] == ':')
			show_key(dev, entry->d_name, 0);
	}

	if (closedir(procdir))
		perror("closedir");

	return 0;
}


int main(int argc, char *argv[])
{
	int opt, idx = 0, list_keys = 0;
	char buf[1024];
	const char *arg_dev = NULL, *arg_addr = NULL, *arg_alg = NULL,
		*arg_key = NULL;
	struct prism2_hostapd_param *param;

	memset(buf, 0, sizeof(buf));
	param = (struct prism2_hostapd_param *) buf;
	param->cmd = PRISM2_SET_ENCRYPTION;

	for (;;) {
		opt = getopt(argc, argv, "123456789tphl");
		if (opt < 0)
			break;
		if (opt == 't')
			param->u.crypt.flags |= HOSTAP_CRYPT_FLAG_SET_TX_KEY;
		else if (opt == 'p')
			param->u.crypt.flags |= HOSTAP_CRYPT_FLAG_PERMANENT;
		else if (opt == 'l')
			list_keys++;
		else if (opt >= '1' && opt <= '9') {
			if (idx != 0)
				usage();
			idx = opt - '0';
		} else {
			/* -h or invalid options */
			usage();
		}
	}

	param->u.crypt.idx = idx > 0 ? idx - 1 : 0;

	if (argc > optind)
		arg_dev = argv[optind++];
	if (argc > optind)
		arg_addr = argv[optind++];
	if (argc > optind)
		arg_alg = argv[optind++];
	if (argc > optind)
		arg_key = argv[optind++];

	if (list_keys) {
		if (!arg_dev)
			usage();
		return show_key_list(arg_dev);
	}

	if (!arg_addr)
		usage();

	if (macstr2addr(arg_addr, param->sta_addr) < 0) {
		fprintf(stderr, "Invalid hwaddr '%s'.\n", arg_addr);
		usage();
	}

	if (!arg_alg)
		usage();

	if (strlen(arg_alg) > HOSTAP_CRYPT_ALG_NAME_LEN) {
		fprintf(stderr, "Too long algorithm name '%s'.\n", arg_alg);
		exit(1);
	}

	strncpy(param->u.crypt.alg, arg_alg, HOSTAP_CRYPT_ALG_NAME_LEN);

	if (arg_key) {
		if (arg_key[0] == 's' && arg_key[1] == ':')
			parse_key_string(param, arg_key + 2);
		else
			parse_key_hex(param, arg_key);
	}

	return do_ioctl(arg_dev, param, 1);
}
