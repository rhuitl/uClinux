/*
 * Prism2/2.5/3 RID get/set tool for Host AP kernel driver
 * Copyright (c) 2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>

#include "util.h"


static void usage(void)
{
	printf("Usage: hostap_rid <device> <get/set> <rid id> [data]\n"
	       "\n"
	       "Examples:\n"
	       "   hostap_rid wlan0 get fc00\n"
	       "   hostap_rid wlan0 set fc00 06 00\n"
	       "   hostap_rid wlan0 set fc0e 06 00 66 6f 6f 62 61 72\n"
	       "\n"
	       "Note:\n"
	       "- Prism2/2.5/3 uses little-endian byte order\n"
	       "- The most common word size is 16 bits\n"
	       "- Set command needs the raw RID contents, i.e., it will be "
	       "written as is to the device\n");
}


static int get_rid(const char *dev, u16 rid)
{
	char buf[PRISM2_HOSTAPD_MAX_BUF_SIZE];
	struct prism2_hostapd_param *param;
	int res, i;

	param = (struct prism2_hostapd_param *) buf;

	res = hostapd_get_rid(dev, param, rid, 1);
	if (res == EPERM) {
		printf("hostap_rid requires root privileges\n");
		return -1;
	}
	if (res == ENODATA) {
		printf("Get RID did not return any data.\n");
		return -1;
	} else if (res) {
		printf("Could not communicate with the kernel driver.\n");
		return -1;
	}

	for (i = 0; i < param->u.rid.len; i++)
		printf("%02x ", param->u.rid.data[i]);
	printf("\n");

	return 0;
}


static int set_rid(const char *dev, u16 rid, int argc, char *argv[])
{
	u8 *data;
	int res, i;
	long int val;

	data = (u8 *) malloc(argc);
	if (data == NULL)
		return -1;

	for (i = 0; i < argc; i++) {
		val = strtol(argv[i], NULL, 16);
		if (val < 0 || val > 255) {
			usage();
			printf("\nInvalid data value '%s'\n", argv[i]);
			return -1;
		}
		data[i] = val;
	}

	res = hostapd_set_rid(dev, rid, data, argc, 1);
	if (res == EPERM) {
		printf("hostap_rid requires root privileges\n");
		return -1;
	}
	if (res) {
		printf("Could not communicate with the kernel driver.\n");
		return -1;
	}

	return 0;
}


int main(int argc, char *argv[])
{
	char *dev;
	int set;
	long int rid;

	if (argc < 4) {
		usage();
		return -1;
	}

	dev = argv[1];
	if (strcmp(argv[2], "set") == 0)
		set = 1;
	else if (strcmp(argv[2], "get") == 0)
		set = 0;
	else {
		usage();
		return -1;
	}

	rid = strtol(argv[3], NULL, 16);
	if (rid < 0 || rid > 65535) {
		usage();
		printf("\nInvalid rid 0x%lx\n", rid);
		return -1;
	}

	if (set)
		return set_rid(dev, rid, argc - 4, &argv[4]);
	else
		return get_rid(dev, rid);
}
