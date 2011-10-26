/*
 * qspi.c
 *
 * A small testbed for receiving data from an MCP3202 device (a small
 * two-channel ADC) on the qspi bus of a Motorola Coldfire 5272 to
 * determine whether data is being correctly received on the qspi bus.
 *
 * The method used to determine whether we are getting sensible data
 * from the ADC across the QSPI bus is as follows: we read a small number
 * of samples from the ADC in rapid succession. If the data points are
 * non trivial (all zero or all one) and changing, then we declare the
 * qspi port to be successfully receiving data, and the program returns
 * zero. Otherwise the program returns 1, signifying a qspi failure.
 *
 *
 * It is based on kendin-config.c, whose copyright appears below,
 * and was modified by Michael Leslie <mleslie> of
 * Arcturus Networks Inc. <arcturusnetworks.com> in 2004
 *
 * Copyright (c) 2003 Miriam Technologies Inc. <uclinux@miriamtech.com>
 * Copyright (c) 2003 Engineering Technologies Canada Ltd. (engtech.ca)
 * Copyright (c) 2003 Travis Griggs <tgriggs@keyww.com>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <getopt.h>

#include <asm/coldfire.h>
#include <asm/mcf_qspi.h>

#define _DECLARE_
#include "qspi.h"

/****** function declarations: ***********************************************/

int spiRead(int port_fd, uint8_t registerIndex)
{
	int registerValue = 0;
	uint32_t count;
	qspi_read_data readData;
	unsigned int *pi;
	unsigned char buf[5] = { 0, 0, 0, 0, 0 };

	memcpy(readData.buf, buf, sizeof(buf));
	pi = (unsigned int *)(&readData.buf[0]);
	*pi = (0xc0000000 | (opt_channel << 29)) >> opt_cmd_shift;

	/* readData.buf[1] = registerIndex; */
	readData.length = 4;
	readData.loop = 0;
	if (ioctl(port_fd, QSPIIOCS_READDATA, &readData))
		perror("QSPIIOCS_READDATA");
	count = read(port_fd, &registerValue, 4);
	if (count != 4)
		perror("read");

	return registerValue;
}

/****** option parsing etc: **************************************************/

void usage()
{
	int i;

	puts("usage: argv[0] <options>\n");

	for (i = 0; options[i].name; i++) {
		printf("  --%-9s", options[i].name);
		if (options[i].val) {
			printf(" (-%c)", options[i].val);
		} else {
			printf("    ");
		}
		if (options[i].has_arg == required_argument) {
			printf(" <arg>: ");
		} else if (options[i].has_arg == optional_argument) {
			printf(" [arg]: ");
		} else {
			printf(":       ");
		}
		if (option_help[i] != NULL)
			printf("%s", option_help[i]);
		puts("");
	}
}

void init_options()
{
	opt_port = "/dev/qspi0\0\0\0";
	opt_polarity = 1;
	opt_phase = 0;
	opt_channel = 0;
	opt_bits = 16;
	opt_cmd_shift = 7;
	opt_ret_shift = 8;
	opt_baud = 200000;	/* baud rate divider =  (MCF_CLK / (2 * baud)) */
	opt_N = 16;		/* number of samples */
	opt_continuous = 0;
	opt_help = 0;
	opt_verbose = 0;
}

int decode_args(int argc, char *argv[])
{
	int optc, optind;
	char *endptr;

	if (build_option_string(options, option_string)) {
		usage();
		exit(-EINVAL);
	}

	while (1) {
		optc = getopt_long(argc, argv, option_string, options, &optind);
		if (optc == -1)
			break;

		switch (optc) {
		case 0:
			/* ie. longopt only: */
			DBG("optind = %d, name = \"%s\", optarg = \"%s\"\n",
			    optind, options[optind].name, optarg);
			/* if (strcmp (options[optind].name, "wisdomfile") == 0) */
			/*      opt_wisdomfile = strdup (optarg); */
			break;

		case 'p':
			opt_port = strdup(optarg);
			if (opt_port == NULL) {
				usage();
				exit(-EINVAL);
			}
			break;

		case 'l':
			opt_polarity = (int)strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage();
				exit(-EINVAL);
			}
			break;

		case 'a':
			opt_phase = (int)strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage();
				exit(-EINVAL);
			}
			break;

		case 'c':
			opt_channel = (int)strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage();
				exit(-EINVAL);
			}
			break;

		case 'b':
			opt_bits = (int)strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage();
				exit(-EINVAL);
			}
			break;

		case 'm':
			opt_cmd_shift = (int)strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage();
				exit(-EINVAL);
			}
			break;

		case 'r':
			opt_ret_shift = (int)strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage();
				exit(-EINVAL);
			}
			break;

		case 'd':
			opt_baud = (int)strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage();
				exit(-EINVAL);
			}
			break;

		case 'n':
			opt_N = (int)strtol(optarg, &endptr, 10);
			if (*endptr != '\0') {
				usage();
				exit(-EINVAL);
			}
			/* impose sensible N? - mles */
			break;

		case 't':
			opt_continuous = 1;
			break;

		case 'v':
			opt_verbose = 1;
			break;

		default:
		case 'h':
			usage();
			exit(0);
			break;
		}
	}

	return (0);
}

/*
 * int build_option_string()
 *
 * takes getopt_long format structs at (struct option *)longopts
 * and builds an option string you point to at (char *)option_string
 */
int build_option_string(struct option *longopts, char *option_string)
{
	struct option *longopt = longopts;
	char *op = option_string;

	if (longopt == NULL)
		return (-1);

	/* DBG ("option_string_size = %d\n", 3*N_OPTIONS); */

	while (longopt->name != NULL) {
		if (longopt->val != 0) {

			/* DBG ("longopt->val = '%c'\n", longopt->val); */

			/* add single option char to string */
			*op++ = longopt->val;
			if (longopt->has_arg)
				*op++ = ':';	/* one colon for required arg */
			if (longopt->has_arg == optional_argument)
				*op++ = ':';	/* two for optional arg */
		}
		longopt++;
	}
	*op = '\0';

	/* DBG("option string = \"%s\"\n", option_string); */
	return (0);
}
