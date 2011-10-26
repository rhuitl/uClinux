/*
 * qspirx.c
 *
 * A small testbed for receiving data from an MCP3202 device (a small
 * two-channel ADC) on the qspi bus of a Motorola Coldfire 5272 using
 * the mcf_qspi kernel driver.
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
#include <asm/mcfsim.h>

#include "qspi.h"

/****** storage declaration: *************************************************/

int32_t serialPort;
char *programName;

unsigned short *buf;

/****** main program: ********************************************************/

int main(int argc, char **argv)
{
	int i;
	unsigned int j;
	unsigned int baud_divider;

	init_options();
	decode_args(argc, argv);

	serialPort = open(opt_port, O_RDWR);
	if (serialPort < 0) {
		perror("open");
		exit(1);
	} else
		printf("%s opened for read\n", opt_port);

	if (ioctl(serialPort, QSPIIOCS_DOUT_HIZ, 0)) {
		perror("QSPIIOCS_DOUT_HIZ");
		exit(-EINVAL);
	}
	if (ioctl(serialPort, QSPIIOCS_BITS, opt_bits)) {
		perror("QSPIIOCS_BITS");
		exit(-EINVAL);
	}
	if (ioctl(serialPort, QSPIIOCS_CPOL, opt_polarity)) {
		perror("QSPIIOCS_CPOL");
		exit(-EINVAL);
	}
	if (ioctl(serialPort, QSPIIOCS_CPHA, opt_phase)) {
		perror("QSPIIOCS_CPHA");
		exit(-EINVAL);
	}
	baud_divider =
	    (int)(((double)MCF_BUSCLK / (2.0 * (double)opt_baud)) + 0.5);
	if (ioctl(serialPort, QSPIIOCS_BAUD, baud_divider)) {
		perror("QSPIIOCS_BAUD");
		exit(-EINVAL);
	}
	PRINTV("baud rate divider = %d; actual baud rate: %d bps\n",
	       baud_divider, MCF_CLK / (2 * baud_divider));

	/* QSPIIOCS_QCD: QSPI_CS to QSPI_CLK setup */
	/* QSPIIOCS_DTL: QSPI_CLK to QSPI_CS hold */
	/* QSPIIOCS_CONT */
	/* QSPIIOCS_DSP_MOD */
	/* QSPIIOCS_ODD_MOD */
	/* QSPIIOCS_POLL_MOD */

	buf = malloc(opt_N * sizeof(short));
	if (buf == NULL) {
		perror("Error allocating read buffer");
		exit(-ENOMEM);
	}

	for (i = 0; i < opt_N; i++) {
		j = spiRead(serialPort, 0);
		j = j >> opt_ret_shift;
		buf[i] = (unsigned short)(j & 0x00000fff);

		if (opt_continuous)
			/* printf ("   0x%03X%s", buf[i], ((i+1)%4)?"":"\n"); */
			printf("   0x%03x%s", buf[i],
			       ((i + 1) % 4) ? "" : "\n");
	}
	printf("\n");

	printf("%d measurements were made from from ADC Channel %i:\n\n", opt_N,
	       opt_channel);

	if (!opt_continuous) {
		for (i = 0; i < opt_N; i++)
			printf("   0x%03X%s", buf[i],
			       ((i + 1) % 4) ? "" : "\n");
	}

	printf("\n\n");

	free(buf);
	return 0;
}
