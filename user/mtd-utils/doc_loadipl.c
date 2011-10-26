/*****************************************************************************/

/*
 *	doc_loadipl -- Load an IPL into a DoC Millennium Plus.
 *
 *	(C) Copyright 2002, Greg Ungerer (gerg@snapgear.com)
 *	(C) Copyright 2003, SnapGear (www.snapgear.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>

#include <linux/types.h>
#include <linux/ioctl.h>
#include "mtd/mtd-user.h"

/*****************************************************************************/

#ifndef MEMREADDATA
/*
 * if the kernel doesn't define these,  then it probably doesn't
 * support them,  just make sure we use really broken values that
 * won't try to work
 */
#define	MEMREADDATA             _IOWR('M', -1, struct mtd_oob_buf)
#define	MEMWRITEDATA            _IOWR('M', -1, struct mtd_oob_buf)
#endif

/*****************************************************************************/

char	*version = "1.0.0";

/*
 *	Hard code DoC sector size and OOB size.
 */
#define	SECTORSIZE	512
#define	OOBSIZE		16

/*
 *	Offset into the raw flash area that the IPL is stored at on
 *	the Millennium Plus devices.
 */
unsigned int	iploffset = 65536;	/* Unit 2 - start address */
unsigned int	iplsize = 32768;	/* 1 Erase segment in size */
unsigned int	iplcopy0offset = 2048;	/* Offset in unit to copy0 of IPL */

/*****************************************************************************/

unsigned int memcpyx2(unsigned char *dst, unsigned char *src, unsigned int len)
{
	int x, y;

	for (x = y = 0; (y < len); ) {
		dst[y++] = src[x];
		dst[y++] = src[x++];
	}
	return(len);
}

/*****************************************************************************/

void usage(int rc)
{
	fprintf(stderr,
		"usage: doc_loadipl [-?hvf] [-e offset] <mtd-device> <ipl-binary>\n\n"
		"\t-v\tprint version and exit\n"
		"\t-e offset\tget ECC from sector at offset bytes\n"
		"\t-h?\tprint this usage\n"
		"\t-f\tdo not write to mtd device, out to stdout\n");

	exit(rc);
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	int i, j, noflash;
	int mtdfd, iplfd;
	char *device, *iplfile;
	unsigned int ipllimit, mtdbufsize, ecc_offset = -1;
	unsigned char *mtdbuf, *mp;
	unsigned char iplbuf[512];
	unsigned char iplecc[16] = {
		0x8e, 0x6e, 0x88, 0x10, 0x94, 0x94, 0x55, 0x55,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	struct mtd_oob_buf oobbuf;
	struct erase_info_user erase;

	noflash = 0;
	device = NULL;
	iplfile = NULL;

	while ((i = getopt(argc, argv, "?hvfe:")) > 0) {
		switch (i) {
		case 'f':
			noflash++;
			break;
		case 'e':
			ecc_offset = atoi(optarg);
			break;
		case 'v':
			fprintf(stderr, "doc_loadipl: version %s\n", version);
			break;
		case 'h':
		case '?':
			usage(0);
			break;
		default:
			fprintf(stderr, "ERROR: unknown option '%c'\n", i);
			usage(1);
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "ERROR: missing <mtd-device> argument\n");
		usage(1);
	}
	device = argv[optind++];

	if (optind >= argc) {
		fprintf(stderr, "ERROR: missing <ipl-file> argument\n");
		usage(1);
	}
	iplfile = argv[optind++];

	/*
	 *	Read the IPL binary into a local buffer.
	 */
	if ((iplfd = open(iplfile, O_RDONLY)) < 0) {
		fprintf(stderr, "ERROR: failed to open(%s) IPL, errno=%d\n",
			iplfile, errno);
		exit(1);
	}
	memset(iplbuf, 0, 512);
	if ((i = read(iplfd, iplbuf, 512)) < 0) {
		fprintf(stderr, "ERROR: failed to read(%d bytes)=%d from "
			"IPL file, errno=%d\n", 512, i, errno);
		exit(1);
	}
	close(iplfd);

	/*
	 *	Merge the IPL code into UNIT 3 of the mtd device.
	 */
	if ((mtdfd = open(device, O_RDWR)) < 0) {
		fprintf(stderr, "ERROR: failed to open(%s) device, errno=%d\n",
			device, errno);
		exit(1);
	}

	mtdbufsize = iplsize + ((iplsize / SECTORSIZE) * OOBSIZE);
	if ((mtdbuf = malloc(mtdbufsize)) == NULL) {
		fprintf(stderr, "ERROR: failed to malloc(%d bytes), errno=%d\n",
			mtdbufsize, errno);
		exit(1);
	}

	ipllimit = iploffset + iplsize;
	for (i = iploffset, j = 0; (i < ipllimit); i += SECTORSIZE) {
		oobbuf.start = i;
		oobbuf.length = SECTORSIZE;
		oobbuf.ptr = &mtdbuf[j];
		if (ioctl(mtdfd, MEMREADDATA, &oobbuf) < 0) {
			fprintf(stderr, "ERROR: failed to ioctl(MEMREADDATA) "
				"from MTD device, errno=%d\n", errno);
			exit(1);
		}
		j += SECTORSIZE;

		oobbuf.start = i;
		oobbuf.length = OOBSIZE;
		oobbuf.ptr = &mtdbuf[j];
		if (ioctl(mtdfd, MEMREADOOB, &oobbuf) < 0) {
			fprintf(stderr, "ERROR: failed to ioctl(MEMREADOOB) "
				"from MTD device, errno=%d\n", errno);
			exit(1);
		}
		j += OOBSIZE;
	}

	/* until proper ECC calculations are working,  do it this way */
	if (ecc_offset != -1) {
		oobbuf.start = ecc_offset;
		oobbuf.length = OOBSIZE;
		oobbuf.ptr = &iplecc[0];
		if (ioctl(mtdfd, MEMREADOOB, &oobbuf) < 0) {
			fprintf(stderr, "ERROR: failed to ioctl(MEMREADOOB) "
				"from MTD device, errno=%d\n", errno);
			exit(1);
		}
	}

	/* Copy 0 and 1 of the IPL */
	j = iplcopy0offset + ((iplcopy0offset / SECTORSIZE) * OOBSIZE);

	if ((j + ((SECTORSIZE + OOBSIZE) * 4)) > mtdbufsize) {
		fprintf(stderr,"ERROR: IPL extends past end of unit?\n");
		exit(1);
	}

	/* FIXME: Generate the ECC checksum for this block */
	//if (ecc_offset == -1)
	//doc_rsencode(&iplbuf[0], &iplecc[0]);

	printf("ECC: ");
	for (i = 0; i < OOBSIZE; i++)
		printf("%02x ", iplecc[i]);
	printf("\n");

	mp = &mtdbuf[j];

	/*
	 *	Crazy data re-arrangement to put the IPL code in the DoC in
	 *	a linear fashion. We need to remap based on the underlying
	 *	way the doc2001plus driver interleaves sector data/oob.
	 */
	memcpyx2(&mp[0], &iplbuf[0], 512);		/* Sector 0 data */
	memcpyx2(&mp[512], &iplbuf[256], 6);		/* Sector 0 ECC */
	memcpyx2(&mp[518], &iplbuf[259], 2);		/* Sector 0 flags */
	memcpyx2(&mp[520], &iplecc[8], 8);		/* Sector 0 header */

	memcpyx2(&mp[528], &iplbuf[261], 502);		/* Sector 1 data */
	memcpyx2(&mp[1030], &iplecc[0], 10);
	memcpyx2(&mp[1040], &iplecc[5], 6);		/* Sector 1 ECC */
	memcpyx2(&mp[1046], &iplbuf[260], 2);		/* Sector 1 flags */
	memcpyx2(&mp[1048], &iplecc[12], 8);		/* Sector 1 header */

	if (noflash) {
		if ((i = write(1, mtdbuf, mtdbufsize)) != mtdbufsize) {
			fprintf(stderr, "ERROR: failed to write(%d bytes)=%d "
				"to stdout, errno=%d\n", mtdbufsize, i, errno);
			exit(1);
		}
	} else {
		/* Erase the IPL sector */
		erase.start = iploffset;
		erase.length = iplsize;
		if (ioctl(mtdfd, MEMERASE, &erase) < 0) {
			fprintf(stderr, "ERROR: failed to ioctl(MEMERASE) "
				"MTD device, errno=%d\n", errno);
			exit(1);
		}

		/* Re-program the IPL sector */
		for (i = iploffset, j = 0; (i < ipllimit); i += SECTORSIZE) {
			oobbuf.start = i;
			oobbuf.length = SECTORSIZE;
			oobbuf.ptr = &mtdbuf[j];
			if (ioctl(mtdfd, MEMWRITEDATA, &oobbuf) < 0) {
				fprintf(stderr, "ERROR: failed to "
					"ioctl(MEMWRITEDATA) from MTD device, "
					"errno=%d\n", errno);
				exit(1);
			}
			j += SECTORSIZE;

			oobbuf.start = i;
			oobbuf.length = OOBSIZE;
			oobbuf.ptr = &mtdbuf[j];
			if (ioctl(mtdfd, MEMWRITEOOB, &oobbuf) < 0) {
				fprintf(stderr, "ERROR: failed to "
					"ioctl(MEMWRITEOOB) from MTD device, "
					"errno=%d\n", errno);
				exit(1);
			}
			j += OOBSIZE;
		}
	}

	close(mtdfd);
	return(0);
}

/*****************************************************************************/
