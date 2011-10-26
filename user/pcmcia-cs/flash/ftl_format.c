/*======================================================================

    Utility to create an FTL partition in a memory region

    ftl_format.c 1.15 2001/04/03 00:04:25

    The contents of this file are subject to the Mozilla Public
    License Version 1.1 (the "License"); you may not use this file
    except in compliance with the License. You may obtain a copy of
    the License at http://www.mozilla.org/MPL/

    Software distributed under the License is distributed on an "AS
    IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
    implied. See the License for the specific language governing
    rights and limitations under the License.

    The initial developer of the original code is David A. Hinds
    <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
    are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.

    Alternatively, the contents of this file may be used under the
    terms of the GNU Public License version 2 (the "GPL"), in which
    case the provisions of the GPL are applicable instead of the
    above.  If you wish to allow the use of your version of this file
    only under the terms of the GPL and not to allow others to use
    your version of this file under the MPL, indicate your decision
    by deleting the provisions above and replace them with the notice
    and other provisions required by the GPL.  If you do not delete
    the provisions above, a recipient may use your version of this
    file under either the MPL or the GPL.

======================================================================*/

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/bulkmem.h>
#include <pcmcia/ftl.h>
#include <pcmcia/memory.h>

/*====================================================================*/

static void print_size(u_int s)
{
    if ((s > 0x100000) && ((s % 0x100000) == 0))
	printf("%d mb", s / 0x100000);
    else if ((s > 0x400) && ((s % 0x400) == 0))
	printf("%d kb", s / 0x400);
    else
	printf("%d bytes", s);
}

/*====================================================================*/

static const char LinkTarget[] = {
    0x13, 0x03, 'C', 'I', 'S'
};
static const char DataOrg[] = {
    0x46, 0x39, 0x00, 'F', 'T', 'L', '1', '0', '0', 0x00
};

static void build_header(erase_unit_header_t *hdr, u_int RegionSize,
			 u_int BlockSize, u_int Spare, int Reserve,
			 u_int BootSize)
{
    u_int i, BootUnits, nbam;
    
    /* Default everything to the erased state */
    memset(hdr, 0xff, sizeof(*hdr));
    memcpy(hdr->LinkTargetTuple, LinkTarget, 5);
    memcpy(hdr->DataOrgTuple, DataOrg, 10);
    hdr->EndTuple[0] = hdr->EndTuple[1] = 0xff;
    BootSize = (BootSize + (BlockSize-1)) & ~(BlockSize-1);
    BootUnits = BootSize / BlockSize;
    
    /* We only support 512-byte blocks */
    hdr->BlockSize = 9;
    hdr->EraseUnitSize = 0;
    for (i = BlockSize; i > 1; i >>= 1)
	hdr->EraseUnitSize++;
    hdr->EraseCount = 0;
    hdr->FirstPhysicalEUN = BootUnits;
    hdr->NumEraseUnits = (RegionSize - BootSize) >> hdr->EraseUnitSize;
    hdr->NumTransferUnits = Spare;
    hdr->FormattedSize =
	RegionSize - ((Spare + BootUnits) << hdr->EraseUnitSize);
    /* Leave a little bit of space between the CIS and BAM */
    hdr->BAMOffset = 0x80;
    /* Adjust size to account for BAM space */
    nbam = ((1 << (hdr->EraseUnitSize - hdr->BlockSize)) * sizeof(u_int)
	    + hdr->BAMOffset + (1 << hdr->BlockSize) - 1) >> hdr->BlockSize;
    hdr->FormattedSize -=
	(hdr->NumEraseUnits - Spare) * (nbam << hdr->BlockSize);
    hdr->FormattedSize -= ((hdr->FormattedSize * Reserve / 100) & ~0xfff);
    hdr->FirstVMAddress = 0xffffffff;
    hdr->NumVMPages = 0;
    hdr->Flags = 0;
    /* hdr->Code defaults to erased state */
    hdr->SerialNumber = time(NULL);
    /* hdr->AltEUHOffset defaults to erased state */

} /* build_header */

/*====================================================================*/

static int format_partition(int fd, int quiet, int interrogate,
			    u_int spare, int reserve, u_int bootsize)
{
    region_info_t region;
    erase_info_t erase;
    erase_unit_header_t hdr;
    u_int step, lun, i, nbam, *bam;
    
    /* Get partition size, block size */
    if (ioctl(fd, MEMGETINFO, &region) != 0) {
	perror("get info failed");
	return -1;
    }

    /* Intel Series 100 Flash: skip first block */
    if ((region.JedecMfr == 0x89) && (region.JedecInfo == 0xaa) &&
	(bootsize == 0)) {
	if (!quiet)
	    printf("Skipping first block to protect CIS info...\n");
	bootsize = 1;
    }
    
    /* Create header */
    build_header(&hdr, region.RegionSize, region.BlockSize,
		 spare, reserve, bootsize);

    if (!quiet) {
	printf("Partition size = ");
	print_size(region.RegionSize);
	printf(", erase unit size = ");
	print_size(region.BlockSize);
	printf(", %d transfer units\n", spare);
	if (bootsize != 0) {
	    print_size(hdr.FirstPhysicalEUN << hdr.EraseUnitSize);
	    printf(" allocated for boot image\n");
	}
	printf("Reserved %d%%, formatted size = ", reserve);
	print_size(hdr.FormattedSize);
	printf("\n");
	fflush(stdout);
    }

    if (interrogate) {
	char str[3];
	printf("This will destroy all data on the target device.  "
	       "Confirm (y/n): ");
	if (fgets(str, 3, stdin) == NULL)
	    return -1;
	if ((strcmp(str, "y\n") != 0) && (strcmp(str, "Y\n") != 0))
	    return -1;
    }
    
    /* Create basic block allocation table for control blocks */
    nbam = ((region.BlockSize >> hdr.BlockSize) * sizeof(u_int)
	    + hdr.BAMOffset + (1 << hdr.BlockSize) - 1) >> hdr.BlockSize;
    bam = malloc(nbam * sizeof(u_int));
    for (i = 0; i < nbam; i++)
	bam[i] = BLOCK_CONTROL;
    
    /* Erase partition */
    if (!quiet) {
	printf("Erasing all blocks...\n");
	fflush(stdout);
    }
    erase.Size = region.BlockSize;
    erase.Offset = region.BlockSize * hdr.FirstPhysicalEUN;
    for (i = 0; i < hdr.NumEraseUnits; i++) {
	if (ioctl(fd, MEMERASE, &erase) != 0) {
	    if (!quiet) {
		putchar('\n');
		fflush(stdout);
	    }
	    perror("block erase failed");
	    return -1;
	}
	erase.Offset += erase.Size;
	if (!quiet) {
	    if (region.RegionSize <= 0x800000) {
		if (erase.Offset % 0x100000) {
		    if (!(erase.Offset % 0x20000)) putchar('-');
		}
		else putchar('+');
	    }
	    else {
		if (erase.Offset % 0x800000) {
		    if (!(erase.Offset % 0x100000)) putchar('+');
		}
		else putchar('*');
	    }
	    fflush(stdout);
	}
    }
    if (!quiet) putchar('\n');

    /* Prepare erase units */
    if (!quiet) {
	printf("Writing erase unit headers...\n");
	fflush(stdout);
    }
    lun = 0;
    /* Distribute transfer units over the entire region */
    step = (spare) ? (hdr.NumEraseUnits/spare) : (hdr.NumEraseUnits+1);
    for (i = 0; i < hdr.NumEraseUnits; i++) {
	u_int ofs = (i + hdr.FirstPhysicalEUN) << hdr.EraseUnitSize;
	if (lseek(fd, ofs, SEEK_SET) == -1) {
	    perror("seek failed");
	    break;
	}
	/* Is this a transfer unit? */
	if (((i+1) % step) == 0)
	    hdr.LogicalEUN = 0xffff;
	else {
	    hdr.LogicalEUN = lun;
	    lun++;
	}
	if (write(fd, &hdr, sizeof(hdr)) == -1) {
	    perror("write failed");
	    break;
	}
	if (lseek(fd, ofs + hdr.BAMOffset, SEEK_SET) == -1) {
	    perror("seek failed");
	    break;
	}
	if (write(fd, bam, nbam * sizeof(u_int)) == -1) {
	    perror("write failed");
	    break;
	}
    }
    if (i < hdr.NumEraseUnits)
	return -1;
    else
	return 0;
} /* format_partition */

/*====================================================================*/

int main(int argc, char *argv[])
{
    int quiet, interrogate, reserve;
    int optch, errflg, fd, ret;
    u_int spare, bootsize;
    char *s;
    extern char *optarg;
    struct stat buf;

    quiet = 0;
    interrogate = 0;
    spare = 1;
    reserve = 5;
    errflg = 0;
    bootsize = 0;
    
    while ((optch = getopt(argc, argv, "qir:s:b:")) != -1) {
	switch (optch) {
	case 'q':
	    quiet = 1; break;
	case 'i':
	    interrogate = 1; break;
	case 's':
	    spare = strtoul(optarg, NULL, 0); break;
	case 'r':
	    reserve = strtoul(optarg, NULL, 0); break;
	case 'b':
	    bootsize = strtoul(optarg, &s, 0);
	    if ((*s == 'k') || (*s == 'K'))
		bootsize *= 1024;
	    break;
	default:
	    errflg = 1; break;
	}
    }
    if (errflg || (optind != argc-1)) {
	fprintf(stderr, "usage: %s [-q] [-i] [-s spare-blocks]"
		" [-r reserve-percent] [-b bootsize] device\n", argv[0]);
	exit(EXIT_FAILURE);
    }

    if (stat(argv[optind], &buf) != 0) {
	perror("status check failed");
	exit(EXIT_FAILURE);
    }
    if (!(buf.st_mode & S_IFCHR)) {
	fprintf(stderr, "%s is not a character special device\n",
		argv[optind]);
	exit(EXIT_FAILURE);
    }
    fd = open(argv[optind], O_RDWR);
    if (fd == -1) {
	perror("open failed");
	exit(EXIT_FAILURE);
    }

    ret = format_partition(fd, quiet, interrogate, spare, reserve,
			   bootsize);
    if (!quiet) {
	if (ret)
	    printf("format failed.\n");
	else
	    printf("format successful.\n");
    }
    close(fd);
    
    exit((ret) ? EXIT_FAILURE : EXIT_SUCCESS);
    return 0;
}
