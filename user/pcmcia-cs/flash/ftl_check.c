/*======================================================================

    Utility to create an FTL partition in a memory region

    ftl_check.c 1.11 2000/06/12 21:33:50

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

static void check_partition(int fd, int verbose)
{
    region_info_t region;
    erase_unit_header_t hdr, hdr2;
    u_int i, j, nbam, *bam;
    int control, data, free, deleted;
    
    /* Get partition size, block size */
    if (ioctl(fd, MEMGETINFO, &region) != 0) {
	perror("get info failed");
	return;
    }

    printf("Memory region info:\n");
    printf("  Card offset = 0x%x, region size = ", region.CardOffset);
    print_size(region.RegionSize);
    printf(", access speed = %u ns\n", region.AccessSpeed);
    printf("  Erase block size = ");
    print_size(region.BlockSize);
    printf(", partition multiple = ");
    print_size(region.PartMultiple);
    printf("\n\n");

    for (i = 0; i < region.RegionSize/region.BlockSize; i++) {
	if (lseek(fd, (i * region.BlockSize), SEEK_SET) == -1) {
	    perror("seek failed");
	    break;
	}
	read(fd, &hdr, sizeof(hdr));
	if ((hdr.FormattedSize > 0) &&
	    (hdr.FormattedSize <= region.RegionSize) &&
	    (hdr.NumEraseUnits > 0) &&
	    (hdr.NumEraseUnits <= region.RegionSize/region.BlockSize))
	    break;
    }
    if (i == region.RegionSize/region.BlockSize) {
	fprintf(stderr, "No valid erase unit headers!\n");
	return;
    }
    
    printf("Partition header:\n");
    printf("  Formatted size = ");
    print_size(hdr.FormattedSize);
    printf(", erase units = %d, transfer units = %d\n",
	   hdr.NumEraseUnits, hdr.NumTransferUnits);
    printf("  Erase unit size = ");
    print_size(1 << hdr.EraseUnitSize);
    printf(", virtual block size = ");
    print_size(1 << hdr.BlockSize);
    printf("\n");
    
    /* Create basic block allocation table for control blocks */
    nbam = (region.BlockSize >> hdr.BlockSize);
    bam = malloc(nbam * sizeof(u_int));

    for (i = 0; i < hdr.NumEraseUnits; i++) {
	if (lseek(fd, (i << hdr.EraseUnitSize), SEEK_SET) == -1) {
	    perror("seek failed");
	    break;
	}
	if (read(fd, &hdr2, sizeof(hdr2)) == -1) {
	    perror("read failed");
	    break;
	}
	printf("\nErase unit %d:\n", i);
	if ((hdr2.FormattedSize != hdr.FormattedSize) ||
	    (hdr2.NumEraseUnits != hdr.NumEraseUnits) ||
	    (hdr2.SerialNumber != hdr.SerialNumber))
	    printf("  Erase unit header is corrupt.\n");
	else if (hdr2.LogicalEUN == 0xffff)
	    printf("  Transfer unit, erase count = %d\n", hdr2.EraseCount);
	else {
	    printf("  Logical unit %d, erase count = %d\n",
		   hdr2.LogicalEUN, hdr2.EraseCount);
	    if (lseek(fd, (i << hdr.EraseUnitSize)+hdr.BAMOffset,
		      SEEK_SET) == -1) {
		perror("seek failed");
		break;
	    }
	    if (read(fd, bam, nbam * sizeof(u_int)) == -1) {
		perror("read failed");
		break;
	    }
	    free = deleted = control = data = 0;
	    for (j = 0; j < nbam; j++) {
		if (BLOCK_FREE(bam[j]))
		    free++;
		else if (BLOCK_DELETED(bam[j]))
		    deleted++;
		else switch (BLOCK_TYPE(bam[j])) {
		case BLOCK_CONTROL: control++; break;
		case BLOCK_DATA: data++; break;
		default: break;
		}
	    }
	    printf("  Block allocation: %d control, %d data, %d free,"
		   " %d deleted\n", control, data, free, deleted);
	}
    }
} /* format_partition */

/*====================================================================*/

int main(int argc, char *argv[])
{
    int verbose;
    int optch, errflg, fd;
    struct stat buf;
    
    errflg = 0;
    verbose = 0;
    while ((optch = getopt(argc, argv, "v")) != -1) {
	switch (optch) {
	case 'v':
	    verbose = 1; break;
	default:
	    errflg = 1; break;
	}
    }
    if (errflg || (optind != argc-1)) {
	fprintf(stderr, "usage: %s [-v] device\n", argv[0]);
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
    fd = open(argv[optind], O_RDONLY);
    if (fd == -1) {
	perror("open failed");
	exit(EXIT_FAILURE);
    }

    check_partition(fd, verbose);
    close(fd);
    
    exit(EXIT_SUCCESS);
    return 0;
}
