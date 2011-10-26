/*
 * FILE flash_unlock.c
 *
 * This utility unlock all sectors of flash device.
 *
 */

#define PROGRAM_NAME "flash_unlock"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <string.h>

#include <mtd/mtd-user.h>

int main(int argc, char *argv[])
{
	int fd;
	struct mtd_info_user mtdInfo;
	struct erase_info_user mtdLockInfo;
	int count;

	/*
	 * Parse command line options
	 */
	if(argc < 2)
	{
		fprintf(stderr, "USAGE: %s <mtd device> <offset in hex> <block count in decimal number>\n", PROGRAM_NAME);
		exit(1);
	}
	else if(strncmp(argv[1], "/dev/mtd", 8) != 0)
	{
		fprintf(stderr, "'%s' is not a MTD device.  Must specify mtd device: /dev/mtd?\n", argv[1]);
		exit(1);
	}

	fd = open(argv[1], O_RDWR);
	if(fd < 0)
	{
		fprintf(stderr, "Could not open mtd device: %s\n", argv[1]);
		exit(1);
	}

	if(ioctl(fd, MEMGETINFO, &mtdInfo))
	{
		fprintf(stderr, "Could not get MTD device info from %s\n", argv[1]);
		close(fd);
		exit(1);
	}

	if (argc > 2)
		mtdLockInfo.start = strtol(argv[2], NULL, 0);
	else
		mtdLockInfo.start = 0;

	if (argc > 3) {
		count = strtol(argv[3], NULL, 0);
		mtdLockInfo.length = mtdInfo.erasesize * count;
	} else {
		mtdLockInfo.length = mtdInfo.size - mtdInfo.erasesize;
	}

	if(ioctl(fd, MEMUNLOCK, &mtdLockInfo))
	{
		fprintf(stderr, "Could not unlock MTD device: %s\n", argv[1]);
		close(fd);
		exit(1);
	}

	return 0;
}
