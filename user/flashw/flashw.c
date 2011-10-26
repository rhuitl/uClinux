/*****************************************************************************/

/*
 *	flashw.c -- FLASH device writter.
 *
 *	(C) Copyright 1999-2001, Greg Ungerer (gerg@snapgear.com).
 *	(C) Copyright 2000-2001, Lineo Inc. (www.lineo.com)
 *	(C) Copyright 2000-2002, SnapGear (www.snapgear.com)
 */

/*****************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/autoconf.h>
#include <linux/version.h>
#ifdef CONFIG_MTD
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
#include <mtd/mtd-user.h>
#else 
#include <linux/mtd/mtd.h>
#endif
#elif defined(CONFIG_BLK_DEV_BLKMEM)
#include <linux/blkmem.h>
#endif
#if defined(CONFIG_NFTL_RW) && !defined(NFTL_MAJOR)
 #define NFTL_MAJOR 93
 #include <sys/mount.h>
#endif
#include <dirent.h>

/*****************************************************************************/

char *version = "1.3.4";

/*****************************************************************************/

void usage(int rc)
{
	printf("usage: flashw [-h?vbpeul] [-o <offset>] [-f <file> | values] "
		"<rom-device>\n\n"
		"\t-h\t\tthis help\n"
		"\t-v\t\tprint version info\n"
		"\t-b\t\targs to written in binary\n"
		"\t-p\t\tpreserve existing FLASH contents\n"
		"\t-e\t\tdo not erase first\n"
		"\t-u\t\tunlock FLASH segments before programming\n"
		"\t-l\t\tlock FLASH segments when done\n"
		"\t-o <offset>\twrite into FLASH at offset\n"
		"\t-F\t\tforce FLASH write\n"
		"\t-f <file>\tprogram contents of file\n\n");
	exit(rc);
}

/*****************************************************************************/

int mkbinbuf(char *str, char *buf, int len)
{
	int pos;
	char *ep, *sbuf;

	for (sbuf = buf, pos = 0; (pos < len); ) {
		*buf++ = strtol(str, &ep, 0);
		pos += (ep - str) + 1;
		str = ep + 1;
	}

	return (buf - sbuf);
}

/*****************************************************************************/

int sanity_check(int fd)
{
	dev_t mydev;
	int count = 0;
	DIR *dp;
	struct dirent *fp;
	struct stat st;
	char buf[300];
	
	if (fstat(fd, &st) < 0)
		return 0;
	mydev = st.st_rdev;

	dp = opendir("/dev/flash");
	if (dp == NULL)
		return 0;
	while ((fp = readdir(dp)) != NULL) {
		sprintf(buf, "%s/%s", "/dev/flash", fp->d_name);
		if (stat(buf, &st) < 0)
			continue;
		if (st.st_rdev == mydev)
			count++;
	}
	closedir(dp);
	return (count > 1);
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	int fd, fdcp;
	int size, pos, binary, erase, preserve, write_chunk;
	int dolock, dounlock, donftl, doforce;
	long offset, sector_size, device_size, data_size = 0;
	char *file, *flashdev, *sp, *pbuf;
	char buf[1024], *data_ptr = buf;
	struct stat stat_buf;

#ifdef CONFIG_MTD
	mtd_info_t mtd_info;
	erase_info_t erase_info;
#endif

	file = NULL;
	binary = 0;
	erase = 1;
	preserve = 0;
	offset = 0;
	dolock = 0;
	dounlock = 0;
	donftl = 0;
	doforce = 0;
	fdcp = -1;

	while ((pos = getopt(argc, argv, "Fh?bepulo:f:")) != EOF) {
		switch (pos) {
		case 'b':
			binary++;
			break;
		case 'F':
			doforce++;
			break;
		case 'f':
			file = optarg;
			break;
		case 'e':
			erase = 0;
			break;
		case 'p':
			preserve++;
			break;
		case 'u':
			dounlock++;
			break;
		case 'l':
			dolock++;
			break;
		case 'o':
			offset = strtol(optarg, NULL, 0);
			break;
		case 'v':
			printf("%s: version %s\n", argv[0], version);
			exit(0);
		case 'h':
		case '?':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (optind >= argc)
		usage(1);

	flashdev = argv[argc - 1];

#if defined(CONFIG_NFTL_RW)
	if (stat(flashdev, &stat_buf) == 0 && S_ISBLK(stat_buf.st_mode) &&
	    major(stat_buf.st_rdev) == NFTL_MAJOR) {
		donftl = 1;
		erase = 0;
		preserve = 0;
		dolock = 0;
	}
#endif

	/* Open and size the FLASH device. */
	if ((fd = open(flashdev, O_RDWR)) < 0) {
		printf("ERROR: failed to open(%s), errno=%d\n",
			flashdev, errno);
		exit(1);
	}
	
	/*
	 * Check the the flash device we're writing to is unique unless we're
	 * doing a forced write or we've set the preserve flash and an explicit
	 * offset or we aren't erasing.
	 */
	if ((preserve && offset > 0) || !erase)
		doforce++;
	if (!doforce && sanity_check(fd)) {
		printf("ERROR: multiple identical flash devices found. "
			"Try -p, -o and -F.\n");
		exit(1);
	}

#ifdef CONFIG_NFTL_RW
	if (donftl) {
		unsigned long l;

		if (ioctl(fd, BLKGETSIZE, &l) < 0) {
			printf("netflash: ioctl(BLKGETSIZE) failed, "
				"errno=%d\n", errno);
			exit(1);
		}
		device_size = l * 512;  /* Sectors are always 512 bytes */
		sector_size = 512;
		write_chunk = 512;
	}
	else
#endif
#if defined(CONFIG_MTD)
	{
		if (ioctl(fd, MEMGETINFO, &mtd_info) < 0) {
			printf("ERROR: ioctl(MEMGETINFO) failed, errno=%d\n",
				errno);
			exit(1);
		}
		device_size = mtd_info.size;
		sector_size = mtd_info.erasesize;
		write_chunk = 512;
	}
#elif defined(BMGETSIZEB) && defined(BMSGSIZE)
	{
		if (ioctl(fd, BMGETSIZEB, &device_size) < 0) {
			printf("ERROR: ioctl(BMGETSIZEB) failed, errno=%d\n",
				errno);
			exit(1);
		}
		if (ioctl(fd, BMSGSIZE, &sector_size) < 0) {
			printf("ERROR: ioctl(BMSGSIZE) failed, errno=%d\n",
				errno);
			exit(1);
		}
		write_chunk = sector_size;
	}
#else
	if (lseek(fd, SEEK_END, 0L) < 0) {
		printf("flashw: lseek (SEEK_END) failed, errno=%d\n", errno);
		exit(1);
	}
	device_size = lseek(fd, SEEK_CUR, 0L);
	sector_size = 512;
	write_chunk = 512;
	lseek(fd, SEEK_SET, 0L);
	printf("Using disk like behaviour, device_size=%d sector_size=512\n",
			device_size);
#endif

	if (offset >= device_size) {
		printf("ERROR: offset=%ld larger then FLASH size=%ld\n",
			offset, device_size);
		exit(1);
	}

	pbuf = (char *) malloc(sector_size);
	if (pbuf == (char *) NULL) {
		printf("ERROR: could not allocate %ld bytes for buffer, "
			"errno=%d\n", sector_size, errno);
		exit(1);
	}

	/*
	 * Work out how much data we have to write.
	 */
	if (file != NULL) {
		if (stat(file, &stat_buf) == -1) {
			printf("ERROR: could not stat %s, errno=%d\n",
				file, errno);
			exit(1);
		}
		data_size = stat_buf.st_size;

		if ((fdcp = open(file, O_RDONLY)) < 0) {
			printf("ERROR: failed to open(%s), errno=%d\n",
				file, errno);
			exit(1);
		}

	} else if (optind < argc - 1) {

		sp = buf;
		for (pos = optind; (pos < (argc - 1)); pos++) {
			if ((sp - buf) >= sizeof(buf))
				continue;

			if (binary) {
				sp += mkbinbuf(argv[pos], sp, strlen(argv[pos]));
			} else {
				if (sp != buf)
					*sp++ = ' ';
				size = sizeof(buf) - (sp - buf);
				strncpy(sp, argv[pos], size);
				sp += strnlen(argv[pos], size);
			}
		}

		/* Put string terminator if not in binary mode */
		if (!binary)
			*sp++ = '\0';

		data_size = sp - buf;
		data_ptr = buf;
	}

	/*
	 * Go through each sector,  preserve/unlock/erase/write/lock as
	 * required.
	 */
	pos = offset - (offset % sector_size);
	offset %= sector_size;
	for (; pos + sector_size <= device_size; pos += sector_size) {
		int last_sector = 0;

		/* Read the data before for preserving */
		if (preserve) {
			if (lseek(fd, pos, SEEK_SET) < 0) {
				printf("ERROR: lseek(pos=0x%x) failed, "
					"errno=%d\n", pos, errno);
				exit(1);
			}
			if (read(fd, pbuf, sector_size) != sector_size) {
				printf("ERROR: read(pos=%x) failed, "
					"errno=%d\n", pos, errno);
				exit(1);
			}
		}

#ifdef CONFIG_MTD
		if (dounlock) {
			erase_info.start = pos;
			erase_info.length = sector_size;
			ioctl(fd, MEMUNLOCK, &erase_info);
		}
#endif

		if (erase) {
#if defined(CONFIG_MTD)
			erase_info.start = pos;
			erase_info.length = sector_size;
			if (ioctl(fd, MEMERASE, &erase_info) == -1)
				printf("ERROR: ioctl(MEMERASE) failed, "
					"pos=%x, errno=%d\n", pos, errno);
#elif defined(BMSERASE)
 			if (ioctl(fd, BMSERASE, pos) < 0)
 				printf("ERROR: ioctl(BMERASE) failed, "
					"pos=%x, errno=%d\n", pos, errno);
#endif
		}

		/*
		 * Read the data after to preserve erase state is not preserving
		 */
		if (!preserve) {
			if (lseek(fd, pos, SEEK_SET) < 0) {
				printf("ERROR: lseek(pos=0x%x) failed, "
					"errno=%d\n", pos, errno);
				exit(1);
			}
			if (read(fd, pbuf, sector_size) != sector_size)
				printf("ERROR: read(pos=%x) failed, "
					"errno=%d\n", pos, errno);
		}

		if (file) {
			if (read(fdcp, &pbuf[offset], sector_size - offset) !=
					sector_size - offset)
				last_sector = 1;
		} else if (data_size) {
			memcpy(&pbuf[offset], data_ptr,
				data_size < (sector_size - offset) ?
				data_size : (sector_size - offset));
			data_ptr  += (sector_size - offset);
			data_size -= (sector_size - offset);
			if (data_size <= 0)
				last_sector = 1;
		}

		if (lseek(fd, pos, SEEK_SET) < 0) {
			printf("ERROR: lseek(pos=0x%x) failed, errno=%d\n",
				pos, errno);
			exit(1);
		}

		for (sp = pbuf; sp < pbuf + sector_size; sp += write_chunk)
			if (write(fd, sp, write_chunk) != write_chunk)
				printf("ERROR: write(size=%d) failed, "
					"errno=%d\n", write_chunk, errno);

#ifdef CONFIG_MTD
		if (dolock) {
			erase_info.start = pos;
			erase_info.length = sector_size;
			if (ioctl(fd, MEMLOCK, &erase_info) < 0)
				printf("ERROR: ioctl(MEMLOCK) failed, "
					"errno=%d\n", errno);
		}
#endif /* CONFIG_MTD */

		if (last_sector)
			break;

		offset = 0;
	}

	free(pbuf);
	if (file)
		close(fdcp);
	close(fd);
	exit(0);
}

/*****************************************************************************/
