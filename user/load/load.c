/*****************************************************************************/

/*
 *	load.c -- simple SPI flash loader
 *
 *	(C) Copyright 2009, Greg Ungerer (gerg@snapgear.com)
 */

/*****************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

/*****************************************************************************/

void usage(FILE *fp, int rc)
{
	fprintf(fp, "Usage: load [-?h] [-o offset] [-d device] <file>\n\n"
		"\t-h?\t\tthis help\n"
		"\t-o offset\toffset into the SPI device to start\n"
		"\t-d\t\tSPI device (default /dev/spi)\n");
	exit(rc);
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	char *device, *file, *buf;
	unsigned int offset;
	struct stat st;
	int ifd, ofd, c;

	device = "/dev/spi";
	file = NULL;
	offset = 0;

	while ((c = getopt(argc, argv, "?ho:d:")) > 0) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case 'o':
			offset = strtoul(optarg, NULL, 0);
			break;
		case 'h':
		case '?':
			usage(stdout, 0);
			break;
		default:
			fprintf(stderr, "ERROR: unkown option '%c'\n", c);
			usage(stderr, 1);
			break;
		}
	}

	if (optind != (argc - 1)) {
		fprintf(stderr, "ERROR: need file to load\n");
		usage(stderr, 1);
	}
	file = argv[optind];

	if ((ifd = open(file, O_RDONLY)) < 0) {
		fprintf(stderr, "ERROR: failed to open %s, %s\n", file,
			strerror(errno));
		exit(1);
	}
	fstat(ifd, &st);

	if ((ofd = open(device, O_WRONLY)) < 0) {
		fprintf(stderr, "ERROR: failed to open %s, %s\n", device,
			strerror(errno));
		exit(1);
	}

	if (offset) {
		if (lseek(ofd, offset, SEEK_SET) != offset) {
			fprintf(stderr, "ERROR: failed to seek to offset %d, "
				"%s\n", offset, strerror(errno));
			exit(1);
		}
	}

	if ((buf = malloc(st.st_size)) == NULL) {
		fprintf(stderr, "ERROR: failed to malloc(%d), %s\n",
			st.st_size, strerror(errno));
		exit(1);
	}
	if (read(ifd, buf, st.st_size) != st.st_size) {
		fprintf(stderr, "ERROR: failed to read(%d), %s\n",
			st.st_size, strerror(errno));
		exit(1);
	}

	if (write(ofd, buf, st.st_size) != st.st_size) {
		fprintf(stderr, "ERROR: failed to write(%d), %s\n",
			st.st_size, strerror(errno));
		exit(1);
	}

	close(ofd);
	close(ifd);
	return 0;
}

/*****************************************************************************/
