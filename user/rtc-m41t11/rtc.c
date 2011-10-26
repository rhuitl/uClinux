/* User level driver for the M41T11 MBUS based real time clock chip.
 *
 * (C) Copyright 2001, Paul Dale (pauli.lineo.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <asm/mcfmbus.h>
#include <time.h>

#define MBUS_DEVICE	"/dev/mbus"
#define MBUS_SLAVE	0x68		// Magic number D0 shifted right one place

#define RTC_SIGNATURE_BASE 32
#define RTC_SIGNATURE "RTC Signature"

static void usage(const char *name) {
	fprintf(stderr,
		"Usage:\n"
		"\t%s            Print time from RTC\n"
		"\t%s -w         Update RTC with current system time\n"
		"\t%s -s         Set system time from RTC\n"
		"\t%s -b x       Display byte <x> in RTC RAM\n"
		"\t%s -b x -w y  Set byte <x> to <y> in RTC RAM\n"
		"\t%s -c         Check the RTC signature\n"
			, name, name, name, name, name, name);
}

int main(int argc, char *argv[]) {
	int bpos = -1;
	unsigned char wval;
	int writep = 0;
	int opt;
	int setclkp = 0;
	int checksig = 0;
	int fd;
	int ac;
	unsigned char sig[32];
	int siglen;

	/* Process command line options */
	while ((opt = getopt(argc, argv, "b:cws")) > 0) {
		switch (opt) {
			case 'b':
				bpos = atoi(optarg);
				break;
			case 'c':
				checksig = 1;
				break;
			case 'w':
				writep = 1;
				break;
			case 's':
				setclkp = 1;
				break;
			default:
				usage(argv[0]);
				return 1;
		}
	}
	ac = argc - optind;
	if (ac > 1) {
		usage(argv[0]);
		return 1;
	} else if (ac == 1) {
		wval = 0xFF & atoi(argv[optind]);
	}

	/* Sanity check args */
	if (writep && bpos >= 0 && ac != 1) {
		fprintf(stderr, "%s: writing to byte %d but no value specified\n", argv[1], bpos);
		return 1;
	}
	if (!writep && ac == 1) {
		usage(argv[0]);
		return 1;
	}
	if (setclkp && (writep || bpos >= 0)) {
		fprintf(stderr, "%s: setting system clock with write or byte position specified\n", argv[0]);
		return 1;
	}

	/* Open the MBUS device */
	fd = open(MBUS_DEVICE, writep?O_RDWR:O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open %s for %s\n",
				argv[0], MBUS_DEVICE, writep?"write":"read");
		return 1;
	}
	if (-1 == ioctl(fd, MBUSIOCSSLADDR, MBUS_SLAVE)) {	// Set slave address
		fprintf(stderr, "%s: ioctl MBUSIOCSSLADDR failed\n", argv[0]);
		return 1;
	}

	// Set base address.
	if (-1 == ioctl(fd, MBUSIOCSSUBADDR, (bpos>=0)?bpos:0)) {
		fprintf(stderr, "%s: ioctl MBUSIOCSSUBADDR failed\n", argv[0]);
		return 1;
	}

	if (bpos >= 0) {
		// Byte read/write operation.
		if (writep) {
			if (1 != write(fd, &wval, 1)) {
				fprintf(stderr, "%s: write failed\n", argv[0]);
				return 1;
			}
		} else {
			unsigned char c;
			if (1 != read(fd, &c, 1)) {
				fprintf(stderr, "%s: read failed\n", argv[0]);
				return 1;
			}
			printf("byte[%d] = %d 0x%02x\n", bpos, c, c);
		}
	} else if (checksig) {
		// Read and verify the signature
		if (-1 == ioctl(fd, MBUSIOCSSUBADDR, RTC_SIGNATURE_BASE)) {
			fprintf(stderr, "%s: ioctl MBUSIOCSSUBADDR failed\n", argv[0]);
			return 1;
		}

		siglen = strlen(RTC_SIGNATURE)+1;
		if (siglen != read(fd, sig, siglen)) {
			fprintf(stderr, "%s: read failed\n", argv[0]);
			return 1;
		}

		if (0 == memcmp(sig, RTC_SIGNATURE, siglen)) {
			printf("Signature is valid\n");
		} else {
			sig[siglen-1] = '\0';
			printf("Signature is invalid\n");
			printf("Expected signature = %s\n", RTC_SIGNATURE);
			printf("Actual signature = %s\n", sig);
			return 1;
		}
	} else {
		// Time read/write operation.
		unsigned char tbuf[7];

		if (writep) {
			struct tm *tm;
			time_t now;

			// Grab current time and convert to chip format
			now = time(NULL);
			tm = gmtime(&now);
			tbuf[0] = (((tm->tm_sec / 10) & 0x7) << 4) | ((tm->tm_sec % 10) & 0x0f);
			tbuf[1] = (((tm->tm_min / 10) & 0x7) << 4) | ((tm->tm_min % 10) & 0x0f);
			tbuf[2] = (((tm->tm_hour / 10) & 0x3) << 4) | ((tm->tm_hour % 10) & 0x0f);
			tbuf[3] = (1 + tm->tm_wday) & 0x7;
			tbuf[4] = (((tm->tm_mday / 10) & 0x3) << 4) | ((tm->tm_mday % 10) & 0x0f);
			tbuf[5] = ((((tm->tm_mon+1) / 10) & 0x1) << 4) | (((tm->tm_mon + 1) % 10) & 0x0f);
			tbuf[6] = ((((tm->tm_year / 10) % 10) & 0xf) << 4) | ((tm->tm_year % 10) & 0x0f);
			
			if (7 != write(fd, tbuf, 7)) {
				fprintf(stderr, "%s: write failed\n", argv[0]);
				return 1;
			}

			// Write the signature
			if (-1 == ioctl(fd, MBUSIOCSSUBADDR, RTC_SIGNATURE_BASE)) {
				fprintf(stderr, "%s: ioctl MBUSIOCSSUBADDR failed\n", argv[0]);
				return 1;
			}

			siglen = strlen(RTC_SIGNATURE)+1;
			if (siglen != write(fd, RTC_SIGNATURE, siglen)) {
				fprintf(stderr, "%s: write failed\n", argv[0]);
				return 1;
			}
		} else {
			struct tm tm;
			int   moffset[] =
   				{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

			if (7 != read(fd, tbuf, 7)) {
				fprintf(stderr, "%s: read failed\n", argv[0]);
				return 1;
			}
			// Decode into a struct tm record
			tm.tm_sec = (tbuf[0] & 0xf) + 10 * ((tbuf[0] >> 4) & 0x7);
			tm.tm_min = (tbuf[1] & 0xf) + 10 * ((tbuf[1] >> 4) & 0x7);
			tm.tm_hour = (tbuf[2] & 0xf) + 10 * ((tbuf[2] >> 4) & 0x3);
			tm.tm_mday = (tbuf[4] & 0xf) + 10 * ((tbuf[4] >> 4) & 0x3);
			tm.tm_mon = (tbuf[5] & 0xf) + 10 * ((tbuf[5] >> 4) & 0x1) - 1;
			tm.tm_year = 100 + (tbuf[6] & 0xf) + 10 * ((tbuf[6] >> 4) & 0xf);
			tm.tm_wday = (tbuf[3] & 0x7) - 1;
			tm.tm_yday = moffset[tm.tm_mon] + tm.tm_mday - 1;
			tm.tm_isdst = 0;
#ifdef INCLUDE_TIMEZONE
			tm.tm_gmtoff = 0;
			tm.tm_zone = NULL;
#else
			tm.__tm_gmtoff__ = 0;
			tm.__tm_zone__ = NULL;
#endif
			if (setclkp) {
				struct timezone tz;
				time_t t;
				
				gettimeofday(NULL, &tz);
				t = mktime(&tm) + tz.tz_minuteswest * 60L;
				stime(&t);
			} else
				printf("%s", asctime(&tm));
		}
	}
	close(fd);

	return 0;
}
