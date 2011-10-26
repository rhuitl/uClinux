/****************************************************************************/

/*
 *	rtc.c -- user level code to support DS1302 real time clock.
 *
 *	(C) Copyright 2001, Greg Ungere (gerg@snapgear.com)
 *	(C) Copyright 2001, Paul Dale (pauli.lineo.com)
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

/****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>

/****************************************************************************/

#define RTC_DEVICE	"/dev/rtc"

/****************************************************************************/

void usage(const char *name)
{
	fprintf(stderr, "Usage:\n"
		"\t%s            Print time from RTC\n"
		"\t%s -w         Update RTC with current system time\n"
		"\t%s -s         Set system time from RTC\n"
		"\t%s -b x       Display byte <x> in RTC RAM\n"
		"\t%s -b x -w y  Set byte <x> to <y> in RTC RAM\n"
		"\t%s -c         ignored\n",
		name, name, name, name, name, name);
}

/****************************************************************************/

int main(int argc, char *argv[])
{
	unsigned char	wval, c;
	int		fd, ac, opt;
	int		bpos = -1;
	int		writep = 0;
	int		setclkp = 0;

	/* Process command line options */
	while ((opt = getopt(argc, argv, "b:cws")) > 0) {
		switch (opt) {
			case 'b':
				bpos = atoi(optarg);
				break;
			case 'c':
				return(0);
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
		return(1);
	} else if (ac == 1) {
		wval = 0xFF & atoi(argv[optind]);
	}

	/* Sanity check args */
	if (writep && bpos >= 0 && ac != 1) {
		fprintf(stderr, "%s: writing to byte %d but "
			"no value specified\n", argv[1], bpos);
		return(1);
	}
	if (!writep && ac == 1) {
		usage(argv[0]);
		return(1);
	}
	if (setclkp && (writep || bpos >= 0)) {
		fprintf(stderr, "%s: setting system clock with write or "
			"byte position specified\n", argv[0]);
		return(1);
	}

	/* Open the RTC device */
	fd = open(RTC_DEVICE, (writep ? O_RDWR : O_RDONLY));
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open %s for %s\n", argv[0],
			 RTC_DEVICE, (writep ? "write" : "read"));
		return(1);
	}

	if (bpos >= 0) {
		/* Byte read/write operation. */
		if (lseek(fd, (bpos + 32), SEEK_SET) < 0) {
			fprintf(stderr, "%s: lseek failed\n", argv[0]);
			return(1);
		}
		if (writep) {
			if (write(fd, &wval, 1) <= 0) {
				fprintf(stderr, "%s: write failed\n", argv[0]);
				return(1);
			}
		} else {
			if (read(fd, &c, 1) <= 0) {
				fprintf(stderr, "%s: read failed\n", argv[0]);
				return(1);
			}
			printf("byte[%d] = %d 0x%02x\n", bpos, c, c);
		}
	} else {
		/* Time read/write operation. */
		unsigned char tbuf[7];

		if (writep) {
			struct tm *tm;
			time_t now;

			/* Grab current time and convert to chip format */
			now = time(NULL);
			tm = gmtime(&now);
			tbuf[0] = (((tm->tm_sec / 10) & 0x7) << 4) |
				(tm->tm_sec % 10);
			tbuf[1] = (((tm->tm_min / 10) & 0x7) << 4) |
				(tm->tm_min % 10);
			tbuf[2] = (((tm->tm_hour / 10) & 0x3) << 4) |
				(tm->tm_hour % 10);
			tbuf[3] = (((tm->tm_mday / 10) & 0x3) << 4) |
				(tm->tm_mday % 10);
			tbuf[4] = ((((tm->tm_mon+1) / 10) & 0x1) << 4) |
				((tm->tm_mon + 1) % 10);
			tbuf[5] = (1 + tm->tm_wday) & 0x7;
			/* Limit year to be in range 00-99 */
			tbuf[6] = (((tm->tm_year / 10) % 10) << 4) |
				(tm->tm_year % 10);
			
			if (7 != write(fd, tbuf, 7)) {
				fprintf(stderr, "%s: write failed\n", argv[0]);
				return 1;
			}
		} else {
			struct tm tm;
			int   moffset[] = {0, 31, 59, 90, 120, 151,
				181, 212, 243, 273, 304, 334};

			if (7 != read(fd, tbuf, 7)) {
				fprintf(stderr, "%s: read failed\n", argv[0]);
				return 1;
			}
			/* Decode into a struct tm record. */
			tm.tm_sec = (tbuf[0] & 0xf) +
				10 * ((tbuf[0] >> 4) & 0x7);
			tm.tm_min = (tbuf[1] & 0xf) +
				10 * ((tbuf[1] >> 4) & 0x7);
			tm.tm_hour = (tbuf[2] & 0xf) +
				10 * ((tbuf[2] >> 4) & 0x3);
			tm.tm_mday = (tbuf[3] & 0xf) +
				10 * ((tbuf[3] >> 4) & 0x3);
			tm.tm_mon = (tbuf[4] & 0xf) +
				10 * ((tbuf[4] >> 4) & 0x1) - 1;
			tm.tm_year = 100 + (tbuf[6] & 0xf) +
				10 * ((tbuf[6] >> 4) & 0xf);
			tm.tm_wday = (tbuf[5] & 0x7) - 1;
			tm.tm_yday = moffset[tm.tm_mon] + tm.tm_mday - 1;
			tm.tm_isdst = 0;
#ifdef INCLUDE_TIMEZONE
			tm.tm_gmtoff = 0;
			tm.tm_zone = NULL;
#else
#ifdef __UC_LIBC__
			tm.__tm_gmtoff__ = 0;
			tm.__tm_zone__ = NULL;
#endif
#endif
			if (setclkp) {
				time_t t;
#ifdef __UC_LIBC__
				struct timezone tz;
				
				gettimeofday(NULL, &tz);
				t = mktime(&tm) + tz.tz_minuteswest * 60L;
#else
				t = mktime(&tm);
#endif
				stime(&t);
			} else
				printf("%s", asctime(&tm));
		}
	}
	close(fd);

	return(0);
}

/****************************************************************************/
