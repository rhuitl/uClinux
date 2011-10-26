/*****************************************************************************/

/*
 *	play -- play "wav" files, through the an audio driver.
 *
 *	(C) Copyright 1999-2001, Greg Ungerer (gerg@snapgear.com)
 *	(C) Copyright 2000-2001, Lineo Inc. (www.lineo.com) 
 */

/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>

#include <linux/soundcard.h>

#include "wav.h"

/*****************************************************************************/

#define	DACDEVICE	"/dev/dsp"

int			verbose = 1;
int			raw = 0;
unsigned char		buf[16*1024];

struct wavefileheader	hdr;
struct wavedataheader	datahdr;


/*
 *	Endian re-arranger :-)
 */
#define	SWAPLONG(a)	((((a) & 0xff000000) >> 24) | \
			(((a) & 0x00ff0000) >> 8) | \
			(((a) & 0x0000ff00) << 8) | \
			(((a) & 0x000000ff) << 24))

#define	SWAPSHORT(a)	(((a) >> 8) | ((a) << 8))

/*****************************************************************************/

void usage(void)
{
	printf("usage: play [-vrmsbw] [-f frequency] filename\n\n");
	printf("            -v          verbose mode\n");
	printf("            -r          raw data file (not wav)\n");
	printf("            -m          mono mode\n");
	printf("            -s          stereo mode\n");
	printf("            -b          8bits per sample (byte)\n");
	printf("            -w          16bits per sample (word)\n");
	printf("            -f          set replay refquency\n");
	exit(1);
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	char	*filename;
	int	ofd, ifd, i, j, n;
	int	freq, chans, bitspersample;
	char	c;

	/* Default to not set for now */
	freq = 0;
	chans = 0;
	bitspersample = 0;

	while ((c = getopt(argc, argv, "vrmswbf:")) > 0) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'f':
			freq = atoi(optarg);
			break;
		case 'r':
			raw++;
			break;
		case 's':
			chans = 2;
			break;
		case 'm':
			chans = 1;
			break;
		case 'w':
			bitspersample = 16;
			break;
		case 'b':
			bitspersample = 8;
			break;
		default:
			usage();
			break;
		}
	}

	if (optind >= argc)
		usage();

	filename = argv[optind];
	if ((ifd = open(filename, O_RDONLY)) < 1) {
		printf("ERROR: failed to wave file %s\n", filename);
		exit(1);
	}
	if ((ofd = open(DACDEVICE, O_RDWR)) < 1) {
		printf("ERROR: failed to open DAC device %s\n", DACDEVICE);
		exit(1);
	}

	if (!raw) {
		/* Parse wav header... */
		if ((n = read(ifd, &hdr, sizeof(hdr))) != sizeof(hdr)) {
			printf("ERROR: failed to read(), errno=%d\n", errno);
			exit(1);
		}

		hdr.filesize = SWAPLONG(hdr.filesize);
		hdr.formattag = SWAPSHORT(hdr.formattag);
		hdr.channels = SWAPSHORT(hdr.channels);
		hdr.samplerate = SWAPLONG(hdr.samplerate);
		hdr.bytespersec = SWAPLONG(hdr.bytespersec);
		hdr.samplesize = SWAPSHORT(hdr.samplesize);
		hdr.bitspersample = SWAPSHORT(hdr.bitspersample);

		if (verbose) {
			printf("FILE=%s\n  Type=0x%x\n  File Length=%d\n",
				filename, hdr.riffid, hdr.filesize);
			printf("  Channels=%d\n  Sample Rate=%d\n  Bytes Per "
				"Second=%d\n  Sample Size=%d\n  "
				"Bits per Sample=%d\n", hdr.channels,
				hdr.samplerate, hdr.bytespersec,
				hdr.samplesize, hdr.bitspersample);
		}
	
		if (hdr.riffid != WAV_RIFFTYPE) {
			printf("ERROR: unknown file type, riffid=%x??\n",
				hdr.riffid);
			exit(1);
		}
		if (hdr.waveid != WAV_WAVETYPE) {
			printf("ERROR: unknown file type, waveid=%x??\n",
				hdr.waveid);
			exit(1);
		}
		if (hdr.fmtid != WAV_FMTTYPE) {
			printf("ERROR: unknown file type, fmtid=%x??\n",
				hdr.fmtid);
			exit(1);
		}

		if (freq == 0)
			freq = hdr.samplerate;
		if (chans == 0)
			chans = hdr.channels;
		if (bitspersample == 0)
			bitspersample = hdr.bitspersample;
	}

	/* Set any remaining defaults if neccessary */
	if (freq == 0)
		freq = 8000;
	if (chans == 0)
		chans = 1;
	if (bitspersample == 0)
		bitspersample = 8;

	if (ioctl(ofd, SNDCTL_DSP_SPEED, &freq) < 0) {
		printf("ERROR: ioctl(SNDCTL_DSP_SPEED,freq) failed, "
			"errno=%d\n", errno);
		exit(1);
	}
	i = (chans == 2) ? 1 : 0;
	if (ioctl(ofd, SNDCTL_DSP_STEREO, &i) < 0) {
		printf("ERROR: ioctl(SNDCTL_DSP_STEREO,0) failed, "
			"errno=%d\n", errno);
		exit(1);
	}
	i = (bitspersample == 16) ? AFMT_S16_LE : AFMT_U8;
	if (ioctl(ofd, SNDCTL_DSP_SAMPLESIZE, &i) < 0) {
		printf("ERROR: ioctl(SNDCTL_DSP_SAMPLESIZE,8) failed, "
			"errno=%d\n", errno);
		exit(1);
	}

	/* Parse data header, and ignore... */
	if ((n = read(ifd, &datahdr, sizeof(datahdr))) != sizeof(datahdr)) {
		printf("ERROR: failed to read(), errno=%d\n", errno);
		exit(1);
	}

#if 1
printf("PLAYING at: freq=%d chans=%d bitspersample=%d\n", freq, chans, bitspersample);
#endif
	/* Output data */
	while ((n = read(ifd, buf, sizeof(buf))) > 0) {

		if ((hdr.bitspersample == 16) && (bitspersample == 8)) {
			/* Make audio track 8 bits only */
			for (i = 1, j = 0; (i < n); i += 2, j++)
				buf[j] = buf[i];
			n = j;
		}
		if ((hdr.channels == 2) && (chans == 1)) {
			/* Make audio track single channel only */
			for (i = 2, j = 1; (i < n); i += 2, j++)
				buf[j] = buf[i];
			n = j;
		}

		if (write(ofd, buf, n) != n) {
			printf("ERROR: write(%s) failed, errno=%d\n",
				DACDEVICE, errno);
		}
	}

	close(ofd);
	close(ifd);
	exit(0);
}

/*****************************************************************************/
