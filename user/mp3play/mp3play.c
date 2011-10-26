/****************************************************************************/

/*
 *	mp3play.c -- Play MP3 data files
 *
 *	(C) Copyright 1999-2002, Greg Ungerer (gerg@snapgear.com)
 *      (C) Copyright 1997-1997, Stéphane TAVENARD
 *          All Rights Reserved
 *
 *	This code is a derivitive of Stephane Tavenard's mpegdev_demo.c.
 *
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

/****************************************************************************/

#include "defs.h"
#include "mpegdec.h"
#include "genre.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <linux/soundcard.h>
#include <sys/resource.h>
#include <config/autoconf.h>

#ifdef CONFIG_USER_SETKEY_SETKEY
#include <key/key.h>
#endif

/****************************************************************************/

int	verbose;
int	quiet;
int	http_streaming;
int	lcd_line, lcd_time;
int	prebuflimit;
int	lcdfd = -1;
int	gotsigusr1;
char	key[128];
static int onlytags;


/*
 *	Keep track of start and end times.
 */
struct timeval	tvstart, tvend;


/*
 *	Global settings per decode stream. Used to control the final
 *	PCM to raw driver data conversion.
 */
static int	stereo;
static int	bits;
static int	testtone;
static int	quality;

/****************************************************************************/

/*
 *	Master MP3 decoder settings.
 */
static MPEGDEC_STREAM	*mps = NULL;

static MPEGDEC_CTRL	mpa_ctrl;
static MPEGDEC_CTRL	mpa_defctrl = {
	NULL,    // Bitstream access is default file I/O
	// Layers I & II settings (#3)
	{ FALSE, { 1, 2, 48000 }, { 1, 2, 48000 } },
	// Layer III settings (#3)
	{ FALSE, { 1, 2, 48000 }, { 1, 2, 48000 } },
	0,		// #2: Don't check mpeg validity at start
			// (needed for mux stream)
	2048		// #2: Stream Buffer size
};

static char *modes[] = { "stereo", "j-stereo", "dual", "mono" };

/****************************************************************************/

/*
 *	MP3 data stream support (could be file or http stream).
 */
#define MP3_BUF_SIZE	(4*1024)

static char	*mp3_filename;
static int	mp3_fd;
static INT8	*mp3_buffer;
static UINT32	mp3_buffer_size;
static UINT32	mp3_buffer_offset;
static UINT32	mp3_buffer_next_block;
static UINT32	mp3_stream_size;

static char	*rawbuf;
static char	*prebuffer;

int		prebufsize;
int		prebufcnt;
int		prebufnow;

/****************************************************************************/

/*
 *	MP3 file TAG info. Output when in verbose mode. This structure is
 *	designed to match the in-file structure, don't change it!
 *	Nice printable strings are generated in the other vars below.
 */
struct mp3tag {
	char		tag[3];
	char		title[30];
	char		artist[30];
	char		album[30];
	char		year[4];
	char		comments[30];
	unsigned char	genre;
};

static struct mp3tag	mp3_tag;
static int		mp3_gottag;

static char		mp3_title[32];
static char		mp3_artist[32];
static char		mp3_year[8];
static char		mp3_album[32];
static char		mp3_comments[32];
static char		*mp3_genre;

/****************************************************************************/

/*
 *	Trivial signal handler, processing is done from the main loop.
 */

void usr1_handler(int ignore)
{
	gotsigusr1 = 1;
}

/****************************************************************************/

/*
 *	Get stream size (just file size).
 */

static int getstreamsize(void)
{
	struct stat	st;
	if (stat(mp3_filename, &st) < 0)
		return(0);
	return(st.st_size);
}

/****************************************************************************/

/*
 *	Get another chunk of data into RAM.
 */

static UINT32 getnextbuffer()
{
	int	rc;

	lseek(mp3_fd, mp3_buffer_next_block, SEEK_SET);
	rc = read(mp3_fd, mp3_buffer, MP3_BUF_SIZE);
	mp3_buffer_size = (rc < 0) ? 0 : rc;
	mp3_buffer_next_block += mp3_buffer_size;
	return(mp3_buffer_size);
}

/****************************************************************************/

/*
 *	Start our own bitstream access routines.
 */

INT32 bs_open(char *stream_name, INT32 buffer_size, INT32 *stream_size)
{
#if 0
	printf("bs_open: '%s'\n", stream_name);
#endif

	if (!mp3_buffer)
		return(0);

	mp3_buffer_offset = 0;

	/* We know total size, we can set it */
	*stream_size = mp3_stream_size;

	/* Just return a dummy handle (not NULL) */
	return(1);
}

/****************************************************************************/

void bs_close(INT32 handle)
{
#if 0
	printf("bs_close\n");
#endif
	/* Don't need to do anything... */
}

/****************************************************************************/

INT32 bs_read(INT32 handle, void *buffer, INT32 num_bytes)
{
	INT32 read_size;

	if (!handle )
		return(-1);

tryagain:
	read_size = mp3_buffer_size - mp3_buffer_offset;
	if (read_size > num_bytes)
		read_size = num_bytes;

	if (read_size > 0) {
		if(!buffer)
			return(-1);
		memcpy(buffer, &mp3_buffer[mp3_buffer_offset], read_size);
		mp3_buffer_offset += read_size;
	} else {
		if (getnextbuffer() > 0) {
			mp3_buffer_offset = 0;
			goto tryagain;
		}
		read_size = -1; /* End of stream */
	}

	return(read_size);
}

/****************************************************************************/

int bs_seek(INT32 handle, INT32 abs_byte_seek_pos)
{
	if (!handle)
		return(-1);

	if (abs_byte_seek_pos <= 0)
		mp3_buffer_offset = 0;
	else if (abs_byte_seek_pos >= mp3_buffer_size)
		return(-1);
	else
		mp3_buffer_offset = abs_byte_seek_pos;
	return(0);
}

/****************************************************************************/

MPEGDEC_ACCESS bs_access = { bs_open, bs_close, bs_read, bs_seek };

/****************************************************************************/

void mkstring(char *str, char *buf, int size)
{
    int i, j = 0;
	char save;
	for (i = size - 1; i >= 0; i--) {
		if (buf[i] != ' ') {
			while (buf[j] == ' ')
				j++;
			strncpy(str, &buf[j], i - j + 1);
			str[i-j+1] = '\0';
			return;
		}
	}
}

/****************************************************************************/

static void displaytags(void)
{
	if (mp3_gottag) {
		printf("    Title:    %s\n", mp3_title);
		printf("    Artist:   %s\n", mp3_artist);
		printf("    Album:    %s\n", mp3_album );
		printf("    Year:     %s\n", mp3_year);
		printf("    Comments: %s\n", mp3_comments);
		printf("    Genre:    %s\n", mp3_genre);
	}
}

/*
 *	Get TAG info from mp3 file, if it is present. No point doing a
 *	fatal exit on errors, just assume no tag info is present.
 */

void getmp3taginfo(void)
{
	long	pos;
	int	size;

	mp3_gottag = 0;
	size = sizeof(mp3_tag);
	pos = mp3_stream_size - size;
	if (pos < 0)
		return;

	if (lseek(mp3_fd, pos, SEEK_SET) < 0)
		return;
	if (read(mp3_fd, &mp3_tag, size) != size)
		return;
	if (strncmp(&mp3_tag.tag[0], "TAG", 3) != 0)
		return;

	/* Return file pointer to start of file */
	lseek(mp3_fd, 0, SEEK_SET);

	/* Construct fill NULL terminated strings */
	mkstring(&mp3_title[0], &mp3_tag.title[0], sizeof(mp3_tag.title));
	mkstring(&mp3_artist[0], &mp3_tag.artist[0], sizeof(mp3_tag.artist));
	mkstring(&mp3_album[0], &mp3_tag.album[0], sizeof(mp3_tag.album));
	mkstring(&mp3_year[0], &mp3_tag.year[0], sizeof(mp3_tag.year));
	mkstring(&mp3_comments[0], &mp3_tag.comments[0], sizeof(mp3_tag.comments));
	mp3_genre = (mp3_tag.genre >= genre_count) ? "Unknown" :
		genre_table[mp3_tag.genre];

	mp3_gottag = 1;
	if (onlytags)
		displaytags();
}

/****************************************************************************/

/*
 *	Print out everything we know about the MP3 stream.
 */

void printmp3info(void)
{
	if (quiet)
		return;

	if (verbose == 0) {
		printf("%s: MPEG%d-%s (%ld ms)\n", mp3_filename, mps->norm,
			(mps->layer == 1)?"I":(mps->layer == 2)?"II":"III",
			mps->ms_duration);
		return;
	}

	/* This is the verbose output */
	printf("%s:\n", mp3_filename);
	printf("    MPEG%d-%s %s %dkbps %dHz (%ld ms)\n", mps->norm,
		(mps->layer == 1) ? "I" : (mps->layer == 2) ? "II" : "III",
		modes[mps->mode], mps->bitrate, mps->frequency,
		mps->ms_duration );
	printf("    Decoding: Channels=%d Quality=%d Frequency=%dHz\n",
		mps->dec_channels, mps->dec_quality, mps->dec_frequency ); 

	displaytags();
}

/****************************************************************************/

/*
 *	Print out the name on a display device if present.
 */

void lcdtitle(void)
{
	char	ctrl, *name;
	int	ivp;
	struct  iovec iv[4];
	char	prebuf[10];
	char	postbuf;
	char	*p;
	int	namelen;

	/* Install a signal handler to allow updates to be forced */
	signal(SIGUSR1, usr1_handler);

	/* Determine the name to display.  We use the tag if it is
	 * present and the basename of the file if not.
	 */
	if (mp3_gottag) {
		name = mp3_title;
		namelen = strlen(name);
	} else {
		name = strrchr(mp3_filename, '/');
		if (name == NULL)
			name = mp3_filename;
		else
			name++;
		p = strchr(name, '.');
		if (p == NULL)
			namelen = strlen(name);
		else
			namelen = p - name;
	}

	if (lcd_line) {
		/* Lock the file so we can access it... */
		if (flock(lcdfd, LOCK_SH | LOCK_NB) == -1)
			return;
		if (lcd_line == 0) {
			prebuf[0] = '\f';
			prebuf[1] = '\0';
		} else if (lcd_line == 1) {
			strcpy(prebuf, "\003\005");
		} else if (lcd_line == 2) {
			strcpy(prebuf, "\003\v\005");
		}

		/*
		 * Now we'll write the title out.  We'll do this atomically
		 * just in case two players decide to coexecute...
		 */
		ivp = 0;
		iv[ivp].iov_len = strlen(prebuf) * sizeof(char);
		iv[ivp++].iov_base = prebuf;
		
		iv[ivp].iov_len = namelen * sizeof(char);
		iv[ivp++].iov_base = name;
		
		//postbuf = '\n';
		//iv[ivp].iov_len = sizeof(char);
		//iv[ivp++].iov_base = &postbuf;
		writev(lcdfd, iv, ivp);

		/* Finally, unlock it since we've finished. */
		flock(lcdfd, LOCK_UN);
	}
}

/****************************************************************************/

/*
 *	Output time info to display device.
 */

void lcdtime(time_t sttime)
{
	static time_t	lasttime;
	time_t		t;
	char		buf[15], *p;
	int		m, s;

	t = time(NULL) - sttime;
	if (t != lasttime && flock(lcdfd, LOCK_SH | LOCK_NB) == 0) {
		p = buf;
		*p++ = '\003';
		if (lcd_time == 2)
			*p++ = '\v';
		*p++ = '\005';
		m = t / 60;
		s = t % 60;
		if (s < 0) s += 60;
		sprintf(p, "%02d:%02d", m, s);
		write(lcdfd, buf, strlen(buf));
		flock(lcdfd, LOCK_UN);
	}
	lasttime = t;
}

/****************************************************************************/

/*
 *	Configure DSP engine settings for playing this track.
 */
 
void setdsp(int fd, int playstereo, int playbits)
{
	if (ioctl(fd, SNDCTL_DSP_SPEED, &mps->dec_frequency) < 0) {
		fprintf(stderr, "ERROR: Unable to set frequency to %d, "
			"errno=%d\n", mps->dec_frequency, errno);
		exit(1);
	}

	/* Check if data stream is stereo, otherwise must play mono. */
	stereo = (mps->channels == 1) ? 0 : playstereo;
	if (ioctl(fd, SNDCTL_DSP_STEREO, &stereo) < 0) {
		fprintf(stderr, "ERROR: Unable to set stereo to %d, "
			"errno=%d\n", stereo, errno);
		exit(1);
	}

#if BYTE_ORDER == LITTLE_ENDIAN
	bits = (playbits == 16) ? AFMT_S16_LE : AFMT_U8;
#else
	bits = (playbits == 16) ? AFMT_S16_BE : AFMT_U8;
#endif
	if (ioctl(fd, SNDCTL_DSP_SAMPLESIZE, &bits) < 0) {
		fprintf(stderr, "ERROR: Unable to set sample size to "
			"%d, errno=%d\n", bits, errno);
		exit(1);
	}
}

/****************************************************************************/

/*
 *	Generate a tone instead of PCM output. This is purely for
 *	testing purposes.
 */

int writetone(int fd, INT16 *pcm[2], int count)
{
	static int	ramp = 0;
	unsigned char	*pbufbp;
	unsigned short	*pbufwp;
	int		i;

	if (count <= 0)
		return(count);

	if (stereo) {
		if (bits == 8) {
			/* 8bit stereo */
			pbufbp = (unsigned char *) rawbuf;
			for (i = 0; (i < count); i++) {
				*pbufbp++ = ramp;
				*pbufbp++ = ramp;
				ramp = (ramp + 0x80) & 0x7ff;
			}
			i = count * 2 * sizeof(unsigned char);
		} else {
			/* 16bit stereo */
			pbufwp = (unsigned short *) rawbuf;
			for (i = 0; (i < count); i++) {
				*pbufwp++ = ramp;
				*pbufwp++ = ramp;
				ramp = (ramp + 0x80) & 0x7ff;
			}
			i = count * 2 * sizeof(unsigned short);
		}
	} else {
		if (bits == 8) {
			/* 8bit mono */
			pbufbp = (unsigned char *) rawbuf;
			for (i = 0; (i < count); i++) {
				*pbufbp++ = ramp;
				ramp = (ramp + 0x80) & 0x7ff;
			}
			i = count * sizeof(unsigned char);
		} else {
			/* 16bit mono */
			pbufwp = (unsigned short *) rawbuf;
			for (i = 0; (i < count); i++) {
				*pbufwp++ = ramp;
				ramp = (ramp + 0x80) & 0x7ff;
			}
			i = count * sizeof(unsigned short);
		}
	}

	write(fd, rawbuf, i);
	return(i);
}

/****************************************************************************/

/*
 *	Write out the PCM data to the file descriptor, translating to
 *	the specified data format.
 */

int writepcm(int fd, INT16 *pcm[2], int count)
{
	unsigned short	*pcm0, *pcm1;
	unsigned char	*pbufbp;
	unsigned short	*pbufwp;
	char		*buf;
	int		i;

	if (count <= 0)
		return(count);
	if (testtone)
		return(writetone(fd, pcm, count));

	buf = rawbuf;

	if (stereo) {
		if (bits == 8) {
			/* 8bit stereo */
			pcm0 = pcm[0];
			pcm1 = pcm[1];
			pbufbp = (unsigned char *) buf;
			for (i = 0; (i < count); i++) {
				*pbufbp++ = (*pcm0++ ^ 0x8000) >> 8;
				*pbufbp++ = (*pcm1++ ^ 0x8000) >> 8;
			}
			i = count * 2 * sizeof(unsigned char);
		} else {
			/* 16bit stereo */
			pcm0 = pcm[0];
			pcm1 = pcm[1];
			pbufwp = (unsigned short *) buf;
			for (i = 0; (i < count); i++) {
				*pbufwp++ = *pcm0++;
				*pbufwp++ = *pcm1++;
			}
			i = count * 2 * sizeof(unsigned short);
		}
	} else {
		if (bits == 8) {
			/* 8bit mono */
			pcm0 = pcm[0];
			pbufbp = (unsigned char *) buf;
			for (i = 0; (i < count); i++)
				*pbufbp++ = (*pcm0++ ^ 0x8000) >> 8;
			i = count * sizeof(unsigned char);
		} else {
			/* 16bit mono, no translation required! */
			i = count * sizeof(unsigned short);
			buf = (char *) pcm[0];
		}
	}

	if (prebufnow) {
		memcpy(&prebuffer[prebufcnt], buf, i);
		prebufcnt += i;
		if (prebufcnt > prebufnow) {
			write(fd, &prebuffer[0], prebufcnt);
			prebufnow = prebufcnt = 0;
		}
	} else {
		write(fd, buf, i);
	}

	return(i);
}

/****************************************************************************/

/*
 *	Flush out any remaining buffered PCM data. This is really to allow
 *	for prebuffing of files smaller than the prebuffer.
 */

void flushpcm(int fd)
{
	if (prebufnow) {
		write(fd, &prebuffer[0], prebufcnt);
		prebufnow = prebufcnt = 0;
	}
}

/****************************************************************************/

void usage(int rc)
{
	printf("usage: mp3play [-hmviqz8RPTZ] [-g <quality>] [-s <time>] "
		"[-d <device>] [-w <filename>] [-B <prebuf>] "
		"[-l <line> [-t]] mp3-files...\n\n"
		"\t\t-h            this help\n"
		"\t\t-v            verbose stdout output\n"
		"\t\t-i            display file tags and exit\n"
		"\t\t-q            quiet (don't print title)\n"
		"\t\t-m            mix both channels (mono)\n"
		"\t\t-8            play 8 bit samples\n"
		"\t\t-R            repeat tracks forever\n"
		"\t\t-z            shuffle tracks\n"
		"\t\t-Z            psuedo-random tracks (implicit -R)\n"
		"\t\t-P            print time to decode/play\n"
		"\t\t-T            do decode, but output test tone\n"
		"\t\t-g <quality>  decode quality (0,1,2)\n"
		"\t\t-s <time>     sleep between playing tracks\n"
#ifdef SWAP_WD
		"\t\t-w <device>   audio device for playback\n"
		"\t\t-d <filename> write output to file\n"
#else
		"\t\t-d <device>   audio device for playback\n"
		"\t\t-w <filename> write output to file\n"
#endif
		"\t\t-l <line>     display title on LCD line (0,1,2) (0 = no title)\n"
		"\t\t-t <line>     display time on LCD line (1,2)\n"
		"\t\t-B <prebuf>   size of pre-buffer\n");
	exit(rc);
}

/****************************************************************************/

int main(int argc, char *argv[])
{
	unsigned long	us;
	INT16		*pcm[MPEGDEC_MAX_CHANNELS];
	int		pcmcount, rawcount;
	int		c, i, j, dspfd, dsphw, slptime;
	int		playbits, playstereo, repeat, printtime;
 	int		argnr, startargnr, rand, shuffle;
	char		*device, *argvtmp;
	time_t		sttime;

	verbose = 0;
	quiet = 0;
	playstereo = 1;
	playbits = 16;
	quality = 2;
	shuffle = 0;
	rand = 0;
	repeat = 0;
	printtime = 0;
	slptime = 0;
	prebuflimit = 64000;
	device = "/dev/dsp";
	dsphw = 1;
	onlytags = 0;

	while ((c = getopt(argc, argv, "?himvqzt:8RZPTg:s:d:w:l:B:V")) >= 0) {
		switch (c) {
		case 'V':
			printf("%s version 1.0\n", argv[0]);
			return 0;
		case 'v':
			verbose++;
			break;
		case 'q':
			verbose = 0;
			quiet++;
			break;
		case 'm':
			playstereo = 0;
			break;
		case '8':
			playbits = 8;
			break;
		case 'R':
			repeat++;
			break;
		case 'z':
			shuffle++;
			break;
		case 'Z':
			rand++;
			repeat++;
			break;
		case 'P':
			printtime++;
			break;
		case 'T':
			testtone++;
			break;
		case 'g':
			quality = atoi(optarg);
			if ((quality < 0) || (quality > 2)) {
				fprintf(stderr, "ERROR: valid quality 0, 1 "
					"and 2\n");
				exit(1);
			}
			break;
		case 's':
			slptime = atoi(optarg);
			break;
		case 'd':
			device = optarg;
#ifdef SWAP_WD
			dsphw = 0;
#endif
			break;
		case 'w':
			device = optarg;
#ifndef SWAP_WD
			dsphw = 0;
#endif
			break;
		case 'l':
			lcd_line = atoi(optarg);
			break;
		case 't':
			lcd_time = atoi(optarg);
			break;
		case 'B':
			prebuflimit = atoi(optarg);
			if ((prebuflimit < 0) || (prebuflimit > (1*1024*1024))){
				fprintf(stderr, "ERROR: valid pre-buffer range "
					"0 to 1000000 bytes\n");
				exit(1);
			}
			break;
		case 'i':
			onlytags = 1;
			break;
		case 'h':
		case '?':
			usage(0);
			break;
		}
	}

	argnr = optind;
	if (argnr >= argc)
		usage(1);
	startargnr = argnr;

	mp3_buffer = (INT8 *) malloc(MP3_BUF_SIZE);
	if (!mp3_buffer) {
		fprintf(stderr, "ERROR: Can't allocate MPEG buffer\n");
		exit(0);
	}

	for (i = 0; (i < MPEGDEC_MAX_CHANNELS); i++) {
		pcm[i] = malloc(MPEGDEC_PCM_SIZE * sizeof(INT16));
		if (!pcm[i]) {
			fprintf(stderr, "ERROR: Can't allocate PCM buffers\n");
			exit(1);
		}
	}

	if ((rawbuf = malloc(MPEGDEC_PCM_SIZE * sizeof(short) * 2)) == NULL) {
		fprintf(stderr, "ERROR: Can't allocate raw buffers\n");
		exit(1);
	}
	if (prebuflimit) {
		prebufsize = prebuflimit + (MPEGDEC_PCM_SIZE*sizeof(short)*2);
		if ((prebuffer = malloc(prebufsize)) == NULL) {
			fprintf(stderr, "ERROR: Can't allocate pre-buffer\n");
			exit(1);
		}
	}

	/* Make ourselves the top priority process! */
	setpriority(PRIO_PROCESS, 0, -20);
	srandom(time(NULL) ^ getpid());

	/* Open the audio playback device */
	if ((dspfd = open(device, (O_WRONLY | O_CREAT | O_TRUNC), 0660)) < 0) {
		fprintf(stderr, "ERROR: Can't open output device '%s', "
			"errno=%d\n", device, errno);
		exit(0);
	}

	/* Open LCD device if we are going to use it */
	if ((lcd_line > 0) || (lcd_time > 0)) {
		lcdfd = open("/dev/lcdtxt", O_WRONLY);
		if (lcdfd < 0) {
			lcd_time = 0;
			lcd_line = 0;
		}
	}

nextall:
	/* Shuffle tracks if slected */
	if (shuffle) {
		for (c = 0; (c < 10000); c++) {
			i = (((unsigned int) random()) % (argc - startargnr)) +
				startargnr;
			j = (((unsigned int) random()) % (argc - startargnr)) +
				startargnr;
			argvtmp = argv[i];
			argv[i] = argv[j];
			argv[j] = argvtmp;
		}
	}

nextfile:
	if (rand) {
		argnr = (((unsigned int) random()) % (argc - startargnr)) +
			startargnr;
	}

	mpa_ctrl = mpa_defctrl;
	mpa_ctrl.bs_access = &bs_access;
	if (playstereo == 0)
		mpa_ctrl.layer_3.force_mono = 1;
	mpa_ctrl.layer_3.mono.quality = quality;
	mpa_ctrl.layer_3.stereo.quality = quality;

	mp3_buffer_offset = 0;
	mp3_buffer_next_block = 0;

	mp3_filename = argv[argnr];

	/* Open file or stream to mp3 data */
	if (strncmp(mp3_filename, "http://", 7) == 0) {
		mp3_stream_size = 0; /*HACK*/
		mp3_fd = openhttp(mp3_filename);
	} else {
		mp3_stream_size = getstreamsize();
		mp3_fd = open(mp3_filename, O_RDONLY);
	}

	if (mp3_fd < 0) {
		fprintf(stderr, "ERROR: Unable to open '%s', errno=%d\n",
			mp3_filename, errno);
		http_streaming = 0;
		goto badfile;
	}

	getmp3taginfo();
	if (onlytags)
		return 0;

	/* Get first part of the stream into a ram buffer */
	getnextbuffer();

mp3_restream:
	mps = MPEGDEC_open(mp3_filename, &mpa_ctrl);
	if (!mps) {
		fprintf(stderr, "ERROR: Unable to open MP3 Audio "
			"stream '%s'\n", mp3_filename);
		http_streaming = 0;
		goto badfile;
	}

#ifdef CONFIG_USER_SETKEY_SETKEY
	if ((i = getdriverkey(&key, sizeof(key))) > 0)
		MPEGDEC_setkey(mps, &key, i);
#endif

	printmp3info();

	if (dsphw)
		setdsp(dspfd, playstereo, playbits);
	if (lcd_line)
		lcdtitle();

	gettimeofday(&tvstart, NULL);
	sttime = time(NULL);

	/* Restart pre-buffering for next track */
	prebufnow = prebuflimit;
	prebufcnt = 0;

	/* We are all set, decode the file and play it */
	while ((pcmcount = MPEGDEC_decode_frame(mps, pcm)) >= 0) {
		writepcm(dspfd, pcm, pcmcount);
		if (gotsigusr1) {
			gotsigusr1 = 0;
			if (lcd_line)
				lcdtitle();
		}
		if (lcd_time)
			lcdtime(sttime);
	}

	/* Flush out any remaining buffer PCM data */
	flushpcm(dspfd);
 
	gettimeofday(&tvend, NULL);
	if (printtime) {
		us = ((tvend.tv_sec - tvstart.tv_sec) * 1000000) +
		    (tvend.tv_usec - tvstart.tv_usec);
		printf("Total time = %d.%06d seconds\n",
			(us / 1000000), (us % 1000000));
	}

badfile:
	if (slptime)
		sleep(slptime);

	close(mp3_fd);
	MPEGDEC_close(mps);
	mps = NULL;

	if (++argnr < argc)
		goto nextfile;

	if (repeat) {
		argnr = startargnr;
		goto nextall;
	}

	close(dspfd);
	if (lcdfd >= 0)
		close(lcdfd);
	exit(0);
}

/****************************************************************************/
