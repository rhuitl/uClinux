
/*
 *	Define the WAV file magic numbers.
 */
#define	WAV_RIFFTYPE	0x52494646
#define	WAV_WAVETYPE	0x57415645
#define	WAV_FMTTYPE	0x666d7420

/*
 *	Define the basic wave file header structure.
 */
struct wavefileheader {
	unsigned long	riffid;		/* "RIFF" */
	unsigned long	filesize;	/* Size of file - RIFF header */

	unsigned long	waveid;		/* "WAVE" */
	unsigned long	fmtid;		/* "fmt " */
	unsigned long	hdrlen;		/* Wave format header len == 16 */

	unsigned short	formattag;	/* Data type */
	unsigned short	channels;	/* Number of audio channels */
	unsigned long	samplerate;	/* Sample rate frequency */
	unsigned long	bytespersec;	/* Bytes per second */
	unsigned short	samplesize;
	unsigned short	bitspersample;	/* Bits per sample */
};

struct wavedataheader {
	unsigned long	dataid;		/* "data" */
	unsigned long	size;		/* Data size */
};
