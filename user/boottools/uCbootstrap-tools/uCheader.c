/*
 * uCheader.c:
 *
 *      Display the image header of a uCimage file and check its MD5.
 *
 * (c) 2004 Arcturus Networks Inc. by
 *     Michael Leslie <mleslie@arcturusnetworks.com>
 *
 * Note that this needs to be change to ensure that the values
 * read from the header are read as little-endian
 *
 * Added 32 bit checksum: add together each 32 bit data.
 *     Aug. 24, 2005 by David Wu
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "md5.h"
#include "uCheader.h"


#define DBG(a1, a2...) if (opt_debug) fprintf(stderr, a1, ##a2)

/****** data declarations: **************************************************/

char *opt_filename = NULL;    /* image filename to load */
int   opt_stdin       = 0;    /* read image from stdin instead of filesystem */
int   opt_quiet = 0;          /* do not print anything to the screen */
int   opt_debug = 0;

uCimage_header header;


FILE *infile;
#define BUFFERSIZE 65536
char buf[BUFFERSIZE];

/****** function prototypes: ************************************************/

int parse_args(int argc, char *argv[]);
void usage(void);


/****** main(): *************************************************************/

int main (int argc, char *argv[])
{
	unsigned int       i;
	unsigned int       n = 0;
	unsigned int       size = 0;
	struct MD5Context  md5c;
	unsigned char      digest[16];
	uint32_t bit32sum = 0;
	uint32_t * pointer_to_buf = (uint32_t *)buf;

	if (parse_args (argc, argv))
		if (!opt_quiet)
			usage();

	/* Initialize MD5 module: */
	MD5Init(&md5c);


	/* Open input and output files: ******************************/
	if (opt_stdin)
		infile = stdin;
	else
		infile = fopen (opt_filename, "r");

	if (infile == NULL) {
		fprintf (stderr, "FATAL: could not open %s\n", opt_filename);
		exit(1);
	}

	if (!opt_quiet) {
		fprintf (stderr, "uCimage file:            \"%s\"\n",
				 opt_filename);
	}

	/* Read various header data: ***************************/

	/* Read header and image file to output, compute MD5: ******/
	/* read header: */
	fread (&header, sizeof(header), 1, infile);

	/* Check magic in header */
	for (i=0;i<sizeof(header.magic);i++) {
		if (header.magic[i] != UCHEADER_MAGIC[i]) {
			fprintf (stderr, "Header magic not: \"%s\" instead: \"%s\"\n",
					 UCHEADER_MAGIC, header.magic);
			/* optionally abort? */
			break;
		}
	}

	/**** to do: largely respond to header version in the interpretation! ***/

	/* read header size */
	DBG ("header_size reported as: %10d\n", header.header_size);

	/* image size: */
	fprintf (stdout, "data_size reported as:   %10d\n", header.data_size);

	/* image size: */
	fprintf (stdout, "partition reported as:   %c\n", header.partition);

	/* header date code */
	fprintf (stdout, "date code reported as:    \"%s\"\n", header.datecode);

	/* header name */
	fprintf (stdout, "name reported as:         \"%s\"\n", header.name);

	/* MD5: */
	fprintf (stdout, "MD5 digest reported as:   ");
	for (i=0;i<16;i++)
		fprintf (stdout, "%02x", header.md5sum[i]);
	fprintf (stdout, "\n");

	/* 32Bit checksum: */
	fprintf (stdout, "32 bit checksum reported as:0x%8x\n", header.bit32sum);

	/* read image and do MD5: */
	while (!feof(infile)) {
		n = fread (buf, 1, BUFFERSIZE, infile);
		size += n;
		MD5Update (&md5c, buf, n);

		/* 32 bit checksum */
		pointer_to_buf = (uint32_t *)buf;
		while ( (char *)pointer_to_buf - buf < n ) {
			bit32sum += htonl(*pointer_to_buf);
			pointer_to_buf++;
		}
	}
	/* save MD5: */
	MD5Final (digest, &md5c);

	if (!opt_stdin)
		fclose (infile);

	/* Verify: */
	for (i=0;i<16;i++) {
		if (header.md5sum[i] != digest[i]) {
			fprintf (stdout, "ERROR: MD5 digest mismatch\n");
			fprintf (stdout, "MD5 digest calculated as: ");
			for (i=0;i<16;i++)
				fprintf (stdout, "%02x", digest[i]);
			fprintf (stdout, "\n");
		}
	}

	/* verify bit32sum */
	if (header.bit32sum != bit32sum){
		fprintf (stdout, "ERROR: 32 bit checksum mismatch\n");
		fprintf (stdout, "This program calculates bit32sum as: 0x%8x\n", bit32sum);
	}	

	/* Also verify that length matches */
	if (header.data_size != size) {
		fprintf (stdout, "ERROR: image size mismatch\n");
		fprintf (stdout, "This program calculates data_size as:  %12d\n", size);
	}


	/* note: rewriting header bits might at some point be desireable */
	/* rewind output file to update header: */
	/* rewind (outfile); */
	/* rewrite header: */
	/* fwrite (&header, sizeof(header), 1, outfile); */
	/* fclose (outfile); */

	return (0);
}


/****** function declarations: **********************************************/

/*
 * parse_args(int argc, char *argv[])
 *
 * Parse command line arguments and set corresponding
 * opt_xxx variables.
 *
 */
int parse_args(int argc, char *argv[])
{
	int i;
	int err = 0;
	char * argvp;

	if (argc < 2)
		return (1);


	for (i=1;i<argc;i++) {
		if (argv[i][0] == '-') {
			argvp = argv[i] + 1;

			if (!*argvp) {
				if (i < argc-1)
					return 1; /* no option */
				else {
					opt_stdin = 1;
					opt_filename = "-";
				}
			}


			while(*argvp) {
				switch (*argvp++)
					{
					case 'f': opt_filename    = argv[++i]; break;

					case 's':
						opt_stdin    = 1;
						opt_filename = "-";
						break;

					case 'h': return 1;
					case 'q': opt_quiet = 1; break;
					case 'd': opt_debug = 1; break;


					default:
						if (!opt_quiet)
							fprintf (stderr,
									 "Error: Unknown option \"%s\" - Aborting.\n\n",
									 argv[i]);
						return 1;
					}
			}

		} else
			opt_filename = argv[i];
	}

	/* print out options if debug enabled: */
	DBG("opt_filename    = %s\n",  opt_filename);


	if(!opt_filename) {
		if (!opt_quiet)
			fprintf(stderr, "Error: No image given.\n");
		err = 1; 	
	}


	if (err) return 1;

	return (0);
}



void usage()
{
	fprintf (stderr,
"usage: uCheader [options] <image filename>\n"
"\n"
"       Display the image header of a uCimage file and check its MD5.\n"
"\n"
);
	fprintf(stderr,
"Options:\n"
"\t-f <filename>\tinput image filename\n"
"\t-s\tRead image file from stdin\n"
"\t-h\tthis help information\n"
"\t-d\tprint debugging message\n"
"\t-q\tdo it quietly, no output to the screen\n\n"
);
	exit(1);
}




/****************************************************************************/

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
