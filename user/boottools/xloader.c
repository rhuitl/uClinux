/*
 * xloader
 *
 * A replacement for ramloader and flashloader, since the loading mechanism
 * is identical and the difference is just in which call to make to the
 * uCbootloader
 *
 * (c) 2002-2003 Arcturus Networks Inc. 
 *     by Michael Leslie <mleslie@arcturusnetworks.com>,
 *
 * Change log:
 *  August  2003 - Oleksandr Zhadan <oleks@arcturusnetworks.com>
 *		   load_image_4k() is fixed.
 *		   Was wrong link number calculation.
 */

/* With uClibc 0.9.26, malloc() is malloc_standard, which uses the slab
 * allocator. This means that malloc(4096) takes 4 KB of memory, not 8 KB, so
 * using load_image_4k() should not incur a penalty of 100% overhead.
 *
 * FIXME: Make load_image4k() recognize opt_stdin.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <byteswap.h>
#include <asm/uCbootstrap.h>
#include "md5.h"
#include "flash.h"

/****** data declarations: **************************************************/

/* Max image size should come at least from (a platform specific
 * part of) uCbootstrap.h, and at best from a uCbootstrap system call.
 * For now we will hard-define it here to be 4M - 128K: */
#define MAX_IMAGE_SIZE (0x400000 - 0x20000)


int   opt_ramloader = 0;    /* invoke ramloader */
int   opt_flashloader = 0;  /* invoke flashloader */
int   opt_quiet = 0;        /* do not print anything to the screen */
int   opt_debug = 0;        /* print debug info here and in uCbootloader */
#define DBG(a1, a2...) if (opt_debug) fprintf(stderr, a1, ##a2)
char *opt_filename = NULL;  /* filename to load */
char *opt_partition = NULL; /* (optional) partition specification to program */

int   opt_4k = 0;           /* Don't use old 4K-based version by default */

int   opt_noop        = 0;  /* no bootloader operation */
int   opt_stdin       = 0;  /* read image from stdin instead of filesystem */

int   opt_program_all = 1;  /* Use the old bsc_program call to program all
                             * of user flash, rather than partition by partition */
int   opt_watchdog    = 0;  /* watchdog must be serviced at key points */

int   flags;
mnode_t m;

FILE *watchdog;

/* memory data structures: */

uCimage_header header;
int header_present = 0;

#define BUFFERSIZE 4096
void **chain;
void **chain_tmp;
int    links;

#define CARSIZE (65536 - 128)
void **train = NULL;
int    cars  = 0;

/****** endian handling for uCimage header: *********************************/

#if (BYTE_ORDER == BIG_ENDIAN)
/* #  warning This target is BIG_ENDIAN */
  /* note "ltoh" = little-endian to host */
#  define ltoh16(x)  bswap_16(x)
#  define ltoh32(x)  __bswap_constant_32(x)
#elif (BYTE_ORDER == LITTLE_ENDIAN)
/* #warning This target is LITTLE_ENDIAN */
  /* note "ltoh" = little-endian to host */
#  define ltoh16(x)  (x)
#  define ltoh32(x)  (x)
#endif

/****** function prototypes: ************************************************/

int parse_args(int argc, char *argv[]);
void usage(void);

_bsc2(int,program,void *,a1,int,a2)
_bsc3(int,program2,void *,a1,int,a2,char *,partition)
_bsc2(int,ramload,void *,a1,int,a2)
_bsc1(int, setbenv, char *, a)

int load_image (char *filename);     /* malloc, sort, and read 64K blocks */
int load_image_4k (char *filename);  /* malloc and read 4K blocks */
int sort_pointers (void **train, int cars);
void deallocate_all (void);          /* safely deallocate all major structures */

int check_uCimage (uCimage_header *header, FILE *handle);


/****** main(): *************************************************************/

int main (int argc, char *argv[])
{

	if (parse_args (argc, argv))
		if (!opt_quiet)
		usage();

	if (opt_watchdog) {
		fprintf (stderr, "Opening /dev/watchdog.\n");
		watchdog = fopen ("/dev/watchdog", "w");
		if (watchdog == NULL) {
			perror ("Error opening watchdog device file");
			exit(-1);
		}
		fputc('c', watchdog);
		fflush (watchdog);
	}

	if (!opt_4k) {
		if (load_image (opt_filename))
			exit (-1);
	} else {
		if (load_image_4k (opt_filename))
			exit (-1);
	}

	if (opt_watchdog) {
		fputc('c', watchdog);
		fflush (watchdog);
	}

	flags = (opt_debug?(PGM_DEBUG):0);

	if (opt_noop) {
		deallocate_all();
		exit (1);
	}

	fflush (stdout);
	fflush (stderr);
	sleep (1);

	if (opt_ramloader)
		ramload(&m, flags | PGM_EXEC_AFTER);
	else if (opt_flashloader) {
		if (opt_program_all)
			program(&m, flags | PGM_ERASE_FIRST | PGM_RESET_AFTER);
		else {
			if (opt_partition)
				program2(&m, flags | PGM_ERASE_FIRST | PGM_RESET_AFTER, opt_partition);
		else
				program2(&m, flags | PGM_ERASE_FIRST | PGM_RESET_AFTER, "0");
		}
	}

	/* not reached:
	 * PGM_EXEC_AFTER starts the new kernel,
	 * PGM_RESET_AFTER resets the board.
	 */
	exit (-1);

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
	char *c;
	int i;
	int err = 0;
	char * argvp;

	/* fprintf (stderr, "argv[0] = \"%s\"\n", argv[0]); */
	c = (char *)strrchr (argv[0], '/');
	if (c == NULL) c = argv[0];
	else           c++;

	if (argc < 2)
		return (1);

	if (!strcmp (c, "ramloader"))
		opt_ramloader = 1;
	else if (!strcmp (c, "flashloader"))
		opt_flashloader = 1;

	for (i=1;i<argc;i++) {
		if (argv[i][0] == '-'){
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
				case 'd': opt_debug       = 1; break;
				case 'r': opt_ramloader   = 1; break;
				case 'f': opt_flashloader = 1; break;
					case 'F': opt_flashloader = 1;
                                                  opt_program_all = 1;
                                                  break;
				case '4': opt_4k          = 1; break;
					case 'n': opt_noop        = 1; break;
				case 'q': opt_quiet       = 1; break;
					case 's':
						opt_stdin    = 1;
						opt_filename = "-";
						break;
					case 'w': opt_watchdog    = 1; break;
				case 'h': return 1;

				default:
						if (!opt_quiet)
					fprintf (stderr,
									 "Error: Unknown option \"%s\" - Aborting.\n\n",
									 argv[i]);
					return 1;
				}
			}

		} else if (opt_filename) {
			/* If the previous arg was a filename (ie the first non '-' arg, then
			 * this must be a partition spec: "X:"
			 */
			c = strchr(argv[i], ':');
			if (c != NULL) {
				*c = 0; /* strip final ':' from partition name */
				opt_partition = argv[i];
				if (opt_program_all) {
					fprintf (stderr, "Error: There is a conflict between programming"
						" all of flash and partition mode.\n\n");
					return 1;
				}
			} else {
			fprintf (stderr, "Error: Only one image is allowed - Aborting.\n\n");
			return 1;
		}

		} else
			opt_filename = argv[i];
	}

	/* print out options if debug enabled: */
	DBG("argv[0] = \"%s\"\n", c);
	DBG("opt_ramloader   = %d;\n", opt_ramloader);
	DBG("opt_flashloader = %d;\n", opt_flashloader);
	DBG("opt_program_all = %d;\n", opt_program_all);
	DBG("opt_quiet       = %d;\n", opt_quiet);
	DBG("opt_debug       = %d;\n", opt_debug);
	DBG("opt_filename    = %s\n",  opt_filename);
	DBG("opt_partition   = %s\n",  opt_partition);
	DBG("opt_4k          = %d\n",  opt_4k);
	DBG("opt_noop        = %d\n",  opt_noop);
	DBG("opt_stdin       = %d\n",  opt_stdin);
	DBG("opt_watchdog    = %d\n",  opt_watchdog);

	/* check the option */
	if(opt_ramloader && opt_flashloader)
	{
		if (!opt_quiet)
		fprintf(stderr, "Error: You cannot use both -r and -f options.\n");
		err = 1; 	
	}
	if(opt_ramloader && opt_partition)
	{
		if (!opt_quiet)
			fprintf(stderr, "Error: specifying a partition to the ramloader makes no sense.\n");
		err = 1; 	
	}
	if(!opt_filename)
	{
		if (!opt_quiet)
		fprintf(stderr, "Error: No image given.\n");
		err = 1; 	
	}

	if (!opt_ramloader && !opt_flashloader) {
		if (!opt_quiet) {
		fprintf (stderr, 
				 "Error: neither ramloader (-r) nor flashloader (-f)\n");
		fprintf (stderr,
				 "       selected. Aborting.\n");
		}
		err = 1; 	
	}
	if (err) return 1;

	if (!opt_quiet) {
		fprintf (stderr, "Load image file: \"%s\" to %s",
			 opt_filename, opt_ramloader?"ram":"flash");

		if (opt_partition)
			fprintf (stderr, " partition %s\n", opt_partition);
		else
			fprintf (stderr, "\n");
        }

	return (0);
}


void usage()
{
	fprintf (stderr,
"usage: xloader | ramloader | flashloader\n"
"\n"
"       Invoked as \"ramloader\" or \"xloader -r\", this program will\n"
"       load a kernel image into RAM and pass it to uCbootloader for\n"
"       execution.\n"
"       Invoked as \"flashloader\" or \"xloader -f\", it will load a\n"
"       cramfs image and pass it to uCbootloader to be written into\n"
"       flash memory.\n"
"       In both cases, this program *will not return*. Once uCbootloader\n"
"       has been given control, interrupts are disabled, and the new\n"
"       image is booted.\n"
);
	fprintf(stderr,
"Options:\n"
"\t-2\twrite to second flash device(default is the first flash device)\n"
"\t-4\tfor 4k-based block, default 64k-based\n"
"\t-d\tprint debugging message\n"
"\t-f\tinvoke flashloader\n"
"\t-F\tinvoke flashloader; use all of user flash\n"
"\t-h\tthis help information\n"
"\t-n\tDo everything except call the bootloader (noop)\n"
"\t-r\tinvoke ramloader\n"
"\t-s\tRead new image file from stdin\n"
"\t-w\tRefresh /dev/watchdog at key points\n"
"\t-q\tdo it quietly, no output to the screen\n\n"
);
	exit(1);
}



int load_image (char *filename)
{
	FILE *image;
	struct stat statbuf;
	int filesize, i, j, n;
	int bytes_read = 0;
	int links_per_car, links_over;
	int percent;
	int ferror_image;
	struct MD5Context  md5c;
	unsigned char      digest[16];

	if (opt_stdin) {
		image = stdin;
	} else {
		/* open image file: */
		image = fopen (filename, "r");
		if (image == NULL) {
			perror ("Error opening image file");
			return (errno);
		}
	}


	/* Check for the presence of a uCimage file header: */
	/* read header: */
	fread (&header, sizeof(header), 1, image);
	check_uCimage (&header, image);

	if (header_present) {
		filesize = header.data_size;
		MD5Init(&md5c); /* Initialize MD5 module */

	} else {
		/* no uCimage header present: */
		if (opt_stdin) {
			/* allocate the maximum size, since we do not know
			 * how big the image will be: */
			filesize = MAX_IMAGE_SIZE;
		} else {
	/* stat input file */
	if (stat (filename, &statbuf)) {
		perror ("Error stat()ing image file");
		return (errno);
	}
	/* otherwise, all is still OK: */
	filesize = statbuf.st_size;	
		}
	}


	/* build buffer chain: */
	links = (int) ((filesize + BUFFERSIZE -1) / BUFFERSIZE);
	/* chain = (void *)malloc (links * sizeof (void *)); */

	/* build link train: */
	links_per_car = CARSIZE / BUFFERSIZE;
	cars = 1 + links / links_per_car;

	/* Can we fit the chain into the last car? */
	/* How many links in the last car? */
	links_over = links - (cars - 1) * links_per_car;
	if ((CARSIZE - links_over*BUFFERSIZE) <
		links * sizeof (void *)) {
		/* then the chain can not be placed in the last car;
		 * allocate one more.*/
		cars++;
		links_over = links - (cars - 1) * links_per_car;
		if (links_over < 0) links_over = 0;
	}

	/* allocate the array of cars: */
	/* note: this array can be discarded once the chain of links
	 * has been mapped onto the actual buffers */
	train = (void *)malloc(cars * sizeof (void *));
	if ( train == NULL) {
		if (!opt_quiet)
		fprintf (stderr, "Error allocating train\n");
		return (errno);
	} else
		memset (train, 0, cars * sizeof (void *));

	/* allocate the cars: */
	for (i=0;i<cars;i++) {
		train[i] = (void *)malloc(CARSIZE);
		if (train[i] == NULL) {
			if (!opt_quiet)
			fprintf (stderr, "Error allocating car %d\n", i);
			/* before we return, free all allocated memories */
			deallocate_all();
			return (errno);
		}
		DBG("train[%d] = %p\n", i, train[i]);
	}

	/* sort the cars */
	sort_pointers (train, cars);

	/* map the chain into the last car: */
	chain = (void *)(train[cars-1]) + (links_over * BUFFERSIZE);

	/* allocate links into the cars: */
	for (i=0;i<cars;i++,j++) {
		DBG("\ntrain[%d] = %p cars:\n", i, train[i]);
		for (j=0;j<links_per_car;j++) {
			if (i*links_per_car+j >= links)
				break;
			chain[i*links_per_car+j] = train[i] + (BUFFERSIZE * j);
			DBG("  0x%08x", (unsigned int)chain[i*links_per_car+j]);
		}
	}

	DBG("\nfilesize = %d, links = %d\n", filesize, links);
	DBG("cars = %d, links_per_car = %d, links_over = %d\n", cars, links_per_car, links_over);
	DBG("car[%d] = %p, chain = %p\n", cars-1, train[cars-1], chain);



	/* populate chain with image file: */
	for (i=0;i<cars;i++) {
		if ((i+1)*links_per_car <= links)
			j = links_per_car;
		else
			j = links_over;

		n = fread (train[i], 1, BUFFERSIZE * j, image);

		if (opt_debug)
			fprintf(stderr, "fread %d bytes to car[%d] = %p\n",
					n, i, train[i]);
		else {
			percent = (((i*links_per_car+j)+1) * 100)/links;
			/* if (percent%10 == 0) */
			if (!opt_quiet)
			fprintf (stderr, "\r%d%%", percent);
		}

		/* Compute MD5 as we read the file: */
		if (header_present)
			MD5Update (&md5c, (char *)(train[i]), n);


		bytes_read += n;
			
		if (n < BUFFERSIZE * j) {
			if (opt_stdin && !header_present) {
				/* assume the transmission has finished */
				break;
			} else {
				if (bytes_read != filesize) {
					ferror_image = ferror (image);
					if (!opt_quiet)
			fprintf (stderr, "Error #%d reading from image file\n",
							 ferror_image);
			fclose (image);
					return ferror_image;
				}
			}
		}
	}

	if (!opt_debug && !opt_quiet)
		fprintf (stderr, "\n");

	if (opt_stdin && !feof(image)) {
		if (bytes_read != filesize) {
			if (!opt_quiet)
				fprintf (stderr, "Image too big, max %d\n", filesize);
 	fclose (image);
			deallocate_all();
			return -1;
		}
	}

 	fclose (image);
	/* free(train); */

	if (opt_stdin) {
		filesize = bytes_read;
		DBG("size of received file = %d bytes\n", filesize);
	}

	/* NOTE THAT we should have some kind of header and / or footer to verify
	 * that our image is error free. For starters, make sure it's not empty.
	 */

	if (filesize == 0) {
		if (!opt_quiet)
			fprintf(stderr, "Image is empty.\n");
		deallocate_all();
		return -1;
	}

	if (opt_watchdog) {
		fputc('c', watchdog);
		fflush (watchdog);
	}


	if (header_present) {
		char buf[42], ascii_md5[34];

		/* save MD5: */
		MD5Final (&(digest[0]), &md5c);

		if (!opt_quiet)
			printf ("Checking MD5 signature... ");

		/* print the signature to a string: */
		for (i=0;i<16;i++)
			sprintf (&(ascii_md5[i*2]), "%02x", digest[i]);

		/* Compare with given digest: */
		for (i=0;i<16;i++) {
			if (digest[i] != header.md5sum[i]) {
				printf ("ERROR: MD5 digest mismatch\n");
				printf ("MD5 digest calculated as:  %s\n", ascii_md5);
				printf ("failed to match given MD5: ");
				for (i=0;i<16;i++)
					printf ("%02x", header.md5sum[i]);
				printf ("\n");
				return (1);
			}
		}

		if (!opt_quiet)
			printf ("verified\n");

		if (opt_watchdog) {
			fputc('c', watchdog);
			fflush (watchdog);
		}

		if (opt_flashloader) {
			/* write uCbootstrap envars for the image: */
			if (opt_partition) {
				sprintf (buf, "p_%s_SIZE=%d", opt_partition, header.data_size);
				setbenv(buf);

				sprintf (buf, "p_%s_MD5=%s", opt_partition, ascii_md5);
				setbenv(buf);
			}
		}
		
	} /* endif header_present */



	/* set uCbootloader arguments: */
	m.len = filesize;
	m.offset = (void *)chain;

	return (0);
}






int sort_pointers (void **pointer, int N)
{
	int i, j;
	void *p;

	/* sort pointers */
	for (i=0;i<N;i++) {
		p = pointer[i];
		for (j=i+1;j<N;j++) {
			if ((unsigned long int)pointer[j] < (unsigned long int)p) {
				p          = pointer[j];
				pointer[j] = pointer[i];
				pointer[i] = p;
			}
		}
	}
	return (0);
}



int load_image_4k (char *filename)
{
	FILE *image;
	struct stat statbuf;
	int filesize, i, n;
	int percent;
	int ferror_image;

	/* stat input file */
	if (stat (filename, &statbuf)) {
		perror ("Error stat()ing image file");
		return (errno);
	}

	/* otherwise, all is still OK: */
	filesize = statbuf.st_size;	

	/* build buffer chain: */
	DBG("links: ");

	links = filesize / BUFFERSIZE;
	if ( filesize % BUFFERSIZE )
	    links++;

	DBG("  %d  \n", links );
	DBG("pointer chain: ");
	chain_tmp = (void *)malloc (links * sizeof (void *));       /* Temporary chain */
	DBG("  0x%08x\n", (unsigned int)chain_tmp);

	for (i=0;i<links;i++) {
	    chain_tmp[i] = (void *)malloc (BUFFERSIZE);
	    DBG("  0x%08x", (unsigned int)chain_tmp[i]);
	    if (chain_tmp[i] == NULL) {
			fprintf (stderr, "Error allocating chain link %d\n", i);
			return (errno);
		}
	}
	DBG("\npointer chain: ");
	chain = (void *)malloc (links * sizeof (void *));	/* Link pointers have to be at the end */
	DBG("  0x%08x\n", (unsigned int)chain);

	for (i=0; i<links; i++)					/* Dup the chain */
	    chain[i] = chain_tmp[i];

	DBG("filesize = %d\n", filesize);

	/* open image file: */
	image = fopen (filename, "r");
	if (image == NULL) {
		perror ("Error opening image file");
		return (errno);
	}

	/* populate chain with image file: */
	for (i=0;i<links;i++) {
		n = fread (chain[i], 1, BUFFERSIZE, image);

		if (opt_debug)
			fprintf(stderr,
					"fread %d bytes to chain[%d] = %p\n", n, i,chain[i]);
		else {
			percent = ((i+1) * 100)/links;
			if (percent%10 == 0)
				fprintf (stderr, "\r%d%%", percent);
		}

		if ((n < BUFFERSIZE) && (BUFFERSIZE*i + n < filesize)) {
			ferror_image = ferror (image);
			fprintf (stderr, "Error #%d reading from image file\n",
					 ferror_image);
			fclose (image);
			return ferror_image;
		}
	}
	if (!opt_debug) fprintf (stderr, "\n");

	fclose (image);

	/* set uCbootloader arguments: */
	m.len = filesize;
	m.offset = (void *)chain;

	return (0);
}


int check_uCimage (uCimage_header *header, FILE *handle)
{
	int i;

	/* Check magic in header */
	for (i=0;i<sizeof(header->magic);i++) {
		if (header->magic[i] != UCHEADER_MAGIC[i]) {
			if (opt_debug)
				fprintf (stderr, "Header magic[%d] not: \"%s\" instead: \"%s\"\n",
					 i, UCHEADER_MAGIC, header->magic);
			fprintf (stderr, "uCimage header not detected.\n");
			rewind (handle);
			return (1); /* header not found */
		}
	}

	header_present = 1;

	/* TODO: check reported header size, seek to data */

	/* Convert from little-endian to host byte order *in place*
	 * in the header: */

	header->header_size = ltoh32(header->header_size);
	DBG ("header_size reported as: %10d\n", header->header_size);

	/* image size: */
	header->data_size   = ltoh32(header->data_size);
	fprintf (stdout, "data_size reported as:   %10d\n", header->data_size);

	/* header date code */
	fprintf (stdout, "date code reported as:    \"%s\"\n", header->datecode);

	/* header name */
	fprintf (stdout, "name reported as:         \"%s\"\n", header->name);

	/* MD5: */
	fprintf (stdout, "MD5 digest reported as:   ");
	for (i=0;i<16;i++)
		fprintf (stdout, "%02x", header->md5sum[i]);
	fprintf (stdout, "\n");

#if 0
	/* read image and do MD5: */
	while (!feof(infile)) {
		n = fread (buf, 1, BUFFERSIZE, infile);
		size += n;
		MD5Update (&md5c, buf, n);
	}
	/* save MD5: */
	MD5Final (digest, &md5c);
#endif

	return (0);
}


/****************************************************************************/

/* safely deallocate all major structures */
void deallocate_all (void)
{
	int i;

	if (train != NULL) {
		for (i=0;i<cars;i++) {
			if (train[i] != NULL) {
				DBG("deallocate_all(): train[%d] == %p\n", i, train[i]);
				free (train[i]);
			}
		}
		free (train);
	}
}

/****************************************************************************/

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
