/*
 * uCmkimage.c:
 *
 *      Prepend an image header to a binary image file destined
 *      for a platform running Arcturus Networks' uCbootstrap
 *      bootloader.
 *
 * (c) 2004-2008 Arcturus Networks Inc. by
 *     June 2008, David Wu added uCheader 0.3 support
 *     Michael Leslie <mleslie@arcturusnetworks.com>
 *
 * Note that this needs to be made to ensure that the values
 * written to the header are little-endian
 */
 /*  David Wu: 
  *  FIXME: error checking for all command options which are required
  * to be set, otherwise cause SIGSEGV since NULL pointer is dereferenced
  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "md5.h"
#include "uCheader.h"
#include <errno.h>

#define DBG(a1, a2...) if (opt_debug) fprintf(stderr, a1, ##a2)

/****** data declarations: **************************************************/

#define MAX_IMAGES 8
char *opt_filename[MAX_IMAGES];    /* image filename to load */
char *opt_outfilename = NULL;      /* image filename to load */
char *opt_partition[MAX_IMAGES];   /* partition to save, only 1 char is allowed */
int   opt_stdin       = 0;         /* read image from stdin instead of filesystem */
char *opt_name;                    /* image filename or ID */
char *opt_datecode;                /* image date code */
char *opt_version     = NULL;      /* uCheader version */
char *opt_start[MAX_IMAGES];       /* image offset to the beginning of current uCheader */
char *opt_length[MAX_IMAGES];      /* image size */
char *opt_address[MAX_IMAGES];     /* Flash address for the image to be written */
char *opt_feature[MAX_IMAGES];     /* feature for the image */

int   opt_quiet = 0;          /* do not print anything to the screen */
int   opt_debug = 0;

int           header_size;  /* after which data begins */
int           data_size;    /* size of image in bytes */
char          datecode[12]; /* output of 'date -I': "yyyy-mm-dd" */
unsigned char md5sum[16];   /* binary md5sum of data */

uCimage_header header;

FILE *infile, *outfile;
#define BUFFERSIZE 65536
unsigned char buf[BUFFERSIZE];

/****** function prototypes: ************************************************/

int make_header_v03(void);
int parse_args(int argc, char *argv[]);
void usage(void);


void initialize(void)
{
	int i;
	for(i=0; i < MAX_IMAGES; i++){
		opt_start[i] = NULL;
		opt_length[i] = NULL;
		opt_address[i] = NULL;
		opt_feature[i]  = NULL;
		opt_filename[i] = NULL;
		opt_partition[i] = NULL;
	}
}

void dump(void)
{
	int i;
	for(i=0; i < MAX_IMAGES; i++){
		if(opt_filename[i]) DBG("\n opt_filename[%d]=[%s]\n", i, opt_filename[i]);
		if(opt_address[i])  DBG("  opt_address[%d]=[%s]\n", i, opt_address[i]);
		if(opt_start[i])    DBG("    opt_start[%d]=[%s]\n", i, opt_start[i]);
		if(opt_length[i])   DBG("   opt_length[%d]=[%s]\n", i, opt_length[i]);
		if(opt_feature[i])  DBG("  opt_feature[%d]=[%s]\n", i, opt_feature[i]);
		if(opt_partition[i])DBG("opt_partition[%d]=[%s]\n", i, opt_partition[i]);
	}
}
/****** main(): *************************************************************/

int main (int argc, char *argv[])
{
	unsigned int       i;
	unsigned int       n = 0;
	unsigned int       size = 0;
	struct MD5Context  md5c;
	uint32_t bit32sum = 0;
	uint32_t * pointer_to_buf = (uint32_t *)buf;

	initialize();

	if (parse_args (argc, argv))
		if (!opt_quiet)
			usage();

        if(opt_version) /* uCheader version */
	{
		if( !strcmp(opt_version, "03"))
			return make_header_v03();
	}	
	if (!opt_quiet) {
		fprintf (stderr, "Prepend header to: \"%s\"\n", opt_filename[0]);
	}
	/* Initialize MD5 module: */
	MD5Init(&md5c);

	/* Initialize various header data: ***************************/

	/* set magic in header */
	for (i=0;i<sizeof(header.magic);i++)
		header.magic[i] = UCHEADER_MAGIC[i];

	/* set header size */
	header.header_size = sizeof(uCimage_header);

	/* set header date code */
	strncpy (header.datecode, opt_datecode, sizeof(header.datecode));

	/* set header name */
	strncpy (header.name, opt_name, sizeof(header.name));


	/* Open input and output files: ******************************/
	if (opt_stdin)
		infile = stdin;
	else
		infile = fopen (opt_filename[0], "r");

	if (infile == NULL) {
		fprintf (stderr, "FATAL: could not open %s\n", opt_filename[0]);
		exit(1);
	}

	outfile = fopen (opt_outfilename, "w");
	if (outfile == NULL) {
		fprintf (stderr, "FATAL: could not open %s\n", opt_outfilename);
		exit(1);
	}

	/* Write header and image file to output, compute MD5: ******/
	/* write header: */
	fwrite (&header, sizeof(header), 1, outfile);

	/* copy image and do MD5: */
	while (!feof(infile)) {
		n = fread (buf, 1, BUFFERSIZE, infile);
		size += n;
		MD5Update (&md5c, buf, n);
		fwrite (buf, 1, n, outfile);

		/* 32 bit checksum */
		pointer_to_buf = (uint32_t *)buf;
		while ( (unsigned char *)pointer_to_buf < buf + n ) {
			bit32sum += htonl(*pointer_to_buf);
			pointer_to_buf++;
                }

	}
	/* write image size to header: */
	header.data_size = size;

	/* write bit32sum to header */
	header.bit32sum = bit32sum;

	/* copy MD5 to header: */
	MD5Final (header.md5sum, &md5c);

	/* write partition information */
	header.partition = opt_partition[0][0];

	/* rewind output file to update header: */
	rewind (outfile);
	/* rewrite header: */
	fwrite (&header, sizeof(header), 1, outfile);


	if (!opt_stdin)
		fclose (infile);
	fclose (outfile);

	return (0);
}

int headers[MAX_IMAGES];

int make_header_v03(void)
{

    unsigned int   i, h;
    unsigned int   n = 0;
    unsigned int   size = 0;
    unsigned int s_address;
    struct MD5Context  md5c;
    uint32_t bit32sum = 0;
    uint16_t bit16sum = 0;
    uint32_t * pointer_to_buf = (uint32_t *)buf;
    uCimage_header_v03 header_v03;
    uint16_t * ptr;
    int header_size = sizeof(uCimage_header_v03);

    /* Open output file */
    outfile = fopen (opt_outfilename, "w");
    if (outfile == NULL) {
        fprintf (stderr, "FATAL: could not open %s\n", opt_outfilename);
        exit(1);
    }

    h = 0; /* position the headers */
    for(i = 0; opt_filename[i]; i++) { /* maximum  3 images: A, B and C (extra data) */
        /* Open input file */
        if (opt_stdin)
            infile = stdin;
        else
            infile = fopen (opt_filename[i], "r");

        if (infile == NULL) {
            fprintf (stderr, "FATAL: could not open %s\n", opt_filename[i]);
            exit(1);
        }
        headers[h] = h * header_size;
        memset(&header_v03, 0, header_size);

        /* Initialize MD5 module: */
        MD5Init(&md5c);

        /* set magic in header */
        {
            int j;
            for (j = 0; j < sizeof(header_v03.magic); j++)
        	header_v03.magic[j] = UCHEADER_MAGIC[j];
        }
        /* set header size */
        header_v03.header_size = header_size;

        /* set header date code */
        strncpy (header_v03.datecode, opt_datecode, sizeof(header_v03.datecode));

        /* set header name */
        strncpy (header_v03.name, opt_name, sizeof(header_v03.name));

        /* Write header and image file to output, compute MD5: ******/
        /* write header: */
        fwrite (&header_v03, sizeof(header_v03), 1, outfile);

        /* copy image and do MD5: */
        while (!feof(infile)) {
            n = fread (buf, 1, BUFFERSIZE, infile);
            size += n;
            MD5Update (&md5c, buf, n);
            fwrite (buf, 1, n, outfile);
        
            /* 32 bit checksum */
            pointer_to_buf = (uint32_t *)buf;
            while ( (unsigned char *)pointer_to_buf < buf + n ) {
                bit32sum += htonl(*pointer_to_buf);
                pointer_to_buf++;
            }
        }

        errno = 0;
        s_address = DEFAULT_ADDR;
        if(opt_address[i]) s_address = strtoul(opt_address[i], NULL, 0) & 0xFFFFFFFF;
        if(errno){
            fprintf (stderr, "FATAL: address error %s\n", opt_address[i]);
            exit(1); //s_address = DEFAULT_ADDR;
        }

        header_v03.A_flash_start_address = s_address;
        header_v03.A_start   = header_v03.header_size;
        header_v03.A_length  = size;
        header_v03.A_feature = opt_feature[i]? strtoul(opt_feature[i], NULL, 0) & 0xFF : DEFAULT_FEATURE;
        header_v03.A_partition = opt_partition[i]? opt_partition[i][0]: DEFAULT_PART;

        /* write image size to header: */
        header_v03.data_size = size;
        
        /* write partition information */
        header_v03.partition = opt_partition[i][0];
        
        /* version */
        header_v03.version[0] = 0;
        header_v03.version[1] = 3;
        
        if (!opt_stdin){
            fclose (infile); /* close first file */
            i++; /* deal with next file*/
            if(opt_filename[i]){
                errno = 0;
                s_address = DEFAULT_ADDR;
                if(opt_address[i]) s_address = strtoul(opt_address[i], NULL, 0) & 0xFFFFFFFF;
                if(errno){
                    fprintf (stderr, "FATAL: address error %s\n", opt_address[i]);
                    exit(1); //s_address = DEFAULT_ADDR;
                }
        
                header_v03.B_flash_start_address = s_address;

                /* wmq: may need to check opt_feature[i] and opt_partition[i] as did for opt_address[i] */
               	header_v03.B_feature = opt_feature[i]? strtoul(opt_feature[i], NULL, 0) & 0xFF : DEFAULT_FEATURE;
	        header_v03.B_partition = opt_partition[i]? opt_partition[i][0]: DEFAULT_PART;
                if(strcmp(opt_filename[i-1], opt_filename[i])){ /* file A != file B */
                    infile = fopen (opt_filename[i], "r");
                    if (infile == NULL) {
                        fprintf (stderr, "FATAL: could not open %s\n", opt_filename[i]);
                        exit(1);
                    }
                    while (!feof(infile)) {
                        n = fread (buf, 1, BUFFERSIZE, infile);
       	                header_v03.B_length += n;
                        MD5Update (&md5c, buf, n);
                        fwrite (buf, 1, n, outfile);
        
                        /* 32 bit checksum */
                        pointer_to_buf = (uint32_t *)buf;
                        while ( (unsigned char *)pointer_to_buf < buf + n ) {
                            bit32sum += htonl(*pointer_to_buf);
                            pointer_to_buf++;
                        }
                    }
                    fclose (infile); /* close input file */
                    /* update image size to header */
                    header_v03.data_size += header_v03.B_length;
                    header_v03.B_start   = header_v03.A_start + header_v03.A_length;
                } else { /* file A = file B */
                    /* opt_start[i] should be in [header_v03.A_start, header_v03.A_length]*/
                    unsigned int start, length;
                    if(opt_start[i]) start = strtoul(opt_start[i], NULL, 0) & 0xFFFFFFFF;
                    else start = header_v03.A_start;
                    if(start < header_v03.A_start || start > header_v03.A_start + header_v03.A_length){
                        fprintf (stderr, "FATAL: start(%s) for %s is not valid.\n", opt_start[i], opt_filename[i]);
                        exit(1);
                    }
                    header_v03.B_start   = start;
                    if(opt_length[i]) length = strtoul(opt_length[i], NULL, 0) & 0xFFFFFFFF;
                    else length = header_v03.A_length;
                    if(length > header_v03.A_length){
                        fprintf (stderr, "FATAL: length(%s) for %s is not valid.\n", opt_length[i], opt_filename[i]);
                        exit(1);
                    }
                    if(start + length > header_v03.A_start + header_v03.A_length){
                        fprintf (stderr, "FATAL: start(%s)/length(%s) for %s is greater than the totol size(0x%x) of %s.\n", opt_start[i], opt_length[i], opt_filename[i], header_v03.A_length+header_v03.A_start, opt_filename[i-1]);
                        exit(1);
                    }
                    header_v03.B_length  = length;
                } 
                i++; /* deal with third file, only as a payload, no uCheader checking/creating */
                if(opt_filename[i]){
                    header_v03.C_offset  = header_v03.header_size + header_v03.data_size;
                    infile = fopen (opt_filename[i], "r");
                    if (infile == NULL) {
                        fprintf (stderr, "FATAL: could not open %s\n", opt_filename[i]);
                        exit(1);
                    }
                    while (!feof(infile)) {
                        n = fread (buf, 1, BUFFERSIZE, infile);
                        header_v03.data_size += n;
                        MD5Update (&md5c, buf, n);
                        fwrite (buf, 1, n, outfile);

                        /* 32 bit checksum */
                        pointer_to_buf = (uint32_t *)buf;
                        while ( (unsigned char *)pointer_to_buf < buf + n ) {
                            bit32sum += htonl(*pointer_to_buf);
                            pointer_to_buf++;
                        }
                    }
                    fclose (infile); /* close input file */
                }
            } else { /* no file B */
                /* do nothing */
            }
        }
	
        /* write bit32sum to header */
        header_v03.bit32sum = bit32sum;

        /* copy MD5 to header: */
        MD5Final (header_v03.md5sum, &md5c);

        /* do header checksum */
        ptr = (uint16_t *) &header_v03;
        size = header_v03.header_size - sizeof(unsigned short); /* exclude checksum fileds */
        while ( size ) {
            bit16sum += htons(*ptr);
            ptr++;
            size -= sizeof(unsigned short);
        }
        header_v03.header_checksum = bit16sum;

        /* rewind output file to update header: */
        fseek(outfile, headers[h], SEEK_SET);
        /* rewrite header: */
        fwrite (&header_v03, sizeof(header_v03), 1, outfile);
        break;
    }
    fclose (outfile);
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
	int i, pi, si, li, fi, ai, Fi;
	int err = 0;
	char * argvp;

	if (argc < 2)
		return (1);
	pi = 0; si = 0; li = 0; fi = 0; ai = 0; Fi = 0;

	for (i=1;i<argc;i++) {
		if (argv[i][0] == '-') {
			argvp = argv[i] + 1;

			if (!*argvp) {
				if (i < argc-1)
					return 1; /* no option */
				else {
					opt_stdin = 1;
					opt_filename[0] = "-";
				}
			}


			while(*argvp) {
				if(si>=MAX_IMAGES || li>=MAX_IMAGES || fi>=MAX_IMAGES
						 || ai>=MAX_IMAGES || Fi>=MAX_IMAGES || pi>=MAX_IMAGES){
					fprintf(stderr, "Error: Too many -f -l -a -F -p -S are given. Maximum is %d\n", MAX_IMAGES);
					fprintf(stderr, "       Try to increase it if that is what you want.\n");
					exit(1);
				}
				switch (*argvp++)
					{
					case 'f': opt_filename[fi++] = argv[++i]; break;
					case 'A': opt_address[ai++]  = argv[++i]; break;
					case 'S': opt_start[si++]    = argv[++i]; break;
					case 'L': opt_length[li++]   = argv[++i]; break;
					case 'F': opt_feature[Fi++]  = argv[++i]; break;
					case 'p': opt_partition[pi++]= argv[++i]; break;

					case 'o': opt_outfilename   = argv[++i]; break;
					case 't': opt_datecode      = argv[++i]; break;
					case 'n': opt_name          = argv[++i]; break;
					case 'v': opt_version       = argv[++i]; break;
					case 's':
						opt_stdin    = 1;
						opt_filename[0] = "-";
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
			opt_filename[0] = argv[i];
	}

	/* print out options if debug enabled: */
	DBG("opt_name        = \"%s\"\n", opt_name);
	DBG("opt_version     = \"%s\"\n", opt_version);
	dump();

	if(!opt_filename[0]) {
		if (!opt_quiet)
			fprintf(stderr, "Error: No image given.\n");
		err = 1;
	}

	if(opt_partition[0] == NULL) opt_partition[0] = "0";
	for ( i = 0; i < fi; i++) {
		if (opt_partition[i] && strlen(opt_partition[i]) != 1) {
			if (!opt_quiet)
				fprintf(stderr, "Error: Partition should be 1 character long(%s is not valid).\n", opt_partition[i]);
			err = 1;
		}
	}

	if (err) return 1;

	return (0);
}



void usage()
{
	fprintf (stderr,
"usage: uCmkimage [options] <image filename>\n"
"\n"
"       Prepend an image header to a binary image file destined\n"
"       for a platform running Arcturus Networks' uCbootstrap\n"
"       bootloader. For uCheader version 03, it only supports \n"
"       maximum 3 input images or binaries. For built-in uCheader\n"
"       support, the third image must be created using this same tool.\n"
"\n"
);
	fprintf(stderr,
"Options:\n"
"\t-v <version>\tuCheader version, Ex. 03(major 0, minor 3)\n"
"\t            \tmultiple -f -p -A -F -S -L must be given, otherwise\n" 
"\t            \tdefault values may be used or errors may occur.\n" 
"\t-f <filename>\tinput image filename\n"
"\t-o <filename>\toutput image filename\n"
"\t-t <date code>\t%d chars, `date -I`\n"
"\t-n <name or ID>\timage name or ID - %d chars\n"
"\t-s           \tRead image file from stdin\n"
"\t-p <partition>\t1 charater partition number where this image should be burn\n"
"\t-A <address>\tFlash address to be programed to\n"
"\t-F <feature>\t0x0 - 0xFF, see uCheader.h for all supported features\n"
"\t-S <offset>\toffset to the beginning of the current uCheader\n"
"\t-L <length>\timage size starting from \"offset\"\n"
"\t-h         \tthis help information\n"
"\t-d         \tprint debugging message\n"
"\t-q         \tdo it quietly, no output to the screen\n\n",
			sizeof(header.datecode),
			sizeof(header.name)
			
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
