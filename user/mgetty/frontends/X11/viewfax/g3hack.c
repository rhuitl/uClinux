/* g3hack.c - hack identical lines off the end of a fax
 *
 * This program is in the public domain.  If it does not work or
 * causes you any sort of grief, blame the public, not me.
 *
 * fdc@cliwe.ping.de, 1995-06-24
 *
 * v2 1995-06-25 - fixed some boundary problems, added named input
 * v3 1995-06-28 - changed write-error detection
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERSION "0.3"

#ifdef BSD
#define strrchr rindex
#endif

extern int getopt();
extern char *optarg;
extern int optind, opterr;

static char *progname;
static char *banner = "\n%s version " VERSION "\n\n";
static char *usage = "\
usage: %s <-n count> <-h size> -o <outputfile> {inputfile}\n\n\
Copy a g3-(1d)-fax file from stdin to stdout and delete any\n\
   more than `count' identical trailing lines (default 10).\n\
Optionally skip `size'-byte header.\n\
Optionally named outputfile (else stdout).\n";

#define nxtbit()	((imask>>=1) ? ((ibits&imask)!=0) :		\
			 ((ibits=getchar()) == EOF) ? -1 :		\
			 (((imask=0x80)&ibits)!=0))
#define putbit(b)							\
    do {								\
	if (b)								\
	    obits |= omask;						\
	if ((omask >>= 1) == 0) {					\
	    this->line[this->length>>3] = obits;			\
	    omask = 0x80;						\
	    obits = 0;							\
	}								\
	this->length++;							\
	if (this->length >= BUFSIZ<<3) {				\
	    fprintf(stderr, "%s: unreasonably long line\n", progname);	\
	    exit(1);							\
	}								\
    } while (0)

static void
copy(int nlines)
{
    int ibits = 0, imask = 0;	/* input bits and mask */
    int obits = 0;		/* output bits */
    int omask = 0x80;		/* output mask */
    int zeros = 0;		/* number of consecutive zero bits */
    int thisempty = 1;		/* empty line (so far) */
    int empties = 0;		/* number of consecutive EOLs */
    int identcount = 0;		/* number of consecutive identical lines */
    struct {
	char line[BUFSIZ];
	int length;
    } lines[2], *prev, *this, *temp;

    this = &lines[0];
    prev = &lines[1];
    this->length = prev->length = 0;
    while (1) {
	int bit = nxtbit();
	if (bit == -1)
	    break;		/* end of file */
	putbit(bit);
	if (bit == 0) {
	    zeros++;
	    continue;
	}
	if (zeros < 11) {	/* not eol and not empty */
	    zeros = 0;
	    thisempty = 0;
	    /* Get rid of any accumulated empties.  Should only happen
	       for the eol at the beginning of the first line (we
	       switch from the |eol data| to the |data eol|
	       viewpoint). */
	    for ( ; empties; empties--)
		if (fwrite("\0\1", 1, 2, stdout) != 2)
		    break;
	    continue;
	}
	/* at end of line */
	zeros = 0;
	omask = 0x80;
	obits = 0;
	if (thisempty) {
	    empties++;
	    if (empties >= 5)
		break;		/* 6 eols in a row */
	    this->length = 0;
	    continue;
	}
	thisempty = 1;
	/* at end of non-empty line */
	this->length = (this->length+7)&~7;
	this->line[(this->length-1)>>3] = 1; /* byte-align the eol */
	if (this->length == prev->length &&
	    memcmp(this->line, prev->line, this->length>>3) == 0) {
	    identcount++;
	    this->length = 0;
	    continue;
	}
	/* at end of non-matching line */
	for ( ; identcount; identcount--)
	    if (fwrite(prev->line, 1, prev->length>>3, stdout) !=
		prev->length>>3)
		break;
	temp = prev;
	prev = this;
	this = temp;
	identcount = 1;
	this->length = 0;
    }
    if (identcount > nlines)
	identcount = nlines;
    for ( ; !ferror(stdout) && identcount; identcount--)
	    fwrite(prev->line, 1, prev->length>>3, stdout);
    if (!ferror(stdout) && !thisempty)
	    fwrite(this->line, 1, this->length>>3, stdout);
    for ( ; !ferror(stdout) && empties; empties--)
	fwrite("\0\1", 1, 2, stdout);
    if (ferror(stdout)) {
	fprintf(stderr, "%s: write error\n", progname);
	exit(1);
    }
}

int
main(int argc, char **argv)
{
    int c, err = 0;
    int header = 0;
    int nlines = 10;

    if ((progname = strrchr(argv[0], '/')) == NULL)
	progname = argv[0];
    else
	progname++;
    opterr = 0;
    while ((c = getopt(argc, argv, "h:n:o:v")) != EOF)
	switch (c) {
	case 'h':
	    header = atoi(optarg);
	    break;
	case 'n':
	    nlines = atoi(optarg);
	    break;
	case 'o':
	    if (freopen(optarg, "w", stdout) == NULL) {
		perror(optarg);
		exit(1);
	    }
	    break;
	case 'v':
	    fprintf(stderr, banner, progname);
	    exit(0);	    
	case '?':
	    err++;
	}
    if (err || optind < argc-1) {
	fprintf(stderr, banner, progname);
	fprintf(stderr, usage, progname);
	exit(1);
    }
    if (optind < argc && freopen(argv[optind], "r", stdin) == NULL) {
	perror(argv[optind]);
	exit(1);
    }
    while (header--)
	putchar(getchar());
    copy(nlines);
    exit(0);
}
