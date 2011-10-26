#ifndef lint
static char rcsid[] = "$Id: siggen.c,v 1.14 1994/07/25 15:24:12 gkim Exp $";
#endif

/*
 * siggen.c
 *
 *	generate signatures for a given file.
 *
 * Gene Kim
 * Purdue University
 * October 14, 1992
 */

#include "../include/config.h"
#include <stdio.h>
#include <fcntl.h>
#ifdef STDLIBH
# include <stdlib.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef XENIX
# include <sys/time.h>
#else
# include <time.h>
#endif 	/* XENIX */
#ifdef DIRENT
# include <dirent.h>
#else
# ifndef XENIX
#  include <sys/dir.h>
# else		/* XENIX */
#  include <sys/ndir.h>
# endif		/* XENIX */
#endif	/* DIRENT */
#if (defined(SYSV) && (SYSV < 3))
# include <limits.h>
#endif	/* SVR2 */
#ifdef STRINGH
#include <string.h>
#else
#include <strings.h>
#endif
#include "../include/list.h"
#include "../include/tripwire.h"

#ifndef L_tmpnam
# define L_tmpnam (unsigned int) MAXPATHLEN
#endif

extern int optind;
int debuglevel = 0;
char *mktemp();

int (*pf_signatures [NUM_SIGS]) () = {
					SIG0FUNC,
					SIG1FUNC,
					SIG2FUNC,
					SIG3FUNC,
					SIG4FUNC,
					SIG5FUNC,
					SIG6FUNC,
					SIG7FUNC,
					SIG8FUNC,
					SIG9FUNC
				      };

int printhex = 0;
int sigallget = 1;
int sigvector[NUM_SIGS] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
char *signames[NUM_SIGS] = {
					SIG0NAME,
					SIG1NAME,
					SIG2NAME,
					SIG3NAME,
					SIG4NAME,
					SIG5NAME,
					SIG6NAME,
					SIG7NAME,
					SIG8NAME,
					SIG9NAME,
			   };
int verbosity = 0;
int quietmode = 0;
char *tmpfilename = NULL;
int readstdin = 0;


char *progname;

void
usage()
{
    int i;

    fprintf(stderr, "siggen: usage: [-0123456789qv] [-h] [ file ... ]\n");
    fprintf(stderr, "	(-h is to print signatures in hexadecimal.  default is base-64.\n");
    for (i = 0; i < sizeof(signames)/sizeof(char *); i++) {
	fprintf(stderr, "\tsig %d: %s\n", i, signames[i]);
    }

    exit(1);
}

int
main(argc, argv)
    int argc;
    char *argv[];
{
    int i, c;
    int fd;
    int errors = 0;

    progname = argv[0];

    optind = 1;
    while ((c = getopt(argc, argv, "0123456789aqvh")) != -1) {
	switch(c) {
	case '0':		sigallget = 0; sigvector[0] = 1; break;
	case '1':		sigallget = 0; sigvector[1] = 1; break;
	case '2':		sigallget = 0; sigvector[2] = 1; break;
	case '3':		sigallget = 0; sigvector[3] = 1; break;
	case '4':		sigallget = 0; sigvector[4] = 1; break;
	case '5':		sigallget = 0; sigvector[5] = 1; break;
	case '6':		sigallget = 0; sigvector[6] = 1; break;
	case '7':		sigallget = 0; sigvector[7] = 1; break;
	case '8':		sigallget = 0; sigvector[8] = 1; break;
	case '9':		sigallget = 0; sigvector[9] = 1; break;
	case 'a':		sigallget = 1; break;
	case 'v':		verbosity = 1; break;
	case 'q':		quietmode = 1; break;
	case 'h':		printhex = 1; break;
	case '?':
	default:
	    usage();
	    exit(1);
	}
    }

    argc -= optind;
    argv += optind;

    if (argc == 0)
	readstdin = 1;
    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "-") == 0) {
	    readstdin = 1;
	    continue;
	}
	else if ((fd = open(argv[i], O_RDONLY, 0)) < 0) {
	    warn_with_err("siggen: skipping '%s'", argv[i]);
	    errors++;
	    continue;
	}
	if (argc > 1)
	    printf("*** %s ***\n", argv[i]);
	if (siggen(fd) < 0)
	    errors++;

	if (fd)
	    close(fd);
    }

    if (readstdin) {
	FILE *fpout;
	/* generate temporary file name */
	if ((tmpfilename = (char *) malloc(L_tmpnam + MAXPATHLEN)) == NULL) {
	    perror("main: malloc()");
	    exit(1);
	};
	(void) strcpy(tmpfilename, "/tmp/twzXXXXXX");

	if ((char *) mktemp(tmpfilename) == NULL) {
	    perror("siggen: mktemp()");
	    exit(1);
	}

	/*  output */
	if (!(fpout = fopen(tmpfilename, "w"))) {
	    char err[1024];
	    sprintf(err, "main: fopen(%s)", tmpfilename);
	    perror(err);
	    exit(1);
	}
	/*  copy */
	while ((c = getc(stdin)) != EOF)
	    putc(c, fpout);
	fclose(fpout);
	if ((fd = open(tmpfilename, O_RDONLY)) < 0) {
	    perror("siggen: open");
	    exit(1);
	}
	if (siggen(fd) < 0)
	    errors++;

	if (fd)
	    close(fd);
	unlink(tmpfilename);
    }

    if (errors) 
	exit(1);


    exit(0);
}

int
siggen(fd)
    int fd;
{
    char 	sigs[NUM_SIGS][SIG_MAX_LEN];
    int 	i;

    /* collect signatures */
    for (i = 0; i < NUM_SIGS; i++) {
	char *pc = sigs[i];

	if (sigallget || sigvector[i]) {

	    if ((*pf_signatures[i])(fd, pc, SIG_MAX_LEN) < 0) {
	        return -1;
	    }
	    if (!quietmode)
		printf("sig%d: %-9s: %s\n", i, signames[i], sigs[i]);
	    else
		printf("%s ", sigs[i]);

	}
    }

    if (quietmode)
        printf("\n");

    return 0;
}
