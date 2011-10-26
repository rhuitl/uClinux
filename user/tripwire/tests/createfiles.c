#include <fcntl.h>
#include <stdio.h>

#define TESTFILEDIR "./testfiles/"

/* @@(string) indicates special test that doesn't use literal strings.  We
 * interpret these down below.
 */
char *pc_strings[] = {
"",
"a",
"abc",
"message digest",
"abcdefghijklmnopqrstuvwxyz",
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
"1\n",
"12\n",
"123\n",
"1234\n",
"12345\n",
"123456\n",
"1234567\n",
"123456789\n",
"The theory of quantum electrodynamics has now lasted for\n\
more than fifty years, and has been tested more and more\n\
accurately over a wider and wider range of conditions.\n\
At the present time I can proudly say that there is no\n\
significant difference between experiment and theory!\n\
\n\
Just to give you an idea of how the theory has been put\n\
through the wringer, I'll give you some recent numbers:\n\
experiments have Dirac's number at 1.00115965221 (with\n\
an uncertainty of about five times as much). To give you\n\
a feeling for the accuracy of these numbers, it comes\n\
out something like this:  If you were to measure the\n\
distance from Los Angeles to New York to this accuracy,\n\
it would be exact to the thickness of a human hair.\n\
That's how delicately quantum electrodynamics has, in the\n\
past fifty years, been checked -- both theoretically and\n\
experimentally.\n",
};

main(argc, argv)
    int argc;
    char *argv[];
{
    int i;
    char *pc;
    int slen;
    int fd;
    char filename[100];
    char *dir;

    if (argc == 2) {
	dir = argv[1];
	mkdir(dir, 0777);
    }
    for (i = 0; i < sizeof(pc_strings)/sizeof(char *); i++) {
	pc = pc_strings[i];

	sprintf(filename, "%s/t_file%d", TESTFILEDIR, i);
	if ((fd = open(filename, O_CREAT|O_WRONLY, 0666)) < 0) {
	    perror("open()");
	    exit(1);
	}

	/* check for special tests */
	if (strncmp(pc, "@@", 2) == 0) {
	    continue;
	}

	/* else, it's a literal string */
	slen = strlen(pc);
	if (write(fd, pc, slen) != slen) {
	    fputs("incomplete write!", stderr);
	    exit(1);
	}
	close(fd);
    }
    exit(0);
}
