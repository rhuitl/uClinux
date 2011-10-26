/*
 * newslock - simple, unbroken version of ln(1) for shell-program locking
 *
 * (System V has broken ln(1) itself.)
 *
 * TAKEN UNMODIFIED FROM C-NEWS BY Geoffrey Collyer AND Henry Spencer
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(argc, argv)
int argc;
char *argv[];
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s tempname lockname\n", argv[0]);
		exit(2);
	}

	if (link(argv[1], argv[2]) < 0)
		exit(1);
	else
		exit(0);
	/* NOTREACHED */
}
