/* hostname.c - poe@daimi.aau.dk */

#include "sash.h"

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <unistd.h>

void do_hostname(int argc, char **argv)
{
	char hn[PATHLEN + 1];
	
	if(argc >= 2) {
		if(strlen(argv[1]) > PATHLEN) {
			printf("That name is too long.\n");
		} else {
			sethostname(argv[1], strlen(argv[1]));
		}
	} else {
		gethostname(hn, PATHLEN);
		printf("%s\n", hn);
	}
}
