/*
** List all living Tamagotchi profiles (max = MAXLIST)
**
** by Milos Glisic, '97.
*/ 

/* includes */
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "tama.h"

extern int s;

/* send tamagotchi list to client */
void list()
{
	char buf[BUFLEN], tmp[BUFLEN];
	unsigned int ctr, num=0;
	FILE *ptr;

	if((ptr=fopen(TAMAFILE, "r"))==NULL) {
		put(NOACCESS);
		return;
	}

	put("\nName\t\tAge\n-------------------------------\n");

	while(fgets(buf, BUFLEN, ptr)!=NULL) {
		for(ctr=0; ctr<BUFLEN; ctr++)
			if(buf[ctr]==':') {
				buf[ctr]=0;
				break;
			}

	/* If Tamagotchi is dead but not cleared, don't list it */
		if((time(NULL)-gettime(buf))/3600 - getweight(buf) > DEATHTIME)
			continue;

		num++;
		if(num == MAXLIST)
			break;

		put(buf);
		
	/* Make sure it lines up... */
		if(strlen(buf) < TAB)
			put("\t\t");
		else
			put("\t");

		sprintf(tmp, "%d hours\n", ((int)time(NULL)-getbirth(buf))/3600);
		put(tmp);
	}
	fclose(ptr);
	put("\n");

	return;
} 

void putmotd(int fd)
{
	char ch;

	while(read(fd, (char *)&ch, 1) > 0)
		write(s, &ch, 1);

	close(fd);
}
