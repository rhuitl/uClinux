/*
** send status information to client
** calling status() also causes appropriate action to be taken
** if the result requires it, ie. to remove the tamagotchi if its dead.
**
** pretty much all of the hunger/loneliness/health behaviour
** is defined here...
**
** by Milos Glisic, 1997.
*/

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "tama.h"


extern int s;

void status(char *name, int proc)
{
	int diff, knockoff;
	char tmp[BUFLEN];

	diff=(time(NULL)-gettime(name))/3600;
	if((time(NULL)-getpet(name))/3600 < LONELYTIME)
		diff--;

	if(proc > 0) {
		if((diff-HUNGERTIME)>0) {
			knockoff = (diff-HUNGERTIME) / HUNGERPOUND;
			if(setweight(name, getweight(name)-knockoff)<0) {
				put(NOACCESS);
				return;			/* paranoid */
			}
		}
	}

	if(getweight(name)<1) {
		put(DEAD);
		del(name);
		close(s);
		exit(0);
	}

	if(diff < HUNGERTIME) {
		if((time(NULL)-getpet(name))/3600 >= LONELYTIME)
			put(LONELY);
		else put(HAPPY);
	}
	else if(diff>=HUNGERTIME && diff <= DEATHTIME)
		put(UNHAPPY);
	else if(diff > DEATHTIME) {
		if(proc > 0 && setweight(name, getweight(name)-(diff-DEATHTIME))<0) {
			put(NOACCESS);
			return;
		}
		if(getweight(name)<1) {
			put(DEAD);
			del(name);
			close(s);
			exit(0);
		}
	}
		put("\nName: ");
		put(name);
		sprintf(tmp, "\t\tAge: %d hours", ((int)time(NULL)-getbirth(name))/3600);
		put(tmp);
		put("\t\tWeight: ");
		sprintf(tmp, "%d units\n", getweight(name));
		put(tmp);

	return;
} 
