/*
**	The Net Tamagotchi command interpreter.
**	ff, 1997.
*/

/* includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include "tama.h"

extern int s;

/* returns -1 if command is to quit, 0 otherwise */
int exec(char *buf, char *arg, char *pass, char *name)
{
	char *ptr;
	int diff, knockoff;

	/* Check if the tamagotchi exists or not */
	if(strcmp(buf, "status")==0 || strcmp(buf, "see")==0 ||
	   strcmp(buf, "passwd")==0 || strcmp(buf, "chpass")==0 ||
	   strcmp(buf, "chname")==0 || strcmp(buf, "feed")==0 ||
	   strcmp(buf, "pet")==0 || strcmp(buf, "play")==0 ||
	   strcmp(buf, "kill")==0 || strcmp(buf, "rm")==0) {
		if(arg[0]==0 || strcmp(arg, name)==0)
			ptr = name;
		else
			ptr = arg;

		if(exist(ptr) < 0) {
			put("Sorry, no Tamagotchi by that name exists.\n");
			return 0;
		}
	}

	if(strcmp(buf, "quit")==0 || strcmp(buf, "exit")==0) return -1;
	else if(strcmp(buf, "help")==0 || strcmp(buf, "?")==0) {
		put(HELP);
		put(HELP_ARG);
	}
	else if(strcmp(buf, "about")==0 || strcmp(buf, "ver")==0)
		put(VER);
	else if(strcmp(buf, "status")==0 || strcmp(buf, "see")==0) {
		if(arg[0]==0 || strcmp(arg, name)==0)
			status(name, 0);
		else {
			if(exist(arg) < 0) {
				put("Sorry, no Tamagotchi by that name exists.\n");
				return 0;
			}

			if(pass == NULL) {
				put("Enter password for ");
				put(arg);
				put(": ");
				get(buf);
				pass = buf;
			}

			if(checkpass(arg, pass)<0) {
				printf("%s Incorrect password for %s\n", logtime(), arg);
				put("Password incorrect.\n");
				return 0;
			}

		/* Process if checking another Tamagotchi */
			status(arg, 1);
			
		}
	}
	else if(strcmp(buf, "passwd")==0 || strcmp(buf, "chpass")==0) {
		if(arg[0]==0 || strcmp(arg, name)==0) ptr = name;
		else {
			if(exist(arg) < 0) {
				put("Sorry, no Tamagotchi by that name exists.\n");
				return 0;
			}

			if(pass == NULL) {
				put("Enter password for ");
				put(arg);
				put(": ");
				get(buf);
				pass = buf;
			}

			if(checkpass(arg, pass)<0) {
				printf("%s Incorrect password for %s\n", logtime(), arg);
				put("Password incorrect.\n");
				return 0;
			}

			ptr = arg;
		}

		put("Enter new password for ");
		put(ptr);
		put(": ");

		get(buf);
		if(check(buf)<0) {
			put("That password is invalid.\n");
			put(STRINGRULE);
			return 0;
		}
		if(setpass(ptr, buf) < 0)
			put(NOACCESS);
		else put("Password changed.\n");	
	}
	else if(strcmp(buf, "chname")==0) {
		if(arg[0]==0 || strcmp(arg, name)==0) ptr = name;
		else {
			if(exist(arg) < 0) {
				put("Sorry, no Tamagotchi by that name exists.\n");
				return 0;
			}

			if(pass == NULL) {
				put("Enter password for ");
				put(arg);
				put(": ");
				get(buf);
				pass = buf;
			}

			if(checkpass(arg, pass)<0) {
				printf("%s Incorrect password for %s\n", logtime(), arg);
				put("Password incorrect.\n");
				return 0;
			}

			ptr = arg;
		}

		put("Enter new name for ");
		put(ptr);
		put(": ");

		get(buf);
		if(check(buf)<0) {
			put("That name is invalid.\n");
			put(STRINGRULE);
			return 0;
		}
		if(exist(buf)==0) {
			put("Sorry, that name is taken.\n");
			return 0;
		}
		if(setname(ptr, buf) < 0)
			put(NOACCESS);
		else {
			put("Changed ");
			put(ptr);
			put("'s name to ");
			put(buf);
			put(".\n");

			if(arg[0]==0) strncpy(name, buf, MAXNAME);

			printf("%s Changed %s's name to '%s'\n", logtime(), ptr, name);
		}
	}
	else if(strcmp(buf, "feed")==0) {
		if(arg[0]==0 || strcmp(arg, name)==0) ptr = name;
		else {
			if(exist(arg) < 0) {
				put("Sorry, no Tamagotchi by that name exists.\n");
				return 0;
			}

			if(pass == NULL) {
				put("Enter password for ");
				put(arg);
				put(": ");
				get(buf);
				pass = buf;
			}

			if(checkpass(arg, pass)<0) {
				printf("%s Incorrect password for %s\n", logtime(), arg);
				put("Password incorrect.\n");
				return 0;
			}

			diff=(time(NULL)-gettime(arg))/3600;
			if((time(NULL)-getpet(arg))/3600 < LONELYTIME)
				diff--;


			if((diff-HUNGERTIME)>0) {
				knockoff = (diff-HUNGERTIME) / HUNGERPOUND;
				if(setweight(arg, getweight(arg)-knockoff)<0) {
					put(NOACCESS);
					return 0;	/* paranoid */
				}
			}

			if(getweight(arg)<1) {
				put(DEAD);
				del(arg);
				return 0;
			}

			ptr = arg;
		}

		switch(feed(ptr)) {
		case -1: {
			put(NOACCESS);
			break;
			}
		case 1: {
			put("No, thank you. I'm not hungry.\n");
			break;
			}
		default:
			put("Thank you!! Your Tamagotchi loves you! :)\n");
		}
	}
	else if(strcmp(buf, "pet")==0 || strcmp(buf, "play")==0) {
		if(arg[0]==0 || strcmp(arg, name)==0) ptr = name;
		else {
			if(exist(arg) < 0) {
				put("Sorry, no Tamagotchi by that name exists.\n");
				return 0;
			}

			if(pass == NULL) {
				put("Enter password for ");
				put(arg);
				put(": ");
				get(buf);
				pass = buf;
			}

			if(checkpass(arg, pass)<0) {
				printf("%s Incorrect password for %s\n", logtime(), arg);
				put("Password incorrect.\n");
				return 0;
			}

			diff=(time(NULL)-gettime(arg))/3600;
			if((time(NULL)-getpet(arg))/3600 < LONELYTIME)
				diff--;


			if((diff-HUNGERTIME)>0) {
				knockoff = (diff-HUNGERTIME) / HUNGERPOUND;
				if(setweight(arg, getweight(arg)-knockoff)<0) {
					put(NOACCESS);
					return 0;	/* paranoid */
				}
			}

			if(getweight(arg)<1) {
				put(DEAD);
				del(arg);
				return 0;
			}

			ptr = arg;
		}
		if(pet(ptr) < 0)
			put(NOACCESS);
		else put("Your Tamagotchi giggles... it just loves attention! :)\n");
	}
	else if(strcmp(buf, "kill")==0 || strcmp(buf, "rm")==0) {
		if(arg[0]==0 || strcmp(arg, name)==0) ptr = name;
		else {
			if(exist(arg) < 0) {
				put("Sorry, no Tamagotchi by that name exists.\n");
				return 0;
			}

			if(pass == NULL) {
				put("Enter password for ");
				put(arg);
				put(": ");
				get(buf);
				pass = buf;
			}

			if(checkpass(arg, pass)<0) {
				printf("%s Incorrect password for %s\n", logtime(), arg);
				put("Password incorrect.\n");
				return 0;
			}

			ptr = arg;
		}
	
		put("Are you sure you want to kill ");
		put(ptr);
		put("? ");
		get(buf);

		if(buf[0]!='y' && buf[0]!='Y')
			put("Good choice.\n");

		else {
			put(DEAD);
			del(ptr);
		}

		if(strcmp(arg, name)==0) {
			close(s);
			exit(0);
		}
	}
	else if(strcmp(buf, "list")==0 || strcmp(buf, "ls")==0 || strcmp(buf, "who")==0)
		list();
	else if(strcmp(buf, "motd")==0) {
		if((diff=open(MOTD, O_RDONLY)) < 0) {
			put("Sorry, there is no MOTD today...\n");
			return 0;
		}
		
		putmotd(diff);
		return 0;
	}

	else put(NOCOMMAND);	

	return 0;
}
