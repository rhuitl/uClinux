/*
**	Tamagotchi header file	- Milos Glisic, 97
*/

#include <sys/types.h>

#define PORT 9111		/* default port */
#define LOCAL "0.0.0.0"
#define MAXQUEUE 3
#define BUFLEN 64
#define MAXNAME 16
#define CHECKTIME 1		/* interval at which to perform checks (minutes) */
#define TIMELIMIT 1000		/* timeout in seconds */
#define MOTD "tama.motd"	/* MOTD file */
#define TAMAFILE "tamas"
#define INITWEIGHT 20
#define FEEDLIMIT 3
#define TAB 8
#define HUNGERTIME 12
#define HUNGERPOUND 12	/* period of hunger to lose a pound */
#define DEATHTIME 48
#define LONELYTIME 6
#define MAXCLIENTS 5	/* maximum number of simultaneous clients */
#define MAXLIST 20	/* maximum number of listings for list() */

#define NOACCESS "Error: Can't open Tamagotchi file. Please try again later.\n"
#define NOCOMMAND "What?\n"
#define NOACCESS "Error: Can't open Tamagotchi file. Please try again later.\n"
#define STRINGRULE "You may not use spaces, control codes, or special characters.\n"
#define BYE "Don't forget to feed your Tamagotchi!\n"
#define VER "Net Tamagotchi " VERSION "\n"
#define COMMANDLINE VER\
		"Usage: tamad [port]\n"

#define HELP "Net Tamagotchi commands:\n\n"\
	"   help                   - this message\n"\
	"   status [name [pass]]   - see how your (or another) Tamagotchi is feeling\n"\
	"   about                  - about Net Tamagotchi\n"\
	"   quit                   - leave your Tamagotchi all alone\n"\
	"   list                   - see how other Tamagotchis are doing\n"\
	"   motd                   - print message of the day\n"
#define HELP_ARG \
	"   feed [name [pass]]     - feed your (or another) Tamagotchi\n"\
	"   pet [name [pass]]      - play with your (or another) Tamagotchi\n"\
	"   passwd [name [pass]]   - change your (or another) Tamagotchi's password\n"\
	"   chname [name [pass]]   - change your (or another) Tamagotchi's name\n"\
	"   kill [name [pass]]     - send your (or another) Tamagotchi to it's demise\n\n"

#define INTRO "\n\nHi! I am your Net Tamagotchi! I love you!!\n"\
		"\n          ***************"\
		"\n       *********************"\
                "\n     ******  *********  ******"\
                "\n    *******  *********  *******"\
                "\n    ***************************"\
                "\n    ***************************"\
                "\n     ****** *********** ******"\
                "\n       *****           *****"\
                "\n          ***************"\
                "\n              ********"\
		"\n\nWhat do you wanna call your Tamagotchi? "

#define HAPPY	"\n     *******"\
		"\n   ***********"\
		"\n  **** *** ****"\
		"\n  *************"\
		"\n  *** ***** ***"\
		"\n   ***     ***"\
		"\n     *******"\
		"\n\nYour Tamagotchi is happy and it loves you!\n"
#define LONELY	"\n     *******"\
		"\n   ***********"\
		"\n  **** *** ****"\
		"\n  *************"\
		"\n  *************"\
		"\n   ****   ****"\
		"\n     *******"\
		"\n\nYour Tamagotchi is lonely and depressed. :(\n"
#define UNHAPPY	"\n     *******"\
		"\n   ***********"\
		"\n  **** *** ****"\
		"\n  *************"\
		"\n  *************"\
		"\n   ***     ***"\
		"\n     *******"\
		"\n\nYour Tamagotchi is hungry and sad and it's scared! :(\n"
#define DEAD	"\n     *******"\
		"\n   ***********"\
		"\n  ****x***x****"\
		"\n  *************"\
		"\n  *************"\
		"\n   ***-----***"\
		"\n     *******"\
		"\n\nYour Tamagotchi is dead. :( You're a meanie!\n"

int getbirth(char *);
int getpassw(char *, char *);
int gettime(char *);
int getpet(char *);
int getweight(char *);
int setweight(char *, int);
int exist(char *);
int check(char *);
int new(char *, char *);
int checkpass(char *, char *);
void del(char *);
int setpass(char *, char *);
int setname(char *, char *);
int feed(char *);
int pet(char *);
int exec(char *, char *, char *, char *);
void list();
void putmotd(int);
char *logtime();
void term(int);
void timeout(int);
void segv(int);
void get(char *);
void put(char *);
void status(char *, int);

struct client {
	pid_t pid;
	char *hostname;
};

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif /* ! _XOPEN_SOURCE */
