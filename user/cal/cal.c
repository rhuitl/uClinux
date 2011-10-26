/* cal - return monthly calendar
 *
 * usage: cal [mm] [yyyy]
 *
 * bugs: 1901 - 32767 only
 *
 * based on Kent Porter's code from "Software Spare Parts," 1986
 * (software routines from the book are for use in any project,
 *  according to the author, but he deserves credit)
 *
 * returns current month's calendar with no arguments
 * prints calendar for specified month and year
 *
 * -i causes interactive mode to prompt for month and year
 *
 * hacked for uClinux on uCsimm, bball@staffnet.com 2000-3-13
 * (yes, i know some of this is ugly, but i don't program for a living)
 *
 */

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

int cal_lm (mo, yr)
int mo, yr;
{
	int d, nd, mt[] = { 0, 21, 59, 90, 120, 151,
			  181, 212, 243, 273, 304, 334 };
	
	if ( yr < 1901 || mo < 1 || mo > 12)
		return (7);
	d = yr - 1901;
	nd = d * 365;
	nd += (( d/4) - (d/100) + (d/400)) + mt[mo-1];
	if (( yr % 4) == 0 && mo > 2)
		nd++;
	return (( nd + 2) % 7);
}

usage() {
	fputs("usage: cal [option] [mm yyyy]\n", stdout);
	fputs("-[h][?] - show help\n",stdout);
	fputs("-i      - interactive\n",stdout);	 
	fputs("print monthly calendar as in: cal 3 2000\n", stdout);
}

int print_cal(mo, year) 
int mo, year;
{
	int i, day, c, s, cal_lm();
        static char *n[] = { "January", "February", "March", "April",
			    "May", "June", "July", "August", "September",
 			    "October", "November", "December" };
        static dmp [] = { 31, 28, 31, 30, 31, 30,
                          31, 31, 30, 31, 30, 31 };

	if (( day = cal_lm (mo, year)) > 6) {
		usage();
		exit(0);
	}
	mo--;
	printf ("\n      %s %d", n[mo], year);
	fputs  ("\n Su Mo Tu We Th Fr Sa",stdout);
	putchar('\n');
 	s = 0;
	if (day >0)
		for (s =0; s < day; s++)
			fputs ( "   ",stdout);
	c = s;
	day = 1;

	do {
		printf ("%3d", day++);
		if (++c > 6) {
			putchar ('\n');
			c = 0;
		}
	} while (day <= dmp [mo] );
	if ( mo == 1 && (year % 4) == 0)
		if (( year % 100 ) != 0 || (year % 400 ) == 0)
			printf( "%3d", day );
	fputs ("\n\n\n",stdout);
} 

int
main(int argc, char *argv[])
{

	int mo, year;
        char m[4], y[5];
	time_t now;
	struct tm *ptr;
	char mbuff[4],ybuff[5];
	char *t;

  if (argc ==1) {
	/* get time */
	time(&now);
	ptr = localtime(&now);
	t = asctime(ptr);

	/* we only need month and year */
	sscanf(t,"%s%s%s%s%s",NULL,mbuff,NULL,NULL,ybuff);
	if (strcmp(mbuff,"Jan") == 0) 
		mo = 1;
	if (strcmp(mbuff,"Feb") == 0)
		mo = 2;
	if (strcmp(mbuff,"Mar") == 0)
		mo = 3;
	if (strcmp(mbuff,"Apr") == 0)
		mo = 4;
	if (strcmp(mbuff,"May") == 0)
		mo = 5;
	if (strcmp(mbuff,"Jun") == 0)
		mo = 6;
	if (strcmp(mbuff,"Jul") == 0)
		mo = 7;
	if (strcmp(mbuff,"Aug") == 0)
		mo = 8;
	if (strcmp(mbuff,"Sep") == 0)
		mo = 9;
	if (strcmp(mbuff,"Oct") == 0)
		mo = 10;
	if (strcmp(mbuff,"Nov") == 0)
		mo = 11;
	if (strcmp(mbuff,"Dec") == 0)
		mo = 12;
        if ((mo <= 0) || (mo > 12)) {
		usage(); exit(0);
	}
	year = atoi(ybuff);
	if ((year < 1901) || (year > 32767)) {
		usage(); exit(0);
	}
	print_cal(mo,year);
	exit(0);
  }		

  else if (argc > 1) {	
	int param = 1;
	if (argv[param][0] == '-') {
		switch(argv[param][1]) {
		case 'i':
			fputs("Enter month [1-12]:\n", stdout);
			fgets(m,3,stdin);
			mo = atoi(m);
			if ((mo <= 0) || (mo > 12)) {
				usage(); exit(0);
			}
			fputs("Enter year [2000]:\n", stdout);
			fgets(y,5,stdin);
			year = atoi(y);
			if ((year < 1901) || (year > 32767)) {
				usage(); exit(0);
			}
			print_cal(mo,year); 
			exit(0);
			break;
		case 'h':
		case '?': 
		default:  usage(); exit(0);
			break;
		}
	}
	mo = atoi(argv[1]);
	if ((mo <= 0) || (mo > 12)) {
		usage(); exit(0);
	}

	year = atoi(argv[2]);
	if ((year < 1901) || (year > 32767)) {
		usage(); exit(0);
	}
   }
print_cal(mo,year);
exit(0);
}

