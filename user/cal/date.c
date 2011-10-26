/*
 * date  small utility to check and set system time.
 *
 * 1999-11-07  mario.frasca@home.ict.nl
 *
 *  Copyright 1999 Mario Frasca
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 *  hacked by whb (bball@staffnet.com) 2000-3-13 for uClinux
 *  (i know, sscanf could parse command line to set date and time)
 */

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

void usage()
{
	fputs("date : read or modify current system date\n", stdout);
	fputs("usage: date [option] \n", stdout);
	fputs(" -i         interactively set date and time\n", stdout);
	fputs(" -h         show usage\n", stdout);
	exit(1);
}

/* our own happy mktime() replacement, with the following drawbacks: */
/*    doesn't check boundary conditions */
/*    doesn't set wday or yday */
/*    doesn't return the local time */
time_t utc_mktime(t)
struct tm *t;
{
	static int moffset[12] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };
	time_t ret;

  /* calculate days from years */
	ret = t->tm_year - 1970;
	ret *= 365L;

  /* count leap days in preceding years */
	ret += ((t->tm_year -1969) >> 2);

  /* calculate days from months */
	ret += moffset[t->tm_mon];

  /* add in this year's leap day, if any */
   if (((t->tm_year & 3) == 0) && (t->tm_mon > 1)) {
		ret ++;
   }

  /* add in days in this month */
   ret += (t->tm_mday - 1);

  /* convert to hours */
	ret *= 24L;  
   ret += t->tm_hour;

  /* convert to minutes */
   ret *= 60L;
   ret += t->tm_min;

  /* convert to seconds */
  	ret *= 60L;
   ret += t->tm_sec;

  /* return the result */
   return ret;
}

/* ugly, no error-checking, but it works */
int setdate (void)
{
	time_t systime;
	char * p, buf[5];
	struct tm tm;
	
	tm.tm_year= tm.tm_mon= tm.tm_mday= tm.tm_hour= tm.tm_min= tm.tm_sec=0;

                fputs("Enter year [2000]:\n",stdout);
                fgets(buf,5,stdin);
		tm.tm_year = atoi(buf);

                fputs("Enter month [1-12]:\n",stdout);
                fgets(buf,5,stdin);
		tm.tm_mon = atoi(buf);
                tm.tm_mon--;

                fputs("Enter day [1-31]:\n",stdout);
                fgets(buf,5,stdin);
		tm.tm_mday = atoi(buf);

                fputs("Enter hour [0-23]:\n",stdout);
                fgets(buf,5,stdin);
		tm.tm_hour = atoi(buf);

                fputs("Enter minute [0-59]:\n",stdout);
                fgets(buf,5,stdin);
		tm.tm_min = atoi(buf);

                fputs("Enter seconds [0-59]:\n",stdout);
                fgets(buf,5,stdin);
		tm.tm_sec = atoi(buf);

	if(tm.tm_year<70) tm.tm_year+=2000;
	else if(tm.tm_year<100)tm.tm_year+=1900;
	else if(tm.tm_year<1970) 
		usage();

	systime = utc_mktime(&tm); /* fill in structure */

        stime(&systime); /* set time */

        fputs(ctime(&systime), stdout); /* display new time */

	exit(0);

}


int main(argc, argv)
char ** argv;
int argc;
{
	time_t systime;
        time(&systime);

	if(argc==1)
	{
		fputs(ctime(&systime), stdout);
	}
	else
	{
		int param = 1;

		if(argv[param][0] != '-')
			usage();
			
		switch(argv[param][1]){
		case 'i':
			setdate(); /* interactively set date and time */
			break;

		case 'h':	   /* show help */
		default:
			usage();
		}

	}

   return 0;
}

