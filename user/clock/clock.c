/* clock.c:
 *
 * Copyright (C) 1999  Pat Adamo (padamo@unix.asb.com)
 *
 * This program used the Dallas Semi DS1302 RTC drivers to get and set
 * the Linux Clock.
 * Usage: 	clock				No args = read RTC Chip
 *				clock --sys    Update the Linux time to the RTC chip's time
 *				clock --set YY/MM/DD HH:MM  00-98 is 20xx, 24 Hr
 *				clock --other  Any other args displays useage
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
//#include <dirent.h>
//#include <errno.h>
//#include <termios.h>
#include <time.h>
#include "ds1302.h"

//#include <fcntl.h>

//#include <linux/sockios.h>
//#include <linux/socket.h>
//#include <linux/fs.h>
//#include <linux/if.h>
//#include <linux/in.h>
//#include <linux/icmp.h>
//#include <linux/route.h>

//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include <termios.h>
//#include <signal.h>
//#include <sys/time.h>

//#include "net.h"

//Why doesn't this work???
//const char days[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};

void error_exit(char * errmsg);

int main(int argc, char *argv[])
	{
   int x;

	time_t the_time;
	struct tm *tm_ptr;
	struct tm tm_struct;
  	unsigned char TimeBuffer[8];
	char * ctime_result;
	//this works here!
	const char days[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};



	tm_ptr = &tm_struct;

	//get Dallas clock port ready
	Setup_1302_Port();

   if (argc > 1)
   	{
		if (argc == 2)
			{
      	if (!strcmp(argv[1], "--sys"))
      		{
				//we want to set the Linux OS system time time from Dallas RTC Chip
				Get_Time(&TimeBuffer[0]);
				printf("Setting Linux Clock from Dallas DS1302 RTC: ");
				//tm_year is # of years since 1900, so assume 00-98 is 2000-2098
				tm_ptr->tm_year = ((TimeBuffer[6]>>4) * 10) + (TimeBuffer[6]& 0xf);
				if (tm_ptr->tm_year < 99) tm_ptr->tm_year = tm_ptr->tm_year+100;
            //tm_mon: Jan = 0, TimeBuffer Jan = 1
				tm_ptr->tm_mon = ((TimeBuffer[4]>>4) * 10) + (TimeBuffer[4]& 0xf)-1;
				tm_ptr->tm_mday = ((TimeBuffer[3]>>4) * 10) + (TimeBuffer[3]& 0xf);
				tm_ptr->tm_hour =(((TimeBuffer[2]&0x30)>>4) * 10) + (TimeBuffer[2]& 0xf);
				tm_ptr->tm_min = ((TimeBuffer[1]>>4) * 10) + (TimeBuffer[1]& 0xf);
				tm_ptr->tm_sec = ((TimeBuffer[0]>>4) * 10) + (TimeBuffer[0]& 0xf);
				the_time = mktime(tm_ptr);
				stime(&the_time);	//# of sec in epoch
				printf("%s",asctime(tm_ptr));
				//tm_tm_mon: Jan = 0
				//printf("date: %s %02i/%02i/%02i\n",&days[TimeBuffer[5]-1][0],
				//		tm_ptr->tm_year, tm_ptr->tm_mon+1, tm_ptr->tm_mday);
				//printf("time: %02i:%02i:%02i\n", tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
				return(0);	//Ok
				}
			  else
				{
				if (!strcmp(argv[1], "--stop"))
					{
					Lock_1302();	//stop the clock, go to low power mode
					printf("Dallas DS1302 RTC Stopped! RTC Time is now invalid.\n");
					return(0);
					}
				  else
					{
					//printf("Illegal arguments.\n");
					//printf("Usage: clock [--sys] | [--set YY/MM/DD HH:MM]\n");
					//printf("YY 00-98 = 20xx, Use 24Hr Format\n");
					error_exit("Illegal arguments.\n");
					//return(1);
					}
				}
			} //end if 2 args
		if (argc != 4)
			{
//			printf("Incorrect number of arguments.\n");
//			printf("Usage: clock [--sys] | [--set YY/MM/DD HH:MM]\n");
//			printf("YY 00-98 = 20xx, Use 24Hr Format\n");
			error_exit("Incorrect number of arguments.\n");
//         return(1);	//error
			} //end if not correct arg count
      if (!strcmp(argv[1], "--set"))
      	{
			//we want to set the time from the next two arguments
         if (strlen(argv[2]) != 8)
				{
				//printf("Bad date length.\n");
				error_exit("Bad date length.\n");
				//return(1);
				} //end if date bad length
         if (strlen(argv[3]) != 8)
				{
				//printf("Bad time length.\n");
				error_exit("Bad time length.\n");
				//return(1);
				} //end if time bad length
         if ((argv[2][2] != '/') || (argv[2][5] != '/'))
				{
				//printf("Bad date /.\n");
				error_exit("Bad date /.\n");
				//return(1);
				} //end if date bad format
         if ((argv[3][2] != ':') || (argv[3][5] != ':'))
				{
				//printf("Bad time :.\n");
				error_exit("Bad time :.\n");
				//return(1);
				} //end if time bad format
			argv[2][2] = '0';
			argv[2][5] = '0';
			argv[3][2] = '0';
			argv[3][5] = '0';
			for (x = 0;x<8;x++)
				{
				if ((argv[2][x]<'0') || (argv[2][x]>'9'))
					{
					//printf("Bad date digits.\n");
					error_exit("Bad date digits.\n");
					//return(1);
					}
				}
			for (x = 0;x<8;x++)
				{
				if ((argv[3][x]<'0') || (argv[3][x]>'9'))
					{
					//printf("Bad time digits.\n");
					error_exit("Bad time digits.\n");
					//return(1);
					}
				}
			//tm_year is # of years since 1900, so assume 00-98 is 2000-2098
			tm_ptr->tm_year = ((argv[2][0] -'0') * 10) + (argv[2][1] -'0');
			if (tm_ptr->tm_year < 99) tm_ptr->tm_year = tm_ptr->tm_year+100;
			//tm_tm_mon: Jan = 0
			tm_ptr->tm_mon = ((argv[2][3] -'0') * 10) + (argv[2][4] -'0')-1;
			tm_ptr->tm_mday = ((argv[2][6] -'0') * 10) + (argv[2][7] -'0');
			tm_ptr->tm_hour = ((argv[3][0] -'0') * 10) + (argv[3][1] -'0');
			tm_ptr->tm_min = ((argv[3][3] -'0') * 10) + (argv[3][4] -'0');
			tm_ptr->tm_sec = ((argv[3][6] -'0') * 10) + (argv[3][7] -'0');
			//all values for year are valid
			if (tm_ptr->tm_mon>11)	//Jan = 0
				{
				//printf("Bad month.\n");
				error_exit("Bad month.\n");
				//return(1);
				}
			if ((!tm_ptr->tm_mday) || (tm_ptr->tm_mday>31))
				{
				//printf("Bad day of month.\n");
				error_exit("Bad day of month.\n");
				//return(1);
				}
			if (tm_ptr->tm_hour>23)
				{
				//printf("Bad hour.\n");
				error_exit("Bad hour.\n");
				//return(1);
				}
			if (tm_ptr->tm_min>59)
				{
				//printf("Bad minute.\n");
				error_exit("Bad minute.\n");
				//return(1);
				}
			if (tm_ptr->tm_sec>59)
				{
				//printf("Bad second.\n");
				error_exit("Bad second.\n");
				//return(1);
				}
			//sets up the Linux Time
			//use mktime to validate settings
			the_time = mktime(tm_ptr);
			if (the_time < 0)
				{
				//printf("Bad Date or Time.\n");
				error_exit("Bad Date or Time.\n");
				//return(1);
				}
			//set the Linux OS time
			stime(&the_time);	//# of sec in epoch


			TimeBuffer[0] = ((argv[3][6] -'0')<<4) + (argv[3][7] -'0');	//BCD Seconds
			TimeBuffer[1] = ((argv[3][3] -'0')<<4) + (argv[3][4] -'0');	//BCD Minutes
			TimeBuffer[2] = ((argv[3][0] -'0')<<4) + (argv[3][1] -'0');	//BCD Hour
			TimeBuffer[3] = ((argv[2][6] -'0')<<4) + (argv[2][7] -'0');	//BCD Day of Month
			TimeBuffer[4] = ((argv[2][3] -'0')<<4) + (argv[2][4] -'0');	//BCD Month, 1=Jan
			TimeBuffer[6] = ((argv[2][0] -'0')<<4) + (argv[2][1] -'0');	//BCD Year
			//use strftime to get the day of the week
			ctime_result = asctime(tm_ptr);
//			printf("%s\n",ctime_result);
			//strftime(&ctime_result[0],30,"%a",tm_ptr);
			//this comes back as "Mon Nov 20 12:30:34 1995\n\0"
			//Mon
			//Tue
			//Wed
			//Thu
			//Fri
			//Sat
			//Sun
			for (x = 0; x < 7; x++)
				{
//				printf("%s\n",&days[x][0]);
				if (strncmp(ctime_result,&days[x][0],3) == 0) break;
				} //next x
//			printf("%s\n",&ctime_result[0]);
//			printf("Day of week: %i %s",x, &days[x][0]);
			TimeBuffer[5] = x+1;		//BCD Way of Week, 1=Sunday
//			return(0);

			printf("Setting Dallas RTC time to:\n");
			//Jan = 0, year is # of years since 1900
			printf("date: %s %02i/%02i/%02i\n",&days[TimeBuffer[5]-1][0],
					tm_ptr->tm_year%100, tm_ptr->tm_mon+1, tm_ptr->tm_mday);
			printf("time: %02i:%02i:%02i\n", tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
			Set_Time(&TimeBuffer[0]);
			return(0);			
         }
		  else
			{
			//printf("Illegal arguments.\n");
			error_exit("Illegal arguments.\n");
			return(1);
			} //end if(!strcmp(argv[1], "--set"))
		return(0); //all was well
		}
	  else
		{
		//no arguments, display the time...
		Get_Time(&TimeBuffer[0]);
		printf("Displaying Dallas RTC time:\n");
		//tm_year is # of years since 1900, so assume 00-98 is 2000-2098
		tm_ptr->tm_year = ((TimeBuffer[6]>>4) * 10) + (TimeBuffer[6]& 0xf);
		if (tm_ptr->tm_year < 99) tm_ptr->tm_year = tm_ptr->tm_year+100;
		//tm_tm_mon: Jan = 0, TimeBuffer Jan = 1
		tm_ptr->tm_mon = ((TimeBuffer[4]>>4) * 10) + (TimeBuffer[4]& 0xf)-1;
		tm_ptr->tm_mday = ((TimeBuffer[3]>>4) * 10) + (TimeBuffer[3]& 0xf);
		tm_ptr->tm_hour =(((TimeBuffer[2]&0x30)>>4) * 10) + (TimeBuffer[2]& 0xf);
		tm_ptr->tm_min = ((TimeBuffer[1]>>4) * 10) + (TimeBuffer[1]& 0xf);
		tm_ptr->tm_sec = ((TimeBuffer[0]>>4) * 10) + (TimeBuffer[0]& 0xf);
		//Jan = 0, year is # of years since 1900
		printf("date: %s %02i/%02i/%02i\n",&days[TimeBuffer[5]-1][0],
					tm_ptr->tm_year%100, tm_ptr->tm_mon+1, tm_ptr->tm_mday);
		printf("time: %02i:%02i:%02i\n", tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
		return(0);	//all was well
		} //end if (argc > 1)
/*
	printf("Clock.c\n");
	printf("%d arguments.\n",argc);
	printf("***\n");
*/
/*	tm_ptr->tm_year = 99;
	tm_ptr->tm_mon = 6-1;
	tm_ptr->tm_mday = 25;
	tm_ptr->tm_hour = 06;
	tm_ptr->tm_min = 25;
	tm_ptr->tm_sec = 0;
	the_time = mktime(tm_ptr);
	//set the time
	stime(&the_time);	//# of sec in epoch
*/
//	Setup_1302_Port();
//	for(x = 0; x<65000;x++)
//		{
//		x = getch();
//		printf("%d\n",Read_1302_Port());
//		if (x == (unsigned int)' ')
//			break;
//		} //next spped
/*	Get_Time(&TimeBuffer[0]);
	printf("Dallas Clock Set at:\n");
	printf("date: %02X/%02X/%02X\n",TimeBuffer[6], TimeBuffer[4],
		TimeBuffer[3]);
	printf("time: %02X:%02X:%02X\n",TimeBuffer[2] & 0x3f, TimeBuffer[1],
		TimeBuffer[0] & 0x7f);
*/
//	TimeBuffer[0] = 0x00;	//BCD Seconds
//	TimeBuffer[1] = 0x45;	//BCD Minutes
//	TimeBuffer[2] = 0x21;	//BCD Hour
//	TimeBuffer[3] = 0x28;	//BCD Day of Month
//	TimeBuffer[4] = 0x5;		//BCD Month, 1=Jan
//	TimeBuffer[5] = 0x6;		//BCD Way of Week, 1=Sunday
//	TimeBuffer[6] = 0x99;	//BCD Year
 //
//
//	printf("Setting time to:\n");
//	printf("date: %02X/%02X/%02X\n",TimeBuffer[6], TimeBuffer[4],
//		TimeBuffer[3]);
//	printf("time: %02X:%02X:%02X\n",TimeBuffer[2] & 0x3f, TimeBuffer[1],
//		TimeBuffer[0] & 0x7f);
//	Set_Time(&TimeBuffer[0]);

/*	Get_Time(&TimeBuffer[0]);
	printf("Dallas Clock Now Shows:\n");
	printf("date: %02X/%02X/%02X\n",TimeBuffer[6], TimeBuffer[4],
		TimeBuffer[3]);
	printf("time: %02X:%02X:%02X\n",TimeBuffer[2] & 0x3f, TimeBuffer[1],
		TimeBuffer[0] & 0x7f);


	(void) time(&the_time);
	tm_ptr = gmtime(&the_time);
	printf("The raw time is %ld.\n", the_time);
	printf("date: %02d/%02d/%02d\n",tm_ptr->tm_year, tm_ptr->tm_mon+1,
		tm_ptr->tm_mday);
	printf("time: %02d:%02d:%02d\n",tm_ptr->tm_hour, tm_ptr->tm_min,
		tm_ptr->tm_sec);
	printf("localtime gives:\n");
	tm_ptr = localtime(&the_time);
	printf("date: %02d/%02d/%02d\n",tm_ptr->tm_year, tm_ptr->tm_mon+1,
		tm_ptr->tm_mday);
	printf("time: %02d:%02d:%02d\n",tm_ptr->tm_hour, tm_ptr->tm_min,
		tm_ptr->tm_sec);
	printf("Setting time to 99/05/25, 06:25:00\n");
	tm_ptr->tm_year = 1999;
	tm_ptr->tm_mon = 6-1;
	tm_ptr->tm_mday = 25;
	tm_ptr->tm_hour = 06;
	tm_ptr->tm_min = 25;
	tm_ptr->tm_sec = 0;
	printf("result %d\n",mktime(tm_ptr));
*/
//	for(i = 1;i <= 10; i++)
//		{
//		the_time = time((time_t *)0);
//		printf("The time is %ld.\n", the_time);
//		sleep(2);
//		}
/*	for(i = 1;i <= 2; i++)
		{
		the_time = time((time_t *)0);
		tm_ptr = gmtime(&the_time);
		printf("The time is %ld.\n", the_time);
		printf("date: %02d/%02d/%02d\n",tm_ptr->tm_year,
			tm_ptr->tm_mon+1, tm_ptr->tm_mday);
		printf("time: %02d:%02d:%02d\n",tm_ptr->tm_hour,
			tm_ptr->tm_min, tm_ptr->tm_sec);
		sleep(2);
		}
*/	
	return(0);



	//	/*        open_raw_socket();
	//if(argc == 1)
	//  printf("No input supplied, assuming defaults.\n");
        //printf("%s: ip address: %s, net: %s, gateway: %s\n", argv[0], ipAddr, ipNet, ipGateway);
        //setifaddr(dev, ipAddr);
        //setifflags(dev, IFF_UP | IFF_RUNNING);
	//
        //addroute(dev, RTF_UP/* | RTF_HOST*/,
        //        ipNet /* dest net */,
        //        "255.255.255.0" /* netmask */,
        //        0 /* gateway */);
	//
        //addroute(dev, RTF_UP/* | RTF_HOST*/,
        //        "0.0.0.0" /* dest net */,
        //        "0.0.0.0" /* netmask */,
        //        ipGateway /* gateway */);
	//
        //close_raw_socket();
	//
	//return (0);*/
}

void error_exit(char * errmsg)
	{
	printf("%s",errmsg);
	printf("Usage: clock [--sys] | [--set YY/MM/DD HH:MM] [--stop]\n");
	printf("YY 00-98 = 20xx, Use 24Hr Format\n");
	exit(1);
	}
