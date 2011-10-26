/* 
 * $smu-mark$ 
 * $name: getusec.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:47 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: getusec.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <sys/time.h>
#include <stdlib.h>

time_t get_usec(void)
{
	struct timeval tmptv;

	gettimeofday(&tmptv, NULL);
	return tmptv.tv_usec;
}

time_t milliseconds(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000);
}
