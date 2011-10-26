/* Copyright (C) 1991, 1992, 1993, 1994 Free Software Foundation, Inc.
This file is part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the, 1992 Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

/*
 *	ANSI Standard: 4.12 DATE and TIME	<time.h>
 */

#ifndef _TIME_H
#define _TIME_H

#include <features.h>
#include <sys/param.h>
#include <sys/time.h>

#ifndef _TIME_T
#define _TIME_T
typedef long time_t;
#endif

#ifndef _CLOCK_T
#define _CLOCK_T
typedef long clock_t;
#endif

#ifndef _SIZE_T
#define _SIZE_T
typedef unsigned int size_t;
#endif

#ifndef NULL
#ifdef __cplusplus
#define NULL	0
#else
#define NULL	((void *) 0)
#endif
#endif

/*
 * these should get defined by sys/time->linux/time->asm/param
 * but just in case give them some defaults
 */
#ifndef CLOCKS_PER_SEC
#define CLOCKS_PER_SEC	100
#endif
#ifndef CLK_TCK
#define CLK_TCK	HZ		/* That must be the same as HZ ???? */
#endif

struct tm {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
	/* Those are for future use. */
#ifdef INCLUDE_TIMEZONE
	long int tm_gmtoff;
	__const char *tm_zone;
#else
	long int __tm_gmtoff__;
	__const char *__tm_zone__;
#endif
};

#define	__isleap(year)	\
  ((year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0))

extern char *tzname[2];
extern int daylight;
extern long int timezone;

__BEGIN_DECLS

extern int	stime __P ((time_t* __tptr));

extern clock_t	clock __P ((void));
extern time_t	time __P ((time_t * __tp));
extern __CONSTVALUE double difftime __P ((time_t __time2,
					  time_t __time1)) __CONSTVALUE2;
extern time_t	mktime __P ((struct tm * __tp));

extern char *	asctime __P ((__const struct tm * __tp));
extern char *	ctime __P ((__const time_t * __tp));
extern size_t	strftime __P ((char * __s, size_t __smax,
			__const char * __fmt, __const struct tm * __tp));
extern char *	strptime __P ((__const char * __s, __const char * __fmt,
			struct tm * __tm));

extern void	tzset __P ((void));

extern struct tm*	gmtime __P ((__const time_t *__tp));
extern struct tm*	localtime __P ((__const time_t * __tp));

#ifdef __USE_MISC
/* Miscellaneous functions many Unices inherited from the public domain
  localtime package.  These are included only for compatibility.  */

/* Like `mktime', but for TP represents Universal Time, not local time.  */
extern time_t timegm __P ((struct tm *__tp));
    
/* Another name for `mktime'.  */
extern time_t timelocal __P ((struct tm *__tp));

#endif

#if defined(_POSIX_THREAD_SAFE_FUNCTIONS) || defined(_REENTRANT)

extern char	* asctime_r	__P((__const struct tm *, char *));
extern char	* ctime_r	__P((__const time_t *, char *));
extern struct tm* gmtime_r	__P((__const time_t *, struct tm *));
extern struct tm* localtime_r	__P((__const time_t *, struct tm *));

#endif

struct timespec;

/* IEEE Std 1003.1b-1993. */
extern int nanosleep __P((__const struct timespec *__rqtp,
		struct timespec *__rmtp));

__END_DECLS

#endif
