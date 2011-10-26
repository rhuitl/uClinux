/* Copyright (C) 1991-1999, 2000, 2001 Free Software Foundation, Inc.
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
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SECSPERMIN	60
#define MINSPERHOUR	60
#define HOURSPERDAY	24
#define DAYSPERWEEK	7
#define DAYSPERNYEAR	365
#define DAYSPERLYEAR	366
#define SECSPERHOUR	(SECSPERMIN * MINSPERHOUR)
#define SECSPERDAY	((long) SECSPERHOUR * HOURSPERDAY)
#define MONSPERYEAR	12

char *tzname[2] = { (char *) "GMT", (char *) "GMT" };
int daylight = 0;
long int timezone = 0L;

#define	min(a, b)	((a) < (b) ? (a) : (b))
#define	max(a, b)	((a) > (b) ? (a) : (b))
#define	sign(x)		((x) < 0 ? -1 : 1)


/* This structure contains all the information about a
   timezone given in the POSIX standard TZ envariable.  */
typedef struct
  {
    const char *name;

    /* When to change.  */
    enum { J0, J1, M } type;	/* Interpretation of:  */
    unsigned short int m, n, d;	/* Month, week, day.  */
    unsigned int secs;		/* Time of day.  */

    long int offset;		/* Seconds east of GMT (west if < 0).  */

    /* We cache the computed time of change for a
       given year so we don't have to recompute it.  */
    time_t change;	/* When to change to this zone.  */
    int computed_for;	/* Year above is computed for.  */
  } tz_rule;

/* tz_rules[0] is standard, tz_rules[1] is daylight.  */
static tz_rule tz_rules[2];

#ifdef TZ_FROM_FILE
#include <fcntl.h>

/* Load the TZ variable from a file */
#define MAXTZLEN	50	/* Max should be 46 plus terminator */
static char *
tz_from_file(void) {
	static char *tzbuf;
	int fd;
	int ok = 0;

	if (tzbuf == NULL) {
		tzbuf = malloc(MAXTZLEN);
		if (tzbuf == NULL)
			return NULL;
	}

	/* Open the timezone file */	
	fd = open("/etc/config/TZ", O_RDONLY);
	if (fd != -1) {
		int i;
		i = read(fd, tzbuf, MAXTZLEN-1);
		close(fd);
		if (i > 0) {
			char *p;
			tzbuf[i] = '\0';		/* Make sure it is terminated */
			p = strchr(tzbuf, '\n');	/* Find a newline if any */
			if (p == NULL)
				p = tzbuf + i;		/* No new line, use end */
			/* Terminate and trim the string we read in */
			do
				*p-- = '\0';
			while (*p == '\n' || *p == ' ' || *p == '\t' || *p == '\r');
			ok = 1;				/* Success */
		}
	}
	if (!ok)
		return NULL;
	return tzbuf;
}
#endif

/* Interpret the TZ envariable.  */
static void
tzset_internal (int always)
{
  static unsigned char is_initialized;
  static char *old_tz;
  const char *tz;
  size_t l;
  char *tzbuf;
  unsigned short int hh, mm, ss;
  unsigned short int whichrule;

  if (is_initialized && !always)
    return;
  is_initialized = 1;

#ifdef TZ_FROM_FILE
  tz = tz_from_file();
#else
  /* Examine the TZ environment variable.  */
  tz = getenv ("TZ");
#endif
  if (tz != NULL && *tz == '\0')
    tz = NULL;

  /* A leading colon means "implementation defined syntax".
     We ignore the colon and always use the same algorithm:
     try a data file, and if none exists parse the 1003.1 syntax.  */
  if (tz && *tz == ':')
    ++tz;

  /* Check whether the value changes since the last run.  */
  if (old_tz != NULL && tz != NULL && strcmp (tz, old_tz) == 0)
    /* No change, simply return.  */
    return;

  tz_rules[0].name = NULL;
  tz_rules[1].name = NULL;

  /* Save the value of `tz'.  */
  if (old_tz != NULL)
    free (old_tz);
  old_tz = tz ? strdup (tz) : NULL;

  /* Default to UTC if nothing specified.  */
  if (tz == NULL || *tz == '\0')
    {
      tz_rules[0].name = tz_rules[1].name = "UTC";
      tz_rules[0].type = tz_rules[1].type = J0;
      tz_rules[0].m = tz_rules[0].n = tz_rules[0].d = 0;
      tz_rules[1].m = tz_rules[1].n = tz_rules[1].d = 0;
      tz_rules[0].secs = tz_rules[1].secs = 0;
      tz_rules[0].offset = tz_rules[1].offset = 0L;
      tz_rules[0].change = tz_rules[1].change = (time_t) -1;
      tz_rules[0].computed_for = tz_rules[1].computed_for = 0;
      return;
    }

  /* Clear out old state and reset to unnamed UTC.  */
  memset (tz_rules, 0, sizeof tz_rules);
  tz_rules[0].name = tz_rules[1].name = "";

  /* Get the standard timezone name.  */
  tzbuf = __builtin_alloca(strlen(tz)+1);
//  strcpy(tzbuf, tz);
//  tzbuf = strdupa (tz);

  if (sscanf (tz, "%[^0-9,+-]", tzbuf) != 1 ||
      (l = strlen (tzbuf)) < 3)
    return;

  tz_rules[0].name = strdup (tzbuf);

  tz += l;

  /* Figure out the standard offset from UTC.  */
  if (*tz == '\0' || (*tz != '+' && *tz != '-' && !isdigit (*tz)))
    return;

  if (*tz == '-' || *tz == '+')
    tz_rules[0].offset = *tz++ == '-' ? 1L : -1L;
  else
    tz_rules[0].offset = -1L;
  switch (sscanf (tz, "%hu:%hu:%hu", &hh, &mm, &ss))
    {
    default:
      return;
    case 1:
      mm = 0;
    case 2:
      ss = 0;
    case 3:
      break;
    }
  tz_rules[0].offset *= (min (ss, 59) + (min (mm, 59) * 60) +
			 (min (hh, 23) * 60 * 60));

  for (l = 0; l < 3; ++l)
    {
      while (isdigit(*tz))
	++tz;
      if (l < 2 && *tz == ':')
	++tz;
    }

  /* Get the DST timezone name (if any).  */
  if (*tz != '\0')
    {
      char *n = tzbuf + strlen (tzbuf) + 1;
      if (sscanf (tz, "%[^0-9,+-]", n) != 1 ||
	  (l = strlen (n)) < 3)
	goto done_names;	/* Punt on name, set up the offsets.  */

      tz_rules[1].name = strdup (n);

      tz += l;

      /* Figure out the DST offset from GMT.  */
      if (*tz == '-' || *tz == '+')
	tz_rules[1].offset = *tz++ == '-' ? 1L : -1L;
      else
	tz_rules[1].offset = -1L;

      switch (sscanf (tz, "%hu:%hu:%hu", &hh, &mm, &ss))
	{
	default:
	  /* Default to one hour later than standard time.  */
	  tz_rules[1].offset = tz_rules[0].offset + (60 * 60);
	  break;

	case 1:
	  mm = 0;
	case 2:
	  ss = 0;
	case 3:
	  tz_rules[1].offset *= (min (ss, 59) + (min (mm, 59) * 60) +
				 (min (hh, 23) * (60 * 60)));
	  break;
	}
      for (l = 0; l < 3; ++l)
	{
	  while (isdigit (*tz))
	    ++tz;
	  if (l < 2 && *tz == ':')
	    ++tz;
	}
    }
  else
    {
      /* There is no DST.  */
      tz_rules[1].name = tz_rules[0].name;
      tz_rules[1].offset = tz_rules[0].offset;
      goto out;
    }

 done_names:
  /* Figure out the standard <-> DST rules.  */
  for (whichrule = 0; whichrule < 2; ++whichrule)
    {
      tz_rule *tzr = &tz_rules[whichrule];

      /* Ignore comma to support string following the incorrect
	 specification in early POSIX.1 printings.  */
      tz += *tz == ',';

      /* Get the date of the change.  */
      if (*tz == 'J' || isdigit (*tz))
	{
	  char *end;
	  tzr->type = *tz == 'J' ? J1 : J0;
	  if (tzr->type == J1 && !isdigit (*++tz))
	    goto out;
	  tzr->d = (unsigned short int) strtoul (tz, &end, 10);
	  if (end == tz || tzr->d > 365)
	    goto out;
	  else if (tzr->type == J1 && tzr->d == 0)
	    goto out;
	  tz = end;
	}
      else if (*tz == 'M')
	{
	  int n;
	  tzr->type = M;
	  if (sscanf (tz, "M%hu.%hu.%hu%n",
		      &tzr->m, &tzr->n, &tzr->d, &n) != 3 ||
	      tzr->m < 1 || tzr->m > 12 ||
	      tzr->n < 1 || tzr->n > 5 || tzr->d > 6)
	    goto out;
	  tz += n;
	}
      else if (*tz == '\0')
	{
	  /* United States Federal Law, the equivalent of "M4.1.0,M10.5.0".  */
	  tzr->type = M;
	  if (tzr == &tz_rules[0])
	    {
	      tzr->m = 4;
	      tzr->n = 1;
	      tzr->d = 0;
	    }
	  else
	    {
	      tzr->m = 10;
	      tzr->n = 5;
	      tzr->d = 0;
	    }
	}
      else
	goto out;

      if (*tz != '\0' && *tz != '/' && *tz != ',')
	goto out;
      else if (*tz == '/')
	{
	  /* Get the time of day of the change.  */
	  ++tz;
	  if (*tz == '\0')
	    goto out;
	  switch (sscanf (tz, "%hu:%hu:%hu", &hh, &mm, &ss))
	    {
	    default:
	      hh = 2;		/* Default to 2:00 AM.  */
	    case 1:
	      mm = 0;
	    case 2:
	      ss = 0;
	    case 3:
	      break;
	    }
	  for (l = 0; l < 3; ++l)
	    {
	      while (isdigit (*tz))
		++tz;
	      if (l < 2 && *tz == ':')
		++tz;
	    }
	  tzr->secs = (hh * 60 * 60) + (mm * 60) + ss;
	}
      else
	/* Default to 2:00 AM.  */
	tzr->secs = 2 * 60 * 60;

      tzr->computed_for = -1;
    }

 out:
  /* We know the offset now, set `timezone'.  */
  timezone = -tz_rules[0].offset;
}

#ifdef INCLUDE_TIMEZONE

static const unsigned short int __mon_yday[2][13] =
  {
    /* Normal years.  */
    { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
    /* Leap years.  */
    { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
  };

/* Figure out the exact time (as a time_t) in YEAR
   when the change described by RULE will occur and
   put it in RULE->change, saving YEAR in RULE->computed_for.
   Return nonzero if successful, zero on failure.  */
static int
compute_change (tz_rule *rule, int year)
{
  time_t t;

  if (year != -1 && rule->computed_for == year)
    /* Operations on times in 2 BC will be slower.  Oh well.  */
    return 1;

  /* First set T to January 1st, 0:00:00 GMT in YEAR.  */
  if (year > 1970)
    t = ((year - 1970) * 365
	 + /* Compute the number of leapdays between 1970 and YEAR
	      (exclusive).  There is a leapday every 4th year ...  */
	 + ((year - 1) / 4 - 1970 / 4)
	 /* ... except every 100th year ... */
	 - ((year - 1) / 100 - 1970 / 100)
	 /* ... but still every 400th year.  */
	 + ((year - 1) / 400 - 1970 / 400)) * SECSPERDAY;
  else
    t = 0;

  switch (rule->type)
    {
    case J1:
      /* Jn - Julian day, 1 == January 1, 60 == March 1 even in leap years.
	 In non-leap years, or if the day number is 59 or less, just
	 add SECSPERDAY times the day number-1 to the time of
	 January 1, midnight, to get the day.  */
      t += (rule->d - 1) * SECSPERDAY;
      if (rule->d >= 60 && __isleap (year))
	t += SECSPERDAY;
      break;

    case J0:
      /* n - Day of year.
	 Just add SECSPERDAY times the day number to the time of Jan 1st.  */
      t += rule->d * SECSPERDAY;
      break;

    case M:
      /* Mm.n.d - Nth "Dth day" of month M.  */
      {
	unsigned int i;
	int d, m1, yy0, yy1, yy2, dow;
	const unsigned short int *myday =
	  &__mon_yday[__isleap (year)][rule->m];

	/* First add SECSPERDAY for each day in months before M.  */
	t += myday[-1] * SECSPERDAY;

	/* Use Zeller's Congruence to get day-of-week of first day of month. */
	m1 = (rule->m + 9) % 12 + 1;
	yy0 = (rule->m <= 2) ? (year - 1) : year;
	yy1 = yy0 / 100;
	yy2 = yy0 % 100;
	dow = ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 - 2 * yy1) % 7;
	if (dow < 0)
	  dow += 7;

	/* DOW is the day-of-week of the first day of the month.  Get the
	   day-of-month (zero-origin) of the first DOW day of the month.  */
	d = rule->d - dow;
	if (d < 0)
	  d += 7;
	for (i = 1; i < rule->n; ++i)
	  {
	    if (d + 7 >= (int) myday[0] - myday[-1])
	      break;
	    d += 7;
	  }

	/* D is the day-of-month (zero-origin) of the day we want.  */
	t += d * SECSPERDAY;
      }
      break;
    }

  /* T is now the Epoch-relative time of 0:00:00 GMT on the day we want.
     Just add the time of day and local offset from GMT, and we're done.  */

  rule->change = t - rule->offset + rule->secs;
  rule->computed_for = year;
  return 1;
}


/* Figure out the correct timezone for TM and set `tzname',
   `timezone', and `daylight' accordingly.  Return nonzero on
   success, zero on failure.  */
static int
tz_compute (const struct tm *tm)
{
  if (! compute_change (&tz_rules[0], 1900 + tm->tm_year)
      || ! compute_change (&tz_rules[1], 1900 + tm->tm_year))
    return 0;
  /* We have to distinguish between northern and southern hemisphere.
     For the latter the daylight saving time ends in the next year.
     It is easier to detect this after first computing the time for the
     wrong year since now we simply can compare the times to switch.  */
  if (tz_rules[0].change > tz_rules[1].change
      && ! compute_change (&tz_rules[1], 1900 + tm->tm_year + 1))
    return 0;

  daylight = tz_rules[0].offset != tz_rules[1].offset;
  timezone = -tz_rules[0].offset;
  tzname[0] = (char *) tz_rules[0].name;
  tzname[1] = (char *) tz_rules[1].name;


  return 1;
}
#endif

/* Reinterpret the TZ environment variable and set `tzname'.  */
void
tzset (void)
{
  tzset_internal (1);

  /* Set `tzname'.  */
  tzname[0] = (char *) tz_rules[0].name;
  tzname[1] = (char *) tz_rules[1].name;
}

#ifdef INCLUDE_TIMEZONE

#define	SECS_PER_HOUR	(60 * 60)
#define	SECS_PER_DAY	(SECS_PER_HOUR * 24)

/* Compute the `struct tm' representation of *T,
   offset OFFSET seconds east of UTC,
   and store year, yday, mon, mday, wday, hour, min, sec into *TP.
   Return nonzero if successful.  */
static int
__offtime (t, offset, tp)
     const time_t *t;
     long int offset;
     struct tm *tp;
{
  long int days, rem, y;
  const unsigned short int *ip;

  days = *t / SECS_PER_DAY;
  rem = *t % SECS_PER_DAY;
  rem += offset;
  while (rem < 0)
    {
      rem += SECS_PER_DAY;
      --days;
    }
  while (rem >= SECS_PER_DAY)
    {
      rem -= SECS_PER_DAY;
      ++days;
    }
  tp->tm_hour = rem / SECS_PER_HOUR;
  rem %= SECS_PER_HOUR;
  tp->tm_min = rem / 60;
  tp->tm_sec = rem % 60;
  /* January 1, 1970 was a Thursday.  */
  tp->tm_wday = (4 + days) % 7;
  if (tp->tm_wday < 0)
    tp->tm_wday += 7;
  y = 1970;

#define DIV(a, b) ((a) / (b) - ((a) % (b) < 0))
#define LEAPS_THRU_END_OF(y) (DIV (y, 4) - DIV (y, 100) + DIV (y, 400))

  while (days < 0 || days >= (__isleap (y) ? 366 : 365))
    {
      /* Guess a corrected year, assuming 365 days per year.  */
      long int yg = y + days / 365 - (days % 365 < 0);

      /* Adjust DAYS and Y to match the guessed year.  */
      days -= ((yg - y) * 365
	       + LEAPS_THRU_END_OF (yg - 1)
	       - LEAPS_THRU_END_OF (y - 1));
      y = yg;
    }
  tp->tm_year = y - 1900;
  if (tp->tm_year != y - 1900)
    return 0;
  tp->tm_yday = days;
  ip = __mon_yday[__isleap(y)];
  for (y = 11; days < (long int) ip[y]; --y)
    continue;
  days -= ip[y];
  tp->tm_mon = y;
  tp->tm_mday = days + 1;
  return 1;
}

/* Return the `struct tm' representation of *TIMER in the local timezone.
   Use local time if USE_LOCALTIME is nonzero, UTC otherwise.  */
struct tm *
__tz_convert (const time_t *timer, int use_localtime, struct tm *tp)
{
  long int leap_correction;
  int leap_extra_secs;
  extern struct tm _tmbuf;

  if (timer == NULL)
    {
      errno = EINVAL;
      return NULL;
    }

  /* Update internal database according to current TZ setting.
     POSIX.1 8.3.7.2 says that localtime_r is not required to set tzname.
     This is a good idea since this allows at least a bit more parallelism.
     By analogy we apply the same rule to gmtime_r.  */
  tzset_internal (tp == &_tmbuf);

  if (! (__offtime (timer, 0, tp) && tz_compute (tp)))
    tp = NULL;
  leap_correction = 0L;
  leap_extra_secs = 0;

  if (tp)
    {
      if (use_localtime)
	{
	  int isdst = (*timer >= tz_rules[0].change
		       && *timer < tz_rules[1].change);
	  tp->tm_isdst = isdst;
	  tp->tm_zone = tzname[isdst];
	  tp->tm_gmtoff = tz_rules[isdst].offset;
	}
      else
	{
	  tp->tm_isdst = 0;
	  tp->tm_zone = "GMT";
	  tp->tm_gmtoff = 0L;
	}

      if (__offtime (timer, tp->tm_gmtoff - leap_correction, tp))
        tp->tm_sec += leap_extra_secs;
      else
	tp = NULL;
    }

  return tp;
}
#endif
