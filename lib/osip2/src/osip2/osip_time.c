/*
  The oSIP library implements the Session Initiation Protocol (SIP -rfc3261-)
  Copyright (C) 2001,2002,2003  Aymeric MOIZARD jack@atosc.org
  
  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
  
  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
  
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <osip2/internal.h>
#include <osip2/osip_time.h>

void
add_gettimeofday (struct timeval *atv, int ms)
{
  int m;
  if (ms>=1000000)
    {
      atv->tv_usec = 0;
      m = ms / 1000;
    }
  else
    {
      atv->tv_usec += ms * 1000;
      m = atv->tv_usec / 1000000;
      atv->tv_usec = atv->tv_usec % 1000000;
    }
  atv->tv_sec += m;
}

void
min_timercmp (struct timeval *tv1, struct timeval *tv2)
{
  if (tv2->tv_sec == -1)
    return;
  if (osip_timercmp (tv1, tv2, >))
    {
      /* replace tv1 with tv2 info */
      tv1->tv_sec = tv2->tv_sec;
      tv1->tv_usec = tv2->tv_usec;
    }
}

#if defined(WIN32) || defined(_WIN32_WCE)

#include <time.h>
#include <sys/timeb.h>

int
osip_gettimeofday (struct timeval *tp, void *tz)
{
  struct _timeb timebuffer;

  _ftime (&timebuffer);
  tp->tv_sec = timebuffer.time;
  tp->tv_usec = timebuffer.millitm * 1000;
  return 0;
}

#endif
