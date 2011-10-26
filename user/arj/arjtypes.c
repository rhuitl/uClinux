/*
 * $Id: arjtypes.c,v 1.7 2004/06/18 16:19:37 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This module provides some multiplatform property types which cover both DOS
 * (as internally involved in ARJ) and UNIX requirements.
 *
 */

#include <time.h>

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Timestamp macros */

#define get_tx(m,d,h,n) (((unsigned long)(m)<<21)+((unsigned long)(d)<<16)+((unsigned long)(h)<<11)+((n)<<5))
#define get_tstamp(y,m,d,h,n,s) ((((unsigned long)((y)-1980))<<25)+get_tx((m),(d),(h),(n))+((s)/2))

#define ts_year(ts)  ((unsigned int)(((ts)>>25)&0x7f)+1980)
#define ts_month(ts) ((unsigned int)((ts)>>21)&0x0f)  /* 1..12 means Jan..Dec */
#define ts_day(ts)   ((unsigned int)((ts)>>16)&0x1f)  /* 1..31 means 1st..31st */
#define ts_hour(ts)  ((unsigned int)((ts)>>11)&0x1f)
#define ts_min(ts)   ((unsigned int)((ts)>>5)&0x3f)
#define ts_sec(ts)   ((unsigned int)(((ts)&0x1f)*2))

static char monthdays[12]={31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

/* Q&D helper macro */

#define is_unix(host_os) (host_os==OS_UNIX||host_os==OS_NEXT)

/* Timestamp storage structures */

#if SFX_LEVEL>=ARJSFX
 static char time_list_format[]="%04u-%02u-%02u %02u:%02u:%02u";
#endif

/*
 * File mode routines
 */

/* Parses a file mode specifier from the archive. The idea is to allow
   creation of DOS attributes under UNIX, but no features exist for
   DOS->UNIX conversion. */

void fm_store(struct file_mode *dest, int host_os, int mode)
{
 if(host_os==OS_SPECIAL)
  dest->dos=dest->native=mode;
 if(is_unix(OS))
 {
  dest->native=mode;
  dest->dos=FATTR_ARCH;
  if(is_unix(OS)&&!(mode&FATTR_IWUSR))
   dest->dos|=FATTR_RDONLY;
 }
 else                                   /* Assume a DOS-style system */
  dest->dos=dest->native=mode;
}

/* Retrieves a native file mode corresponding to the host OS */

unsigned int fm_native(struct file_mode *fm, int host_os)
{
 return(is_unix(host_os)?fm->native:fm->dos);
}

/*
 * Timestamp routines
 */

/* Returns 1 if there's a leap year */

static int isleapyear(int year)
{
 if(year%400==0)
  return(1);
 if(year%100==0)
  return(0);
 if(year%4==0)
  return(1);
 return(0);
}

/* A "home-brew" implemenation of localtime(). This is for cases when we have a TZ_VAR
   of our own. */

#ifdef TZ_VAR
static struct tm *ununixtime(unsigned long *pt)
#define localtime(t) ununixtime((unsigned long *)(t))
{
 unsigned long unixtime, timepart;
 int year, month, mdays;
 static struct tm stm;

 unixtime=*pt-TZ_VAR;
 if(_daylight)
  unixtime+=3600;
 timepart=unixtime%86400L; unixtime/=86400L;
 for(year=1970; 365+isleapyear(year)<=unixtime; year++)
  unixtime-=365+isleapyear(year);
 stm.tm_year=year-1900;
 month=0;
 while(1)
 {
  if(month==1)
   mdays=isleapyear(year)?29:28;
  else
   mdays=monthdays[month];
  if(mdays>unixtime||month==11)
   break;
  unixtime-=mdays;
  month++;
 }
 stm.tm_mon=month;
 stm.tm_mday=unixtime+1;
 stm.tm_hour=timepart/3600;
 stm.tm_min=timepart/60%60;
 stm.tm_sec=timepart%60;
 return(&stm);
}
#endif

/* Converts a UNIX timestamp to the DOS style */

static unsigned long ts_unix2dos(const long ts)
{
 struct tm *stm;

 stm=localtime((time_t*)&ts);
 return(get_tstamp(stm->tm_year+1900, stm->tm_mon+1, stm->tm_mday,
        stm->tm_hour, stm->tm_min, stm->tm_sec));
}

/* Creates a Unix timestamp from the given date and time */

static unsigned long mk_unixtime(int y, int m, int d, int hh, int mm, int ss)
{
 unsigned long u=0;
 int i;
 /* Clash with NetBSD/x86-64 patch: leaving rc as unsigned long still permits
    to escape the year 2038 problem in favor of year 2106 problem, while a
    dedicated time_t structure can be expected as a 64-bit value on relevant
    platforms -- ASR fix 25/01/2004 */
 unsigned long rc;
 time_t tt;
 long tzshift;
 #ifndef TZ_VAR
  long shiftd1, shiftd2;
 #endif
 struct tm *stm;

 if(y>=2001)
 {
  i=y-2001;
  u=11323;
  /* The following piece of code is rather paranoid in 16/32-bit world, where the
     timestamps are limited to year 2108. */
  #if defined(__32BIT__)||defined(TILED)
   if(i>=400)
   {
    u+=1022679L*(i/400);
    i%=400;
   }
  #endif
  if(i>=100)
  {
   u+=36524L*(i/100);
   i%=100;
  }
  u+=1461L*(i/4);
  u+=365L*(i%4);
 }
 else if(y>=1973)
  u=1096+(y-1973)/4*1461L+((y-1973)%4)*365L;
 else
  u=(y-1970)*365L;
 for(i=1; i<m; i++)
 {
  u+=(int)monthdays[i-1];
  if(i==2)
   u+=isleapyear(y);
 }
 rc=86400*(unsigned long)(u+d-1)+(unsigned long)hh*3600+(unsigned long)mm*60+(unsigned long)ss;
 /* If we have to use the timezone variable, do it now */
 #ifdef TZ_VAR
  tzshift=-TZ_VAR;
  if(_daylight)
   tzshift+=3600;
 #else
  tt=(time_t)rc;
  stm=localtime(&tt);
  debug_assert(stm!=NULL);              /* LIBCS.DLL returns NULL for unixtime beyond
                                           0x7FFFFFFF */
  tzshift=(long)stm->tm_hour*3600+(long)stm->tm_min*60;
  shiftd1=stm->tm_mday;
  stm=gmtime(&tt);
  debug_assert(stm!=NULL);
  shiftd2=stm->tm_mday;
  /* Local time overruns GMT, add 24 hours for safety */
  if(shiftd1<shiftd2&&shiftd1==1&&shiftd2>=28)
   tzshift+=86400;
  else if(shiftd1>shiftd2&&shiftd1>=28&&shiftd2==1)
   tzshift-=86400;
  else if(shiftd1>shiftd2)
   tzshift+=86400;
  else if(shiftd1<shiftd2)
   tzshift-=86400;
  tzshift-=(long)stm->tm_hour*3600+(long)stm->tm_min*60;
  tzshift%=86400;
 #endif
 /* Fix the timezone if it does not roll over the zero */
 return((tzshift>0&&rc<tzshift)?rc:rc-tzshift);
}

/* Converts a DOS timestamp to the UNIX representation */

static unsigned long ts_dos2unix(unsigned long ts)
{
 unsigned int y, m, d, hh, mm, ss;

 if(ts==0)
  return(0);
 y=ts_year(ts);
 m=ts_month(ts);
 d=ts_day(ts);
 hh=ts_hour(ts);
 mm=ts_min(ts);
 ss=ts_sec(ts);
 /* TODO: These assertions must be replaced by run-time check for incorrect timestamps
    like 31/15/2063 or 00/00/1980, since month array is 1...12 only. */
 #ifdef DEBUG
  debug_assert(m>=1&&m<=12);
  debug_assert(d>=1&&d<=31);
 #endif
 return(mk_unixtime(y, m, d, hh, mm, ss));
}

/* Stores a timestamp */

void ts_store(struct timestamp *dest, int host_os, unsigned long value)
{
 if(host_os==OS_SPECIAL)
  dest->dos=dest->unixtime=value;
 else if(is_unix(host_os))
 {
  dest->unixtime=value;
  dest->dos=ts_unix2dos(value);
 }
 else
 {
  dest->dos=value;
  dest->unixtime=ts_dos2unix(value);
 }
}

/* Retrieves a native timestamp corresponding to the host OS */

unsigned long ts_native(struct timestamp *ts, int host_os)
{
 return(is_unix(host_os)?ts->unixtime:ts->dos);
}

/* Compares two timestamps */

int ts_cmp(struct timestamp *ts1, struct timestamp *ts2)
{
 unsigned long tsn1, tsn2;

 tsn1=ts_native(ts1, OS);
 tsn2=ts_native(ts2, OS);
 if(tsn1<tsn2)
  return(-1);
 else if(tsn1==tsn2)
  return(0);
 else
  return(1);
}

#if SFX_LEVEL>=ARJ||defined(REARJ)

/* Produces an ARJ timestamp from the given date */

void make_timestamp(struct timestamp *dest, int y, int m, int d, int hh, int mm, int ss)
{
 dest->unixtime=mk_unixtime(y, m, d, hh, mm, ss);
 dest->dos=ts_unix2dos(dest->unixtime);
}

#endif

#if SFX_LEVEL>=ARJSFX

/* Restores the given timestamp to character form */

void timestamp_to_str(char *str, struct timestamp *ts)
{
 struct tm *stm;

 stm=localtime((time_t *)&ts->unixtime);
 /* Workaround for a MS C v 7.0 CRT bug */
 #if TARGET==DOS&&COMPILER==MSC&&_MSC_VER==700
  if(stm->tm_year<70)                   /* 31 -> 101 */
   stm->tm_year+=70;
 #endif
 sprintf(str, time_list_format, stm->tm_year+1900, stm->tm_mon+1, stm->tm_mday,
         stm->tm_hour, stm->tm_min, stm->tm_sec);
}

#endif
