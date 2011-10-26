/*
 * $Id: arjdata.c,v 1.6 2004/04/17 11:44:46 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * User-modifyable resource information. It must be kept binding-independent.
 *
 */

#include <time.h>

#include "arj.h"

/* Tags */

#define TAG_CHAR                 '@'
#define TAG_SPECIAL_BEGIN        '{'
#define TAG_SPECIAL_END          '}'

/* Alignments */

#define ALIGN_NONE                 0
#define ALIGN_RIGHT                1
#define ALIGN_CENTER               2

/* Resource list hash array. The syntax is: <tag> <substitution> */

static char *resources[][2]=
{
 /* Version */
 {
  "VERSION",
  #ifdef TILED
   "2.78"
  #else
   "3.10"
  #endif
 },
 /* ARJ Software, Inc. counterparts (note: always 4 chars, spaces allowed!) */
 {
  "COUNTERPARTS", "2.7x"                /* The docs mention DOS */
 },
 /* Short product description */
 {
  "PRODUCT",
  "ARJ"
  #if TARGET==OS2
   "/2"
  #endif
  #ifndef TILED
   #if TARGET==OS2
    "-"
   #endif
   "32"
  #endif
 },
 /* Platform */
 {
  "PLATFORM",
  #if TARGET==DOS
   "DOS"
  #elif TARGET==OS2
   "OS/2"
  #elif TARGET==WIN32
   "Win32"
  #elif TARGET==UNIX
   #if defined(linux)
    "Linux"
   #elif defined(__FreeBSD__)
    "FreeBSD"
   #elif defined(SUNOS)
    "SunOS"
   #elif defined(__QNXNTO__)
    "QNX"
   #else
    "UNIX"
   #endif
  #endif
 },
 /* Platform -- legal filename format */
 {
  "PLATFORM_FN",
  #if TARGET==OS2
   "OS2",
  #elif TARGET==UNIX
   "UNIX",
  #else
   "@PLATFORM",
  #endif
 },
 /* Platform specification for FILE_ID.DIZ (appended to description) */
 {
  "PLATFORM_APPENDIX",
  #if defined(linux)
   "/Linux",
  #elif defined(__FreeBSD__)
   "/FreeBSD",
  #elif defined(SUNOS)
   "/SunOS",
  #elif defined(__QNXNTO__)
   "/QNX",
  #elif TARGET==WIN32
   "/Win32",
  #else
   "",
  #endif
 },
 /* Long product description */
 {
  "PRODUCT_LONG",
  #if TARGET==DOS
   #if LOCALE==LANG_en
    "ARJ version @VERSION Open-Source"
   #elif LOCALE==LANG_ru
    "ARJ, версия @VERSION"
   #endif
  #else
   #if LOCALE==LANG_en
    "ARJ for @PLATFORM, version @VERSION"
   #elif LOCALE==LANG_ru
    "ARJ для @PLATFORM, версия @VERSION"
   #endif
  #endif
 },
 /* Registration token */
 {
  "REGTYPE",
  #ifdef TILED
   "A2"
  #else
   "A3"
  #endif
 },
 /* Extension of executables (for resources) */
 {"EXE_EXT", EXE_EXTENSION},
 /* Archive extension */
 {"ARJ_EXT",
  #if TARGET==DOS
   ".ARJ"                               /* ASR 27/10/2000 -- for packaging
                                           under OS/2 MDOS */
  #else
   ".arj"
  #endif
 },
 /* Ending marker */
 {NULL, NULL}
};

/* Returns year (for Q&D copyright formatting) */

static int cur_year()
{
 struct tm *stm;
 time_t cur_unixtime;

 cur_unixtime=time(NULL);
 stm=localtime(&cur_unixtime);
 return(stm->tm_year+1900); 
}

/* Date formatter */

void date_fmt(char *dest)
{
 #if LOCALE==LANG_en
  static char *mon[]={"January", "February", "March", "April", "May", "June",
                     "July", "August", "September", "October", "November",
                     "December"};
 #elif LOCALE==LANG_fr
  static char *mon[]={"janvier", "fevrier", "mars", "avril", "mai", "juin",
                     "juillet", "aout", "septembre", "octobre", "novembre",
                     "decembre"};
 #elif LOCALE==LANG_de
  static char *mon[]={"Januar", "Februar", "Maerz", "April", "Mai", "Juni",
                     "Juli", "August", "September", "Oktober", "November",
                     "Dezember"};
 #elif LOCALE==LANG_ru
  static char *mon[]={"января", "февраля", "марта", "апреля", "мая", "июня",
                     "июля", "августа", "сентября", "октября", "ноября",
                     "декабря"};
 #endif
 time_t cur_unixtime;
 struct tm *stm;
 #if LOCALE==LANG_en
  char *enstr;                          /* -rd, -th, ... */
 #endif

 cur_unixtime=time(NULL);
 stm=localtime(&cur_unixtime);
 #if LOCALE==LANG_en
  if(stm->tm_mday==1||stm->tm_mday==21||stm->tm_mday==31)
   enstr="st";
  else if(stm->tm_mday==2||stm->tm_mday==22)
   enstr="nd";
  else if(stm->tm_mday==3||stm->tm_mday==23)
   enstr="rd";
  else
   enstr="th";
  sprintf(dest, "%s %d%s, %d", mon[stm->tm_mon], stm->tm_mday, enstr, cur_year());
 #elif LOCALE==LANG_fr
  sprintf(dest, "%d %s %d", stm->tm_mday, mon[stm->tm_mon], cur_year());
 #elif LOCALE==LANG_de
  sprintf(dest, "%d %s %d", stm->tm_mday, mon[stm->tm_mon], cur_year());
 #elif LOCALE==LANG_ru
  sprintf(dest, "%d %s %d г.", stm->tm_mday, mon[stm->tm_mon], cur_year());
 #endif
}

/* A safe strcpy() */

static void safe_strcpy(char *dest, char *src)
{
 memmove(dest, src, strlen(src)+1);
}

/* Context substitution routine */

char *expand_tags(char *str, int limit)
{
 int i, j, sl;
 int l, rl;                             /* Tag/substitution length */
 int align_lmargin=0, align_rmargin=0;
 int align_type=ALIGN_NONE;
 char *p, *et;
 int shift;
 char date_stg[128];
 int repl_len, repl_j;

 sl=strlen(str);
 p=str;
 while(*p!='\0')
 {
  if(*p==TAG_CHAR)
  {
   if(*(p+1)==TAG_CHAR)
   {
    strcpy(p, p+1);
    p++;
   }
   else if(*(p+1)==TAG_SPECIAL_BEGIN&&(et=strchr(p+3, TAG_SPECIAL_END))!=NULL)
   {
    switch(*(p+2))
    {
     case 'd':
     case 'y':
      if(*(p+2)=='y')
       sprintf(date_stg, "%u", cur_year());
      else
       date_fmt(date_stg);
      rl=strlen(date_stg);
      if(sl+rl<limit)
      {
       safe_strcpy(p+rl, p);
       memcpy(p, date_stg, rl);
       limit+=rl;
       p+=rl;
       et+=rl;
      }
      break;
     case 'r':
      align_type=ALIGN_RIGHT;
      align_lmargin=p-str;
      align_rmargin=atoi(p+3);
      break;
     case 'c':
      align_type=ALIGN_CENTER;
      align_lmargin=p-str;
      align_rmargin=atoi(p+3);
      break;
     case '_':
      i=p-str;
      if(align_type==ALIGN_RIGHT)
       shift=align_rmargin-i;           /* The margin is 1-relative! */
      else if(align_type==ALIGN_CENTER)
       shift=align_rmargin-(i+align_lmargin)/2-1;
      if(align_type!=ALIGN_NONE&&shift>0&&sl+shift<limit)
      {
       sl+=shift;
       safe_strcpy(str+align_lmargin+shift, str+align_lmargin);
       memset(str+align_lmargin, 32, shift);
       p+=shift;
       et+=shift;
      }
      align_type=ALIGN_NONE;
      align_rmargin=0;
      break;
    }
    sl-=(et-p);
    safe_strcpy(p, et+1);
   }
   else
   {
    repl_len=0;
    for(j=0; resources[j][0]!=NULL; j++)
    {
     l=strlen(resources[j][0]);
     if(!memcmp(p+1, resources[j][0], l))
     {
      /* Try to find the longest possible match */
      if(l>repl_len)
      {
       repl_j=j;
       repl_len=l;
      }
     }
    }
    if(repl_len==0)
    {
     printf("ARJDATA: unknown tag <%s>\n", p);
     p++;
    }
    else
    {
     rl=strlen(resources[repl_j][1]);
     /* Is it OK to stick the substitution in? */
     if((sl+=rl)>=limit)
      return(NULL);
     safe_strcpy(p+rl, p+repl_len+1);
     memcpy(p, resources[repl_j][1], rl);
    }
   }
  }
  else
   p++;
 }
 return(str);
}
