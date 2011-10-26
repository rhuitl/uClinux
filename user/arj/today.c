/*
 * $Id: today.c,v 1.3 2003/06/22 11:12:28 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * A utility to produce locale-dependent timestamps instead of __TIME__.
 *
 */

#include "environ.h"
#include "filemode.h"

#include <time.h>

/* Date array */

static char *months_en[]={"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
                          "Aug", "Sep", "Oct", "Nov", "Dec"};

/* Main routine */

int main(int argc, char **argv)
{
 char date_sig[40], f_date[120];
 char out_name[CCHMAXPATH];
 time_t cur_unixtime;
 struct tm *stm;
 FILE *stream;
 int is_new=0;
 char *p;
 int l;

 printf("TODAY v 1.22  [29/10/2000]  Not a part of any binary package!\n\n");
 if(argc<3)
 {
  printf("Usage: TODAY <locale> <base_dir>\n"
         "Where: <locale> is one of the known locales,\n"
         "     <base_dir> is base directory name\n");
  exit(1);
 }
 strcpy(out_name, argv[2]);
 l=strlen(out_name)-1;
 if(out_name[l]!=PATHSEP_DEFAULT)
 {
  out_name[++l]=PATHSEP_DEFAULT;
  out_name[++l]='\0';
 }
 strcat(out_name, "date_sig.c");
 cur_unixtime=time(NULL);
 stm=localtime(&cur_unixtime);
 if(!stricmp(argv[1], "en"))
  sprintf(date_sig, "[%02d %s %04d]", stm->tm_mday, months_en[stm->tm_mon], stm->tm_year+1900);
 else if(!stricmp(argv[1], "fr"))
  sprintf(date_sig, "[%d.%d.%04d]", stm->tm_mday, stm->tm_mon+1, stm->tm_year+1900);
 else if(!stricmp(argv[1], "de"))
  sprintf(date_sig, "[%02d.%02d.%04d]", stm->tm_mday, stm->tm_mon+1, stm->tm_year+1900);
 else if(!stricmp(argv[1], "ru"))
  sprintf(date_sig, "[%02d/%02d/%04d]", stm->tm_mday, stm->tm_mon+1, stm->tm_year+1900);
 else
  sprintf(date_sig, "[%02d-%02d-%04d]", stm->tm_mday, stm->tm_mon+1, stm->tm_year+1900);
 if((stream=fopen(out_name, m_r))==NULL)
  is_new=1;
 else
 {
  if(fgets(f_date, sizeof(f_date), stream)==NULL)
   is_new=1;
  else if((p=strchr(f_date, '\"'))==NULL)
   is_new=1;
  else if(memcmp(p+1, date_sig, min(strlen(date_sig), strlen(p+1))))
   is_new=1;
  fclose(stream);
 }
 if(is_new)
 {
  if((stream=fopen(out_name, m_w))==NULL)
  {
   printf("Failed to open %s\n", out_name);
   exit(2);
  }
  fprintf(stream, "char build_date[]=\"%s\";\n", date_sig);
  fclose(stream);
 }
 return(0);
}
