/*
 * $Id: makestub.c,v 1.2 2003/06/22 11:12:28 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This program compiles SFX-STUB locale-dependent files.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "arj.h"
#include "msg_stb.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Translation routine */

void store_xlat(FILE *ostream, char *banner, unsigned char *msg)
{
 int i, j=0;

 fprintf(ostream, "%s db ", banner);
 if(msg[0]=='\0')
  fprintf(ostream, "63");
 for(i=0; msg[i]!='\0'; i++)
 {
  if(msg[i]==10)
  {
   fprintf(ostream, "13,");
   j++;
  }
  fprintf(ostream, "%d", (int)msg[i]);
  j++;
  if(msg[i+1]!='\0')
  {
   if(i%20==19)
    fprintf(ostream, "\ndb ");
   else
    fprintf(ostream, ",");
  }
 }
 #if TARGET==DOS
  fprintf(ostream, "\ndb 36");
 #endif
 fprintf(ostream, "\nL_%s EQU %d\n", banner, j);
}

/* Main routine */

int main(int argc, char **argv)
{
 FILE *stream;

 printf("MAKESTUB v 1.11  [30/11/2001]  Not a part of any binary package!\n\n");
 if(argc<2)
 {
  printf("Usage: MAKESTUB <target>\n");
  exit(1);
 }
 if((stream=fopen(argv[1], m_w))==NULL)
 {
  printf("Failed to open include file\n");
  exit(1);
 }
 fprintf(stream, "; DO NOT MODIFY! This file has been automatically generated with MAKESTUB\n\n");
 store_xlat(stream, "M_SFXSTUB_BANNER", M_SFXSTUB_BANNER);
 store_xlat(stream, "M_SFXSTUB_BLURB_1", M_SFXSTUB_BLURB_1);
 store_xlat(stream, "M_SFXSTUB_BLURB_2", M_SFXSTUB_BLURB_2);
 fclose(stream);
 return(0);
}
