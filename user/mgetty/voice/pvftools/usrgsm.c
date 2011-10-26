/* usrgsm.c v 0.1
 *
 * Mark Edwards <medwards@greenside.demon.co.uk>
 *
 * usrgsm is a utility that will convert to and from the encapsulated
 * GSM format used by USRobotics Sportster Vi modems (with personal voice
 * mail.
 * This has not been tested on Sportster Voice modems, but I don't suspect
 * any difference. No support for adpcm.
 *
 * usrgsm will convert to and from the format used in the 'gsm-1.0' utilities
 * that have the 'toast','untoast' and 'tcat' binaries. This allows for
 * converting from the raw USRobotics format out to .au or anything else
 * that you have a conversion utility for. I have found that using untoast -o
 * on the converted file to produce an .au appears to work well.
 *
 * usage of this util is:
 *
 * usrgsm < in.rmd > out.gsm
 *
 * gsmusr < in.gsm > out.rmd
 *
 * Note. Files are playable on the USRobotics after conversion to .rmd format.
 *
 * $Id: usrgsm.c,v 1.3 1999/01/23 15:17:08 marcs Exp $
 *
 */

#include <stdio.h>
#include <fcntl.h>

void *buf;
short numelem=0;

int  f_usrtogsm     =0;

typedef unsigned char    gsm_byte;
typedef gsm_byte    gsm_frame[33];
typedef gsm_byte    usr_frame[38];

gsm_byte USR_Header[]={  0x52,0x4D,0x44,0x31,0x55,0x53,0x20,0x52,
               0x6F,0x62,0x6F,0x74,0x69,0x63,0x73,0x00,
               0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,
               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};


int
GSM_to_USR(usr_frame pUFr,gsm_frame pGFr)
{
  void* ptr=(void*)pUFr;
  pUFr[0]=pUFr[1]=0xFE;
  ptr++; ptr++;
  memcpy((void*)ptr,(void*)pGFr,(size_t)33);
  pUFr[35]=0x00;
  pUFr[36]=pUFr[37]=0xAE;
  return 0;
}

/* This function strips the encapsulated USRobotics frame
   and returns the 33 raw GSM Bytes */
int
USR_to_GSM(usr_frame pUFr,gsm_frame pGFr)
{
  void* ptr=(void*)pUFr;
  ptr++; ptr++;
  if (!((pUFr[0]==0xB6 && pUFr[1]==0xB6) || (pUFr[0]==0xFE && pUFr[1]==0xFE)))
    return -1;
  if (!(pUFr[35]==0x00 && pUFr[36]==0xA5 && pUFr[37]==0xA5))
    return -1;
  memcpy((void*)pGFr,(void*)ptr,(size_t)33);
  (*(unsigned char*)pGFr)|=(0xD0);
  return 0;
}

/* Stip the Header information from the vgetty USRobotics file. */
int
StripUSRHeader(FILE *inf)
{
  numelem=fread(buf,1,32,inf);
  if (numelem<32)
    return -1;
  return 0;
}

int
AddUSRHeader(FILE *of)
{
  fwrite((void*)USR_Header,1,sizeof(USR_Header),of);
  return 0;
}

void
main (int argc, char** argv)
{
  gsm_frame g;
  usr_frame r;
  int nelem=0;
  int fcount=0;

  /* Lets see what we were called as...*/
  if (!strcmp(argv[0],"usrgsm"))
   {
    fprintf(stderr,"Converting USR format to GSM format.\n");
    f_usrtogsm=1;
   }
  else if (!strcmp(argv[0],"gsmusr"))
   {
    fprintf(stderr,"Converting GSM format to USR format.\n");
    f_usrtogsm=0;
   }
  else
   {
    fprintf(stderr,"Use as gsmusr or usrgsm only.\n");
    exit (0);
   }

  /* Scratchpad */
  buf = (void*)malloc((size_t)1024);

  if (f_usrtogsm)
   {
    StripUSRHeader(stdin);
    while (!feof(stdin))
     {
      nelem=fread(r,1,sizeof(r),stdin);
      if (nelem<(int)sizeof(r))
       {
        if (nelem==0)
          goto done;
        fprintf(stderr,"Unable to read full USR frame.\n");
        fprintf(stderr,"Only read %i bytes.\n",nelem);
        goto done;
       }
      if (USR_to_GSM(r,g))
       {
        fprintf(stderr,"Unable to convert USR Frame.\n");
        goto done;
       }
      nelem=fwrite(g,1,sizeof(g),stdout);
      if (nelem<(int)sizeof(g))
       {
        fprintf(stderr,"Unable to write full gsm frame.\n");
        goto done;
       }
      else
       fcount++;
     }
   }
  else
   {
    AddUSRHeader(stdout);
    while (!feof(stdin))
     {
      nelem=fread(g,1,sizeof(g),stdin);
      if (nelem<(int)sizeof(g))
       {
        if (nelem==0)
          goto done;
        fprintf(stderr,"Unable to read full gsm frame.\n");
        fprintf(stderr,"Only read %i bytes.\n",nelem);
        goto done;
       }
      if (GSM_to_USR(r,g))
       {
        fprintf(stderr,"Unable to convert gsm Frame.\n");
        goto done;
       }
      nelem=fwrite(r,1,sizeof(r),stdout);
      if (nelem<(int)sizeof(r))
       {
        fprintf(stderr,"Unable to write full USR frame.\n");
        goto done;
       }
      else
       fcount++;
     }
   }
done:
   free(buf);
   fprintf(stderr,"Frames Converted=%i\n",fcount);
   fflush(stdout);
   fflush(stderr);
   exit(0);
}

