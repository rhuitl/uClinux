/*
 * $Id: join.c,v 1.3 2003/04/27 20:54:42 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This program writes overlay data to ARJ executables.
 *
 */

#include "arj.h"

static char buffer[PROC_BLOCK_SIZE];

static void _fput_dword(const unsigned long l, FILE *stream)
{
#ifdef WORDS_BIGENDIAN
 fputc(l    ,stream);
 fputc(l>>8 ,stream);
 fputc(l>>16,stream);
 fputc(l>>24,stream);
#else
 fwrite(&l,4,1,stream);
#endif
}
 
int main(int argc, char **argv)
{
 FILE *V1, *V2;
 unsigned long b;
 int i, rc=0;

 printf("JOIN v 1.30  [26/04/2003]  Not a part of any binary package!\r\n\r\n");
 if(argc>=3)
 {
  if((V1=fopen(argv[1], m_abp))!=NULL)
  {
   if((V2=fopen(argv[2], m_rb))!=NULL)
   {
    fseek(V1, 0, SEEK_END);
    b=ftell(V1);
    fgetc(V1);
    fwrite("ARJ_SFX", 1, 8, V1); _fput_dword(b, V1);
    fseek(V2, 0, SEEK_END); b=ftell(V2); fseek(V2, 0, SEEK_SET);
    _fput_dword(b, V1);
    /* Now simply copy the file */
    printf("Copying ");
    while((i=fread(buffer, 1, sizeof(buffer), V2))!=0)
    {
     fwrite(buffer, 1, i, V1);
     printf(".");
    }
    printf(" done!\r\n");
    fclose(V2);
   }
   else
   {
    printf("Can't open %s\r\n", argv[1]);
    rc=3;
   }
   fclose(V1);
  }
  else
  {
   printf("Can't open ARJ.EXE\r\n");
return 0;
   rc=2;
  }
 }
 else
 {
  printf("Usage: JOIN <target> <overlay>,\r\n"
         "       e.g, to append HELP.ARJ to ARJ.EXE, type JOIN ARJ.EXE HELP.ARJ\r\n");
  rc=1;
 }

 return rc;
}
