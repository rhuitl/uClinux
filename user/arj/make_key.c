/*
 * $Id: make_key.c,v 1.3 2003/10/20 20:49:15 andrew_belov Exp $
 * ---------------------------------------------------------------------------
 * This is a key generation utility.
 *
 */

#include "arj.h"

#include <stdlib.h>

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Main routine */

int main(int argc, char **argv)
{
 FILE *stream;
 int i, rc;
 unsigned long validation[8];

 printf("MAKE_KEY v 1.13  [16/12/2000]  Not a part of any binary package!\n\n");
 if(argc<5)
 {
  printf("Usage: MAKE_KEY \"<username>\" <license code> <product ID> <filename>\n"
         "Where: <username> is the quoted \"<name> [<license>] [<ARJ key>|<SDN key>]\n"
         "                     <name> is a free-form string\n"
         "                  <license> is \"(EXT LIC)\" if extended license\n"
         "                  <ARJ key> is \"R#nnnn\", zero-padded\n"
         "                  <SDN key> is \"SDN#0xnnnn\", where x is:\n"
         "                               1 is for SDN-originated packages\n"
         "                               2 is for SDN-distributed packages\n"
         "   <license code> is the license code (e.g., ARJR#1)\n"
         "                               ARJR#1 is a private license\n"
         "                               ARJR#2 is a public license\n"
         "     <product ID> is a product version number: <series><version>\n"
         "                   <series> is product series (\"A\" for ARJ)\n"
         "                  <version> is product version (\"3\" for v 3.x)\n"
         "       <filename> is the name of file which accepts the registration data\n"
         "\n"
         "Example: MAKE_KEY \"John Doe (EXT LIC) R#0843\" ARJR#2 A2 arj.key\n");
  exit(1);
 }
 printf("Initializing...\n");
 build_crc32_table();
 printf("Creating key signature...\n");
 create_reg_key(argv[2], argv[3], argv[1], (char *)validation);
 rc=verify_reg_name(argv[2], argv[3], argv[1], (char *)validation);
 printf("Verifying key... RC = %d\n", rc);
 if(rc==0)
 {
  if((stream=fopen(argv[4], "w"))!=NULL)
  {
   for(i=0; i<8; i++)
    fprintf(stream, "%10lu ", validation[i]);
   fprintf(stream, "%s %s %s", argv[2], argv[3], argv[1]);
   fclose(stream);
  }
  printf("ARJ-SECURITY calculation completed.\n");
  return(0);
 }
 else
 {
  printf("Key creation error!\n");
  return(1);
 }
}
