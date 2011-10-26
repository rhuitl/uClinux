/*
 * pvftolin.c
 *
 * pvftolin converts from the pvf (portable voice format) format to linear
 * headerless samples.
 *
 * $Id: pvftolin.c,v 1.4 1998/09/09 21:07:52 gert Exp $
 *
 */

#include "../include/voice.h"

char *program_name;

static void usage (void)
     {
     fprintf(stderr, "\n%s %s\n\n", program_name, vgetty_version);
     fprintf(stderr, "usage:\n");
     fprintf(stderr, "\t%s [options] [<pvffile> [<file>]]\n",
      program_name);
     fprintf(stderr, "\noptions:\n");
     fprintf(stderr, "\t-h     this help message\n");
     fprintf(stderr, "\t-C     output 8 bit samples (default)\n");
     fprintf(stderr, "\t-W     output 16 bit samples\n");
     fprintf(stderr, "\t-U     output unsigned values (default)\n");
     fprintf(stderr, "\t-S     output signed values\n");
     fprintf(stderr,
      "\t-N     don't output with intel byte order (default)\n");
     fprintf(stderr, "\t-I     output with intel byte order\n\n");
     exit(ERROR);
     }

int main (int argc, char *argv[])
     {
     int option;
     FILE *fd_in = stdin;
     FILE *fd_out = stdout;
     char *name_in = "stdin";
     char *name_out = "stdout";
     pvf_header header_in;
     int is_signed = FALSE;
     int bits16 = FALSE;
     int intel = FALSE;

     check_system();
     program_name = argv[0];

     while ((option = getopt(argc, argv, "hCWUSNI")) != EOF)
          {

          switch (option)
               {
               case 'C':
                    bits16 = FALSE;
                    break;
               case 'W':
                    bits16 = TRUE;
               case 'U':
                    is_signed = FALSE;
                    break;
               case 'S':
                    is_signed = TRUE;
                    break;
               case 'N':
                    intel = FALSE;
                    break;
               case 'I':
                    intel = TRUE;
                    break;
               default:
                    usage();
               };

          };

     if (optind < argc)
          {
          name_in = argv[optind];

          if ((fd_in = fopen(name_in, "r")) == NULL)
               {
               fprintf(stderr, "%s: Could not open file %s\n", program_name,
                name_in);
               exit(ERROR);
               };

          optind++;
          };

     if (read_pvf_header(fd_in, &header_in) != OK)
          exit(ERROR);

     if (optind < argc)
          {
          name_out = argv[optind];

          if ((fd_out = fopen(name_out, "w")) == NULL)
               {
               fprintf(stderr, "%s: Could not open file %s\n", program_name,
                name_out);
               exit(FAIL);
               };

          };

     if (pvftolin(fd_in, fd_out, &header_in, is_signed, bits16, intel) != OK)
          {
          fclose(fd_out);

          if (fd_out != stdout)
               unlink(name_out);

          exit(ERROR);
          };

     fclose(fd_out);
     exit(OK);
     }
