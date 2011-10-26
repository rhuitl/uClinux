/*
 * voctopvf.c
 *
 * voctopvf converts from the voc (Creativ voice file) format to the pvf
 * (portable voice format) format.
 *
 * $Id: lintopvf.c,v 1.4 1998/09/09 21:07:44 gert Exp $
 *
 */

#include "../include/voice.h"

char *program_name;

static void usage (void)
     {
     fprintf(stderr, "\n%s %s\n\n", program_name, vgetty_version);
     fprintf(stderr, "usage:\n");
     fprintf(stderr, "\t%s [options] [<file> [<pvffile>]]\n", program_name);
     fprintf(stderr, "\noptions:\n");
     fprintf(stderr, "\t-h     this help message\n");
     fprintf(stderr, "\t-C     input 8 bit samples (default)\n");
     fprintf(stderr, "\t-W     input 16 bit samples\n");
     fprintf(stderr, "\t-U     input unsigned values (default)\n");
     fprintf(stderr, "\t-S     input signed values\n");
     fprintf(stderr,
      "\t-N     don't intput with intel byte order (default)\n");
     fprintf(stderr, "\t-I     input with intel byte order\n");
     fprintf(stderr, "\t-s <n> samples per second (default is 8000)\n");
     fprintf(stderr, "\t-a     output pvf ascii format\n");
     fprintf(stderr, "\t-b     output pvf binary format (default)\n");
     fprintf(stderr, "\t-8     output 8 bit samples\n");
     fprintf(stderr, "\t-16    output 16 bit samples\n");
     fprintf(stderr, "\t-32    output 32 bit samples (default)\n\n");
     exit(ERROR);
     }

int main (int argc, char *argv[])
     {
     int option;
     FILE *fd_in = stdin;
     FILE *fd_out = stdout;
     char *name_in = "stdin";
     char *name_out = "stdout";
     pvf_header header_out = init_pvf_header;
     int is_signed = FALSE;
     int bits16 = FALSE;
     int intel = FALSE;

     check_system();
     program_name = argv[0];

     while ((option = getopt(argc, argv, "hs:CWUSNIab81632")) != EOF)
          {

          switch (option)
               {
               case 's':
                    header_out.speed = atoi(optarg);
                    break;
               case 'C':
                    bits16 = FALSE;
                    break;
               case 'W':
                    bits16 = TRUE;
                    break;
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
               case 'a':
                    header_out.ascii = TRUE;
                    break;
               case 'b':
                    header_out.ascii = FALSE;
                    break;
               case '8':
                    header_out.nbits = 8;
                    break;
               case '1':
               case '6':
                    header_out.nbits = 16;
                    break;
               case '3':
               case '2':
                    header_out.nbits = 32;
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

     if (write_pvf_header(fd_out, &header_out) != OK)
          {
          fclose(fd_out);

          if (fd_out != stdout)
               unlink(name_out);

          exit(ERROR);
          }

     if (lintopvf(fd_in, fd_out, &header_out, is_signed, bits16, intel) != OK)
          {
          fclose(fd_out);

          if (fd_out != stdout)
               unlink(name_out);

          exit(ERROR);
          }

     fclose(fd_out);
     exit(OK);
     }
