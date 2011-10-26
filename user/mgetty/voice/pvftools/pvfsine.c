/*
 * pvfsine.c
 *
 * pvfsine produces a simple sine wave. Output is in the pvf
 * (portable voice format) format.
 *
 * $Id: pvfsine.c,v 1.4 1998/09/09 21:07:50 gert Exp $
 *
 */

#include "../include/voice.h"

char *program_name;

static void usage (void)
     {
     fprintf(stderr, "\n%s %s\n\n", program_name, vgetty_version);
     fprintf(stderr, "usage:\n");
     fprintf(stderr, "\t%s [options] [<pvffile>]\n", program_name);
     fprintf(stderr, "\noptions:\n");
     fprintf(stderr, "\t-h     this help message\n");
     fprintf(stderr, "\t-F <n> frequency in Hz (default is 933.0)\n");
     fprintf(stderr, "\t-L <n> length in seconds (default is 1.5)\n");
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
     FILE *fd_out = stdout;
     char *name_out = "stdout";
     pvf_header header_out = init_pvf_header;
     double frequency = 933.0;
     double flength = 1.5;
     int length;
     double k;
     int i;

     check_system();
     program_name = argv[0];

     while ((option = getopt(argc, argv, "abh12368F:L:s:")) != EOF)
          {

          switch (option)
               {
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
               case 'F':
                    frequency = atof(optarg);
                    break;
               case 'L':
                    flength = atof(optarg);
                    break;
               case 's':
                    header_out.speed = atoi(optarg);
                    break;
               default:
                    usage();
               };

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

     length = (int) (header_out.speed * flength);
     k = 2.0 * M_PI / header_out.speed * frequency;

     for (i = 0; i < length; i++)
          header_out.write_pvf_data(fd_out, (int) (sin(k * i) * 0x7fffff));

     fclose(fd_out);
     exit(OK);
     }
