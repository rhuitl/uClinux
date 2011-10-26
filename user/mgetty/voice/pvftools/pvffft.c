/*
 * pvffft.c
 *
 * pvffft does a fast fourier transformation of the input pvf samples and
 * output the result in form of a table or decides, whether the input
 * samples belong to a data call or to a voice call.
 *
 * $Id: pvffft.c,v 1.4 1998/09/09 21:07:47 gert Exp $
 *
 */

#include "../include/voice.h"

char *program_name;

static void usage (void)
     {
     fprintf(stderr, "\n%s %s\n\n", program_name, vgetty_version);
     fprintf(stderr, "usage:\n");
     fprintf(stderr, "\t%s [options] [<pvffile>]\n",
      program_name);
     fprintf(stderr, "\noptions:\n");
     fprintf(stderr, "\t-h     this help message\n");
     fprintf(stderr,
      "\t-H <n> seconds to remove from the start (default is 0.0)\n");
     fprintf(stderr,
      "\t-N <n> number of samples to analyse (default is 1024)\n");
     fprintf(stderr,
      "\t-T <n> threshold for the voice/data decision (default is 1.0)\n");
     fprintf(stderr, "\t-P <n> vgetty pid (default is no pid) \n");
     fprintf(stderr, "\t-D     display fft table\n\n");
     exit(ERROR);
     }

int main (int argc, char *argv[])
     {
     int option;
     FILE *fd_in = stdin;
     char *name_in = "stdin";
     pvf_header header_in = init_pvf_header;
     double fskip = 0.0;
     int sample_size = 1024;
     double threshold = 1.0;
     int vgetty_pid = -1;
     int display = FALSE;

     check_system();
     program_name = argv[0];

     while ((option = getopt(argc, argv, "hH:N:T:P:D")) != EOF)
          {

          switch (option)
               {
               case 'H':
                    fskip = atof(optarg);
                    break;
               case 'N':
                    sample_size = atoi(optarg);
                    break;
               case 'T':
                    threshold = atof(optarg);
                    break;
               case 'P':
                    vgetty_pid = atoi(optarg);
                    break;
               case 'D':
                    display = TRUE;
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
               exit(FAIL);
               };

          optind++;
          };

     if (read_pvf_header(fd_in, &header_in) != OK)
          exit(ERROR);

     pvffft(fd_in, &header_in, (int) (fskip * header_in.speed), sample_size,
      threshold, vgetty_pid, display);
     fclose(fd_in);
     exit(OK);
     }
