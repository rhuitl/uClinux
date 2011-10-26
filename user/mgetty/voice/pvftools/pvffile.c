/*
 * pvffile.c
 *
 * pvffile prints out some useful information about .pvf files.
 *
 * $Id: pvffile.c,v 1.5 1999/03/16 09:59:23 marcs Exp $
 *
 */

#include "../include/voice.h"

char *program_name;

static void usage (void)
     {
     fprintf(stderr, "\n%s %s\n\n", program_name, vgetty_version);
     fprintf(stderr, "usage:\n");
     fprintf(stderr, "\t%s [options] [pvffile]\n", program_name);
     fprintf(stderr, "\noptions:\n");
     fprintf(stderr, "\t-c     also print sample count\n");
     fprintf(stderr, "\t-h     this help message\n\n");
     exit(ERROR);
     }

int main (int argc, char *argv[])
     {
     int option;
     int cflag = 0;
     FILE *fd_in = stdin;
     char *name_in = "stdin";
     pvf_header header;

     check_system();
     program_name = argv[0];

     while ((option = getopt(argc, argv, "hc")) != EOF)
          {

          switch (option)
               {
               case 'c':
                    cflag = 1;
                    break;
               default:
                    usage();
               }
          }

     if ((option = getopt(argc, argv, "h")) != EOF)
          usage();

     if (optind < argc)
          {
          name_in = argv[optind];

          if ((fd_in = fopen(name_in, "r")) == NULL)
               {
               fprintf(stderr, "%s: Could not open file %s\n", program_name,
                name_in);
               exit(FAIL);
               };

          };

     if (read_pvf_header(fd_in, &header) != OK)
          exit(FAIL);

     if (header.ascii)
          printf("%s: PVF2 (ascii)\n", name_in);
     else
          printf("%s: PVF1 (binary)\n", name_in);

     printf("channels: %d\n", header.channels);
     printf("sample speed: %d\n", header.speed);
     printf("bits per sample: %d\n", header.nbits);

     if (cflag)
	  {
          int count = 0;
          int data;

          while (1)
               {
	       data = header.read_pvf_data(fd_in);
	       if (feof(fd_in))
		    break;
               ++count;
               }
	  printf("samples: %d\n", count);
	  }

     exit(OK);
     }
