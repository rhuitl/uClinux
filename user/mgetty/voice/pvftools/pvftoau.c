/*
 * pvftoau.c
 *
 * pvftoau converts from the pvf (portable voice format) format to the
 * au (Sun audio) format.
 *
 * $Id: pvftoau.c,v 1.4 1998/09/09 21:07:51 gert Exp $
 *
 */

#include "../include/voice.h"

char *program_name;

static void usage (void)
     {
     fprintf(stderr, "\n%s %s\n\n", program_name, vgetty_version);
     fprintf(stderr, "usage:\n");
     fprintf(stderr, "\t%s [options] [<pvffile> [<aufile>]]\n",
      program_name);
     fprintf(stderr, "\noptions:\n");
     fprintf(stderr, "\t-h     this help message\n");
     fprintf(stderr, "\t-U     output 8-bit uLaw (default)\n");
     fprintf(stderr, "\t-8     output 8-bit linear\n");
     fprintf(stderr, "\t-16    output 16-bit linear\n\n");
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
     int dataFormat = SND_FORMAT_MULAW_8;

     check_system();
     program_name = argv[0];

     while ((option = getopt(argc, argv, "hU816")) != EOF)
          {

          switch (option)
               {
               case 'U':
                    dataFormat = SND_FORMAT_MULAW_8;
                    break;
               case '8':
                    dataFormat = SND_FORMAT_LINEAR_8;
                    break;
               case '1':
               case '6':
                    dataFormat = SND_FORMAT_LINEAR_16;
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

     if (pvftoau(fd_in, fd_out, &header_in, dataFormat) != OK)
          {
          fclose(fd_out);

          if (fd_out != stdout)
               unlink(name_out);

          exit(ERROR);
          };

     fclose(fd_out);
     exit(OK);
     }
