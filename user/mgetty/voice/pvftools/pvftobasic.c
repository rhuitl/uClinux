/*
 * pvftobasic.c
 *
 * pvftovoc converts from the pvf (portable voice format) format to the
 * audio/basic format as defined in RFC 1521 (MIME) as the "absolutely
 * minimal lowest common denominator audio format", which is 8-bit ISDN
 * uLaw (PCM) at a sampling rate of 8000 Hz to the pvf (portable voice
 * format) format.
 *
 * $Id: pvftobasic.c,v 1.4 1998/09/09 21:07:52 gert Exp $
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
     fprintf(stderr, "\t-h     this help message\n\n");
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

     check_system();
     program_name = argv[0];

     while ((option = getopt(argc, argv, "h")) != EOF)
          {

          switch (option)
               {
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

     if (pvftobasic(fd_in, fd_out, &header_in) != OK)
          {
          fclose(fd_out);

          if (fd_out != stdout)
               unlink(name_out);

          exit(ERROR);
          };

     fclose(fd_out);
     exit(OK);
     }
