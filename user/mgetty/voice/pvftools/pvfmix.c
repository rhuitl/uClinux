/*
 * pvfmix.c
 *
 * pvfmix mixes two voice files into one voice file. Input and output
 * is in the pvf (portable voice format) format.
 *
 * $Id: pvfmix.c,v 1.4 1998/09/09 21:07:48 gert Exp $
 *
 */

#include "../include/voice.h"

char *program_name;

static void usage (void)
     {
     fprintf(stderr, "\n%s %s\n\n", program_name, vgetty_version);
     fprintf(stderr, "usage:\n");
     fprintf(stderr, "\t%s [options] [<pvffile in> [<pvffile out>]]\n",
      program_name);
     fprintf(stderr, "\noptions:\n");
     fprintf(stderr, "\t-h     this help message\n");
     fprintf(stderr,
      "\t-N <s> name of the voice file to add (default is none)\n");
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
     FILE *fd2_in = NULL;
     FILE *fd_out = stdout;
     char *name_in = "stdin";
     char *name2_in = NULL;
     char *name_out = "stdout";
     pvf_header header_in = init_pvf_header;
     pvf_header header2_in = init_pvf_header;
     pvf_header header_out = init_pvf_header;
     int data1;
     int data2;

     check_system();
     program_name = argv[0];

     while ((option = getopt(argc, argv, "abh12368N:")) != EOF)
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
               case 'N':
                    name2_in = optarg;
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

     if (name2_in != NULL)
          {

          if ((fd2_in = fopen(name2_in, "r")) == NULL)
               {
               fprintf(stderr, "%s: Could not open file %s\n", program_name,
                name_in);
               exit(FAIL);
               };

          if (read_pvf_header(fd2_in, &header2_in) != OK)
               exit(ERROR);

          if (header_in.speed != header2_in.speed)
               {
               fprintf(stderr,
                "%s: both voice files must have the same sample rate\n",
                program_name);
               exit(FAIL);
               }

          }

     header_out.speed = header_in.speed;

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

     while (TRUE)
          {
          data1 = header_in.read_pvf_data(fd_in);

          if (fd2_in != NULL)
               data2 = header2_in.read_pvf_data(fd2_in);
          else
               data2 = EOF;

          if (feof(fd_in) && feof(fd2_in))
               break;

          if (feof(fd_in))
               data1 = 0;

          if (feof(fd2_in))
               data2 = 0;

          header_out.write_pvf_data(fd_out, data1 + data2);
          };

     fclose(fd_in);
     fclose(fd2_in);
     fclose(fd_out);
     exit(OK);
     }
