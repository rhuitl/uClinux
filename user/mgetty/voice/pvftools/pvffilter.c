/*
 * pvffilter.c
 *
 * pvffilter can filter a range of frequencies out of a given voice signal.
 * Input and output is in the pvf (portable voice format) format.
 *
 * $Id: pvffilter.c,v 1.2 1999/03/16 09:59:23 marcs Exp $
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
     fprintf(stderr, "\t-F <n> frequency of the filter in Hz (default is 1000)\n");
     fprintf(stderr, "\t-W <n> width of the filter in Hz (default is 100)\n");
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
     pvf_header header_in = init_pvf_header;
     pvf_header header_out = init_pvf_header;
     double fwidth = 100.0;
     double ffrequency = 1000.0;

     check_system();
     program_name = argv[0];

     while ((option = getopt(argc, argv, "abh12368F:W:")) != EOF)
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
                    ffrequency = atof(optarg);
                    break;
               case 'W':
                    fwidth = atof(optarg);
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

     header_out.speed = header_in.speed;
     fwidth /= header_in.speed;
     ffrequency /= header_in.speed;

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

     {
     int p;
     #define N 50
     double c[2 * N + 1];
/*     double c[2 * N + 1] = {7.0, 24.0, 34.0, 24.0, 7.0}; */
     double u[2 * N + 1];

     for (p = -N; p <= N; p++)
          {
          
          if (p != 0)
               c[p + N] = 2.0 / p / M_PI * cos(2.0 * M_PI * p * ffrequency) *
                sin(M_PI * p * fwidth);
          else
               c[p + N] = 2.0 * fwidth;

          u[p + N] = 0.0;
          };

     for (p = 0; p < N; p++)
          u[p] = header_in.read_pvf_data(fd_in) / ONE;

     p = N;

     while (1)
          {
          static int k;
          static double y;

          u[p] = header_in.read_pvf_data(fd_in) / ONE;
          if (feof(fd_in))
               break;
          y = 0.0;

          for (k = -N; k <= N; k++)
               y += c[k + N] * u[(k + (p - N) + (2 * N + 1)) % (2 * N + 1)];
               
/*          y = u[((p - N) + (2 * N + 1)) % (2 * N + 1)] - y; */
          header_out.write_pvf_data(fd_out, (int) y * ONE);
          p++;
          p %= (2 * N + 1);
          }

     }
     
     fclose(fd_in);
     fclose(fd_out);
     exit(OK);
     }
