/*
 * pvfspeed.c
 *
 * pvfspeed changes the sample rate of the voice file. It does this by
 * interpolating the samples at the new rate. Input and output is in
 * the pvf (portable voice format) format.
 *
 * $Id: pvfspeed.c,v 1.5 1999/03/16 09:59:24 marcs Exp $
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
      "\t-s <n> new number of samples per seconds (default is old one)\n");
     fprintf(stderr,
      "\t-E <n> exponent for special effects (default is 1.0)\n");
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
     double fexponent = 1.0;
     int exponent;
     int speed;
     int srate;

     check_system();
     program_name = argv[0];
     header_out.speed = -1;

     while ((option = getopt(argc, argv, "abh12368s:E:")) != EOF)
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
               case 's':
                    header_out.speed = atoi(optarg);
                    break;
               case 'E':
                    fexponent = atof(optarg);
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

     if (header_out.speed == -1)
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

     if (header_out.speed == 0)
          {
          fprintf(stderr, "%s: Sample speed is 0\n", program_name);
          exit(ERROR);
          }

     speed = (int) ((vgetty_s_int64) ONE * header_in.speed /
      header_out.speed);
     exponent = (int) ((vgetty_s_int64) ONE * fexponent);
     srate = header_in.speed / 10;

     if (speed <= ONE)
          {

          /*
           * slow down the sample, create new values using
           * simple linear interpolation
           */

          int a = 0;
          int b;
          int t;
          int i = 0;

	  a = header_in.read_pvf_data(fd_in);
          if (!feof(fd_in))
               header_out.write_pvf_data(fd_out, a);

          t = speed;

          while (1)
               {
               b = header_in.read_pvf_data(fd_in);
               if (feof(fd_in))
                    break;

               while (t <= ONE)
                    {
                    header_out.write_pvf_data(fd_out, (int) (a +
                     ((((vgetty_s_int64) b - a) * t) >> SHIFT)));
                    t += speed;
                    };

               t -= ONE;
               a = b;

               if (++i == srate)
                    {
                    i -= srate;
                    speed = (speed * exponent) >> SHIFT;
                    };

               };

          }
     else
          {

          /*
           * speed up the sample, use averaging
           */

          int t = 0;
          int sum = 0;
          int i = 0;
          int b;

          while (1)
               {
               b = header_in.read_pvf_data(fd_in);
               if (feof(fd_in))
                    break;
               t += ONE;

               if (t >= speed)
                    {
                    t -= speed;
                    sum += b * ((vgetty_s_int64) ONE - t) >> SHIFT;
                    header_out.write_pvf_data(fd_out, (vgetty_s_int64) sum *
                     ONE / speed);
                    sum = ((vgetty_s_int64) b * t) >> SHIFT;
                    }
               else
                    sum += b;

               if (++i == srate)
                    {
                    i -= srate;
                    speed = (speed * exponent) >> SHIFT;
                    };

               };

          };

     fclose(fd_in);
     fclose(fd_out);
     exit(OK);
     }
