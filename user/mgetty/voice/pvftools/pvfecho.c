/*
 * pvfecho.c
 *
 * pvfecho adds echo to the sound signal. Input and output is in the pvf
 * (portable voice format) format.
 *
 * $Id: pvfecho.c,v 1.6 2005/03/13 11:39:32 gert Exp $
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
     fprintf(stderr, "\t-A <n> echo volume factor (default is 0.3)\n");
     fprintf(stderr, "\t-D <n> delay in seconds (default is 0.15)\n");
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
     double fdelay = 0.15;
     double fvol = 0.3;
     int delay;
     int vol;
     int voice_samples = 0;
     int buffer_size = 0;
     int *buffer = NULL;
     int data;
     int i;

     check_system();
     program_name = argv[0];

     while ((option = getopt(argc, argv, "abh12368A:D:")) != EOF)
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
               case 'A':
                    fvol = atof(optarg);
                    break;
               case 'D':
                    fdelay = atof(optarg);
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

     delay = (int) (header_in.speed * fdelay);
     vol = (int) (ONE * fvol);

     while (1)
          {
          data = header_in.read_pvf_data(fd_in);
          if (feof(fd_in))
               break;

          if (voice_samples >= buffer_size)
               {
               buffer_size += BLOCK_SIZE;
	       if ( buffer == NULL )
		   buffer = (int *) malloc(buffer_size * sizeof(int));
	       else
		   buffer = (int *) realloc(buffer, buffer_size * sizeof(int));

               if (buffer == NULL)
                    {
                    fprintf(stderr, "%s: out of memory in pvfcut",
                     program_name);
                    exit(99);
                    };

               };

          buffer[voice_samples++] = data;
          };

     for(i = 0; i < voice_samples; i++)
          {
          int data_out;

          if (i >= delay)
               data_out = buffer[i - delay];
          else
               data_out = 0;

          buffer[i] += ((vgetty_s_int64) data_out * vol) >> SHIFT;
          header_out.write_pvf_data(fd_out, buffer[i]);
          };

     fclose(fd_in);
     fclose(fd_out);
     exit(OK);
     }
