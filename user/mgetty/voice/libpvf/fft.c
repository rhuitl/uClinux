/*
 * fft.c
 *
 * Original code by ulrich@Gaston.westfalen.de (Heinz Ulrich Stille).
 *
 * $Id: fft.c,v 1.5 1999/03/16 09:59:19 marcs Exp $
 *
 */

#include "../include/voice.h"


static void fft (float *real, float *imag, int n)
     {
     float a;
     float tr;
     float ti;
     float wr;
     float wi;
     int mr = 0;
     int l;
     int istep;
     int m;
     int i;
     int j;

     for (m = 1; m <= (n - 1); m++)
          {
          l = n / 2;

          while ((mr + l) > (n - 1))
               l /= 2;

          mr = (mr % l) + l;

          if (mr > m)
               {
               tr = real[m];
               real[m] = real[mr];
               real[mr] = tr;
               ti = imag[m];
               imag[m] = imag[mr];
               imag[mr] = ti;
               }

          }

     for (l = 1; l < n; l = istep)
          {
          istep = 2 * l;

          for (m = 1; m <= l; m++)
               {
               a = -M_PI * (m - 1.0) / l;
               wr = cos(a);
               wi = sin(a);
               i = m - 1;

               do
                    {
                    j = i + l;
                    tr = wr * real[j] - wi * imag[j];
                    ti = wr * imag[j] + wi * real[j];
                    real[j] = real[i] - tr;
                    imag[j] = imag[i] - ti;
                    real[i] += tr;
                    imag[i] += ti;
                    i += istep;
                    }
               while (i < n);

               }

          }

     }

int pvffft (FILE *fd_in, pvf_header *header_in, int skip, int sample_size,
 double threshold, int vgetty_pid, int display)
     {

     /*
      * Read pvf data, transform it into amplitude data and
      * compute an index for the distribution of energy over the
      * frequencies.
      */

     int i;
     int data;
     float val;
     float sum = 0.0;
     float max = 0.0;
     float *real;
     float *imag;

     for (i = sample_size; i > 0; i >>= 1)
          {

          if (((i & 0x01) != 0) && (i != 1))
               {
               fprintf(stderr, "%s: sample size (%d) must be a power of 2\n",
                program_name, sample_size);
               return(ERROR);
               }

          }

     real = malloc((sample_size + 8) * sizeof(float));
     imag = malloc((sample_size + 8) * sizeof(float));

     if ((real == NULL) || (imag == NULL))
          {
          fprintf(stderr, "%s: not enough memory\n", program_name);
          return(ERROR);
          }

     for(i = 0; i < sample_size; i++)
          {
          real[i] = 0;
          imag[i] = 0;
          }


     /*
      * skip the first few seconds
      */

     for (i = 0; i < skip; i++)
          data = header_in->read_pvf_data(fd_in);

     /*
      * store a few seconds' worth of data
      */

     for (i = 0; i < sample_size; i++)
          {

          real[i] = (float) header_in->read_pvf_data(fd_in);
          if (feof(fd_in))
               {

               /*
                * assume it isn't data
                */

               fprintf(stderr, "%s: not enough samples available\n",
                program_name);
               return(ERROR);
               }

          }

     /*
      * tell the calling process that it can stop writing
      */

     if (vgetty_pid > 0)
          kill(vgetty_pid, SIGPIPE);

     /*
      * note that it will get another sigpipe once this is
      * really finished - a close won't do since other processes
      * (i.e. the calling shell) will still have the fd opened.
      */

     fft(real, imag, sample_size);

     for (i = 10; i < sample_size; i++)
          {
          val = sqrt(real[i] * real[i] + imag[i] * imag[i]);
          sum += val;

          if (val > max)
               max = val;
          }

     sum /= sample_size;

     if (max > 1e-10)
          sum /= max;

     if (vgetty_pid > 0)
          {

          if (sum < threshold)
               kill(vgetty_pid, SIGUSR2);

          return(OK);
          }

     if (display)
          {

          for (i = 10; i < (sample_size >> 1); i++)
               printf("%f %f\n", ((double) i / sample_size) *
                header_in->speed, sqrt(real[i] * real[i] +
                imag[i] * imag[i]) / max);

          return(OK);
          };

     printf("%s: FFT level is %g\n", program_name, sum);
     return(OK);
     }
