/*
 * zyxel.c
 *
 * Converts the ZyXEL 1496 2, 3 and 4 bit voice format to the pvf format
 * and the other way around. The conversion algorithm is based on the
 * ZyXEL vcnvt program.
 *
 * The ZyXEL 2864 and the ISDN4Linux driver can also store voice data in
 * this format.
 *
 * $Id: zyxel.c,v 1.4 1998/09/09 21:07:06 gert Exp $
 *
 */

#include "../include/voice.h"

static int Mx[3][8] =
     {
     {0x3800, 0x5600, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000},
     {0x399a, 0x3a9f, 0x4d14, 0x6607, 0x0000, 0x0000, 0x0000, 0x0000},
     {0x3556, 0x3556, 0x399A, 0x3A9F, 0x4200, 0x4D14, 0x6607, 0x6607}
     };

int zyxeltopvf (FILE *fd_in, FILE *fd_out, int nbits, pvf_header *header_out)
     {
     state_t s;
     int a = 0;
     int d = 5;
     int sign;
     int e;

     if (nbits == 30)
          nbits = 3;

     if ((nbits != 2) && (nbits != 3) && (nbits != 4))
          return(FAIL);

     s = init_state;

     while ((e = read_bits(fd_in, &s, nbits)) != EOF)
          {

          if ((nbits == 4) && (e == 0))
               d = 4;

          sign = (e >> (nbits - 1)) ? (-1) : (1);
          e = e & bitmask[nbits - 1];
          a = (a * 4093 + 2048) >> 12;
          a += sign * ((e << 1) + 1) * d >> 1;

          if (d & 1)
               a++;

          header_out->write_pvf_data(fd_out, a << 10);
          d = (d * Mx[nbits - 2][e] + 0x2000) >> 14;

          if (d < 5)
               d = 5;

          };

     return(OK);
     }

int pvftozyxel (FILE *fd_in, FILE *fd_out, int nbits, pvf_header *header_in)
     {
     int a = 0;
     int d = 5;
     state_t s;
     int e;
     int nmax;
     int sign;
     int delta;
     int data_new;

     s = init_state;

     while (!feof(fd_in))
          {
          data_new = header_in->read_pvf_data(fd_in);
          e = 0;
          nmax = 1 << (nbits - 1);
          delta = (data_new >> 10) - a;

          if (delta < 0)
               {
               e = nmax;
               delta = -delta;
               };

          while((--nmax) && (delta > d))
               {
               delta -= d;
               e++;
               };

          if ((nbits == 4) && ((e & 0x0f) == 0))
               e = 0x08;

          write_bits(fd_out, &s, nbits, e);
          a = (a * 4093 + 2048) >> 12;
          sign = (e >> (nbits - 1)) ? (-1) : (1);
          e = e & bitmask[nbits - 1];
          a += sign * ((e << 1) + 1) * d >> 1;

          if (d & 1)
               a++;

          d = (d * Mx[nbits - 2][e] + 0x2000) >> 14;

          if (d < 5)
               d = 5;

          };

     if (s.nleft > 0)
          write_bits(fd_out, &s, 8 - s.nleft, 0x00);

     return(OK);
     }
