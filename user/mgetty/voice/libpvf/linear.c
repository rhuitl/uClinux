/*
 * linear.c
 *
 * Converts pvf <--> linear.
 *
 * $Id: linear.c,v 1.5 1999/03/16 09:59:20 marcs Exp $
 *
 */

#include "../include/voice.h"

int pvftolin (FILE *fd_in, FILE *fd_out, pvf_header *header_in, int is_signed,
 int bits16, int intel)
     {
     int data;

     while (1)
          {
          data = header_in->read_pvf_data(fd_in) >> 8;
          if (feof(fd_in))
               break;

          if (data > 0x7fff)
               data = 0x7fff;

          if (data < -0x8000)
               data = -0x8000;

          if (!is_signed)
               data += 0x8000;

          if (bits16 && intel)
               putc(data & 0xff, fd_out);

          putc((data >> 8), fd_out);

          if (bits16 && !intel)
               putc(data & 0xff, fd_out);

          }

     return(OK);
     }

int lintopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out,
 int is_signed, int bits16, int intel)
     {
     int data;

     while ((data = getc(fd_in)) != EOF)
          {

          if (bits16)
               {

               if (intel)
                    data |= (getc(fd_in) << 8);
               else
                    {
                    data <<= 8;
                    data |= (getc(fd_in));
                    }

               }
          else
               data = (data << 8);

          if (is_signed)
               {

               if (data > 0x7fff)
                    data -= 0x10000;

               }
          else
               data -= 0x8000;

          header_out->write_pvf_data(fd_out, ((data) << 8));
          }

     return(OK);
     }
