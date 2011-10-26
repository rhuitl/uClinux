/*
 * voc.c
 *
 * Converts pvf <--> voc.
 *
 * $Id: voc.c,v 1.4 1998/09/09 21:07:05 gert Exp $
 *
 */

#include "../include/voice.h"

static char voc_hdr[32] =
     {
     'C','r','e','a','t','i','v','e',' ',
     'V','o','i','c','e',' ','F','i','l','e',
     0x1a,0x1a,0x00,0x0a,0x01,0x29,0x11,
     0x01,(unsigned char) 0x82,0x70,0x00,(unsigned char) 0x98,0x00
     };

/*
 * static char *voc_type[] =
 *   {
 *   "8 bit",
 *   "4 bit",
 *   "2.6 bit",
 *   "2 bit",
 *   "Multi DAC, 1 channel",
 *   "Multi DAC, 2 channels",
 *   "Multi DAC, 3 channels",
 *   "Multi DAC, 4 channels",
 *   "unknown"
 *   };
 */

int pvftovoc (FILE *fd_in, FILE *fd_out, pvf_header *header_in)
     {
     int blocksize = 0x7080;
     int count;
     long rate = header_in->speed;
     static unsigned char voc_blk[4] = {0x02, 0x80, 0x70, 0x00};
     int data;

     voc_hdr[30] = 256 - ((long) 1000000 / rate);
     fwrite(voc_hdr, 1, sizeof(voc_hdr), fd_out);

     count = blocksize;

     while (!feof(fd_in))
          {
          data = header_in->read_pvf_data(fd_in) >> 16;

          if (data > 0x7f)
               data = 0x7f;

          if (data < -0x80)
               data = -0x80;

          putc(data + 0x80, fd_out);
          count--;

          if (!count)
               {
               count = blocksize;
               fwrite(voc_blk, 1, 4, fd_out);
               };

          };

     while (count--)
          putc(0x7f, fd_out);

     putc(0x00, fd_out);
     return(OK);
     }

int voctopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out)
     {
     char hdr[32];
     int data_offset;
     int type;
     long count;
     long blocksize;

     header_out->speed = -1;
     fread(hdr, 1, 0x1a, fd_in);

     if (strncmp(hdr, voc_hdr, 0x14))
          {
          fprintf(stderr, "%s: not a VOC file", program_name);
          return(ERROR);
          };

     data_offset = hdr[0x14] | (hdr[0x15] << 8);

     if (hdr[0x17] != 1)
          {
          fprintf(stderr, "%s: unsupported VOC major version %d",
           program_name, hdr[0x17]);
          return(ERROR);
          };

     for (count = 0x20; count < data_offset; count++)
          getc(fd_in);

     /*
      * read the data blocks
      */

     blocksize = 0;
     count = 0;

     while (TRUE)
          {
          type = getc(fd_in);

          if (type == 0)
               {
               /*
                * terminator
                */

               return(OK);
               }
          else
               {
               blocksize = getc(fd_in);
               blocksize |= (getc(fd_in) << 8);
               blocksize |= (getc(fd_in) << 16);
               count = blocksize;

               if (type > 2)
                    fprintf(stderr,
                     "%s: unknown block type %d, skipping...\n", program_name,
                     type);

               if (type == 1)
                    {
                    long sample_rate = 1000000L / (long) (256 - getc(fd_in));
                    int data_type = getc(fd_in);

                    if (header_out->speed == -1)
                         {
                         header_out->speed = sample_rate;
                         write_pvf_header(fd_out, header_out);
                         }
                    else

                         if (header_out->speed != sample_rate)
                              {
                              fprintf(stderr,
                               "%s: unsupported sample rate change",
                               program_name);
                              return(ERROR);
                              };

                    if (data_type != 0)
                         {
                         fprintf(stderr, "%s: unsupported data type %d",
                          program_name, data_type);
                         return(ERROR);
                         };

                    count -= 2;
                    };

               while (count--)
                    {
                    int d = getc(fd_in);

                    if (feof(fd_in))
                         return(OK);

                    if (type <= 2)
                         header_out->write_pvf_data(fd_out, (d - 0x80) << 16);

                    };

               };

          };

     return(OK);
     }
