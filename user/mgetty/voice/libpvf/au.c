/*
 * au.c
 *
 * Conversion pvf <--> au.
 *
 * $Id: au.c,v 1.6 2001/05/14 09:52:30 marcs Exp $
 *
 */

#include "../include/voice.h"

typedef long Word; /* must be 32 bits */

typedef struct
     {
     Word magic;               /* magic number SND_MAGIC */
     Word dataLocation;        /* offset or pointer to the data */
     Word dataSize;            /* number of bytes of data */
     Word dataFormat;          /* the data format code */
     Word samplingRate;        /* the sampling rate */
     Word channelCount;        /* the number of channels */
     Word info;                /* optional text information */
     } SNDSoundStruct;

#define SND_MAGIC             (0x2e736e64L)
#define SND_HEADER_SIZE       28
#define SND_UNKNOWN_SIZE      ((Word)(-1))

#ifdef PRINT_INFO
static char sound_format[][30] =
     {
     "unspecified",
     "uLaw_8",
     "linear_8",
     "linear_16",
     "linear_24",
     "linear_32",
     "float",
     "double",
     "fragmented",
     "aLaw_8",
     };
#endif

/*
 * This routine converts from linear 16 bit to 8 bit ulaw.
 *
 * Craig Reese: IDA/Supercomputing Research Center
 * Joe Campbell: Department of Defense
 * 29 September 1989
 *
 * References:
 * 1) CCITT Recommendation G.711  (very difficult to follow)
 * 2) "A New Digital Technique for Implementation of Any
 *     Continuous PCM Companding Law," Villeret, Michel,
 *     et al. 1973 IEEE Int. Conf. on Communications, Vol 1,
 *     1973, pg. 11.12-11.17
 * 3) MIL-STD-188-113,"Interoperability and Performance Standards
 *     for Analog-to_Digital Conversion Techniques,"
 *     17 February 1987
 *
 * Input: Signed 16 bit linear sample
 * Output: 8 bit ulaw sample
 */

#define ZEROTRAP    /* turn on the trap as per the MIL-STD */
#undef ZEROTRAP
#define BIAS 0x84   /* define the add-in bias for 16 bit samples */
#define CLIP 32635

unsigned char linear2ulaw (int sample)
     {
     static int exp_lut[256] =
          {
          0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3,
          4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
          5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
          5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
          6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
          6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6 ,6,
          6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
          6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
          };
     int sign;
     int exponent;
     int mantissa;
     unsigned char ulawbyte;

     /*
      * Get the sample into sign-magnitude.
      */

     sign = (sample >> 8) & 0x80;   /* set aside the sign */

     if (sign != 0)                 /* get magnitude */
          sample = -sample;

     if (sample > CLIP)             /* clip the magnitude */
          sample = CLIP;

     /*
      * Convert from 16 bit linear to ulaw.
      */

     sample = sample + BIAS;
     exponent = exp_lut[(sample >> 7 ) & 0xff];
     mantissa = (sample >> (exponent + 3)) & 0x0f;
     ulawbyte = ~(sign | (exponent << 4) | mantissa);

#ifdef ZEROTRAP

     if (ulawbyte == 0)
          ulawbyte = 0x02;          /* optional CCITT trap */

#endif

     return(ulawbyte);
     }

/*
 * This routine converts from ulaw to 16 bit linear.
 *
 * Craig Reese: IDA/Supercomputing Research Center
 * 29 September 1989
 *
 * References:
 * 1) CCITT Recommendation G.711  (very difficult to follow)
 * 2) MIL-STD-188-113,"Interoperability and Performance Standards
 *     for Analog-to_Digital Conversion Techniques,"
 *     17 February 1987
 *
 * Input: 8 bit ulaw sample
 * Output: signed 16 bit linear sample
 */

int ulaw2linear (unsigned char ulawbyte)
     {
     static int exp_lut[8] = {0, 132, 396, 924, 1980, 4092, 8316, 16764};
     int sign;
     int exponent;
     int mantissa;
     int sample;

     ulawbyte = ~ulawbyte;
     sign = (ulawbyte & 0x80);
     exponent = (ulawbyte >> 4) & 0x07;
     mantissa = ulawbyte & 0x0f;
     sample = exp_lut[exponent] + (mantissa << (exponent + 3));

     if (sign != 0)
          sample = -sample;

     return(sample);
     }

/* The following routines convert 8bit ulaw/alaw to 8bit alaw/ulaw
 * This is merely a copy of the stuff in the ISDN4Linux kernel driver
 */
unsigned char ulaw2alaw (unsigned char ulawbyte)
     {
     static unsigned char ulaw_to_alaw[] =
          {
          0xab, 0x55, 0xd5, 0x15, 0x95, 0x75, 0xf5, 0x35,
          0xb5, 0x45, 0xc5, 0x05, 0x85, 0x65, 0xe5, 0x25,
          0xa5, 0x5d, 0xdd, 0x1d, 0x9d, 0x7d, 0xfd, 0x3d,
          0xbd, 0x4d, 0xcd, 0x0d, 0x8d, 0x6d, 0xed, 0x2d,
          0xad, 0x51, 0xd1, 0x11, 0x91, 0x71, 0xf1, 0x31,
          0xb1, 0x41, 0xc1, 0x01, 0x81, 0x61, 0xe1, 0x21,
          0x59, 0xd9, 0x19, 0x99, 0x79, 0xf9, 0x39, 0xb9,
          0x49, 0xc9, 0x09, 0x89, 0x69, 0xe9, 0x29, 0xa9,
          0xd7, 0x17, 0x97, 0x77, 0xf7, 0x37, 0xb7, 0x47,
          0xc7, 0x07, 0x87, 0x67, 0xe7, 0x27, 0xa7, 0xdf,
          0x9f, 0x7f, 0xff, 0x3f, 0xbf, 0x4f, 0xcf, 0x0f,
          0x8f, 0x6f, 0xef, 0x2f, 0x53, 0x13, 0x73, 0x33,
          0xb3, 0x43, 0xc3, 0x03, 0x83, 0x63, 0xe3, 0x23,
          0xa3, 0x5b, 0xdb, 0x1b, 0x9b, 0x7b, 0xfb, 0x3b,
          0xbb, 0xbb, 0x4b, 0x4b, 0xcb, 0xcb, 0x0b, 0x0b,
          0x8b, 0x8b, 0x6b, 0x6b, 0xeb, 0xeb, 0x2b, 0x2b,
          0xab, 0x54, 0xd4, 0x14, 0x94, 0x74, 0xf4, 0x34,
          0xb4, 0x44, 0xc4, 0x04, 0x84, 0x64, 0xe4, 0x24,
          0xa4, 0x5c, 0xdc, 0x1c, 0x9c, 0x7c, 0xfc, 0x3c,
          0xbc, 0x4c, 0xcc, 0x0c, 0x8c, 0x6c, 0xec, 0x2c,
          0xac, 0x50, 0xd0, 0x10, 0x90, 0x70, 0xf0, 0x30,
          0xb0, 0x40, 0xc0, 0x00, 0x80, 0x60, 0xe0, 0x20,
          0x58, 0xd8, 0x18, 0x98, 0x78, 0xf8, 0x38, 0xb8,
          0x48, 0xc8, 0x08, 0x88, 0x68, 0xe8, 0x28, 0xa8,
          0xd6, 0x16, 0x96, 0x76, 0xf6, 0x36, 0xb6, 0x46,
          0xc6, 0x06, 0x86, 0x66, 0xe6, 0x26, 0xa6, 0xde,
          0x9e, 0x7e, 0xfe, 0x3e, 0xbe, 0x4e, 0xce, 0x0e,
          0x8e, 0x6e, 0xee, 0x2e, 0x52, 0x12, 0x72, 0x32,
          0xb2, 0x42, 0xc2, 0x02, 0x82, 0x62, 0xe2, 0x22,
          0xa2, 0x5a, 0xda, 0x1a, 0x9a, 0x7a, 0xfa, 0x3a,
          0xba, 0xba, 0x4a, 0x4a, 0xca, 0xca, 0x0a, 0x0a,
          0x8a, 0x8a, 0x6a, 0x6a, 0xea, 0xea, 0x2a, 0x2a
          };
     return ulaw_to_alaw[ulawbyte];
     }

unsigned char alaw2ulaw (unsigned char alawbyte)
     {
     static unsigned char alaw_to_ulaw[] =
          {
          0xab, 0x2b, 0xe3, 0x63, 0x8b, 0x0b, 0xc9, 0x49,
          0xba, 0x3a, 0xf6, 0x76, 0x9b, 0x1b, 0xd7, 0x57,
          0xa3, 0x23, 0xdd, 0x5d, 0x83, 0x03, 0xc1, 0x41,
          0xb2, 0x32, 0xeb, 0x6b, 0x93, 0x13, 0xcf, 0x4f,
          0xaf, 0x2f, 0xe7, 0x67, 0x8f, 0x0f, 0xcd, 0x4d,
          0xbe, 0x3e, 0xfe, 0x7e, 0x9f, 0x1f, 0xdb, 0x5b,
          0xa7, 0x27, 0xdf, 0x5f, 0x87, 0x07, 0xc5, 0x45,
          0xb6, 0x36, 0xef, 0x6f, 0x97, 0x17, 0xd3, 0x53,
          0xa9, 0x29, 0xe1, 0x61, 0x89, 0x09, 0xc7, 0x47,
          0xb8, 0x38, 0xf2, 0x72, 0x99, 0x19, 0xd5, 0x55,
          0xa1, 0x21, 0xdc, 0x5c, 0x81, 0x01, 0xbf, 0x3f,
          0xb0, 0x30, 0xe9, 0x69, 0x91, 0x11, 0xce, 0x4e,
          0xad, 0x2d, 0xe5, 0x65, 0x8d, 0x0d, 0xcb, 0x4b,
          0xbc, 0x3c, 0xfa, 0x7a, 0x9d, 0x1d, 0xd9, 0x59,
          0xa5, 0x25, 0xde, 0x5e, 0x85, 0x05, 0xc3, 0x43,
          0xb4, 0x34, 0xed, 0x6d, 0x95, 0x15, 0xd1, 0x51,
          0xac, 0x2c, 0xe4, 0x64, 0x8c, 0x0c, 0xca, 0x4a,
          0xbb, 0x3b, 0xf8, 0x78, 0x9c, 0x1c, 0xd8, 0x58,
          0xa4, 0x24, 0xde, 0x5e, 0x84, 0x04, 0xc2, 0x42,
          0xb3, 0x33, 0xec, 0x6c, 0x94, 0x14, 0xd0, 0x50,
          0xb0, 0x30, 0xe8, 0x68, 0x90, 0x10, 0xce, 0x4e,
          0xbf, 0x3f, 0xfe, 0x7e, 0xa0, 0x20, 0xdc, 0x5c,
          0xa8, 0x28, 0xe0, 0x60, 0x88, 0x08, 0xc6, 0x46,
          0xb7, 0x37, 0xf0, 0x70, 0x98, 0x18, 0xd4, 0x54,
          0xaa, 0x2a, 0xe2, 0x62, 0x8a, 0x0a, 0xc8, 0x48,
          0xb9, 0x39, 0xf4, 0x74, 0x9a, 0x1a, 0xd6, 0x56,
          0xa2, 0x22, 0xdd, 0x5d, 0x82, 0x02, 0xc0, 0x40,
          0xb1, 0x31, 0xea, 0x6a, 0x92, 0x12, 0xcf, 0x4f,
          0xae, 0x2e, 0xe6, 0x66, 0x8e, 0x0e, 0xcc, 0x4c,
          0xbd, 0x3d, 0xfc, 0x7c, 0x9e, 0x1e, 0xda, 0x5a,
          0xa6, 0x26, 0xdf, 0x5f, 0x86, 0x06, 0xc4, 0x44,
          0xb5, 0x35, 0xee, 0x6e, 0x96, 0x16, 0xd2, 0x52
          };
     return alaw_to_ulaw[alawbyte];
     }


static Word read_word (FILE *in)
     {
     Word w;

     w = getc(in);
     w = (w << 8) | getc(in);
     w = (w << 8) | getc(in);
     w = (w << 8) | getc(in);
     return(w);
     }

static void write_word (Word w, FILE *out)
     {
     putc((w & 0xff000000) >> 24, out);
     putc((w & 0x00ff0000) >> 16, out);
     putc((w & 0x0000ff00) >> 8, out);
     putc((w & 0x000000ff), out);
     }

int pvftoau (FILE *fd_in, FILE *fd_out, pvf_header *header_in,
 int dataFormat)
     {
     SNDSoundStruct hdr;
     int sample;

     hdr.magic = SND_MAGIC;
     hdr.dataLocation = SND_HEADER_SIZE;
     hdr.dataSize = SND_UNKNOWN_SIZE;
     hdr.dataFormat = dataFormat;
     hdr.samplingRate = header_in->speed;
     hdr.channelCount = 1;
     hdr.info = 0;

     write_word(hdr.magic, fd_out);
     write_word(hdr.dataLocation, fd_out);
     write_word(hdr.dataSize, fd_out);
     write_word(hdr.dataFormat, fd_out);
     write_word(hdr.samplingRate, fd_out);
     write_word(hdr.channelCount, fd_out);
     write_word(hdr.info, fd_out);

     switch (hdr.dataFormat)
          {
          case SND_FORMAT_MULAW_8:

               while (1)
                    {
                    sample = header_in->read_pvf_data(fd_in) >> 8;
                    if (feof(fd_in))
                         break;

                    if (sample > 0x7fff)
                         sample = 0x7fff;

                    if (sample < -0x8000)
                         sample = -0x8000;

                    putc(linear2ulaw(sample) & 0xff, fd_out);
                    }

               break;
          case SND_FORMAT_ALAW_8:

               while (1)
                    {
                    sample = header_in->read_pvf_data(fd_in) >> 8;
                    if (feof(fd_in))
                         break;

                    if (sample > 0x7fff)
                         sample = 0x7fff;

                    if (sample < -0x8000)
                         sample = -0x8000;

                    putc(ulaw2alaw(linear2ulaw(sample) & 0xff), fd_out);
                    }

               break;
          case SND_FORMAT_LINEAR_8:

               while (1)
                    {
                    sample = header_in->read_pvf_data(fd_in) >> 16;
                    if (feof(fd_in))
                         break;

                    if (sample > 0x7f)
                         sample = 0x7f;

                    if (sample < -0x80)
                         sample = -0x80;

                    putc(sample & 0xff, fd_out);
                    }

               break;
          case SND_FORMAT_LINEAR_16:

               while (1)
                    {
                    sample = header_in->read_pvf_data(fd_in) >> 8;
                    if (feof(fd_in))
                         break;

                    if (sample > 0x7fff)
                         sample = 0x7fff;

                    if (sample < -0x8000)
                         sample = -0x8000;

                    putc((sample >> 8) & 0xff, fd_out);
                    putc(sample & 0xff, fd_out);
                    }

               break;
          default:
               fprintf(stderr, "%s: unsupported sound file format requested",
                program_name);
               return(ERROR);
          }

     return(OK);
     }

int autopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out)
     {
     SNDSoundStruct hdr;
     int i;
     int sample;

     hdr.magic = read_word(fd_in);
     hdr.dataLocation = read_word(fd_in);
     hdr.dataSize = read_word(fd_in);
     hdr.dataFormat = read_word(fd_in);
     hdr.samplingRate = read_word(fd_in);
     hdr.channelCount = read_word(fd_in);
     /* hdr.info = read_word(fd_in); */ /* this is sometimes missing */

     if (hdr.magic != SND_MAGIC)
          {
          fprintf(stderr, "%s: illegal magic number for an .au file",
           program_name);
          return(ERROR);
          }

#ifdef PRINT_INFO
          {
          Word fmt=hdr.dataFormat;

     if ((hdr.dataFormat >= 0) && (hdr.dataFormat < (sizeof(sound_format) /
      sizeof(sound_format[0]))))
          printf("%s: Data format: %s\n", program_name,
           sound_format[hdr.dataFormat]);
     else
          printf("%s: Data format unknown, code=%ld\n", prgoram_name,
           (long) hdr.dataFormat);

     fprintf(stderr, "Sampling rate: %ld\n", (long) hdr.samplingRate);
     fprintf(stderr, "Number of channels: %ld\n", (long) hdr.channelCount);
     fprintf(stderr, "Data location: %ld\n", (long) hdr.dataLocation);
     fprintf(stderr, "Data size: %ld\n", (long) hdr.dataSize);
#endif

     if (hdr.channelCount != 1)
          {
          fprintf(stderr, "%s: number of channels (%ld) is not 1\n",
           program_name, hdr.channelCount);
          return(ERROR);
          }

     header_out->speed = hdr.samplingRate;

     if (write_pvf_header(fd_out, header_out) != OK)
          {
          fprintf(stderr, "%s: could not write pvf header\n",
           program_name);
          return(ERROR);
          };

     for (i = ftell(fd_in); i < hdr.dataLocation; i++)

          if (getc(fd_in) == EOF)
               {
               fprintf(stderr, "%s: unexpected end of file\n",
                program_name);
               return(ERROR);
               }

     switch (hdr.dataFormat)
          {
          case SND_FORMAT_MULAW_8:

               while ((sample = getc(fd_in)) != EOF)
                    header_out->write_pvf_data(fd_out,
                     ulaw2linear(sample) << 8);

               break;
          case SND_FORMAT_ALAW_8:

               while ((sample = getc(fd_in)) != EOF)
                    header_out->write_pvf_data(fd_out,
                     ulaw2linear(alaw2ulaw(sample)) << 8);

               break;
          case SND_FORMAT_LINEAR_8:

               while ((sample = getc(fd_in)) != EOF)
                    {
                    sample &= 0xff;

                    if (sample > 0x7f)
                         sample -= 0x100;

                    header_out->write_pvf_data(fd_out, (sample << 16));
                    }

               break;
          case SND_FORMAT_LINEAR_16:

               while ((sample = getc(fd_in)) != EOF)
                    {
                    sample &= 0xffff;

                    if (sample > 0x7fff)
                         sample -= 0x10000;

                    header_out->write_pvf_data(fd_out, (sample << 8));
                    }

               break;
          default:
               fprintf(stderr, "%s: unsupported or illegal sound encoding\n",
                program_name);
               return(ERROR);
          }

     return(OK);
     }

int pvftoulaw(FILE *fd_in, FILE *fd_out, pvf_header *header_in)
     {
     int sample;

     if (header_in->speed != 8000)
          {
          fprintf(stderr, "%s: sample speed (%d) must be 8000\n",
           program_name, header_in->speed);
          return(ERROR);
          };

     while (1)
          {
          sample = header_in->read_pvf_data(fd_in) >> 8;
          if (feof(fd_in))
               break;
          putc(linear2ulaw(sample), fd_out);
          }

     return(OK);
     }

int ulawtopvf(FILE *fd_in, FILE *fd_out, pvf_header *header_out)
     {
     int sample;

     if (header_out->speed != 8000)
          {
          fprintf(stderr, "%s: sample speed (%d) must be 8000\n",
           program_name, header_out->speed);
          return(ERROR);
          };

     while ((sample = getc(fd_in)) != EOF)
          header_out->write_pvf_data(fd_out, ulaw2linear(sample) << 8);

     return(OK);
     }

int pvftoalaw(FILE *fd_in, FILE *fd_out, pvf_header *header_in)
     {
     int sample;

     if (header_in->speed != 8000)
          {
          fprintf(stderr, "%s: sample speed (%d) must be 8000\n",
           program_name, header_in->speed);
          return(ERROR);
          };

     while (1)
          {
          sample = header_in->read_pvf_data(fd_in) >> 8;
          if (feof(fd_in))
               break;
          putc(ulaw2alaw(linear2ulaw(sample)), fd_out);
          }

     return(OK);
     }

int alawtopvf(FILE *fd_in, FILE *fd_out, pvf_header *header_out)
     {
     int sample;

     if (header_out->speed != 8000)
          {
          fprintf(stderr, "%s: sample speed (%d) must be 8000\n",
           program_name, header_out->speed);
          return(ERROR);
          };

     while ((sample = getc(fd_in)) != EOF)
          header_out->write_pvf_data(fd_out, ulaw2linear(alaw2ulaw(sample)) << 8);

     return(OK);
     }
