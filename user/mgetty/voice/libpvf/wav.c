/*
 * wav.c
 *
 * Converts pvf <--> wav.
 * it was written by Karlo Gross kg@orion.ddorf.rhein-ruhr.de
 * by using parts from Rick Richardson and Lance Norskog's
 * wav.c, found in sox-11-gamma. Thank you for some funtions.
 * This is the 1. alpha release from 1997/2/14
 *
 * $Id: wav.c,v 1.7 2005/03/13 11:40:10 gert Exp $
 */

#include "../include/voice.h"

char *sizes[] =
     {
     "NONSENSE!",
     "bytes",
     "shorts",
     "NONSENSE",
     "longs",
     "32-bit floats",
     "64-bit floats",
     "IEEE floats"
     };

/* Private data for .wav file */

typedef struct wavstuff
     {
     long samples;
     int  second_header; /* non-zero on second header write */
     } *wav_t;

/* wave file characteristics */

unsigned short wFormatTag;              /* data format */
unsigned short wChannels;               /* number of channels */
unsigned long  wSamplesPerSecond;       /* samples per second per channel */
unsigned long  wAvgBytesPerSec;    /* estimate of bytes per second needed */
unsigned short wBlockAlign;     /* byte alignment of a basic sample block */
unsigned short wBitsPerSample;          /* bits per sample */
unsigned long  data_length;             /* length of sound data in bytes */
unsigned long  bytespersample;          /* bytes per sample (per channel) */

static char *wav_format_str();

/* Read short, little-endian: little end first. VAX/386 style. */

unsigned short rlshort(ft_t ft)
     {
     unsigned char uc, uc2;
     uc  = getc(ft->fp);
     uc2 = getc(ft->fp);
     return (uc2 << 8) | uc;
     }

/* Read long, little-endian: little end first. VAX/386 style. */

unsigned long rllong(ft_t ft)
     {
     unsigned char uc, uc2, uc3, uc4;

/*   if (feof(ft->fp))
          fprintf(stderr,readerr);       No worky! */

     uc  = getc(ft->fp);
     uc2 = getc(ft->fp);
     uc3 = getc(ft->fp);
     uc4 = getc(ft->fp);
     return ((long)uc4 << 24) | ((long)uc3 << 16) | ((long)uc2 << 8) | (long)uc;
     }

/* Write long, little-endian: little end first. VAX/386 style. */

int wllong(ft_t ft, unsigned long ul)
     {
     int datum;

     datum = (ul) & 0xff;
     putc(datum, ft->fp);
     datum = (ul >> 8) & 0xff;
     putc(datum, ft->fp);
     datum = (ul >> 16) & 0xff;
     putc(datum, ft->fp);
     datum = (ul >> 24) & 0xff;
     putc(datum, ft->fp);

     if (ferror(ft->fp))
          return 1;

     return 0;
     }

/* Write short, little-endian: little end first. VAX/386 style. */

int wlshort(ft_t ft, unsigned short us)
     {
     putc(us, ft->fp);
     putc(us >> 8, ft->fp);

     if (ferror(ft->fp))
          return 1;

     return 0;
     }

int wavstartread(ft_t ft)
     {
     wav_t     wav = (wav_t) ft->priv;
     char magic[4];
     unsigned int len;
     int  littlendian = 1;
     char *endptr;

     ft->info.rate      = 0;
     ft->info.size      = -1;
     ft->info.style     = -1;
     ft->info.channels  = -1;
     ft->comment   =  NULL;
     ft->swap      = 0;

     endptr = (char *) &littlendian;
     if   (!*endptr) ft->swap = 1;

     /* If you need to seek around the input file. */
     if   (0 && ! ft->seekable)
          fprintf(stderr, "Sorry, .wav input file must be a file, not a pipe");

     if   (   fread(magic, 1, 4, ft->fp) != 4
         || strncmp("RIFF", magic, 4))
          {
          fprintf(stderr, "Sorry, not a RIFF file");
          return ERROR;
          }

     len = rllong(ft);

     if   (   fread(magic, 1, 4, ft->fp) != 4
         || strncmp("WAVE", magic, 4))
          {
          fprintf(stderr, "Sorry, not a WAVE file");
          return ERROR;
          }

     /* Now look for the format chunk */
     for (;;)
          {
          if   ( fread(magic, 1, 4, ft->fp) != 4 )
               {
               fprintf(stderr, "Sorry, missing fmt spec");
               return ERROR;
               }
          len = rllong(ft);
          if   (strncmp("fmt ", magic, 4) == 0)
               break;    /* Found the format chunk */
          while (len > 0 && !feof(ft->fp))   /* skip to next chunk */
               {
               getc(ft->fp);
               len--;
               }
          }

     if   ( len < 16 )
          fprintf(stderr, "Sorry, fmt chunk is too short");

     wFormatTag = rlshort(ft);
     switch (wFormatTag)
          {
          case WAVE_FORMAT_UNKNOWN:
               fprintf(stderr, "Sorry, this WAV file is in Microsoft Official Unknown format.");
               return ERROR;
          case WAVE_FORMAT_PCM:    /* this one, at least, I can handle */
               break;
          case WAVE_FORMAT_ADPCM:
               fprintf(stderr, "Sorry, this WAV file is in Microsoft ADPCM format.");
               return ERROR;
          case WAVE_FORMAT_ALAW:   /* Think I can handle this */
               ft->info.style = ALAW;
               break;
          case WAVE_FORMAT_MULAW:  /* Think I can handle this */
               ft->info.style = ULAW;
               break;
          case WAVE_FORMAT_OKI_ADPCM:
               fprintf(stderr, "Sorry, this WAV file is in OKI ADPCM format.");
               return ERROR;
          case WAVE_FORMAT_DIGISTD:
               fprintf(stderr, "Sorry, this WAV file is in Digistd format.");
               return ERROR;
          case WAVE_FORMAT_DIGIFIX:
               fprintf(stderr, "Sorry, this WAV file is in Digifix format.");
               return ERROR;
          case IBM_FORMAT_MULAW:
               fprintf(stderr, "Sorry, this WAV file is in IBM U-law format.");
               return ERROR;
          case IBM_FORMAT_ALAW:
               fprintf(stderr, "Sorry, this WAV file is in IBM A-law format.");
               return ERROR;
          case IBM_FORMAT_ADPCM:
               fprintf(stderr, "Sorry, this WAV file is in IBM ADPCM format.");
               return ERROR;
          default:
               fprintf(stderr, "Sorry, don't understand format");
               return ERROR;
          }

     wChannels = rlshort(ft);
     ft->info.channels = wChannels;
     wSamplesPerSecond = rllong(ft);
     ft->info.rate = wSamplesPerSecond;
     wAvgBytesPerSec = rllong(ft); /* Average bytes/second */
     wBlockAlign = rlshort(ft);    /* Block align */
     wBitsPerSample =  rlshort(ft);     /* bits per sample per channel */
     bytespersample = (wBitsPerSample + 7)/8;
     switch (bytespersample)
     {
          case 1:
                    ft->info.size = BYTE;
               break;
          case 2:
                    ft->info.size = WORD;
               break;
          case 4:
                    ft->info.size = LONG;
               break;
          default:
               fprintf(stderr, "Sorry, don't understand .wav size");
               return ERROR;
     }
     len -= 16;
     while (len > 0 && !feof(ft->fp))
     {
          getc(ft->fp);
          len--;
     }

     /* Now look for the wave data chunk */
     for (;;)
     {
          if ( fread(magic, 1, 4, ft->fp) != 4 )
               {
               fprintf(stderr, "Sorry, missing data chunk");
               return ERROR;
               }
          len = rllong(ft);
          if (strncmp("data", magic, 4) == 0)
               break;    /* Found the data chunk */
          while (len > 0 && !feof(ft->fp)) /* skip to next chunk */
          {
               getc(ft->fp);
               len--;
          }
     }
     data_length = len;
     wav->samples = data_length/ft->info.size;    /* total samples */

     fprintf(stderr, "Reading Wave file: %s format, %d channel%s, %ld samp/sec\n",
             wav_format_str(wFormatTag), wChannels,
             wChannels == 1 ? "" : "s", wSamplesPerSecond);

     fprintf(stderr, "%ld byte/sec, %d block align, %d bits/samp, %lu data bytes\n",
                wAvgBytesPerSec, wBlockAlign, wBitsPerSample, data_length);
     return OK;
     }

int wavwritehdr(ft_t ft,long data_size)
     {

     switch (ft->info.size)
          {
          case BYTE:
               wBitsPerSample = 8;
               if (ft->info.style == -1 || ft->info.style == UNSIGNED)
                    ft->info.style = UNSIGNED;
               else if (ft->info.style != ALAW && ft->info.style != ULAW)
                    fprintf(stderr, "User options overiding style written to .wav header");
               break;
          case WORD:
               wBitsPerSample = 16;
               if (ft->info.style == -1 || ft->info.style == SIGN2)
                    ft->info.style = SIGN2;
               break;
          case LONG:
               wBitsPerSample = 32;
               if (ft->info.style == -1 || ft->info.style == SIGN2)
                    ft->info.style = SIGN2;
               break;
          default:
               wBitsPerSample = 32;
               if (ft->info.style == -1)
                    ft->info.style = SIGN2;
               break;
          }

     switch (ft->info.style)
          {
          case UNSIGNED:
               wFormatTag = WAVE_FORMAT_PCM;
               if (wBitsPerSample != 8 )
                    fprintf(stderr, "Warning - writing bad .wav file using unsigned data and %d bits/sample",wBitsPerSample);
               break;
          case SIGN2:
               wFormatTag = WAVE_FORMAT_PCM;
               if (wBitsPerSample == 8 )
                    fprintf(stderr, "Warning - writing bad .wav file using signed data and %d bits/sample",wBitsPerSample);
               break;
          case ALAW:
               wFormatTag = WAVE_FORMAT_ALAW;
               if (wBitsPerSample != 8 )
                    fprintf(stderr, "Warning - writing bad .wav file using A-law data and %d bits/sample",wBitsPerSample);
               break;
          case ULAW:
               wFormatTag = WAVE_FORMAT_MULAW;
               if (wBitsPerSample != 8 )
                    fprintf(stderr, "Warning - writing bad .wav file using U-law data and %d bits/sample",wBitsPerSample);
               break;
          }

     wSamplesPerSecond = ft->info.rate;
     bytespersample = (wBitsPerSample + 7)/8;
     wAvgBytesPerSec = ft->info.rate * ft->info.channels * bytespersample;
     wChannels = ft->info.channels;
     wBlockAlign = ft->info.channels * bytespersample;
          data_length = data_size;

     /* figured out header info, so write it */
     fputs("RIFF", ft->fp);
     wllong(ft, data_length + 8+16+12+1);    /* Waveform chunk size: FIXUP(4) */
                                    /* die 1 ist von mir karlo */
     fputs("WAVE", ft->fp);
     fputs("fmt ", ft->fp);
     wllong(ft, (long)16);         /* fmt chunk size */
     wlshort(ft, wFormatTag);
     wlshort(ft, wChannels);
     wllong(ft, wSamplesPerSecond);
     wllong(ft, wAvgBytesPerSec);
     wlshort(ft, wBlockAlign);
     wlshort(ft, wBitsPerSample);

     fputs("data", ft->fp);
     wllong(ft, data_length);  /* data chunk size: FIXUP(40) */


     fprintf(stderr, "Writing Wave file: %s format, %d channel%s, %ld samp/sec",
               wav_format_str(wFormatTag), wChannels,
               wChannels == 1 ? "" : "s", wSamplesPerSecond);
     fprintf(stderr, " %ld byte/sec, %d block align, %d bits/samp\n",
                     wAvgBytesPerSec, wBlockAlign, wBitsPerSample);

     return OK;
     }

int wavstartwrite(ft_t ft,long data_size)
     {
     wav_t     wav = (wav_t) ft->priv;
     int  littlendian = 1;
     char *endptr;

     endptr = (char *) &littlendian;
     if (!*endptr) ft->swap = 1;

     wav->samples = 0;
     wav->second_header = 0;

     if   (wavwritehdr(ft,data_size) != OK)
          return ERROR;
     return OK;
     }

/*
 * Return a string corresponding to the wave format type.
 */

static char * wav_format_str(unsigned wFormatTag)
     {

     switch (wFormatTag)
          {
          case WAVE_FORMAT_UNKNOWN:
               return "Microsoft Official Unknown";
          case WAVE_FORMAT_PCM:
               return "Microsoft PCM";
          case WAVE_FORMAT_ADPCM:
               return "Microsoft ADPCM";
          case WAVE_FORMAT_ALAW:
               return "Microsoft A-law";
          case WAVE_FORMAT_MULAW:
               return "Microsoft U-law";
          case WAVE_FORMAT_OKI_ADPCM:
               return "OKI ADPCM format.";
          case WAVE_FORMAT_DIGISTD:
               return "Digistd format.";
          case WAVE_FORMAT_DIGIFIX:
               return "Digifix format.";
          case IBM_FORMAT_MULAW:
               return "IBM U-law format.";
          case IBM_FORMAT_ALAW:
               return "IBM A-law";
          case IBM_FORMAT_ADPCM:
               return "IBM ADPCM";
          default:
               return "Unknown";
          }

     }

int pvftowav (FILE *fd_in, FILE *fd_out, pvf_header *header_in, int wav_bits)
     {
     int bytespersample;
     long data_size = 0;
     int buffer_size = 0;
     int *buffer = NULL;
     int data,*ptr;
     int voice_samples = 0;
     struct soundstream s;

     bytespersample = (wav_bits + 7) / 8;

     switch (bytespersample)
          {
          case 1:
               s.info.size = BYTE;
               break;
          case 2:
               s.info.size = WORD;
               break;
          case 4:
               s.info.size = LONG;
               break;
          default:
               fprintf(stderr, "sorry, don't understand .wav size");
               return(ERROR);
          }

     s.info.rate     = header_in->speed;
     s.info.style    = -1;
     s.info.channels = header_in->channels;
     s.comment      = NULL;
     s.swap         = 0;
     s.filetype     = (char *) 0;
     s.fp                = fd_out;
     s.seekable          = 0;

     while(!feof(fd_in))
          {
          data = header_in->read_pvf_data(fd_in);

          if (voice_samples >= buffer_size)
               {
               buffer_size += BLOCK_SIZE;
	       if ( buffer == NULL )
		   buffer = (int *) malloc( buffer_size * sizeof(int) );
	       else
                   buffer = (int *) realloc(buffer, buffer_size * sizeof(int));

               if (buffer == NULL)
                    {
                    fprintf(stderr, "%s: out of memory in pvftowav", program_name);
                    free(buffer);
                    exit(99);
                    };

               }

          buffer[voice_samples++] = data;
          data_size++;
          }

     if   (wavstartwrite(&s,data_size) != OK)
          {
          free(buffer);
          return ERROR;
          }

     ptr = buffer;

     switch (s.info.size)
          {
          case BYTE:

               while (data_size--)
                    {
                    *ptr >>=16;

                    if   (*ptr > 0x7f)
                         *ptr = 0x7f;

                    if   (*ptr < -0x80)
                         *ptr = -0x80;

                    putc(*ptr+0x80,fd_out);
                    ptr++;
                    };

               break;
          case WORD:

               while (data_size--)
                    {
                    *ptr >>=8;

                    if   (*ptr > 0x7fff)
                         *ptr = 0x7fff;

                    if   (*ptr < -0x8000)
                         *ptr = -0x8000;

                    putc(*ptr, fd_out);
                    putc(*ptr++ >> 8, fd_out);
                    };

               break;
          case LONG:

               while (data_size--)
                    {
                    putc(*ptr, fd_out);
                    putc(*ptr >> 8, fd_out);
                    putc(*ptr >> 16, fd_out);
                    putc(*ptr++ >> 24, fd_out);
                    }

               break;
          }

     free(buffer);
     return(OK);
     }

int wavtopvf (FILE *fd_in, FILE *fd_out, pvf_header *header_out)
     {
     struct soundstream s;
     int d;

     s.fp = fd_in;

     if   (wavstartread(&s) != OK)
          return ERROR;

     header_out->channels = (int) wChannels;
     header_out->speed = (int) wSamplesPerSecond;
     write_pvf_header(fd_out, header_out);

     while (data_length--)
          {

          if (feof(fd_in))
               return(OK);

          switch (wBitsPerSample)
               {
               case 8:
                    d = getc(fd_in) - 0x80;
                    d <<= 16;
                    break;
               case 16:
                    d = getc(fd_in) & 0xFF;
                    d += (getc(fd_in) << 8);

                    if (d & 0x8000)
                     d |= 0xFFFF0000;

                    d <<= 8;
                    break;
               default:
                    fprintf(stderr,
                     "%s: unsupported number of bits per sample (%d)\n",
                     program_name, wBitsPerSample);
                    return(ERROR);
               };

          header_out->write_pvf_data(fd_out, d);
          };

     return(OK);
     }

