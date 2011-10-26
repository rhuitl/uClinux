/*
 * lib.c
 *
 * Contains some basic functions for reading and writing files
 *
 * $Id: lib.c,v 1.4 1998/09/09 21:07:00 gert Exp $
 *
 */

#include "../include/voice.h"

rmd_header init_rmd_header = {"RMD1", "", 0x0000, 0, 0, {0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00}};
state_t init_state = {0x0000, 0};

int bitmask[17] = {0x0000, 0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f,
 0x007f, 0x00ff, 0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff,
 0xffff};

int read_bits (FILE *fd_in, state_t *state, int nbits)
     {
     static int data_new;

     while(state->nleft < nbits)
          {

          if ((data_new = getc(fd_in)) == EOF)
               return(EOF);

          state->data = (state->data << 8) | data_new;
          state->nleft += 8;
          }

     state->nleft -= nbits;
     return(state->data >> state->nleft) & bitmask[nbits];
     }

void write_bits (FILE *fd_out, state_t *state, int nbits, int data)
     {
     state->data = (state->data << nbits) | (data & bitmask[nbits]);
     state->nleft += nbits;

     while (state->nleft >= 8)
          {
          putc((state->data >> (state->nleft - 8)) & 0xff, fd_out);
          state->nleft -= 8;
          }

     }

int read_bits_reverse (FILE *fd_in, state_t *state, int nbits)
     {
     static int data;
     static int data_new;

     while(state->nleft < nbits)
          {

          if ((data_new = getc(fd_in)) != EOF)
               return(EOF);

          state->data |= (data_new << state->nleft);
          state->nleft += 8;
          }

     data = state->data & bitmask[nbits];
     state->nleft -= nbits;
     state->data >>= nbits;
     return(data);
     }

void write_bits_reverse (FILE *fd_out, state_t *state, int nbits, int data)
     {
     state->data |= ((data & bitmask[nbits]) << state->nleft);
     state->nleft += nbits;

     while(state->nleft >= 8)
          {
          putc(state->data & 0xff, fd_out);
          state->nleft -= 8;
          state->data >>= 8;
          }

     }

int read_rmd_header(FILE *fd_in, rmd_header *header_in)
     {
     *header_in = init_rmd_header;

     if (fread(header_in, sizeof(rmd_header), 1, fd_in) != 1)
          {
          fprintf(stderr, "%s: Could not read rmd header\n", program_name);
          return(FAIL);
          };

     if (strncmp(header_in->magic, "RMD1", 4) != 0)
          {
          fprintf(stderr, "%s: No rmd (raw modem data) header found\n",
           program_name);
          return(FAIL);
          };

     return(OK);
     }

int write_rmd_header(FILE *fd_out, rmd_header *header_out)
     {

     if (fwrite(header_out, sizeof(rmd_header), 1, fd_out) != 1)
          {
          fprintf(stderr, "%s: Could not write rmd header\n", program_name);
          return(FAIL);
          };

     return(OK);
     }

static int read_pvf_data_8_ascii(FILE *fd_in)
     {
     static int data_new;

     if (fscanf(fd_in, "%d", &data_new) != 1)
          return(EOF);

     if (data_new < -0x80)
          data_new = -0x80;

     if (data_new > 0x7f)
          data_new = 0x7f;

     return(data_new << 16);
     }

static int read_pvf_data_16_ascii(FILE *fd_in)
     {
     static int data_new;

     if (fscanf(fd_in, "%d", &data_new) != 1)
          return(EOF);

     if (data_new < -0x8000)
          data_new = -0x8000;

     if (data_new > 0x7fff)
          data_new = 0x7fff;

     return(data_new << 8);
     }

static int read_pvf_data_32_ascii(FILE *fd_in)
     {
     static int data_new;

     if (fscanf(fd_in, "%d", &data_new) != 1)
          return(EOF);

     return(data_new);
     }

static int read_pvf_data_8(FILE *fd_in)
     {
     static signed char data_new;

     if (fread(&data_new, 1, 1, fd_in) != 1)
          return(EOF);

     return(data_new << 16);
     }

static int read_pvf_data_16(FILE *fd_in)
     {
     static signed short data_new;

     if (fread(&data_new, 2, 1, fd_in) != 1)
          return(EOF);

     data_new = ntohs(data_new);
     return(data_new << 8);
     }

static int read_pvf_data_32(FILE *fd_in)
     {
     static int data_new;

     if (fread(&data_new, 4, 1, fd_in) != 1)
          return(EOF);

     return(ntohl(data_new));
     }

static void write_pvf_data_8_ascii(FILE *fd_out, int data)
     {
     data >>= 16;

     if (data > 0x7f)
          data = 0x7f;

     if (data < -0x80)
          data = -0x80;

     fprintf(fd_out, "%d\n", data);
     }

static void write_pvf_data_16_ascii(FILE *fd_out, int data)
     {
     data >>= 8;

     if (data > 0x7fff)
          data = 0x7fff;

     if (data < -0x8000)
          data = -0x8000;

     fprintf(fd_out, "%d\n", data);
     }

static void write_pvf_data_32_ascii(FILE *fd_out, int data)
     {
     fprintf(fd_out, "%d\n", data);
     }

static void write_pvf_data_8(FILE *fd_out, int data)
     {
     data >>= 16;

     if (data > 0x7f)
          data = 0x7f;

     if (data < -0x80)
          data = -0x80;

     putc(data, fd_out);
     }

static void write_pvf_data_16(FILE *fd_out, int data)
     {
     static signed short out;

     data >>= 8;

     if (data > 0x7fff)
          data = 0x7fff;

     if (data < -0x8000)
          data = -0x8000;

     out = htons((short) data);
     fwrite(&out, 2, 1, fd_out);
     }

static void write_pvf_data_32(FILE *fd_out, int data)
     {
     static signed int out;

     out = htonl((long) data);
     fwrite(&out, 4, 1, fd_out);
     }

int read_pvf_header(FILE *fd_in, pvf_header *header_in)
     {
     char buffer[VOICE_BUF_LEN];
     int i;

     *header_in = init_pvf_header;

     if (fread(&buffer, 5, 1, fd_in) != 1)
          {
          fprintf(stderr, "%s: Could not read pvf header\n", program_name);
          return(FAIL);
          };

     if (strncmp(buffer, "PVF1\n", 5) == 0)
          header_in->ascii = FALSE;
     else if (strncmp(buffer, "PVF2\n", 5) == 0)
          header_in->ascii = TRUE;
     else
          {
          fprintf(stderr, "%s: No pvf (portable voice format) header found\n",
           program_name);
          return(FAIL);
          };

     for (i = 0; i < VOICE_BUF_LEN; i++)
          {

          if (fread(&buffer[i], 1, 1, fd_in) != 1)
               {
               fprintf(stderr, "%s: Could not read pvf header\n", program_name);
               return(FAIL);
               };

          if (buffer[i] == '\n')
               break;

          };

     buffer[i] = 0x00;
     sscanf(buffer, "%d %d %d", &header_in->channels, &header_in->speed,
      &header_in->nbits);

     if ((header_in->channels < 1) || (32 < header_in->channels))
          {
          fprintf(stderr, "%s: Invalid number of channels (%d)\n",
           program_name, header_in->channels);
          return(FAIL);
          };

     if ((header_in->speed < 0) || (50000 < header_in->speed))
          {
          fprintf(stderr, "%s: Invalid sample speed (%d)\n", program_name,
           header_in->speed);
          return(FAIL);
          };

     if ((header_in->nbits != 8) && (header_in->nbits != 16) &&
      (header_in->nbits != 32))
          {
          fprintf(stderr, "%s: Invalid number of bits (%d) per sample\n",
           program_name, header_in->nbits);
          return(FAIL);
          };

     if (header_in->ascii)
          {

          switch (header_in->nbits)
               {
               case 8:
                    header_in->read_pvf_data = &read_pvf_data_8_ascii;
                    break;
               case 16:
                    header_in->read_pvf_data = &read_pvf_data_16_ascii;
                    break;
               case 32:
                    header_in->read_pvf_data = &read_pvf_data_32_ascii;
                    break;
               default:
                    fprintf(stderr, "%s: Illegal bit size for pvf input\n",
                     program_name);
                    return(FAIL);
               };

          }
     else
          {

          switch (header_in->nbits)
               {
               case 8:
                    header_in->read_pvf_data = &read_pvf_data_8;
                    break;
               case 16:
                    header_in->read_pvf_data = &read_pvf_data_16;
                    break;
               case 32:
                    header_in->read_pvf_data = &read_pvf_data_32;
                    break;
               default:
                    fprintf(stderr, "%s: Illegal bit size for pvf input\n",
                     program_name);
                    return(FAIL);
               };

          };

     return(OK);
     }

int write_pvf_header(FILE *fd_out, pvf_header *header_out)
     {
     char buffer[VOICE_BUF_LEN];

     if (header_out->ascii)
          {
          sprintf(buffer, "PVF2\n%d %d %d\n", header_out->channels,
           header_out->speed, header_out->nbits);

          switch (header_out->nbits)
               {
               case 8:
                    header_out->write_pvf_data = &write_pvf_data_8_ascii;
                    break;
               case 16:
                    header_out->write_pvf_data = &write_pvf_data_16_ascii;
                    break;
               case 32:
                    header_out->write_pvf_data = &write_pvf_data_32_ascii;
                    break;
               default:
                    fprintf(stderr, "%s: Illegal bit size for pvf output\n",
                     program_name);
                    return(FAIL);
               };

          }
     else
          {
          sprintf(buffer, "PVF1\n%d %d %d\n", header_out->channels,
           header_out->speed, header_out->nbits);

          switch (header_out->nbits)
               {
               case 8:
                    header_out->write_pvf_data = &write_pvf_data_8;
                    break;
               case 16:
                    header_out->write_pvf_data = &write_pvf_data_16;
                    break;
               case 32:
                    header_out->write_pvf_data = &write_pvf_data_32;
                    break;
               default:
                    fprintf(stderr, "%s: Illegal bit size for pvf output\n",
                     program_name);
                    return(FAIL);
               };

          };

     if (fwrite(&buffer, strlen(buffer), 1, fd_out) != 1)
          {
          fprintf(stderr, "%s: Could not write pvf header\n", program_name);
          return(FAIL);
          };

     return(OK);
     }

pvf_header init_pvf_header = {FALSE, 1, 8000, 32, &read_pvf_data_32,
 &write_pvf_data_32};
