/*
 * record.c
 *
 * This command records voice data from the voice modem and
 * saves them in the given file.
 *
 * $Id: record.c,v 1.5 1999/06/27 14:29:02 marcs Exp $
 *
 */

#include "../include/voice.h"

int voice_record_file (char *name)
     {
     FILE *fd;
     int result;
     rmd_header header;
     int bits;

     lprintf(L_MESG, "recording voice file %s", name);

     if (!voice_impersonify()) {
        return(FAIL);
     }

     fd = fopen(name, "w");

     if (!voice_desimpersonify()) {
        if (fd) {
          fclose(fd);
        }
        return(FAIL);
     }

     if (fd == NULL)
          {
          lprintf(L_WARN, "%s: Could not open voice file", program_name);
          return(FAIL);
          }

     if (voice_modem->set_compression(&cvd.rec_compression.d.i,
      &cvd.rec_speed.d.i, &bits) != OK)
          {
          lprintf(L_WARN, "%s: Illegal compression method 0x%04x, speed %d",
           program_name, cvd.rec_compression.d.i, cvd.rec_speed.d.i);
          fclose(fd);
          return(FAIL);
          }

     if (!cvd.raw_data.d.i)
          {
          memset(&header, 0x00, sizeof(rmd_header));
          sprintf(header.magic, "%s", "RMD1");
          sprintf(header.voice_modem_type, "%s", voice_modem_rmd_name);
          header.compression = htons(cvd.rec_compression.d.i);
          header.speed = htons(cvd.rec_speed.d.i);
          header.bits = bits;

          if (fwrite(&header, sizeof(rmd_header), 1, fd) != 1)
               {
               lprintf(L_WARN, "%s: Could not write header", program_name);
               return(FAIL);
               }

          }

     result = voice_modem->record_file(fd, cvd.rec_speed.d.i * bits);
     fclose(fd);
     return(result);
     }






