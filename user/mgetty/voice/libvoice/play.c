/*
 * play.c
 *
 * This command plays the given file.
 *
 * $Id: play.c,v 1.6 1999/12/02 09:51:31 marcs Exp $
 *
 */

#include "../include/voice.h"

int voice_play_file (char *name)
     {
     FILE *fd;
     rmd_header header;
     int compression;
     int speed;
     int bits;

     lprintf(L_MESG, "playing voice file %s", name);

     if (!voice_impersonify()) {
        return(FAIL);
     }

     fd = fopen(name, "r");

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
          };

     if (!cvd.raw_data.d.i)
          {

          if (fread(&header, sizeof(rmd_header), 1, fd) != 1)
               {
               lprintf(L_WARN, "%s: Could not read header", program_name);
               return(FAIL);
               };

          if (strncmp(header.magic, "RMD1", 4) != 0)
               {
               lprintf(L_WARN, "%s: No raw modem data header found",
                program_name);
               return(FAIL);
               }
          else
               lprintf(L_NOISE, "%s: raw modem data header found",
                program_name);

          if (!voice_modem->check_rmd_adequation(header.voice_modem_type))
               {
               lprintf(L_WARN, "%s: Wrong modem type found", program_name);
               return(FAIL);
               }
          else
               lprintf(L_NOISE, "%s: modem type %s found", program_name,
                header.voice_modem_type);

          compression = ntohs(header.compression);
          speed = ntohs(header.speed);
          bits = header.bits;
          lprintf(L_NOISE, "%s: compression method 0x%04x, speed %d, bits %d",
           program_name, compression, speed, bits);
          }
     else
          {
          compression = cvd.rec_compression.d.i;
          speed = cvd.rec_speed.d.i;
          }

     if (voice_modem->set_compression(&compression, &speed, &bits) != OK)
          {
          lprintf(L_WARN, "%s: Illegal compression method", program_name);
          return(FAIL);
          }

     if (voice_modem->start_play_file != NULL)

          if (voice_modem->start_play_file() != OK)
               {
               lprintf(L_WARN, "%s: start_play_file command failed", program_name);
               return(FAIL);
               }

     if (voice_modem->play_file(fd, speed * bits) != OK)
          {
          lprintf(L_WARN, "%s: play_file command failed", program_name);
          return(FAIL);
          }

     if (voice_modem->stop_play_file != NULL)

          if (voice_modem->stop_play_file() != OK)
               {
               lprintf(L_WARN, "%s: stop_play_file command failed", program_name);
               return(FAIL);
               }

     fclose(fd);
     return(OK);
     }
