/*
 * rings.c
 *
 * The number of rings to answer the phone is determined with the
 * following procedure:
 *
 * - First the variable cvd.rings is checked. If it starts with
 *   a "/", it is assumed to be the name of a file that contains
 *   the number of rings. Otherwise it is assumed that the variable
 *   cvd.rings contains the number of rings as a string constant.
 *   If cvd.rings is an empty string the parameter rings_wanted is
 *   used.
 *
 * - Second, if the message flag file exists, the number of rings
 *   is decremented by the number of toll saver rings.
 *
 * - Third, if the number of rings is less than 2 it is set to 2.
 *
 * $Id: rings.c,v 1.4 1998/09/09 21:08:09 gert Exp $
 *
 */

#include "../include/voice.h"

void vgetty_rings(int *rings_wanted)
     {

     if (strlen(cvd.rings.d.p) != 0)

          if (strncmp((char*) cvd.rings.d.p, "/", 1) == 0)
               {
               char ring_file_name[VOICE_BUF_LEN];
               FILE *ring_file;

               sprintf(ring_file_name, "%s.%s", (char*) cvd.rings.d.p, DevID);
               ring_file = fopen(ring_file_name, "r");

               if (ring_file != NULL)
                    {
                    fscanf(ring_file, "%d", rings_wanted);
                    fclose(ring_file);
                    lprintf(L_JUNK,
                     "%s: read number of rings (%d) from file %s",
                     program_name, *rings_wanted, ring_file_name);
                    }
               else
                    {
                    sprintf(ring_file_name, "%s", (char*) cvd.rings.d.p);
                    ring_file = fopen(ring_file_name, "r");

                    if (ring_file != NULL)
                         {
                         fscanf(ring_file, "%d", rings_wanted);
                         fclose(ring_file);
                         lprintf(L_JUNK,
                          "%s: read number of rings (%d) from file %s",
                          program_name, *rings_wanted, ring_file_name);
                         };

                    };

               }
          else
               {
               *rings_wanted = atoi(cvd.rings.d.p);
               lprintf(L_JUNK, "%s: number of rings (%d) was set directly",
                program_name, *rings_wanted);
               };

     if (strlen(cvd.message_flag_file.d.p) != 0)
          {
          char flag_file_name[VOICE_BUF_LEN];
          FILE *flag_file;

          make_path(flag_file_name, cvd.voice_dir.d.p,
           cvd.message_flag_file.d.p);
          flag_file = fopen(flag_file_name, "r");

          if (flag_file != NULL)
               {
               *rings_wanted -= cvd.toll_saver_rings.d.i;
               fclose(flag_file);
               lprintf(L_JUNK, "%s: decremented number of rings (%d) by %d",
                program_name, *rings_wanted, cvd.toll_saver_rings.d.i);
               };

          };

     if (*rings_wanted < 2)
          {
          lprintf(L_WARN,
           "%s: number of rings (%d) too small, reseting to 2",
           program_name, *rings_wanted);
          *rings_wanted = 2;
          };

     }
