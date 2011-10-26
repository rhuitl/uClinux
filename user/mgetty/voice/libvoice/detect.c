/*
 * detect.c
 *
 * autodetect the modemtype we are connected to.
 *
 * $Id: detect.c,v 1.44 2005/04/10 21:20:25 gert Exp $
 *
 */

#include "../include/voice.h"

struct modem_type_struct
     {
     const char *at_cmnd;
     const char *at_answr;
     const char *next_cmnd;
     voice_modem_struct *modem_type;
     };

struct pnp_modem_type_struct
     {
     const char *pnpid;
     const char *modelid;
     voice_modem_struct *modem_type;
     const char *verbose;
     };

typedef struct {
   char *s;
   voice_modem_struct *modem_type;
} pnp_partial_matches_t;

static const struct pnp_modem_type_struct pnp_modem_database[] =
     {
     {"SUP", NULL, &Supra, "SupraFAX modem (generic)" },
     {"ZYX", "02FF", &ZyXEL_2864, "ZyXEL 2864I (DSS1)" },
     {"USR", "0088", &US_Robotics, "U.S. Robotics 56k Message" },
     {"ELS", "0687", &Elsa, "ELSA ML 56k DE" },
     {"ELS", "0566", &Elsa, "ELSA ML 56k CH" },
     {"ELS", "0707", &Elsa, "ELSA ML 56k AT" },
     {"ELS", "8318", &Elsa, "ELSA ML 56k pro" },
     {"ELS", "0853", &Elsa, "ELSA/1&1 Speedmaster pro" },
     {"ELS", "8548", &Elsa, "ELSA ML Office" },
     {"ELS", "0754", &Elsa, "ELSA ML 56k basic" },
     {"ELS", "0350", &Elsa, "ELSA ML 56k internet" },
     {"ELS", "0503", &Elsa, "ELSA ML 56k internet" },
     {"ELS", "0667", &Elsa, "ELSA ML 56k internet" },
     {"ELS", "0152", &Elsa, "ELSA ML 56k internet c" },
     {"ELS", "0363", &V253modem, "ELSA ML 56k fun" },
     {"ELS", "0862", &V253modem, "ELSA MicroLink 56k Internet II" },
     {"ELS", "6026", &V253modem, "ELSA ML 56k Fun II a" },
     {"ELS", "6027", &V253modem, "ELSA ML 56k Fun II c" },
     {NULL, NULL, NULL}
     };
     
const char ati[] = "ATI";
const char ati3[] = "ATI3";
const char ati6[] = "ATI6";
const char ati4[] = "ATI4";
const char ati9[] = "ATI9";
const char ati0[] = "ATI0";


static const struct modem_type_struct modem_database[] =
     {
     {ati, "TP560 Data/Fax/Voice 56K Modem",
                                   NULL, &Multitech_5634ZBAV},
     {ati, "1.04",                 NULL,   &Cirrus_Logic},
     {ati, "144",                  NULL,   &UMC},
     {ati, "144 VOICE",            NULL,   &Rockwell},
     {ati, "14400",                NULL,   &Rockwell},
     {ati, "1443",                 NULL,   &Dolphin},
     {ati, "1445",                 NULL,   &US_Robotics},
     {ati, "1496",                 NULL,   &ZyXEL_1496},
     {ati, "1500",                 NULL,   &ZyXEL_Omni56K},
     {ati, "1501",                 NULL,   &ZyXEL_Omni56K},
     {ati, "247",                  NULL,   &Multitech_2834ZDXv},
     {ati, "248",                  NULL,   &Sierra},
     {ati, "249",                  NULL,   &Rockwell},
     {ati, "282",                  NULL,   &Elsa},
     {ati, "288",                  NULL,   &ZyXEL_2864},
     {ati, "2864",                 NULL,   &ZyXEL_2864},
     {ati, "28641",                NULL,   &ZyXEL_2864},
     {ati, "28642",                NULL,   &ZyXEL_2864},
     {ati, "28643",                NULL,   &ZyXEL_2864},
     {ati, "Venus V.90 USB U052099a", NULL, &Lucent},
     {ati, "AEIGPM560LKTF1  Voice V2 V92cap", NULL, &V253modem},
     {ati, "LT V.90 1.0 MT5634ZPX-PCI Internal Data/Fax/Voice Modem Version 4.18f",
                                   NULL,   &Multitech_5634ZPX},
     {ati, "LT V.90 1.0 MT5634ZPX-PCI Internal Data/Fax/Voice Modem Version 8.19i",
                                   NULL,   &V253modem},
     {ati, "LT V.92 1.0 MT5634ZPX-PCI-V92 Internal Data/Fax/Voice Modem Version 1.25p",
                                   NULL,   &V253modem},
     {ati, "LT V.92 1.0 MT5634ZPX-PCI-V92 Internal Data/Fax/Voice Modem Version 1.32c",
                                   NULL,   &V253modem},
     {ati, "LT V.92 1.0 MT5634ZPX-PCI-V92 Internal Data/Fax/Voice Modem Version 1.32h",
                                   NULL,   &V253modem},
     {ati, "LT V.92 1.0 MT5634ZPX-PCI-U Internal Data/Fax/Voice Modem Version 1.32i",
                                   NULL,   &V253modem},
     /* Hans Fugal <hans@fugal.net>, debian bug#254404 */
     {ati, "AEIGPM560LKTF1",       NULL,   &Lucent},
     {ati, "Zoom V.90 PCI I030100gV -H Z207",NULL, &Lucent},
     /* next two come from Andreas Barth, debian patches */
     {ati, "Zoom V.90 PCI I052099gV -G Z207",NULL, &Lucent},
     {ati, "Zoom V.90 Serial s052099g -I Z207", NULL, &Lucent},

     {ati, "28800",                ati6, NULL},
     {ati, "2886",                 NULL,   &US_Robotics},
     {ati, "336",                  NULL,   &Rockwell},
     {ati, "3361",                 NULL,   &US_Robotics},
     {ati, "3362",                 NULL,   &US_Robotics},
     {ati, "3366",                 NULL,   &US_Robotics},

     /* 2000-12-16 schaefer@alphanet.ch
      * NOTES
      *    - This is the same as returned by some Neuhaus variant.
      *      However we will do ATI9 detection first, which should
      *      detect it. If you have a Neuhaus modem which now breaks,
      *      please report the problem to me, including full vgetty
      *      log at log level 6 and mid output.
      */
     {ati, "33600",                NULL,   &Rockwell},

     {ati, "3X WYSIWYF 628DBX",    NULL,   &Rockwell},
     {ati, "56000",                NULL,   &Rockwell},
     {ati, "5601",                 NULL,   &US_Robotics},
     /* Andreas Barth, debian patch */
     {ati, "57600",                NULL,   &Multitech_2834ZDXv},
     {ati, "961",                  NULL,   &Rockwell},
     {ati, "Digi RAS modem 56000", NULL,   &Digi_RAS},
     {ati, "Linux ISDN",           NULL,   &ISDN4Linux},
     {ati, "MT5600ZDXV",           NULL,   &Multitech_5600ZDXv},
     {ati, "LT 33.6 MT3334ZDXV Serial Data/Fax/Voice Modem Version 1.18j",
				   NULL, &Multitech_5634ZPX},
     {ati, "LT V.90 1.0 MT5634ZBAV Serial Data/Fax/Voice Modem Version 4.09a",
                                   NULL,   &Multitech_5634ZBAV},
     /* Andreas Barth, debian patch */
     {ati, "LT V.92 1.0 MT5634ZBAV-V92 Serial Data/Fax/Voice Modem Version 1.25p",
				   NULL,   &Multitech_5634ZBAV},
     {ati4, "33600bps Voice Modem For Italy",
                                   NULL, &Rockwell},
     {ati6, "RCV336DPFSP Rev 44BC",
                                   NULL, &Rockwell},
     {ati, "ERROR", ati0, NULL}, /* it also shows up as North America,
                                  * then OK in ATI9. Please also read
                                  * libvoice/README.lucent.
                                  */

     {ati6, "OK",      NULL, &Dr_Neuhaus},
     {ati6, "RCV288DPi Rev 05BA",  NULL,   &Rockwell},
     {ati6, "RCV288*", NULL, &Rockwell},

#if 0 /* Please read libvoice/README.lucent */
     {ati0, "ZOOM*", NULL, &Lucent},
#endif

     {ati4, "WS-3314JS3", NULL, &Rockwell},
     {ati, "LT V.90 1.0 MT5634ZPX Internal Data/Fax/Voice Modem Version 4.16h",
                                   NULL,   &Multitech_5634ZPX_ISA},
     {ati, "LT V.90 1.0 MT5634ZPX-PCI Internal Data/Fax/Voice Modem Version 4.18f",
                                   NULL, &Multitech_5634ZPX},                                                        
     {NULL, NULL, NULL, NULL}
     };

static const pnp_partial_matches_t pnp_partial_matches[]
   = { { "SMARTY ", &Dr_Neuhaus },
       { NULL, NULL }
     };

int voice_detect_modemtype(void)
     {
     char buffer[VOICE_BUF_LEN];
     char *cmnd;

     lprintf(L_MESG, "detecting voice modem type");

     /*
      * Do we have to probe for a voice modem or was it preset?
      */

     if (voice_modem != &no_modem)
          {
          lprintf(L_NOISE, "voice modem type was set directly");
          return(OK);
          }
     else
          {
          int i;
          char *s;

          /*
           * First of all, let's see if a modem is connected and answering
           * and also initialize the modem echo command correctly.
           */
	  if (cvd.command_delay.d.i != 0)
		 delay(cvd.command_delay.d.i);

          if (cvd.enable_command_echo.d.i)
               {

               if (voice_write("ATE1") != OK)
                    {
                    lprintf(L_WARN, "modem detection failed");
                    exit(FAIL);
                    }

               if ((voice_command("", "OK|ATE1") & VMA_USER) == VMA_USER)
                    voice_flush(1);
               else
                    {
                    lprintf(L_WARN, "modem detection failed");
                    exit(FAIL);
                    }

               }
          else
               {

               if (voice_write("ATE0") != OK)
                    {
                    lprintf(L_WARN, "modem detection failed");
                    exit(FAIL);
                    }

               voice_flush(3);
               }

          /*
           * Let's detect the voice modem type.
           */

	  /* Let's try plug and play (Rob Ryan <rr2b@pacbell.net>) */

	  /* some typical pnp return strings look like this:
	   * (1.0USR9100\\Modem\PNPC107\U.S. Robotics 56K Message)FF
	   * (^A#ELS8318\00717242\MODEM\\MicroLink 56k00)
	   * (^A$ZYX56FF\00000000\MODEM\\  Omni56K Plus   1.05    CB)
	   * (1.00HAY0001\\MODEM\\OPT288 V34+FAX+VOICE, 5310AM DB)
	   */

	  memset( buffer, '\0', sizeof(buffer) );
	  cmnd=(char *)ati9;
	  if (voice_command(cmnd, "") != OK)
               {
               lprintf(L_WARN, "modem detection failed");
               exit(FAIL);
               }
	  if (voice_read(buffer) != OK)
                    {
                    lprintf(L_WARN, "modem detection failed");
                    exit(FAIL);
	  }

          /* force V253 comandset */
          if(TRUE==cvd.forceV253.d.i)
          {
             lprintf(L_NOISE, "V253 forced");
             voice_modem = &V253modem;
          }
          /* force V253 comandset wothout AT+IFC */
          if(TRUE==cvd.forceV253subset.d.i)
          {
             lprintf(L_NOISE, "V253ugly forced");
             voice_modem = &V253ugly;
          }


          /* Some modems have no meaningful output except in ATI9, but
           * they do not respect the standard. For them we will use
           * another table of partial matches. We do not want to slow
           * even more by adding ATI9s to the global table.
           */

          i = 0;
          while ((voice_modem == &no_modem) && (pnp_partial_matches[i].s)) {
             if (!strncmp(pnp_partial_matches[i].s,
                          buffer,
                          strlen(pnp_partial_matches[i].s))) {
                voice_modem = pnp_partial_matches[i].modem_type;
             }
             i++;
          }

          if (voice_modem != &no_modem) {
             lprintf(L_MESG, "%s detected", voice_modem->name);
             lprintf(L_NOISE,
                     "voice modem type was set by ATI9 partial match");
             return(OK);
          }

          /* Else, standard ATI9 */

	  s = strchr(buffer, '(');
	  if ( s && s[1] != '\0' )
	  {
	      if ( s[1] == '\1' )	/* binary format "(^Ax" */
		  s+=3;
	      else			/* ASCII format: "(1.0[0]" */
	          do { s++; } while( isdigit(*s) || *s == '.' );

	      lprintf(L_NOISE, "PNP String: '%s'", s);
	      i = 0;
	      while (voice_modem == &no_modem &&
		     pnp_modem_database[i].pnpid)
	      {
		   lprintf(L_JUNK, "checking pnpid %s / modelid %s",
			       pnp_modem_database[i].pnpid,
			       pnp_modem_database[i].modelid ? 
				   pnp_modem_database[i].modelid : "<none>");

		   if (strncmp(pnp_modem_database[i].pnpid, s, 3) == 0)
		   {
		       if (pnp_modem_database[i].modelid == NULL ||
			   strncmp(pnp_modem_database[i].modelid, s+3, 4) == 0)
		       {
			   lprintf( L_MESG, "PNP: found modem: %s",
					pnp_modem_database[i].verbose );
			   voice_modem = pnp_modem_database[i].modem_type;
			   break;
		       }
		   }
		   i++;
	       }
	       /* eat the OK... */
	       voice_read(buffer);
	  }

	  voice_flush(3);

	  if (voice_modem != &no_modem)
	  	{
          	lprintf(L_NOISE, "voice modem type was set by pnp id");
         	 return(OK);
         	}

          /* Detection using identification strings. Seems that it
           * is required for some very specific modem types.
           * -- (Rojhalat Ibrahim, roschi@ribrahim.de)
           * IMPLEMENTATION NOTES
           *    - We used to have a complicated ATI3 scheme with a table
           *      which was wrong (every added entry to the table would have
           *      consumed more lines of the modem output when a second
           *      line was required; would cause timeouts on modems returning
           *      less than 3 lines). We have simplified that.
           * BUGS
           *    - This implementation, although less likely to cause problems,
           *      will make detection longer (timeout) on modems returning
           *      something different than OK or ERROR, when they return
           *      less than 2 lines (case significative).
           */
	  
	  cmnd = (char *) ati3;
	  if (voice_command(cmnd, "") != OK) {
             lprintf(L_WARN, "modem detection failed");
             exit(FAIL);
          }

          if (voice_read(buffer) != OK) {
             lprintf(L_WARN, "modem detection failed");
             exit(FAIL);
          }

          if ((strstr(buffer, "OK") == NULL)
              && (strstr(buffer, "ERROR") == NULL)) {
             /* The non-empty string wasn't OK/ERROR, so let's ignore it and
              * go to the next line (that we assume exists -- else will
              * timeout but recover).
              */
             if (voice_read(buffer) == OK) {
                if (strstr(buffer, "SupraExpress 56e PRO")) {
                   voice_modem = &Supra56ePRO;
                }
             }
          }
          /* else the modem already returned OK/ERROR, so no need to create
           * a timeout.
           */

          /* Flush remaining data. We can't read, might not be there,
           * and that would timeout, too.
           */
          voice_flush(1); /* wait until no chars and 100 ms have passed */

          if (voice_modem != &no_modem) {
             lprintf(L_MESG, "%s detected", voice_modem->name);
             lprintf(L_NOISE, "voice modem type was set by using \
                              identification strings");
             return(OK);
          }

          cmnd = (char *) ati;
          if (voice_command(cmnd, "") != OK) {
             lprintf(L_WARN, "modem detection failed");
             exit(FAIL);
          }

          do
               {
               if (voice_read(buffer) != OK)
                    {
                    lprintf(L_WARN, "modem detection failed");
                    exit(FAIL);
                    }

               /*
                * Strip off leading and trailing whitespaces and tabs
                */

               s = buffer + strlen(buffer) - 1;

               while ((s >= buffer) && isspace(*s) )
                    *s-- = '\0';

               s = buffer;
	       while( isspace(*s) ) s++;

               for (i = 0; ((modem_database[i].at_cmnd != NULL) &&
                (voice_modem == &no_modem)); i++)
                    {

                    if ((strcmp(modem_database[i].at_cmnd, cmnd) == 0) &&
                     (strcmp(modem_database[i].at_answr, s) == 0))
                         {

                         if (modem_database[i].next_cmnd != NULL)
                              {
                              voice_flush(1);
                              cmnd = (char *) modem_database[i].next_cmnd;

                              if (voice_command(cmnd, "") != OK)
                                   {
                                   lprintf(L_WARN, "modem detection failed");
                                   exit(FAIL);
                                   }

                              sprintf(buffer, "OK");
                              break;
                              }
                         else
                              voice_modem = modem_database[i].modem_type;

                         }

                    }

               }
          while ((voice_modem == &no_modem) &&
           (voice_analyze(buffer, "", TRUE) != VMA_FAIL));

          voice_flush(1);
          }

     if (voice_modem->init == NULL)
          {
          lprintf(L_WARN, "%s detected, but driver is not available",
           voice_modem->name);
          voice_modem = &no_modem;
          exit(FAIL);
          };

     if (voice_modem == &no_modem) {
        /* Supports the modem V253 commands? */
        voice_command("AT+FCLASS=8", "OK");
        if (voice_command("AT+VSM=1,8000", "OK")== VMA_USER) {
           voice_modem=&V253modem;
           /* if the modem answers with ok then it supports ITU V253 commands
            * and compression mode 8 bit PCM = nocompression.
            */
        }
        voice_command("AT+FCLASS=0", "OK"); /* back to normal */
     }

     if (voice_modem != &no_modem)
          {
          lprintf(L_MESG, "%s detected", voice_modem->name);
          return(OK);
          };

     voice_flush(1);
     voice_modem = &no_modem;
     lprintf(L_WARN, "no voice modem detected");
     exit(FAIL);
     }
