/*
 * V253modem.c
 *
 * This file contains the commands for V253 complaient modems
 *
  For this File I (Juergen.Kosel@gmx.de) used the ELSA.c as template and replaced all pre-V.253 commands
  with the commands defined in the ITU V.253 specification.
  Newer ELSA-modems follow this specification.
  So some ELSA-modems like the "ML 56k pro" could be used with the ELSA.c (and the old commands)
  AND with this V253modem (But for these modems you should set sample rate in your voice.conf to 7200
  otherwise fax/data-callingtonedetection will fail).
  The "ML 56k FUN" and future ELSA-modems work only with this V253modem.

  Because there are only V.253 commands here, this IS a GENERIC-DRIVER!

  Hint: Recorded voice files are in .ub format (refer to the sox manpage about this) except the header.
        So you can use this files with sox.
 *
 * $Id: V253modem.c,v 1.9 2005/03/13 17:27:46 gert Exp $
 *
 */


#include "../include/V253modem.h"
#include <string.h>

// The compression id numbers used by vgetty in voice.conf, pvftools etc
// will be mapped to the id numbers used by the modem. 
// This is done by an array, which is initialized with the defined 
// values from V. 253.

int Kompressiontable[256];

     int V253modem_init (void)
     {
     char buffer[VOICE_BUF_LEN];

     reset_watchdog();
     voice_modem_state = INITIALIZING;
     lprintf(L_MESG, "initializing V253 voice modem");

     V253_init_compression_table();

     /* enabling voicemode */
     sprintf(buffer, "AT+FCLASS=8");
     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "could not set +FCLASS=8");

     V253_querry_compressions();


     /* set silence-sensitvity-level and silence length */
/*
first value of the +vsd command means:
 0: silence detection of/ or silencecompression with the +vsm command
128: manufacturer default
<128: less aggressive [more sensitive, lower noise levels considered to
be silence].
>128: more aggressive [less sensitive, higher noise levels considered to be silence].

 */
#if 1 /* enable this when cvd.rec_silence_threshold.d.i  is set as an absolut value
(with default 128) instead of percent */
     sprintf(buffer, "AT+VSD=%d,%d", cvd.rec_silence_threshold.d.i , cvd.rec_silence_len.d.i);
#else /* until this, the sensitvity is hardcoded with manufaturer default! */
    sprintf(buffer, "AT+VSD=%d,%d", 128 , cvd.rec_silence_len.d.i);
#endif
     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set silence threshold VSD");

/* set transmit-gain manufacturer default is 128 so the vgetty default of 127 isn't far away */
     if (cvd.transmit_gain.d.i == -1)
          cvd.transmit_gain.d.i = 50;

     sprintf(buffer, "AT+VGT=%d", cvd.transmit_gain.d.i * 255 / 100 );

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set speaker volume");

/* set recieve-gain manufacturer default is 128 so the vgetty default of 127 isn't far away */

     if (cvd.receive_gain.d.i == -1)
          cvd.receive_gain.d.i = 50;

     sprintf(buffer, "AT+VGR=%d", cvd.receive_gain.d.i * 255 / 100 );

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "can't set record volume");

     /* Delay after ringback or before any ringback
      * before modem assumes phone has been answered.
      */
     sprintf(buffer,
             "AT+VRA=%d;+VRN=%d",
             cvd.ringback_goes_away.d.i,     /* 1/10 seconds */
             cvd.ringback_never_came.d.i/10); /* seconds */

     if (voice_command(buffer, "OK") != VMA_USER_1)
          lprintf(L_WARN, "setting ringback delay didn't work");


/* set hardflow */
     if ((cvd.do_hard_flow.d.i) && (voice_command("AT+IFC=2,2", "OK") ==
      VMA_USER_1) )
          {
          TIO tio;
          tio_get(voice_fd, &tio);
          tio_set_flow_control(voice_fd, &tio, FLOW_HARD);
          tio_set(voice_fd, &tio);
          }
     else
          lprintf(L_WARN, "can't turn on hardware flow control");


     /* enable callerid (if supported) and setformat */
     voice_command("AT+VCID=1", "OK");
     /* mgetty supports formated callerid output */

     /* set hangupcontroll */
     voice_command("AT+VNH=0", "OK");
     /* this means modem will hangup after is has switched to data/faxmode as normal
        with +VNH=1 the modem doesn't make an automatic disconnect if connect fails in
	data/faxmode so mgetty could switch back to voicemode */

     /* voice-inactivity-timer: This means that the modem should go back
        to fclass 0 and enable autobauding (which wasn't disabled by vgetty with
        AT+IPR or AT+VPR). Since it's in the TODO list that vgetty stays in voice
        the voice-inactivity-timer is disabled.
     */
     voice_command("AT+VIT=0", "OK");

     /* enable distinctivering in pulse/pauseformat
       this will look like this:
DRON=20
RING
DROF=40
DRON=20
RING */
     sprintf(buffer, "AT+VDR=1,%d", cvd.ring_report_delay.d.i);
     voice_command(buffer, "OK");

     voice_modem_state = IDLE;
     return(OK);
     }
/*
Table 17/V.253 - Compression method identifier numerics and strings
# 	String ID 	Description
------------------------------------------------
0 	SIGNED PCM 	Linear PCM sampling using two complement signed numbers
1 	UNSIGNED PCM 	Linear PCM sampling using unsigned numbers
2 	RESERVED
3 	G.729.A 	G.729 Annex A - Recommendation V.70 DSVD default coder.
4 	G.711U 		u-Law companded PCM
5 	G.711A 		A-Law companded PCM
6 	G.723 		H.324 Low bit rate videotelephone default speech coder
7 	G.726 		ITU-T 40, 32, 24, 16 kit/s ADPCM.
8 	G.728 		H.320 Low bit rate videotelephone speech coder
9-127 			Reserved for future standardization
128-255 		Manufacturer specific
*/

void V253_init_compression_table() {
  // The compression id numbers used by vgetty in voice.conf, pvftools etc
  // will be mapped to the id numbers used by the modem. 
  // This is done by an array, which is initialized with the defined 
  // values from V. 253.
  
  memset( Kompressiontable, 1, sizeof(Kompressiontable) );
  Kompressiontable[0]=cvd.compression_8bit_linear_unsigned.d.i; // 8 Bit PCM/8 bit linear
  Kompressiontable[1]=cvd.compression_8bit_linear_unsigned.d.i; // 8 Bit PCM/8 bit linear
  Kompressiontable[2]=cvd.compression_2bit_adpcm.d.i; /*  2bit ADPCM for some ELSA-modems */
  Kompressiontable[4]=cvd.compression_4bit_adpcm.d.i; /* 4bit ADPCM for some ELSA-modems */
  Kompressiontable[5]=cvd.compression_4bit_ima_adpcm.d.i; /* ->4bit IMA ADPCM for the ML 56k Fun, Internet II and Lucent*/
  Kompressiontable[6]=cvd.compression_8bit_ulaw.d.i; /* 8bit uLAW for the ML 56k Fun and Lucent*/
  Kompressiontable[7]=cvd.compression_8bit_ulaw.d.i; /* 8bit aLAW for the ML 56k Fun and Lucent*/
  Kompressiontable[8]=cvd.compression_8bit_linear_unsigned.d.i; // 8 Bit PCM/8 bit linear
  Kompressiontable[9]=cvd.compression_8bit_linear_signed.d.i; // 8 Bit signed PCM
  Kompressiontable[10]=cvd.compression_8bit_ulaw.d.i; /* ITU defined uLaw */
  Kompressiontable[11]=cvd.compression_8bit_alaw.d.i; /* ITU defined aLaw */
  Kompressiontable[12]=cvd.compression_16bit_linear_signed.d.i; /* ITU defined signed PCM 16-bit Intel Order */
};

#ifdef __USE_GNU
// the function strcasestr is a GNU extension to libc
// so this function is only availble with glibc with the macro __USE_GNU defined
#define mSTRSTR strcasestr
#else
#define mSTRSTR strstr
#endif

void V253_querry_compressions() {
     char buffer[VOICE_BUF_LEN];
     memset( buffer, '\0', sizeof(buffer) );

     if (!cvd.enable_compression_mapping_querry.d.i) {
       lprintf(L_NOISE, "voice compression querry disabled");
       return;
     }
     if (voice_command("AT+VSM=?", "") != OK)
       {
	 lprintf(L_WARN, "voice compression querry failed");
	 return;
       }
     do {
       if (voice_read(buffer) != OK)
	 {
	   lprintf(L_WARN, "voice compression querry failed");
	   break;
	  }
#ifndef NO_STRSTR
       // now check, if the line contains a supported compression method
       if(mSTRSTR(buffer,"\"SIGNED PCM\",8")) {
	 // The leading number in buffer contains the modem compression id
	 Kompressiontable[9]= strtol(buffer, NULL, 10);
	 lprintf(L_NOISE, "Mapped signed PCM, 9 -> %d",Kompressiontable[9]);
       } else if(mSTRSTR(buffer,"\"SIGNED PCM\",16")) {
	 // The leading number in buffer contains the modem compression id
	 Kompressiontable[12]= strtol(buffer, NULL, 10);
	 lprintf(L_NOISE, "Mapped signed PCM, 12 -> %d",Kompressiontable[12]);
       } else if(mSTRSTR(buffer,"UNSIGNED PCM\",8")) {
	 // The leading number in buffer contains the modem compression id
	 Kompressiontable[0]= 
	   Kompressiontable[1]= 
	   Kompressiontable[8]= strtol(buffer, NULL, 10);
	 lprintf(L_NOISE, "Mapped default (8 bit linear), 0 -> %d",Kompressiontable[0]);
	 lprintf(L_NOISE, "Mapped unsigned PCM, 1 -> %d",Kompressiontable[1]);
	 lprintf(L_NOISE, "Mapped 8 bit linear, 8 -> %d",Kompressiontable[8]);
       } else if(mSTRSTR(buffer,"8-BIT LINEAR")) {
	 // The leading number in buffer contains the modem compression id
	 Kompressiontable[0]= 
	   Kompressiontable[1]= 
	   Kompressiontable[8]= strtol(buffer, NULL, 10);
	 lprintf(L_NOISE, "Mapped default (8 bit linear), 0 -> %d",Kompressiontable[0]);
	 lprintf(L_NOISE, "Mapped unsigned PCM, 1 -> %d",Kompressiontable[1]);
	 lprintf(L_NOISE, "Mapped 8 bit linear, 8 -> %d",Kompressiontable[8]);
       } else if(mSTRSTR(buffer,"IMA ADPCM\",4")) {
	 // The leading number in buffer contains the modem compression id
	 Kompressiontable[5]= strtol(buffer, NULL, 10);
	 lprintf(L_NOISE, "Mapped 4 bit IMA ADPCM, 5 -> %d",Kompressiontable[5]);
       } else if(mSTRSTR(buffer,"4-BIT ADPCM")) {
	 // The leading number in buffer contains the modem compression id
	 Kompressiontable[5]= strtol(buffer, NULL, 10);
	 lprintf(L_NOISE, "Mapped 4 bit IMA ADPCM, 5 -> %d",Kompressiontable[5]);
       } else if(mSTRSTR(buffer,"ULAW")) {
	 // The leading number in buffer contains the modem compression id
	 Kompressiontable[10]= strtol(buffer, NULL, 10);
	 lprintf(L_NOISE, "Mapped ulaw, 10 -> %d",Kompressiontable[10]);
       } else if(mSTRSTR(buffer,"ALAW")) {
	 // The leading number in buffer contains the modem compression id
	 Kompressiontable[11]= strtol(buffer, NULL, 10);
	 lprintf(L_NOISE, "Mapped alaw, 11 -> %d",Kompressiontable[11]);
       } else if(mSTRSTR(buffer,"16-BIT LINEAR")) {
	 // The leading number in buffer contains the modem compression id
	 Kompressiontable[13]= strtol(buffer, NULL, 10);
	 lprintf(L_NOISE, "Mapped 16 bit linear, 13 -> %d",Kompressiontable[13]);
       } else 
#endif
	 {
	   lprintf(L_NOISE, "Unknown: %s",buffer);
	 }
       
     } while (strncmp("OK",buffer,2)); //search for the terminating "OK"
}

     int V253modem_set_compression (int *compression, int *speed, int *bits)
     {
     char buffer[VOICE_BUF_LEN];
     int Kompressionmethod = 1; /* id for the compression, used by the modem */
     int sil_sense = 0; 	/* silence compression sensitivity */
     int sil_clip = 0;  	/* silence clip                    */
     reset_watchdog();

     if(*compression < sizeof(Kompressiontable)/sizeof(int) ) {
       Kompressionmethod = Kompressiontable[*compression];
     }

     switch (*compression)
     {
       case 0:
       case 1:
       case 8:
       {
          *bits=8;
          break;
       }
     /*  default is 8 Bit PCM/8 bit linear which should be supported by most modems
         and be mapped to the V.253 defined AT+VSM=1 .
         With 8000 samples/sec it's also the default for soundcards.

         On the otherside the compressionmodes from the Elsa.c
         are mapped to the manufacturer specific +VSM values (above 127)
         so voice files recorded with the &Elsa driver can be played with
         this &V253modem driver (and the same modem of course) */
       case 2:       /*  2bit ADPCM for some ELSA-modems */
       {
         *bits = 2;
         break;
        }
       case 4:           /* 4bit ADPCM for some ELSA-modems */
       {
         *bits=4;
         break;
       }
       case 5:
       {
         *bits = 4;      /* 129 ->4bit ADPCM for the ML 56k Fun*/
         break;
       }
       case 6:
       {
         *bits = 8;      /* 8bit uLAW for the ML 56k Fun*/
         break;
       }
       case 7:
       {
         *bits = 8;      /* 8bit aLAW for the ML 56k Fun*/
         break;
       }
       case 9:        /* ITU defined signed PCM */
       {
          *bits=8;
          break;
       }
       case 10:        /* ITU defined uLaw */
       {
          *bits=8;
          break;
       }
       case 11:        /* ITU defined aLaw */
       {
          *bits=8;
          break;
       }
       case 12:        /* ITU defined signed PCM 16-bit Intel Order */
       {
	 			/* Chipset Agere/Lucent Venus v.92 found on 
	  			 * ActionTec v.92 Call Waiting PCI modem    */
	 *bits=16;		/* 16 bit			   	    */
	 break;
       }


       default:
       {
          lprintf(L_WARN, "compression method %d is not supported -> edit voice.conf",*compression);
        /*  return(FAIL);  */
          Kompressionmethod = 1;
          *bits=8;
       }
     }
     if (*speed == 0)
     /* default value for the PCM voiceformat is 8000 */
          *speed = 8000;

     sprintf(buffer, "AT+VSM=%d,%d",Kompressionmethod, *speed);
     /* only no compression is common! */
     /* ATTENTION the AT+VSM=? output is diffrent from the AT+VSM=<Parameter> */
     if (voice_command(buffer, "OK")!= VMA_USER_1)
     sprintf(buffer, "AT+VSM=%d,%d,%d,%d",Kompressionmethod, *speed, sil_sense, sil_clip); 
     if (voice_command(buffer, "OK")!= VMA_USER_1)
      {
         lprintf(L_WARN, "can't set compression and speed");
         /*return(FAIL);*/   /* when we don't say FAIL here,
           the modem can still record the message with its
           last/default compression-setting */
         voice_command("AT+VSM?", "OK");
         /* write the actual setting to the logfile */
      }

     lprintf(L_NOISE, "Just for info: port_speed should be greater than %d bps",(*bits)*(*speed)*10/8);
     /* 8 Databits + 1 Stopbit +1 startbit  */
     return(OK) ;
     }

     int V253modem_set_device (int device)
     {
       int Result;
       reset_watchdog();
       lprintf(L_JUNK, "%s: %s: (%d)", voice_modem_name, 
	       voice_device_mode_name(device), device);

     switch (device)
          {
          case NO_DEVICE:
	    Result = voice_command("AT+VLS=0", "OK");
	    break;
          case DIALUP_LINE:
	    Result = voice_command("AT+VLS=1", "OK");
	    break;
          case EXTERNAL_MICROPHONE:
	    Result = voice_command("AT+VLS=11", "OK");
	    break;
          case INTERNAL_MICROPHONE:
	    Result = voice_command("AT+VLS=6", "OK");
	    break;
          case INTERNAL_SPEAKER:
	    Result = voice_command("AT+VLS=4", "OK");
	    break;
          case EXTERNAL_SPEAKER:
	    Result = voice_command("AT+VLS=8", "OK");
	    break;
          case LOCAL_HANDSET :
	    Result = voice_command("AT+VLS=2", "OK");
	    break;
          case DIALUP_WITH_EXT_SPEAKER :
	    Result = voice_command("AT+VLS=9", "OK");
	    break;
          case DIALUP_WITH_INT_SPEAKER :
	    Result = voice_command("AT+VLS=5", "OK");
	    break;
          case DIALUP_WITH_LOCAL_HANDSET :
	    Result = voice_command("AT+VLS=3", "OK");
	    break;
          case DIALUP_WITH_EXTERNAL_MIC_AND_SPEAKER:
	    Result = voice_command("AT+VLS=13", "OK");
	    break;
          case DIALUP_WITH_INTERNAL_MIC_AND_SPEAKER:
	    Result = voice_command("AT+VLS=7", "OK");
	    break;
	  default:
	    lprintf(L_WARN, "%s: Unknown device (%d)", 
		    voice_modem_name, device);
	    return(FAIL);
          }

     if (Result != VMA_USER_1)   
       {
	 lprintf(L_WARN, "can't set %s (modem hardware can't do that)",
		 voice_device_mode_name(device));
	 return(VMA_DEVICE_NOT_AVAIL);
       }
     return(OK);
     }

/* Only verifies the RMD name */
int V253_check_rmd_adequation(char *rmd_name) 
{
   return !strncmp(rmd_name,
                   V253modem_RMD_NAME,
                   sizeof(V253modem_RMD_NAME))
          || !strncmp(rmd_name,
                      ELSA_RMD_NAME,
                      sizeof(ELSA_RMD_NAME));
}


// juergen.kosel@gmx.de : voice-duplex-patch start
int V253modem_handle_duplex_voice(FILE *tomodem, FILE *frommodem, int bps)
     {
     TIO tio;
     int input_byte;
     int got_DLE_ETX = FALSE;
     int was_DLE = FALSE;
     int count = 0;
     time_t watchdog_reset;

     watchdog_reset = time(NULL) + (cvd.watchdog_timeout.d.i / 2);

     reset_watchdog();
     voice_modem_state = DUPLEXMODE;
     voice_check_events();
     tio_get(voice_fd, &tio);

     if (cvd.do_hard_flow.d.i)
          {

          if ((voice_command(voice_modem->hardflow_cmnd,
           voice_modem->hardflow_answr) & VMA_USER) != VMA_USER)
               return(FAIL);

          tio_set_flow_control(voice_fd, &tio, FLOW_HARD | FLOW_XON_IN);
          }
     else
          {

          if ((voice_command(voice_modem->softflow_cmnd,
           voice_modem->softflow_answr) & VMA_USER) != VMA_USER)
               return(FAIL);

          tio_set_flow_control(voice_fd, &tio, FLOW_XON_IN);
          };

     tio_set(voice_fd, &tio);

     if ((voice_command(voice_modem->start_duplex_voice_cmnd,
      voice_modem->start_duplex_voice_answr) & VMA_USER) != VMA_USER)
          return(FAIL);

     while ((!got_DLE_ETX)&&(DUPLEXMODE == voice_modem_state ))
          {
          input_byte = voice_read_byte();

          if ((input_byte < 0) && (input_byte != -EINTR) && (input_byte != -EAGAIN))
               return(FAIL);

          if (input_byte >= 0)
               {

               if (was_DLE)
                    {
                    was_DLE = FALSE;

                    switch (input_byte)
                         {
                         case DLE:
                              fputc(DLE, frommodem);
                              break;
                         case ETX:
                              got_DLE_ETX = TRUE;
                              lprintf(L_JUNK, "%s: <VOICE DATA %d bytes>",
                               voice_modem_name, count);
                              lprintf(L_JUNK, "%s: <DLE> <ETX>",
                               voice_modem_name);
                              voice_modem->handle_dle(input_byte);
                              break;
                         case SUB:
                              fputc(DLE, frommodem);
                              fputc(DLE, frommodem);
                              break;
                         default:
                              lprintf(L_JUNK, "%s: <DLE> <%c>",
                               voice_modem_name, input_byte);
                              voice_modem->handle_dle(input_byte);
                         }

                    }
               else
                    {

                    if (input_byte == DLE)
                         was_DLE = TRUE;
                    else
                         fputc(input_byte, frommodem);

                    }

	       fflush(frommodem); /* send the voice data with no 
				   * delay to the soundcard/file
				   */

               count++;

               if (watchdog_reset < time(NULL))
                    {
                    lprintf(L_JUNK, "%s: <VOICE DATA %d bytes>", voice_modem_name,
                     count);
                    reset_watchdog();
                    watchdog_reset = time(NULL) + (cvd.watchdog_timeout.d.i / 2);
                    count = 0;
                    }

               }

          voice_check_events();

          if (input_byte == -EAGAIN)
	    {
	      delay(cvd.poll_interval.d.i);
	    }
	  else
	    {
	      int output_byte = fgetc(tomodem);
	      if (EOF == output_byte)
		{
		  /* that indicates the end of one stream */
		  got_DLE_ETX = TRUE;
		  break;
		}
	      if (0 < output_byte)
		{
		  if (OK != voice_write_char(output_byte) )
		    return(FAIL);
		  /* double DLEs */
		  if (DLE == output_byte)
		    {
		      if (OK != voice_write_char(output_byte) )
			return(FAIL);
		    }
		}
	    }
          }

     tio_set(voice_fd, &voice_tio);

     /* if duplexmode isn't allready left -> do leave now (only once) */
     if (DUPLEXMODE == voice_modem_state )
       {
	 if ( voice_modem->stop_duplex_voice () !=
	      VMA_USER)
	   return(FAIL);
       }
     voice_check_events();
     return(OK);
     }

int V253modem_stop_duplex (void)
{
  voice_modem_state = IDLE;
  return voice_command( voice_modem->stop_duplex_voice_cmnd , 
			voice_modem->stop_duplex_voice_answr );
}
// juergen.kosel@gmx.de : voice-duplex-patch end


const char V253modem_pick_phone_cmnd[] = "AT+FCLASS=8";  /* because this will be followed by a
                                                             V253modem_set_device (DIALUP_LINE)
                                                             -> this picks up the line!*/
const char V253modem_pick_phone_answr[] = "VCON|OK";


const char V253modem_hardflow_cmnd[] = "AT+IFC=2,2";
const char V253modem_softflow_cmnd[] = "AT+IFC=1,1";

const char V253modem_beep_cmnd[] = "AT+VTS=[%d,,%d]";
// juergen.kosel@gmx.de : voice-duplex-patch start
const char V253modem_start_duplex_voice_cmnd [] = "AT+VTR";
const char V253modemstart_duplex_voice_answr [] = "CONNECT";
const char V253modem_stop_duplex_voice_cmnd [] = {DLE, '^', 0x00};
const char V253modem_stop_duplex_voice_answr [] = "OK";
// juergen.kosel@gmx.de : voice-duplex-patch end


voice_modem_struct V253modem =
    {
    "V253 modem",
    V253modem_RMD_NAME,
     (char *) V253modem_pick_phone_cmnd,
     (char *) V253modem_pick_phone_answr,
     (char *) V253modem_beep_cmnd,
     (char *) IS_101_beep_answr,
              IS_101_beep_timeunit,
     (char *) V253modem_hardflow_cmnd,
     (char *) IS_101_hardflow_answr,
     (char *) V253modem_softflow_cmnd,
     (char *) IS_101_softflow_answr,
     (char *) IS_101_start_play_cmnd,
     (char *) IS_101_start_play_answer,
     (char *) IS_101_reset_play_cmnd,
     (char *) IS_101_intr_play_cmnd,
     (char *) IS_101_intr_play_answr,
     (char *) IS_101_stop_play_cmnd,
     (char *) IS_101_stop_play_answr,
     (char *) IS_101_start_rec_cmnd,
     (char *) IS_101_start_rec_answr,
     (char *) IS_101_stop_rec_cmnd,
     (char *) IS_101_stop_rec_answr,
     (char *) IS_101_switch_mode_cmnd,
     (char *) IS_101_switch_mode_answr,
     (char *) IS_101_ask_mode_cmnd,
     (char *) IS_101_ask_mode_answr,
     (char *) IS_101_voice_mode_id,
     (char *) IS_101_play_dtmf_cmd,
     (char *) IS_101_play_dtmf_extra,
     (char *) IS_101_play_dtmf_answr,
     // juergen.kosel@gmx.de : voice-duplex-patch start
     (char *) V253modem_start_duplex_voice_cmnd,
     (char *) V253modemstart_duplex_voice_answr,
     (char *) V253modem_stop_duplex_voice_cmnd ,
     (char *) V253modem_stop_duplex_voice_answr,
     // juergen.kosel@gmx.de : voice-duplex-patch end

    &IS_101_answer_phone,
    &IS_101_beep,
    &IS_101_dial,
    &IS_101_handle_dle,
    &V253modem_init,
    &IS_101_message_light_off,
    &IS_101_message_light_on,
    &IS_101_start_play_file,
    NULL,
    &IS_101_stop_play_file,
    &IS_101_play_file,
    &IS_101_record_file,
    &V253modem_set_compression,
    &V253modem_set_device,
    &IS_101_stop_dialing,
    &IS_101_stop_playing,
    &IS_101_stop_recording,
    &IS_101_stop_waiting,
    &IS_101_switch_to_data_fax,
    &IS_101_voice_mode_off,
    &IS_101_voice_mode_on,      /* it's also possible to say AT+FCLASS=8.0 */
    &IS_101_wait,
    &IS_101_play_dtmf,
    &V253_check_rmd_adequation,
     // juergen.kosel@gmx.de : voice-duplex-patch start
    &V253modem_handle_duplex_voice,
    &V253modem_stop_duplex,
     // juergen.kosel@gmx.de : voice-duplex-patch end
    0
    };
