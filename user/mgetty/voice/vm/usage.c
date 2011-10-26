/* main.c
 *
 * VoiceModem is the program for handling the voice modem functionality
 * from shell scripts.
 *
 * $Id: usage.c,v 1.8 2005/03/13 17:27:50 gert Exp $
 *
 */

#include "vm.h"

void usage(void)
     {
       int i;
     fprintf(stderr, "\n%s %s\n\n", program_name, vgetty_version);
     fprintf(stderr, "usage:\n");
     fprintf(stderr,
      "\t%s beep   [options] [<frequency> [<length in 0.001sec>]]\n",
      program_name);
     fprintf(stderr, "\t%s diagnostics <device name (e.g. ttyS2)>\n",
      program_name);
     fprintf(stderr, "\t%s dial   [options] <phone number>\n", program_name);
     fprintf(stderr, "\t%s help\n", program_name);
     fprintf(stderr, "\t%s play   [options] <file names>\n", program_name);
     fprintf(stderr, "\t%s record [options] <file name>\n", program_name);
     fprintf(stderr,
      "\t%s shell  [options] [<shell script> [shell options]]\n", program_name);
     fprintf(stderr, "\t%s wait   [options] [<time in seconds>]\n",
      program_name);
     fprintf(stderr, "\t%s devicetest\n", program_name);
     // juergen.kosel@gmx.de : voice-duplex-patch start
     fprintf(stderr, "\t%s duplex playfilename recordfilename\n", program_name);
     // juergen.kosel@gmx.de : voice-duplex-patch end
     fprintf(stderr, "\noptions:\n");
     fprintf(stderr, "\t-c <n> use compression type <n> (default is %d)\n",
      cvd.rec_compression.d.i);
     fprintf(stderr, "\t-h     this help message\n");

     fprintf(stderr, "\t-d <n> set i/o device to\n");
     for (i = 1; i <= NUMBER_OF_MODEM_DEVICE_MODES; i++)
       {                      
	 fprintf(stderr, "\t       <n>=%2i: %s\n", 
		 i, voice_device_mode_name(i));
       }

     fprintf(stderr, "\t-t, -m, -i, -e, -s, -H     equals to -d <2,3,4,5,6,7>\n");

     fprintf(stderr, "\t-l <s> set device string (e.g. -l ttyS2:ttyC0)\n");
     fprintf(stderr, "\t-v     verbose output\n");
     fprintf(stderr, "\t-w     use off / on hook signal from local handset\n");
     fprintf(stderr, "\t       to start and stop recording\n");
     fprintf(stderr, "\t-x <n> set debug level\n");
     fprintf(stderr, "\t-L <n> set maximum recording length in sec\n");
     fprintf(stderr, "\t-P     print first DTMF tone on stdout and exit\n");
     fprintf(stderr,
      "\t-R     read and print DTMF string on stdout and exit\n");
     fprintf(stderr,
      "\t-S <s> set default shell for shell scripts (e.g. -S /bin/sh)\n");
     fprintf(stderr, "\t-T <n> set silence timeout in 0.1sec\n");
     fprintf(stderr, "\t-V <n> set silence threshold to <n> (0-100%%)\n\n");
     exit(ERROR);
     }
