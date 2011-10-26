/*
 * pvftormd.c
 *
 * pvftormd converts from the pvf (portable voice format) format to the
 * rmd (raw modem data) format.
 *
 * $Id: pvftormd.c,v 1.19 2005/03/13 17:27:48 gert Exp $
 *
 */

#include "../include/voice.h"

char *program_name;

static void usage (void)
     {
     fprintf(stderr, "\n%s %s\n\n", program_name, vgetty_version);
     fprintf(stderr, "usage:\n");
     fprintf(stderr, "\t%s <modem type> <compression method> \\\n",
      program_name);
     fprintf(stderr, "\t  [options] [<pvffile> [<rmdfile>]]\n");
     fprintf(stderr, "\noptions:\n");
     fprintf(stderr, "\t-h     this help message\n");
     fprintf(stderr, "\t-L     list of supported raw modem data formats\n");
     fprintf(stderr, "\t       and compression methods\n\n");
     exit(ERROR);
     }

static void supported_formats (void)
     {
     fprintf(stderr, "\n%s %s\n\n", program_name, vgetty_version);
     fprintf(stderr, "supported raw modem data formats:\n\n");
     fprintf(stderr, " - Digi           4        G.711u PCM\n");
     fprintf(stderr, " - Digi           5        G.711A PCM\n");
     fprintf(stderr, " - Elsa           2, 3, 4  2/3/4-bit Rockwell ADPCM\n");
     fprintf(stderr, " - ISDN4Linux     2, 3, 4  2/3/4-bit ZyXEL ADPCM\n");
     fprintf(stderr, " - ISDN4Linux     5        G.711A PCM\n");
     fprintf(stderr, " - ISDN4Linux     6        G.711u PCM\n");
     fprintf(stderr, " - Lucent         1        8 bit linear PCM\n");
     fprintf(stderr, " - Lucent         2        16 bit linear PCM\n");
     fprintf(stderr, " - Lucent         3        G.711A PCM\n");
     fprintf(stderr, " - Lucent         4        G.711u PCM\n");
     fprintf(stderr, " - Lucent         5        4 bit IMA ADPCM\n");
     fprintf(stderr, " - MT_2834        4        4 bit IMA ADPCM\n");
     fprintf(stderr, " - MT_5634        4        bit IMA ADPCM\n");
     fprintf(stderr, " - Rockwell       2, 3, 4  2/3/4-bit Rockwell ADPCM\n");
     fprintf(stderr, " - Rockwell       8        8-bit Rockwell PCM\n");
     fprintf(stderr, " - UMC            4        G.721 ADPCM\n");
     fprintf(stderr, " - US_Robotics    1        USR-GSM\n");
     fprintf(stderr, " - US_Robotics    4        G.721 ADPCM\n");
     fprintf(stderr, " - V253modem      2, 4     2/4-bit Rockwell ADPCM\n");
     fprintf(stderr, " - V253modem      5        4-bit IMA ADPCM\n");
     fprintf(stderr, " - V253modem      6        G.711u PCM\n");
     fprintf(stderr, " - V253modem      7        G.711A PCM\n");
     fprintf(stderr, " - V253modem      8        8-bit linear unsigned PCM\n");
     fprintf(stderr, " - V253modem      9        8-bit linear signed PCM\n");
     fprintf(stderr, " - V253modem      12       16-bit linear signed PCM Intel Order\n");
     fprintf(stderr, " - V253modem      13       16-bit linear unsigned PCM Intel Order\n");
     fprintf(stderr, " - ZyXEL_1496     2, 3, 4  2/3/4-bit ZyXEL ADPCM\n");
     fprintf(stderr, " - ZyXEL_2864     2, 3, 4  2/3/4-bit ZyXEL ADPCM\n");
     fprintf(stderr, " - ZyXEL_2864     81       8-bit Rockwell PCM\n");
     fprintf(stderr, " - ZyXEL_Omni56K  4        4-bit Digispeech ADPCM (?)\n");
     fprintf(stderr, "\nexample:\n\t%s Rockwell 4 infile.pvf outfile.rmd\n\n",
      program_name);
     exit(ERROR);
     }

int main (int argc, char *argv[])
     {
     int option;
     FILE *fd_in = stdin;
     FILE *fd_out = stdout;
     char *name_in = "stdin";
     char *name_out = "stdout";
     pvf_header header_in;
     rmd_header header_out = init_rmd_header;
     char *modem_type;
     int compression;

     check_system();
     program_name = argv[0];

     if (argc < 3)
          {

          if ((argc == 2) && (strcmp(argv[1], "-L") == 0))
               supported_formats();
          else
               usage();

          };

     modem_type = argv[1];
     compression = atoi(argv[2]);
     optind = 3;

     while ((option = getopt(argc, argv, "hL")) != EOF)
          {

          switch (option)
               {
               case 'L':
                    supported_formats();
               default:
                    usage();
               };

          };

     if (strcmp(modem_type, "MT_2834") == 0)
          modem_type = "Multitech2834";

     if (strcmp(modem_type, "MT_5634") == 0)
          modem_type = "Multitech5634";

     if (strcmp(modem_type, "Lucent") == 0)
 	  modem_type = "Lucent";

     if (strcmp(modem_type, "UMC") == 0)
          modem_type = "UMC";

     if (strcmp(modem_type, "US_Robotics") == 0)
          modem_type = "US Robotics";

     if (strcmp(modem_type, "ZyXEL_1496") == 0)
          modem_type = "ZyXEL 1496";

     if (strcmp(modem_type, "ZyXEL_2864") == 0)
          modem_type = "ZyXEL 2864";

     if (strcmp(modem_type, "ZyXEL_Omni56K") == 0)
          modem_type = "ZyXEL Omni 56K";

     if (strcmp(modem_type, "Digi") == 0)
          modem_type = "Digi RAS";		/* should be ITU V.253! */

     if ((strcmp(modem_type, "Digi RAS") == 0) ||
      (strcmp(modem_type, "Elsa") == 0) ||
      (strcmp(modem_type, "V253modem") == 0) ||
      (strcmp(modem_type, "ISDN4Linux") == 0) ||
      (strcmp(modem_type, "Multitech2834") == 0) ||
      (strcmp(modem_type, "Multitech5634") == 0) ||
      (strcmp(modem_type, "Rockwell") == 0) ||
      (strcmp(modem_type, "US Robotics") == 0) ||
      (strcmp(modem_type, "Lucent") == 0) ||
      (strcmp(modem_type, "UMC") == 0) ||
      (strcmp(modem_type, "ZyXEL 1496") == 0) ||
      (strcmp(modem_type, "ZyXEL 2864") == 0) ||
      (strcmp(modem_type, "ZyXEL Omni 56K") == 0))
          strcpy(header_out.voice_modem_type, modem_type);
     else
          {
          fprintf(stderr, "%s: Invalid modem type (%s)\n", program_name,
           modem_type);
          supported_formats();
          };

     if (optind < argc)
          {
          name_in = argv[optind];

          if ((fd_in = fopen(name_in, "r")) == NULL)
               {
               fprintf(stderr, "%s: Could not open file %s\n", program_name,
                name_in);
               exit(ERROR);
               };

          optind++;
          };

     if (read_pvf_header(fd_in, &header_in) != OK)
          exit(ERROR);

     header_out.speed = htons(header_in.speed);
     header_out.compression = htons(compression);

     if (optind < argc)
          {
          name_out = argv[optind];

          if ((fd_out = fopen(name_out, "w")) == NULL)
               {
               fprintf(stderr, "%s: Could not open file %s\n", program_name,
                name_out);
               exit(FAIL);
               };

          };

     if (strcmp(modem_type, "Digi RAS") == 0 && compression == 4)
          {
          header_out.bits = compression;

          if (header_in.speed != 8000)
               {
               fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                program_name, header_in.speed);
               fprintf(stderr,
                "%s: The Digi RAS only supports 8000 samples per second\n",
                program_name);
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(FAIL);
               };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftoulaw(fd_in, fd_out, &header_in) == OK)
               exit(OK);

          };

     if (strcmp(modem_type, "Digi RAS") == 0 && compression == 5)
          {
          header_out.bits = compression;

          if (header_in.speed != 8000)
               {
               fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                program_name, header_in.speed);
               fprintf(stderr,
                "%s: The Digi RAS only supports 8000 samples per second\n",
                program_name);
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(FAIL);
               };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

	  if (pvftoalaw(fd_in, fd_out, &header_in) == OK)
	       exit(OK); 

          };

     if ((strcmp(modem_type, "Elsa") == 0) && ((compression == 2) ||
      (compression == 3) || (compression == 4)))
          {
          header_out.bits = compression;

          if (header_in.speed != 7200)
               {
               fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                program_name, header_in.speed);
               fprintf(stderr,
                "%s: The Elsa Microlink only supports 7200 samples per second\n",
                program_name);
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(FAIL);
               };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftorockwell(fd_in, fd_out, compression, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "ISDN4Linux") == 0) &&
      ((compression == 2) || (compression == 3) || (compression == 4)))
          {
          header_out.bits = compression;

          if (header_in.speed != 8000) 
             {
                fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                 program_name, header_in.speed);
                fprintf(stderr,
                 "%s: The ISDN4Linux driver only supports 8000 samples/second\n",
                 program_name);
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(FAIL);
             };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftozyxel(fd_in, fd_out, compression, &header_in) == OK)
               exit(OK);

          };

     if (strcmp(modem_type, "ISDN4Linux") == 0 && compression == 5)
          {
          header_out.bits = 8;

          if (header_in.speed != 8000) 
             {
                fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                 program_name, header_in.speed);
                fprintf(stderr,
                 "%s: The ISDN4Linux driver only supports 8000 samples/second\n",
                 program_name);
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(FAIL);
             };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftoalaw(fd_in, fd_out, &header_in) == OK)
               exit(OK);

          };

     if (strcmp(modem_type, "ISDN4Linux") == 0 && compression == 6)
          {
          header_out.bits = 8;

          if (header_in.speed != 8000) 
             {
                fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                 program_name, header_in.speed);
                fprintf(stderr,
                 "%s: The ISDN4Linux driver only supports 8000 samples/second\n",
                 program_name);
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(FAIL);
            };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

  	    if (pvftoulaw(fd_in, fd_out, &header_in) == OK)
	         exit(OK);

          };

     if ((strcmp(modem_type, "Lucent") == 0) && (compression == 1))
          {
          header_out.bits = 8;

	    if ((header_in.speed != 7200) && (header_in.speed != 8000) &&
	     (header_in.speed != 11025))
	      {
		fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
		 program_name, header_in.speed);
	 	fprintf(stderr,
	         "%s: The Lucent only supports 7.2k, 8k and 11.025k samples/second\n",
	         program_name);
	        fclose(fd_out);

	 	if (fd_out != stdout)
			unlink(name_out);

		exit(FAIL);
		};

	if (write_rmd_header(fd_out, &header_out) != OK)
	      {
		fclose(fd_out);

		if (fd_out != stdout)
			unlink(name_out);

		exit(ERROR);
	      };

          if (pvftolin(fd_in, fd_out, &header_in, 0, 8, 0) == OK)
               exit(OK);

            };

     if ((strcmp(modem_type, "Lucent") == 0) && (compression == 2))
          {
          header_out.bits = 16;

          if ((header_in.speed != 7200) && (header_in.speed != 8000) &&
              (header_in.speed != 11025))
             {
                fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                 program_name, header_in.speed);
                fprintf(stderr,
                 "%s: The Lucent only supports 7.2k, 8k and 11.025k samples/second\n",
                 program_name);
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(FAIL);
                };

        if (write_rmd_header(fd_out, &header_out) != OK)
             {
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(ERROR);
             };

          if (pvftolin(fd_in, fd_out, &header_in, 0, 16, 0) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "Lucent") == 0) && (compression == 3))
          {
          header_out.bits = 8;

          if (header_in.speed != 8000) 
             {
                fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                 program_name, header_in.speed);
                fprintf(stderr,
                 "%s: The Lucent only supports 8000 samples/second\n",
                 program_name);
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(FAIL);
                };

        if (write_rmd_header(fd_out, &header_out) != OK)
             {
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(ERROR);
             };

          if (pvftoalaw(fd_in, fd_out, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "Lucent") == 0) && (compression == 4))
          {
          header_out.bits = 8;

          if (header_in.speed != 8000) 
             {
                fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                 program_name, header_in.speed);
                fprintf(stderr,
                 "%s: The Lucent only supports 8000 samples/second\n",
                 program_name);
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(FAIL);
                };

        if (write_rmd_header(fd_out, &header_out) != OK)
             {
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(ERROR);
             };

  	if (pvftoulaw(fd_in, fd_out, &header_in) == OK)
	  exit(OK);

          };

     if ((strcmp(modem_type, "Lucent") == 0) && (compression == 5))
          {
          header_out.bits = 4;

	  if ((header_in.speed != 7200)  && (header_in.speed != 8000) &&
	      (header_in.speed != 11025))
             {
                fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                 program_name, header_in.speed);
                fprintf(stderr,
		 "%s: The Lucent only supports 7.2k, 8k and 11.025k samples/second\n",
                 program_name);
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(FAIL);
                };

        if (write_rmd_header(fd_out, &header_out) != OK)
             {
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(ERROR);
             };
          
	  if (pvftoimaadpcm(fd_in, fd_out, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "Lucent") == 0) && (compression == 6))
          {
          header_out.bits = 8;

          if (header_in.speed != 8000) 
             {
                fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                 program_name, header_in.speed);
                fprintf(stderr,
                 "%s: The Lucent only supports 8000 samples/second\n",
                 program_name);
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(FAIL);
                };

        if (write_rmd_header(fd_out, &header_out) != OK)
             {
                fclose(fd_out);

                if (fd_out != stdout)
                        unlink(name_out);

                exit(ERROR);
             };

	/*          if (pvftog728(fd_in, fd_out, compression, &header_in) == OK)
		    exit(OK); */
	fprintf(stderr, "%s: G.728 compression is not yet supported!\n",
                 program_name);

          };

     if (strcmp(modem_type, "Multitech2834") == 0 && compression == 4)
          {
          header_out.bits = compression;

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftoimaadpcm(fd_in, fd_out, &header_in) == OK)
               exit(OK);

          };

     if (strcmp(modem_type, "Multitech5634") == 0)
          {
	    /* hard coded bits and compression */  
          header_out.bits = 4;
	  header_out.compression = htons(132);

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftoimaadpcm(fd_in, fd_out, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "Rockwell") == 0) && ((compression == 2) ||
      (compression == 3) || (compression == 4)))
          {
          header_out.bits = compression;

          if (header_in.speed != 7200)
               {
               fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                program_name, header_in.speed);
               fprintf(stderr,
                "%s: Rockwell modems only support 7200 samples per second\n",
                program_name);
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(FAIL);
               };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftorockwell(fd_in, fd_out, compression, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "Rockwell") == 0) && (compression == 8))
          {
          header_out.bits = compression;

          if (header_in.speed != 7200 && header_in.speed != 11025)
               {
               fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                program_name, header_in.speed);
               fprintf(stderr,
                "%s: Rockwell modems only support 7200 & 11025 samples per second\n",
                program_name);
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(FAIL);
               };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftorockwellpcm(fd_in, fd_out, compression, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "UMC") == 0) && (compression == 4))
          {
          header_out.bits = compression;

          if (header_in.speed != 7200)
               {
               fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                program_name, header_in.speed);
               fprintf(stderr,
                "%s: UMC modems only support 7200 samples per second\n",
                program_name);
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(FAIL);
               };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftousr(fd_in, fd_out, compression, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "US Robotics") == 0) && ((compression == 1) ||
         (compression == 4)))
          {
          if(compression == 1) header_out.bits = 8;
          else header_out.bits = 4;

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftousr(fd_in, fd_out, compression, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "V253modem") == 0) && ((compression == 2) ||
      (compression == 4)))
          {
          header_out.bits = compression;

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftorockwell(fd_in, fd_out, compression, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "V253modem") == 0) && (compression == 5))
          {
          header_out.bits = 4;

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftoimaadpcm(fd_in, fd_out, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "V253modem") == 0) && (compression == 6))
          {
          header_out.bits = 8;

        if (write_rmd_header(fd_out, &header_out) != OK)
             {
             fclose(fd_out);

             if (fd_out != stdout)
                     unlink(name_out);

             exit(ERROR);
             };

  	  if (pvftoulaw(fd_in, fd_out, &header_in) == OK)
	       exit(OK);

          };

     if ((strcmp(modem_type, "V253modem") == 0) && (compression == 7))
          {
          header_out.bits = 8;

        if (write_rmd_header(fd_out, &header_out) != OK)
             {
             fclose(fd_out);

             if (fd_out != stdout)
                     unlink(name_out);

             exit(ERROR);
             };

  	  if (pvftoalaw(fd_in, fd_out, &header_in) == OK)
	       exit(OK);

          };

     if ((strcmp(modem_type, "V253modem") == 0) && (compression == 8))
          {
          header_out.bits = 8;

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };
          if (pvftolin(fd_in, fd_out, &header_in, 0, 0, 0) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "V253modem") == 0) && (compression == 9))
          {
          header_out.bits = 8;

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };
          if (pvftolin(fd_in, fd_out, &header_in, 1, 0, 0) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "V253modem") == 0) && (compression == 12))
          {
          header_out.bits = 16;

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };
          /* Signed PCM 16-bit Intel bit ordering */
          if (pvftolin(fd_in, fd_out, &header_in, 1, 16, 1) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "V253modem") == 0) && (compression == 13))
          {
          header_out.bits = 16;

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };
          /* Unsigned PCM 16-bit Intel bit ordering */
          if (pvftolin(fd_in, fd_out, &header_in, 0, 16, 1) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "ZyXEL 1496") == 0) &&
      ((compression == 2) || (compression == 3) || (compression == 4)))
          {
          header_out.bits = compression;

          if (header_in.speed != 9600)
               {
               fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                program_name, header_in.speed);
               fprintf(stderr,
                "%s: The ZyXEL 1496 only supports 9600 samples per second\n",
                program_name);
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(FAIL);
               };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftozyxel(fd_in, fd_out, compression, &header_in) == OK)
               exit(OK);

          };

     if ((strcmp(modem_type, "ZyXEL 2864") == 0) &&
      ((compression == 2) || (compression == 3) || (compression == 4)))
          {
          header_out.bits = compression;

          if ((header_in.speed != 7200) && (header_in.speed != 8000) &&
           (header_in.speed != 9600) && (header_in.speed != 11025))
               {
               fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                program_name, header_in.speed);
               fprintf(stderr,
                "%s: The ZyXEL 2864 supports the following sample rates:\n",
                program_name);
               fprintf(stderr,
                "%s: 7200, 8000, 9600 and 11025\n", program_name);
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(FAIL);
               };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

	     if (pvftozyxel(fd_in, fd_out, compression, &header_in) == OK)
		  exit(OK);

          };

     if ((strcmp(modem_type, "ZyXEL 2864") == 0) && (compression == 81))
          {
          header_out.bits = compression;

          if ((header_in.speed != 7200) && (header_in.speed != 8000) &&
           (header_in.speed != 9600) && (header_in.speed != 11025))
               {
               fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                program_name, header_in.speed);
               fprintf(stderr,
                "%s: The ZyXEL 2864 supports the following sample rates:\n",
                program_name);
               fprintf(stderr,
                "%s: 7200, 8000, 9600 and 11025\n", program_name);
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(FAIL);
               };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

	     if (pvftorockwellpcm(fd_in, fd_out, compression, &header_in) == OK)
	          exit(OK);

          };

     if (strcmp(modem_type, "ZyXEL Omni 56K") == 0 && compression == 4)
          {
          header_out.bits = compression;

          if (header_in.speed != 9600)
               {
               fprintf(stderr, "%s: Unsupported sample speed (%d)\n",
                program_name, header_in.speed);
               fprintf(stderr, "%s: The ZyXEL Omni 56K"
                " only supports 9600 samples per second\n",
                program_name);
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(FAIL);
               };

          if (write_rmd_header(fd_out, &header_out) != OK)
               {
               fclose(fd_out);

               if (fd_out != stdout)
                    unlink(name_out);

               exit(ERROR);
               };

          if (pvftozo56k(fd_in, fd_out, &header_in) == OK)
               exit(OK);

          };

     fclose(fd_out);

     if (fd_out != stdout)
          unlink(name_out);

     fprintf(stderr, "%s: Unsupported compression method\n", program_name);
     exit(FAIL);
     }
