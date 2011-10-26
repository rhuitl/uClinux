/*
 * Copyright (c) 1993 by David I. Bell
 * Permission is granted to use, distribute, or modify this source,
 * provided that this copyright notice remains intact.
 *
 * Most simple built-in commands are here.
 */

#include "sash.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <errno.h>

void
do_hexdump(argc, argv)
	int	argc;
	char	**argv;
{
	FILE	*fp;
	int	count;
	int	c;
	char	text[17];
	unsigned char	buf[130];

	char	*name = 0;
	unsigned long pos = 0;
	char	*myname = argv[0];
 
	if ( (argc > 2) && !strcmp(argv[1],"-s") ) {
		pos = strtoul(argv[2], 0, 0);
		argc -= 2;
		argv += 2;
	}
	
	if (argc <= 1) {
		fprintf(stderr, "No filename provided\n");
		return;
	}

	name = argv[1];
	fp = fopen(name, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open file '%s': %s\n",
			name, strerror(errno));
		return;
	}

	if (pos)
		fseek(fp, pos, SEEK_SET);
	
	c = 0;
	
	text[16] = 0;
	
	while(!feof(fp)) {
	
	  strcmp(text, "                ");
	
	  while (c < (pos & 0xf)) {
	    if (c == 0)
	      printf("%4X:", pos & 0xfffffff0);
	    printf( (c == 8) ? "-  " : "   ");
	    text[c] = ' ';
	    c++;
	  }
	
	  {
	    int p = 0;
            count = fread(buf, 1, 128 - (pos % 16), fp);
          
            if (count <= 0)
              break;

            while (p < count) {
              c = (pos & 0xf);
            
              if (c == 0)
                printf("%4X:", pos & 0xfffffff0);
              
              if ((buf[p] < 32) || (buf[p]>126))
                text[c] = '.';
              else
                text[c] = buf[p];
            
	      printf( (c==15) ? " %02.2X" : (c == 8) ? "-%02.2X" : " %02.2X", buf[p]);
	      
	      if (c == 15)
	        printf(" %s\n", text);
	    
              pos++;
              p++;
            }
	  }
	  
	  if (c = (pos & 0x0f)) {

	    while (c < 16) {
	      printf( (c == 8) ? "-  " : "   ");
	      text[c] = ' ';
	      c++;
	    }
	  
	    printf(" %s\n", text);
	  }
	    
	  if (feof(fp))
	    break;
	  
	  printf("--more--");
	  fflush(stdout);
	  
	  fgets(buf, 80, stdin);
	  if (toupper(buf[0]) == 'Q')
	    break;
	}

	if (fp != stdin)
		fclose(fp);
}

