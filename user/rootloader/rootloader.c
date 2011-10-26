/* rootloader.c:
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/stat.h>
#include <signal.h>

#include <sys/mount.h>
#include <linux/fs.h>
#include <linux/blkmem.h>

#if __GNU_LIBRARY__ > 5
#include <sys/reboot.h>
#endif

#define RB 4096
char readbuf[RB];

int tried_unvar = 0;
int do_reboot = 0;

unsigned char * buffer[32];
unsigned int bufferlength[32];

struct blkmem_program_t * prog;

unsigned long base_address = 0;
unsigned long checksum = 0;

int block_len = 32000; /*4000;*/

void restart(void)
{
	kill(1, SIGCONT);
	if (do_reboot) {
#if __GNU_LIBRARY__ > 5
		reboot(0x01234567);
#else
		reboot(0xfee1dead, 672274793, 0x01234567);
#endif
	}
}

void add_data(unsigned long address, unsigned char * data, unsigned long len)
{
	int i;
	
	/*printf("add_data(%lx:%lx)\n", address, len);*/
	
again:	for(i=0;i<prog->blocks;i++) {
	  if (((prog->block[i].length+len) <= block_len) &&
	      ((prog->block[i].pos+prog->block[i].length) == address)) {
	    int l = block_len - prog->block[i].length;
	    if (l > len)
	      l = len;
	    memcpy(prog->block[i].data + prog->block[i].length, data, l);
	    prog->block[i].length += l;
	    
	    address += l;
	    data += l;
	    len -= l;

	/*printf("block[%d] -> data=%x, pos=%x, length=%x\n", 
		i, prog->block[i].data, prog->block[i].pos, prog->block[i].length);*/

	    if (len > 0)
	      goto again;
	    else
	      return;
	  }
	}
	if (i==prog->blocks) {
	  int l;
shrink:
	  l = block_len;
	  if (l > len)
	    l = len;
	    
	  prog->block[i].data = malloc(block_len);
	  
	  
	  if (!prog->block[i].data) {
	    if (!tried_unvar) {
	    	printf("Trying to unmount /var\n");
	    	if (umount("/var") == 0) {
	    		int l;
	    		printf("Did unmount /var\n");
	    		l = open("/dev/ram0", O_RDWR);
	    		if (l!=-1) {
	    			int k;
	    			printf("Opened ramdisk\n");
	    			k = ioctl(l, BLKFLSBUF, 0);
	    			if (k != -1)
	    				printf("Flushed ramdisk\n");
	    			else
	    				printf("Couldn't flush: %s\n", strerror(k));
	    			close(l);
	    		}
	    		do_reboot = 1;
	    	} else
	    		printf("Couldn't unmount /var\n");
	    	tried_unvar = 1;
	    
	    }
	    block_len /= 2;
	    if (block_len > 1024)
	    	goto shrink;
	    printf("Insufficient memory for rootloader!\n");
	    exit(1);
	  }
	  prog->block[i].pos = address;
	  prog->block[i].length = l;
	  memcpy(prog->block[i].data, data, l);
	  prog->block[i].magic3 = BMPROGRAM_MAGIC_3;
	  
	  address += l;
	  data += l;
	  len -= l;

	/*printf("block[%d] -> data=%x, pos=%x, length=%x\n", 
		i, prog->block[i].data, prog->block[i].pos, prog->block[i].length);*/
		
	  prog->blocks++;

	  if (len > 0)
	    goto again;

	}
	
}

void read_a_line(char * dest)
{
  int i = 0;
  char * orig = dest;
  for(;;) {
    if (i > 100)
      exit(0);
    if (read(0, dest, 1) <= 0)
      exit(0);
    if (*dest == '\n') {
      if ((i>0) && (dest[-1] == '\r'))
        dest--;
      *dest = '\0';
      printf("Read line |%s|\n", orig);
      return;
    }
    dest++;
    i++;
  }
}

int
main(int argc, char *argv[])
{
  int fd, s;
  int i;
  unsigned long l, size;
  unsigned long erase;
  int rd;
  int current = 0;
  unsigned long pos = 0;

  unsigned long check_address = 0;
  unsigned long base_address = 0;
  unsigned long checksum = 0;
  unsigned long our_checksum = 0;
  unsigned long image_length = 0;
  unsigned long print_length = 0;
  unsigned long total_length = 0;

  close(1);
  close(2);
  
  freopen("/dev/ttyS0", "w", stdout);
  
  printf("rootloader launching, shutting down other tasks\n");
  
  kill(1, SIGTSTP);		/* Stop init from reforking tasks */
  atexit(restart);		/* If we exit prematurely, restart init */
  sync();
  signal(SIGTERM,SIG_IGN);	/* Don't kill ourselves... */
  setpgrp(); 			/* Don't let our parent kill us */
  kill(-1, SIGTERM);		/* Kill everything that'll die */
  sleep(2);			/* give em a moment... */

  freopen("/dev/ttyS0", "w", stdout);
  
  printf("rootloader reopening ttys0\n");
  
  /* Go through validity checks */
  
  read_a_line(readbuf);
  
  if (strcmp(readbuf, "Pass1"))
    exit(0);

  read_a_line(readbuf);

  if (strcmp(readbuf, "Pass2"))
    exit(0);
  

  prog = malloc(3980 /*4080*/);
  
  if (!prog)
    exit(0);

  prog->magic1 = 0;
  prog->magic2 = 0;
  prog->blocks = 0;
  prog->reset = 1;

  for (;;) {

    read_a_line(readbuf);			/* Addres */
  
    base_address = strtoul(readbuf, 0, 0);
    
    read_a_line(readbuf);			/* Check-address */
    
    check_address = strtoul(readbuf, 0, 0);

    read_a_line(readbuf);			/* Data length */
  
    total_length = strtoul(readbuf, 0, 0);

    read_a_line(readbuf);			/* Checksum */
  
    checksum = strtoul(readbuf, 0, 0);

    if (total_length==0)
      break;

    if ((base_address ^ 0xC0EDCAFE) != check_address) {
      printf("Bogus address\n");
      exit(0);
    }
    
    printf("Block 0x%X-0x%X\n", base_address, base_address + total_length-1);
    
    image_length = 0;
    print_length = 0;
    our_checksum = 0;
  
    for (;;) {
      int r = total_length - image_length;
      if (r > RB)
        r = RB;
    
      l = read(0, readbuf, r);
    
      if (l <= 0)
        break;
      
      for(i=0;i<l;i++)
        our_checksum = (our_checksum + readbuf[i]) & 0xff;
    
      add_data(base_address + image_length, readbuf, l);
    
      image_length += l;
    
      if (image_length >= print_length) {
        print_length += RB;
        printf("0x%X\n", base_address + print_length);
      }
    
    }
    
    printf("Read %x bytes of data, wanted %x\n", image_length, total_length);
    
    if (total_length != image_length) {
      printf("Read wrong amount of data\n");
      exit(0);
    }
    
    printf("Our checksum = %x, original checksum = %x\n", our_checksum, checksum);
    if ((our_checksum & 0xff) != checksum) {
      printf("Bad checksum, exiting\n");
      /*exit(0);*/
    }
  }
    
  /*for(i=0;i<prog->blocks;i++) {
  	printf("Block %d = %X-%X\n", i, prog->block[i].pos, prog->block[i].pos+prog->block[i].length-1);
  }*/
  
  close(0);
  
  sleep(2); /* try to let the socket queue flush */

  kill(-1, SIGHUP);		/* Kill links (pppd, slattach) */
  sleep(2);
  kill(-1, SIGKILL);		/* Give them another go */
  sync();
  sleep(2);			/* For good luck */
  
  printf("Opening\n");
  fflush(stdout);
  rd = open("/dev/rom2", O_RDWR);
  printf("Opened: %d (%d)\n", rd, errno);
  fflush(stdout);
  
  prog->magic1 = BMPROGRAM_MAGIC_1;
  prog->magic2 = BMPROGRAM_MAGIC_2;
  
  printf("Ioctling\n");
  fflush(stdout);
  
  rd = ioctl(rd, BMPROGRAM, prog);
  
  printf("Ioctl: %d (%d)\n", rd, errno);
  fflush(stdout);
  
  printf("hah!\n");
  fflush(stdout);
 
}
