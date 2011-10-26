/*
  Lan Bypass Control Program
  (C) 2005  Cplus Shen <cplus.shen@advantech.com.tw>
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* 
 * File:	lanbypass.c   
 * Description:	Setup lan bypass or not
 * Author:	Cplus Shen
 *
 * Usage: ./lanbypass { -e group_id | -d group_id | -s }
 * Usage: 	./lanbypass { -e group_id | -d group_id | -s group_id }
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/io.h>
#include <errno.h>

/* data structure definition */
#define LANBYPASS_MAX_GROUP 3
#define GPIOBASE  0x480

#define SUPERIO_ADDR_PORT 0x2E
#define SUPERIO_DATA_PORT 0x2F

typedef unsigned char uchar;

/* local function declaration */
static void usage(void);
static void init();
static void lb_group_show();
static void lb_gpio_disable(int i);
static void lb_gpio_enable(int i);
static void lb_gpio_power(int i);

/* global function implementation */
int main(int argc, char *argv[])
{
  int group;
  char c;

  if (iopl(3)) {
    perror(NULL);
    exit(1);
  }

  if (argc == 1) {
    usage();
    exit(2);
  }

  while ((c = getopt(argc, argv, "hse:d:p:")) != EOF) {
    switch (c) {
    case 'h':
      usage();
      break;
    case 's':
      /* read lan bypass statis */
      printf("Lan Bypass Status\n");
      printf("=======================\n");

			lb_group_show();
      break;
    case 'e':
      {
				group = atoi(optarg);
				lb_gpio_enable(group);
      }
      break;
    case 'd':
      {
				group = atoi(optarg);
				lb_gpio_disable(group);
      }
      break;
    case 'p':
      {
        uchar s;

				s = atoi(optarg);
        if(s) {
          lb_gpio_power(1);
        } else {
					lb_gpio_power(0);
        }
      }
      break;
 		   default:
      usage();
      exit(3);
    }
    
  }

  exit(0);
}

/* local function implementation */
static void usage(void)
{
  printf("Usage: lanbypass { -e group_id | -d group_id | -p power_on -s }\n");
  printf("    where group_id from 0 to %d\n", LANBYPASS_MAX_GROUP - 1);
  printf("    -e enable lan bypass\n");
  printf("    -d disable lan bypass\n");
  printf("    -p power on/off\n");
  printf("    -s show all lan bypass status\n");
}

static void init(void){
	//enable super IO
  outb_p(0x87,SUPERIO_ADDR_PORT);
  outb_p(0x87,SUPERIO_ADDR_PORT);
  //select device 7
  outb_p(0x07,SUPERIO_ADDR_PORT);
  outb_p(0x07,SUPERIO_DATA_PORT);
}

static void lb_group_show()
{

	init();

	unsigned int data;
	unsigned int val;
	unsigned int gdata;

	//READ SUPERIO => GPIO 
	outb_p(0xF0,SUPERIO_ADDR_PORT);
	data = inb_p(SUPERIO_DATA_PORT);
	
	printf("GPIO 10-17: 0x:%x\n",data);

	outb_p(0xF1,SUPERIO_ADDR_PORT);
  val = inb_p(SUPERIO_DATA_PORT);

	if(((data>>7)&1) > 0 ){
		printf("LAN 1-2 bypass : disable\n");
	}else{

		if(((val>>7)&1) > 0 ){
			printf("LAN 1-2 bypass : disable\n");
		}else{
			printf("LAN 1-2 bypass : enable\n");
		}
	}

  if(((data>>6)&1) > 0 ){
    printf("LAN 3-4 bypass : disable\n");
  }else{
    if(((val>>6)&1) > 0 ){
      printf("LAN 3-4 bypass : disable\n");
    }else{
      printf("LAN 3-4 bypass : enable\n");
    }
  }

	gdata = inb_p(GPIOBASE+0x0E);
	gdata = gdata&1 ;

	if(gdata > 0){
		printf("LAN 5-6 bypass : disable\n");
	}else{
		printf("LAN 5-6 bypass : enable\n");
	}

	if(((data>>5)&1) > 0 /* && (data>>4)&1 != 1*/  ){
		printf("Power On/Off bypass : enable\n");
	}else{
		printf("Power On/Off bypass : disable\n");
	}

}

static void lb_gpio_enable(int i)
{

	unsigned int data;
	unsigned int val;

	init();

	if(i==1){
		
		outb_p(0xF0,SUPERIO_ADDR_PORT);
		data = inb_p(SUPERIO_DATA_PORT);
		outb_p( 0x7F&data,SUPERIO_DATA_PORT );

		outb_p(0xF1,SUPERIO_ADDR_PORT);
    val = inb_p(SUPERIO_DATA_PORT);
		outb_p( 0x7F&val,SUPERIO_DATA_PORT );

		printf("Lan 1-2 lanbypass : enable\n");

	}else if(i==2){

		outb_p(0xF0,SUPERIO_ADDR_PORT);
    data = inb_p(SUPERIO_DATA_PORT);
    outb_p( 0xBF&data,SUPERIO_DATA_PORT );

    outb_p(0xF1,SUPERIO_ADDR_PORT);
    val = inb_p(SUPERIO_DATA_PORT);
    outb_p( 0xBF&val,SUPERIO_DATA_PORT );

		printf("Lan 3-4 lanbypass : enable\n");

	}else if(i==3){

		data = inb_p(GPIOBASE+0x0E);
    data = data&0xFE ;
    outb_p(data,GPIOBASE+0x0E);

    printf("Lan 5-6 lanbypass : enable\n");

	}

}

static void lb_gpio_disable(int i)
{

	unsigned int data;
  unsigned int val;

  init();

  if(i==1){

    outb_p(0xF0,SUPERIO_ADDR_PORT);
    data = inb_p(SUPERIO_DATA_PORT);
    outb_p( 0x80|data,SUPERIO_DATA_PORT );

    outb_p(0xF1,SUPERIO_ADDR_PORT);
    val = inb_p(SUPERIO_DATA_PORT);
    outb_p( 0x80|val,SUPERIO_DATA_PORT );

		printf("Lan 1-2 lanbypass : disable\n");
	  
  }else if(i==2){

    outb_p(0xF0,SUPERIO_ADDR_PORT);
    data = inb_p(SUPERIO_DATA_PORT);
    outb_p( 0x40|data,SUPERIO_DATA_PORT );

    outb_p(0xF1,SUPERIO_ADDR_PORT);
    val = inb_p(SUPERIO_DATA_PORT);
    outb_p( 0x40|val,SUPERIO_DATA_PORT );

		printf("Lan 3-4 lanbypass : disable\n");

  }else if(i==3){

    data = inb_p(GPIOBASE+0x0E);
    data = data|0x1 ;
    outb_p(data,GPIOBASE+0x0E);
    printf("Lan 5-6 lanbypass : disable\n");

  }

}

static void lb_gpio_power(int i){

	unsigned int b ;
	unsigned int data;
  unsigned int val;

  init();

  if(i==1){

		/* enable */
    outb_p(0xF0,SUPERIO_ADDR_PORT);
    data = inb_p(SUPERIO_DATA_PORT);
		b = 0x20|data;
		b = 0xEF&b ;
    outb_p( b,SUPERIO_DATA_PORT );

    outb_p(0xF1,SUPERIO_ADDR_PORT);
    val = inb_p(SUPERIO_DATA_PORT);

		b = 0x20|val;
    b = 0xEF&b ;
    outb_p( b,SUPERIO_DATA_PORT );

		printf("Power on/off lanbypass : enable\n");

  }else{

		/* disable */

    outb_p(0xF0,SUPERIO_ADDR_PORT);
    data = inb_p(SUPERIO_DATA_PORT);
		b =0x10|data;
		b =0xDF&b;
    outb_p( b,SUPERIO_DATA_PORT );

    outb_p(0xF1,SUPERIO_ADDR_PORT);
    val = inb_p(SUPERIO_DATA_PORT);
		b =0x10|val;
    b =0xDF&b;
    outb_p( b,SUPERIO_DATA_PORT );

		printf("Power on/off lanbypass : disable\n");
  }

}

