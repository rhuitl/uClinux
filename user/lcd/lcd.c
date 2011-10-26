/*
 * Test of lcddma device driver
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Get a test bitmap */
//#include "penguin.h"
#include "peng_small.h"

/* Define LCD screen parameters */
// Pixels per word
#define SCREEN_X  240
#define LCD_XDIM  (SCREEN_X/4)
// Number of lines in a screen
#define LCD_YDIM  64
#define LCD_HFP   LCD_XDIM
#define LCD_HSYNC ((LCD_XDIM+1))
#define LCD_HBP   ((LCD_XDIM+2))
#define LCD_HTOT  ((LCD_XDIM+3))
/* Define LCD connections */
/* LCD data */
#define LCD_DATA_MASK (0xF0)
/* LCD Frame Line Marker or "vertical sync" */
#define LCD_FLM       (0x08)
/* LCD AC drive - if vsync is 60Hz, this is 30Hz */
#define LCD_M         (0x04)
/* LCD Latch Pulse or "horizontal sync" */
#define LCD_LP        (0x02)
/* LCD Clock Pulse or "dot clock" */
#define LCD_CP        (0x01)

static unsigned char test_bits[16] = { 0x12, 0x34, 0x56, 0x78,
				       0x9a, 0xbc, 0xde, 0xf0,
				       0xde, 0xaf, 0xda, 0xbe,
				       0xab, 0xbe, 0xca, 0xfe};

int mkbitmap(unsigned short *lcd_array, int do_M) {
  int i, j, k;
  int peng_x, peng_y;
  unsigned short lcd_data;
  unsigned char  bitmap_data;

  for (j = 0; j < LCD_YDIM; j++) {
    for (i = 0; i < LCD_HTOT; i++) {
      /* Get bitmap data, if we're inside it */
      /* Only get four bits, since that's how many we disp per word sent */
      if ((i < peng_small_width/4) && (j < peng_small_height)) 
	bitmap_data = ((peng_small_bits[(j * peng_small_width/8) + (i/2)])
		       << (4*(1 -(i & 1)))) & LCD_DATA_MASK;
      else
	bitmap_data = 0x0;

      lcd_data = (unsigned short)bitmap_data;
      
      /* Do a hsync */
      lcd_data |= (i == LCD_HSYNC) ? LCD_LP : 0 ;

      /* Do a vsync */
      /* Vsync must have setup/hold time wrt hsync falling edge */

      if (j == 0) {
	lcd_data |= LCD_FLM;
	/* M must change concident with Hsync falling edge */
	if (i > LCD_HSYNC)
	  lcd_data |= do_M ? 0 : LCD_M;
	else
	  lcd_data |= do_M ? LCD_M : 0;
      }
      else {
	lcd_data |= do_M ? LCD_M : 0;
      }

      /* Do a clock */
      /* Data is setup to falling edge */
      if (i < LCD_XDIM) {
	lcd_array[(j * LCD_HTOT + i) * 2]     = lcd_data | LCD_CP;
	lcd_array[(j * LCD_HTOT + i) * 2 + 1] = lcd_data;
      }
      else {
	lcd_array[(j * LCD_HTOT + i) * 2]     = lcd_data;
	lcd_array[(j * LCD_HTOT + i) * 2 + 1] = lcd_data;
      }
    }
  }
}

int main() {
  int i, fd;
  char dummy;
  unsigned char buf[5];
  unsigned char readbuf[5];
  unsigned int value;

  unsigned short *lcdbuf;

  printf ("opening lcddma...");
  fd = open("/dev/lcddma",O_RDWR,0);
  printf ("returned: %d\n", fd);

  if (fd < 0) return(fd);

  printf("reading from lcddma...");
  read(fd,  (unsigned char *)(&value), 4);

  printf("\nreturned: %x\n", value);

  printf("Changing buffer contents\n");

  lcdbuf = (unsigned short *)value;

  mkbitmap(lcdbuf, 0);
  mkbitmap(lcdbuf + (LCD_YDIM) * (LCD_HTOT) * 2, 1);

  printf("Addr: %08x\n", lcdbuf);
  printf("data: %02x %02x %02x %02x\n", 
	 lcdbuf[0], lcdbuf[1], lcdbuf[2], lcdbuf[3]);
  
  // 2 bytes/word * 2 words/clk * 2 screens/mclk
  value = ((LCD_YDIM) * (LCD_HTOT)) * 2 * 2 * 2; 
  printf("writing new xfer len: %d\n", value);
  write(fd, (unsigned char *)(&value), 4);

  dummy = getchar();
  printf("\nclosing device\n");
}
