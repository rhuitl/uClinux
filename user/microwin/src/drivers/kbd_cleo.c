/*
 * Copyright (c) 2002 Roman Wagner <rw@feith.de>
 *
 *
 * Keyboard Driver, uClinux-CLEOPATRA version
 */

#include "device.h"

#if CLEOPATRA
 #if CLEOVERSION
 #include "cleopatra2.h"
 #else
 #include "cleopatra.h"
 #endif
#endif

static int  CLEO_Open(KBDDEVICE *pkd);
static void CLEO_Close(void);
static void CLEO_GetModifierInfo(int *modifiers);
static int  CLEO_Read(MWUCHAR *buf, int *modifiers);
static int	CLEO_Poll(void);

KBDDEVICE kbddev = {
	CLEO_Open,
	CLEO_Close,
	CLEO_GetModifierInfo,
	CLEO_Read,
	CLEO_Poll
};


/*
 * Init CLEOPATRA Hardware
 */
static int init_cleopatra(void)
{
   unsigned char error;

   error = test_xilinx();
	if(error)
   {
      error = prog_xilinx();
	   if(error)
	   {
		   if(error == 1)
	  		   printf("\Error XILINX: open fpga.bin error.\n");
		   else
	   	   printf("\Error XILINX: programming error.\n");
		   return(0);
	   }
   }
	// ***********  Hardware init  ***************
	iic_setup();
	set_pll_20mhz();
	init_dac_timing(0);
	init_dac_palette();
//	init_dac_ram(0xFFFF);
	init_dac_ram(0);

	error = setup_ccd(0);
	if (error==0)
		printf(", ccd done ...\n");
	else
	{
		printf(", error CCD : keine bekannte ccd kamera gefunden\n");
		return(0);
	}

	fill_vram(0);
	fill_vram(1);

	set_ad_nref(14);
	set_ad_pref(72);	printf("referenzen adc done ...\n");

	return 1;
}



/*
 * Open the keyboard.
 */
static int
CLEO_Open(KBDDEVICE *pkd)
{
   if(!init_cleopatra())
   	return -1;

   init_key();
	return 1;

}

/*
 * Close the keyboard.
 */
static void
CLEO_Close(void)
{
}

/*
 * Return the possible modifiers for the keyboard.
 */
static  void
CLEO_GetModifierInfo(int *modifiers)
{
	*modifiers = 0;
}

/*
 * This reads one keystroke from the keyboard, and the current state of
 * the mode keys (ALT, SHIFT, CTRL).  Returns -1 on error, 0 if no data
 * is ready, and 1 if data was read.  This is a non-blocking call.
 */
static int
CLEO_Read(MWUCHAR *buf, int *modifiers)
{
	/* wait until a char is ready*/
//	if(!bioskey(1))
//		return 0;

	/* read keyboard shift status*/
	*modifiers = 0;

	/* read keyboard character*/
//	*buf = get_key_wb();

   *buf = get_key();
//printf("key org = %d\n",*buf);
   if(*buf == 0x00)
		return 0;

	if(*buf == 0x1b)	/* special case ESC*/
		return -2;
	return 1;
}

/*
**
*/
static int
CLEO_Poll(void)
{
   set_key();
   return(key_hit());

/*	if (get_key_wb()==0)
	  return 0;
	else
	  return 1;
*/
}

