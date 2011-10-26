/*
 * Microwindows touch screen driver for uClinux-CLEOPATRA touch screen
 *
 * Copyright (c) 2002 Roman Wagner <rw@feith.de>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include "device.h"

#if CLEOPATRA
 #if CLEOVERSION
 #include "cleopatra2.h"
 #else
 #include "cleopatra.h"
 #endif
#endif

#define TEST	0


extern SCREENDEVICE scrdev;
/*
 * Open up the mouse device.
 * Returns the fd if successful, or negative if unsuccessful.
 */
static int PD_Open(MOUSEDEVICE *pmd)
{
   if(!init_touch(398,3720,3550,500,0))
   {
      printf("error init touch\n");
      return -1;
   }
   else
   {
      GdHideCursor(&scrdev);
   	return 1;
   }
}

/*
 * Close the mouse device.
 */
static void PD_Close(void)
{
   close_touch();
}

/*
 * Get mouse buttons supported
 */
static int PD_GetButtonInfo(void)
{
 	/* get "mouse" buttons supported */
	return MWBUTTON_L;
}

/*
 * Get default mouse acceleration settings
 */
static void PD_GetDefaultAccel(int *pscale,int *pthresh)
{
	/*
	 * Get default mouse acceleration settings
	 * This doesn't make sense for a touch panel.
	 * Just return something inconspicuous for now.
	 */
	*pscale = 3;
	*pthresh = 5;
}

static int PD_Read(MWCOORD *px, MWCOORD *py, MWCOORD *pz, int *pb)
{
   short m_button = 0;
   short tp_x = -1;
   short tp_y = -1;

   get_touch(&m_button,&tp_x,&tp_y);
   *px = tp_x;
   *py = tp_y;
   *pb = (m_button == 1?MWBUTTON_L:0);
	*pz = 0;

  	if((*px == -1 || *py == -1) && *pb == MWBUTTON_L)
     	return 3;			/* only have button data */
   else if((*px == -1 || *py == -1) && *pb == 0)
		return 0;			/* don't have any data   */
	else
	   return 2;			/* have full set of data */
}

static int PD_Poll(void)
{
   set_touch();
   return(touch_hit());
}

MOUSEDEVICE mousedev = {
	PD_Open,
	PD_Close,
	PD_GetButtonInfo,
	PD_GetDefaultAccel,
	PD_Read,
	PD_Poll
};


#ifdef TEST
int main1()
{
	MWCOORD x, y, z;
	int	b;
	int result;

	DPRINTF("Opening touch panel...\n");

	if((result=PD_Open(0)) < 0)
		DPRINTF("Error %d, result %d opening touch-panel\n", errno, result);

	DPRINTF("Reading touch panel...\n");

	while(1) {
		result = PD_Read(&x, &y, &z, &b);
		if( result > 0) {
			/* DPRINTF("%d,%d,%d,%d,%d\n", result, x, y, z, b); */
		}
	}
}
#endif

