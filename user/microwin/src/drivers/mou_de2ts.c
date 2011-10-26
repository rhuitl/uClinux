/*
 * Microwindows touch screen driver for DragonEngine uClinux
 *
 * Requires /dev/ts kernel driver
 *
 * Copyright (C) 2003 Georges Ménie
 *
 * modified from mou_ucts.c
 * Copyright (C) Lineo, davidm@lineo.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/de2ts.h>
#include "device.h"

/* set to 0 if you don't want to read the calibration
 * data from the eeprom.
 */
#define EEPROM_STORED_CALDATA 1

/* file descriptor for touch panel */
static int de2ts_fd = -1;

/* Hack extern to used when hiding the mouse cursor
 * There needs to be a better way to do this
*/
extern SCREENDEVICE scrdev;

#if EEPROM_STORED_CALDATA

#define EEPROM_CAL_MAGIC 0xbebe2003

static struct {
	int magic;
	struct de2ts_cal_params prm;
	unsigned short cksum;
} eep_stored_prm;

static int read_eeprom_param(void)
{
	int eep_fd, count;
	unsigned short cks;

	eep_fd = open("/dev/eeprom", O_RDONLY);
	if (eep_fd < 0) {
		EPRINTF("Error opening eeprom\n");
		return -1;
	}

	/* calibration data are stored at the end of the eeprom */
	if (lseek(eep_fd, -sizeof eep_stored_prm, SEEK_END) < 0) {
		EPRINTF("Error seeking eeprom\n");
		close(eep_fd);
		return -1;
	}

	count = read(eep_fd, &eep_stored_prm, sizeof eep_stored_prm);
	if (count != sizeof eep_stored_prm) {
		EPRINTF("Error reading eeprom\n");
		close(eep_fd);
		return -1;
	}

	close(eep_fd);

	if (eep_stored_prm.magic != EEPROM_CAL_MAGIC) {
		EPRINTF("Error reading eeprom: bad magic number\n");
		return -1;
	}

	for (count = cks = 0; count < sizeof eep_stored_prm/2; ++count) {
		cks += *(((unsigned short *) &eep_stored_prm) + count);
	}

	if (cks) {
		EPRINTF("Error reading eeprom: bad checksum\n");
		return -1;
	}

	return 0;
}

#endif

static void DE2TS_Close(void)
{
	if (de2ts_fd >= 0)
		close(de2ts_fd);
	de2ts_fd = -1;
}

static int DE2TS_Open(MOUSEDEVICE *pmd)
{
	struct de2ts_cal_params drv_params;

#if EEPROM_STORED_CALDATA
	if (read_eeprom_param() == 0) {
		drv_params = eep_stored_prm.prm;
	} else
#endif
	{
		/* use reasonnable default */
		drv_params.version = DE2TS_VERSION;
		drv_params.xoff = 500;
		drv_params.xden = 2840;
		drv_params.yoff = 3484;
		drv_params.yden = -3129;
		drv_params.xrng = 320;
		drv_params.yrng = 240;
	}

 	/*
	 * open up the touch-panel device.
	 * Return the fd if successful, or negative if unsuccessful.
	 */

	de2ts_fd = open("/dev/ts", O_NONBLOCK | O_RDWR);
	if (de2ts_fd < 0) {
		EPRINTF("Error %d opening touch panel\n", errno);
		return -1;
	}

	if (ioctl(de2ts_fd, DE2TS_CAL_PARAMS_SET, &drv_params) < 0) {
		EPRINTF("Unable to set touchscreen information\n");
		DE2TS_Close();
		return -1;
	}

	GdHideCursor(&scrdev);
	return de2ts_fd;
}

static int DE2TS_GetButtonInfo(void)
{
 	/* get "mouse" buttons supported */
	return MWBUTTON_L;
}

static void DE2TS_GetDefaultAccel(int *pscale,int *pthresh)
{
	/*
	 * Get default mouse acceleration settings
	 * This doesn't make sense for a touch panel.
	 * Just return something inconspicuous for now.
	 */
	*pscale = 1;
	*pthresh = 1;
}

static int DE2TS_Read(MWCOORD *px, MWCOORD *py, MWCOORD *pz, int *pb)
{
	struct de2ts_event ev;
	int bytes_read;
	static MWCOORD old_x, old_y;
	static int init = 0;

	bytes_read = read(de2ts_fd, &ev, sizeof(struct de2ts_event));

	if (bytes_read != sizeof(struct de2ts_event)) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;
		/*
		 * kernel driver bug: select returns read available,
		 * but read returns -1
		 * we return 0 here to avoid GsError above
		 */
		return 0;
	}

	if (!init) {
		GdGetCursorPos(&old_x, &old_y);
		init = 1;
	}

    switch(ev.event) {
    case EV_PEN_UP:
		*pb = 0;
		*px = ev.x - old_x;
		*py = ev.y - old_y;
		break;
    case EV_PEN_DOWN:
		*pb = MWBUTTON_L;
		*px = ev.x - old_x;
		*py = ev.y - old_y;
		break;
    case EV_PEN_MOVE:
		*pb = MWBUTTON_L;
		*px = ev.x - old_x;
		*py = ev.y - old_y;
		break;
	}
	*pz = 0;

	old_x = ev.x;
	old_y = ev.y;

	return 1;
}

MOUSEDEVICE mousedev = {
	DE2TS_Open,
	DE2TS_Close,
	DE2TS_GetButtonInfo,
	DE2TS_GetDefaultAccel,
	DE2TS_Read,
	NULL
};
