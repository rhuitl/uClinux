/*
 * Microwindows touch screen driver for uClinux touch screen palm/mc68ez328
 * driver.
 *
 * Requires /dev/ts kernel driver (char special 10,9)
 *
 * Copyright (C) Lineo, davidm@lineo.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/mc68328digi.h>
#include "device.h"

/* file descriptor for touch panel */
static int pd_fd = -1;
static int pd_down = 0; /* pen down */

/* Hack extern to used when hiding the mouse cursor
 * There needs to be a better way to do this
*/
extern SCREENDEVICE scrdev;

static int PD_Open(MOUSEDEVICE *pmd)
{
	int err;
	struct ts_drv_params  drv_params;
	int mx1, mx2, my1, my2;
	int ux1, ux2, uy1, uy2;

 	/*
	 * open up the touch-panel device.
	 * Return the fd if successful, or negative if unsuccessful.
	 */

	pd_fd = open("/dev/ts", O_NONBLOCK | O_RDWR);
	if (pd_fd < 0) {
		EPRINTF("Error %d opening touch panel\n", errno);
		return -1;
	}

	err = ioctl(pd_fd, TS_PARAMS_GET, &drv_params);
	if (err == -1) {
		close(pd_fd);
		return(err);
	}

	drv_params.version_req    = MC68328DIGI_VERSION;
	drv_params.event_queue_on = 1;
	drv_params.deglitch_ms    = 0;
	drv_params.sample_ms      = 10;
	drv_params.follow_thrs    = 0;
	drv_params.mv_thrs        = 2;
	drv_params.y_max          = 159 + 66;  // to allow scribble area
	drv_params.y_min          = 0;
	drv_params.x_max          = 159;
	drv_params.x_min          = 0;
	drv_params.xy_swap        = 0;

	// according to mc68328digi.h 'How to calculate the parameters', we have
	// measured:
	mx1 = 508; ux1 =   0;
	my1 = 508; uy1 =   0;
	mx2 = 188; ux2 = 159;
	my2 = 188; uy2 = 159;

	// now calculate the params:
	drv_params.x_ratio_num    = ux1 - ux2;
	drv_params.x_ratio_den    = mx1 - mx2;
	drv_params.x_offset       =
	ux1 - mx1 * drv_params.x_ratio_num / drv_params.x_ratio_den;

	drv_params.y_ratio_num    = uy1 - uy2;
	drv_params.y_ratio_den    = my1 - my2;
	drv_params.y_offset       =
	uy1 - my1 * drv_params.y_ratio_num / drv_params.y_ratio_den;

	err = ioctl(pd_fd, TS_PARAMS_SET, &drv_params);
	if (err == -1) {
		close(pd_fd);
		return(err);
	}

	GdHideCursor(&scrdev);
	return pd_fd;
}

static void PD_Close(void)
{
 	/* Close the touch panel device. */
	EPRINTF("PD_Close called\n");
	if (pd_fd >= 0)
		close(pd_fd);
	pd_fd = -1;
}

static int PD_GetButtonInfo(void)
{
 	/* get "mouse" buttons supported */
	return MWBUTTON_L;
}

static void PD_GetDefaultAccel(int *pscale,int *pthresh)
{
	/*
	 * Get default mouse acceleration settings
	 * This doesn't make sense for a touch panel.
	 * Just return something inconspicuous for now.
	 */
	*pscale = 1;
	*pthresh = 1;
}

static int PD_Read(MWCOORD *px, MWCOORD *py, MWCOORD *pz, int *pb)
{
	struct ts_pen_info    pen_info;
	int bytes_read;
	static int old_x = 79, old_y = 79; /* we start in the middle */

	bytes_read = read(pd_fd, &pen_info, sizeof(pen_info));

	if (bytes_read != sizeof(pen_info)) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;
		/*
		 * kernel driver bug: select returns read available,
		 * but read returns -1
		 * we return 0 here to avoid GsError above
		 */
		/*return -1;*/
		return 0;
	}

    switch(pen_info.event) {
    case EV_PEN_UP:
		*pb = 0;
		*px = pen_info.x - old_x;
		*py = pen_info.y - old_y;
		break;
    case EV_PEN_DOWN:
		*pb = MWBUTTON_L;
		*px = pen_info.x - old_x;
		*py = pen_info.y - old_y;
		break;
    case EV_PEN_MOVE:
		*pb = MWBUTTON_L;
		// *px = pen_info.dx;
		// *py = pen_info.dy;
		*px = pen_info.x - old_x;
		*py = pen_info.y - old_y;
		break;
	}
	*pz = 0;

	old_x = pen_info.x;
	old_y = pen_info.y;

	return 1;
}

MOUSEDEVICE mousedev = {
	PD_Open,
	PD_Close,
	PD_GetButtonInfo,
	PD_GetDefaultAccel,
	PD_Read,
	NULL
};

