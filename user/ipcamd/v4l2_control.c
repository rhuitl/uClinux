/*
This file is part of ipcamd, an embedded web server for IP cameras.

Copyright (c) 2011-2013, Robert Huitl <robert@huitl.de>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "v4l2_control.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <linux/videodev2.h>
#include <sys/ioctl.h>

extern int fd;

int ctrl_get_value(int control_id)
{
	struct v4l2_control control;

	memset (&control, 0, sizeof (control));
	control.id = control_id;

	if (0 != ioctl (fd, VIDIOC_G_CTRL, &control)) {
		perror ("VIDIOC_G_CTRL");
		exit (EXIT_FAILURE);
	}

	return control.value;
}

void ctrl_set_value(int control_id, int val)
{
	struct v4l2_control control;

	memset (&control, 0, sizeof (control));
	control.id = control_id;
	control.value = val;

	if (0 != ioctl (fd, VIDIOC_S_CTRL, &control)) {
		perror ("VIDIOC_S_CTRL");
		exit (EXIT_FAILURE);
	}
}

int jpeg_get_quality()
{
	struct v4l2_jpegcompression jpegcompression;
	memset(&jpegcompression, 0, sizeof (jpegcompression));

	if (0 != ioctl(fd, VIDIOC_G_JPEGCOMP, &jpegcompression)) {
		perror("VIDIOC_G_JPEGCOMP");
		exit(EXIT_FAILURE);
	}

	return jpegcompression.quality;
}

void jpeg_set_quality(int quality)
{
	struct v4l2_jpegcompression jpegcompression;
	memset(&jpegcompression, 0, sizeof (jpegcompression));

	if (0 != ioctl(fd, VIDIOC_G_JPEGCOMP, &jpegcompression)) {
		perror("VIDIOC_G_JPEGCOMP");
		exit(EXIT_FAILURE);
	}

	jpegcompression.quality = quality;
	if (0 != ioctl(fd, VIDIOC_S_JPEGCOMP, &jpegcompression)) {
		perror("VIDIOC_S_JPEGCOMP");
		exit(EXIT_FAILURE);
	}
}

#ifdef ENUM_CONTROLS

/*
struct image_ctrls_s
{
	int id, min, max, default_val;
};
struct image_ctrls_s image_ctrls[6];

#define IMAGE_CTRL_BRIGHTNESS  0
#define IMAGE_CTRL_CONTRAST    1
#define IMAGE_CTRL_GAMMA       2
#define IMAGE_CTRL_AUOGAIN     3
#define IMAGE_CTRL_LIGHTFILTER 4
#define IMAGE_CTLR_SHARPNESS   5
*/

static const char* ctrl_type_names[] = {
		"woo", "int", "bool", "menu", "button", "int64", "ctrl", "string"};

static void enumerate_menu(struct v4l2_queryctrl* queryctrl)
{
	struct v4l2_querymenu querymenu;
	memset(&querymenu, 0, sizeof (querymenu));
	querymenu.id = queryctrl->id;

	printf("Menu items:\n");

	for(querymenu.index = queryctrl->minimum; querymenu.index <= queryctrl->maximum;
		querymenu.index++) {
		if (0 == ioctl(fd, VIDIOC_QUERYMENU, &querymenu)) {
			printf("  %s\n", querymenu.name);
		} else {
			perror("VIDIOC_QUERYMENU");
			exit(EXIT_FAILURE);
		}
	}
}

void enumerate_controls()
{
	struct v4l2_queryctrl queryctrl;
	memset(&queryctrl, 0, sizeof(queryctrl));

	for (queryctrl.id = V4L2_CID_BASE; queryctrl.id < V4L2_CID_LASTP1; queryctrl.id++) {
		if (0 == ioctl(fd, VIDIOC_QUERYCTRL, &queryctrl)) {
			if (queryctrl.flags & V4L2_CTRL_FLAG_DISABLED)
				continue;

			int val = ctrl_get_value(queryctrl.id);
			printf("Control %s, type: %s (%d), value: %d, range: [%d %d], default: %d, step: %d, flags: 0x%x\n",
				   queryctrl.name, ctrl_type_names[queryctrl.type],
				   queryctrl.type, val, queryctrl.minimum, queryctrl.maximum,
				   queryctrl.default_value, queryctrl.step, queryctrl.flags);

			if (queryctrl.type == V4L2_CTRL_TYPE_MENU)
				enumerate_menu(&queryctrl);
		} else {
			if (errno == EINVAL)
				continue;

			perror("VIDIOC_QUERYCTRL");
			exit(EXIT_FAILURE);
		}
	}

	/* private controls (if any)
	for (queryctrl.id = V4L2_CID_PRIVATE_BASE;; queryctrl.id++) {
		...
	}*/

	int jpeg_quality = jpeg_get_quality();
	printf("JPEG quality is %d\n", jpeg_quality);
}
#endif
