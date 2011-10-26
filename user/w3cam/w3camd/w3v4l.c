/*
 * w3v4l.c
 *
 * Copyright (C) 1998 - 2000 Rasca, Berlin
 * EMail: thron@gmx.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <linux/videodev.h>
#include "w3v4l.h"

/*
 */
video_t *
v4l_init (char *dev, int input, int width, int height)
{
	int fd;
	struct video_capability vid_caps;
	struct video_mbuf vid_mbuf;
	struct video_channel vid_chnl;
	video_t *vid;

	fd = open (dev, O_RDWR);
	if (fd == -1) {
		perror (dev);
		return (NULL);
	}
	if (ioctl (fd, VIDIOCGCAP, &vid_caps) == -1) {
		perror ("ioctl (VIDIOCGCAP)");
		return (NULL);
	}

	vid = malloc (sizeof (video_t));
	vid->fd = fd;
	if (ioctl (fd, VIDIOCGMBUF, &vid_mbuf) == -1) {
		struct video_window vid_win;
		vid->map_size = 0;
		if (ioctl(fd, VIDIOCGWIN, &vid_win) != -1) {
			vid_win.width = width;
			vid_win.height= height;
			ioctl (fd, VIDIOCSWIN, &vid_win);
		}
	} else {
		vid->map_size = vid_mbuf.size;
	}
#ifdef DEBUG
	printf ("%s: mbuf.size=%d\n", __FILE__, vid_mbuf.size);
#endif

	if (input > -1) {
		vid_chnl.channel = input;
		if (ioctl (fd, VIDIOCGCHAN, &vid_chnl) == -1) {
			perror ("ioctl (VIDIOCGCHAN)");
		} else {
			vid_chnl.channel = input;
			if (ioctl (fd, VIDIOCSCHAN, &vid_chnl) == -1) {
				perror ("ioctl (VIDIOCSCHAN)");
			}
		}
	}
	if (vid->map_size > 0) {
		vid->mem = mmap (0,vid->map_size, PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
		if ((unsigned char *) -1 == (unsigned char *)vid->mem) {
			perror ("mmap()");
			close (fd);
			free (vid);
			return (NULL);
		}
	} else {
		vid->mem = malloc (width * height * 3);
	}
	vid->width = width;
	vid->height= height;
	return (vid);
}

/*
 */
void
v4l_fini (video_t *vid)
{
	if (vid->fd >= 0) {
		if (vid->map_size == 0)
			free (vid->mem);
		else
			munmap (vid->mem, vid->map_size);
		close (vid->fd);
	}
	free (vid);
}

/*
 * return a new image
 */
int
v4l_image (video_t *vid)
{
	struct video_mmap vid_mmap;

	if (vid->map_size == 0) {
		printf ("%s: reading image .. \n", __FILE__);
		if (read (vid->fd, vid->mem, vid->width * vid->height * 3) <= 0) {
			free (vid->mem);
			return (0);
		}
	} else {
		vid_mmap.format = VIDEO_PALETTE_RGB24;
		vid_mmap.frame = 0;
		vid_mmap.width = vid->width;
		vid_mmap.height= vid->height;
		if (ioctl (vid->fd, VIDIOCMCAPTURE, &vid_mmap) == -1) {
			perror ("ioctl (VIDIOCMCAPTURE)");
			return (0);
		}
		if (ioctl (vid->fd, VIDIOCSYNC, &vid_mmap) == -1) {
			perror ("ioctl (VIDIOCSYNC)");
			return (0);
		}
	}
	printf ("%s: done\n", __FILE__);
	return (1);
}

