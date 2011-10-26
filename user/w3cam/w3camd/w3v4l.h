/*
 * w3v4l.h
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

#ifndef __W3V4L_H__
#define __W3V4L_H__

typedef struct {
	int fd;
	int map_size;
	char *mem;	/* memory for the image */
	int width, height;
} video_t;

video_t *v4l_init  (char *, int, int, int);
void   v4l_fini  (video_t *);
int    v4l_image (video_t *);
#endif

