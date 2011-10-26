/*
 * v4l.h
 *
 * Copyright (C) 2001 Rasca, Berlin
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

#ifndef __V4L_H__
#define __V4L_H__

#define INPUT_DEFAULT	-1
#define NORM_DEFAULT	-1

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

int v4l_set_input (int fd, int input, int norm);
int v4l_check_size (int fd, int *width, int *height);
int v4l_check_palette (int fd, int *palette);
int v4l_mute_sound (int fd);
int v4l_check_mmap (int fd, int *size);
int v4l_yuv420p2rgb (unsigned char *, unsigned char *, int, int, int);
int v4l_yuv422p2rgb (unsigned char *, unsigned char *, int, int, int);
#endif
