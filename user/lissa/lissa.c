/* lissa.c: Graphics demos
 *
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <sys/types.h>
#include <linux/fb.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <mathf.h>


char * device = "/dev/fb0";

struct fb_var_screeninfo screeninfo;
int screen_fd;
unsigned char * screen_ptr;
int screen_width;
int screen_height;

inline void draw_pixel(int x, int y, int color)
{
	int mask = 1 << (7-(x % 8));
	unsigned char * loc = screen_ptr + (y * screen_width / 8) + x / 8;
	
	if ((x<0) || (x>=screen_width) || (y<0) || (y>=screen_height))
		return;
	
	if (color)
		*loc |= mask;
	else
		*loc &= ~mask;
}

/* Abrash's take on the simplest Bresenham line-drawing algorithm. 
 *
 * This isn't especially efficient, as we aren't combining the bit-mask
 * logic and addresses with the line drawing code, never mind higher
 * level optimizations like run-length slicing, etc.
 *
 */

inline void draw_xish_line(int x, int y, int dx, int dy, int xdir, int color)
{
	int dyX2;
	int dyX2mdxX2;
	int error;
	
	dyX2 = dy * 2;
	dyX2mdxX2 = dyX2 - (dx * 2);
	error = dyX2 - dx;
	
	draw_pixel(x, y, color);
	while (dx--) {
		if (error >= 0) {
			y++;
			error += dyX2mdxX2;
		} else {
			error += dyX2;
		}
		x += xdir;
		draw_pixel(x,y, color);
	}
}

inline void draw_yish_line(int x, int y, int dx, int dy, int xdir, int color)
{
	int dxX2;
	int dxX2mdyX2;
	int error;
	
	dxX2 = dx * 2;
	dxX2mdyX2 = dxX2 - (dy * 2);
	error = dxX2 - dy;
	
	draw_pixel(x, y, color);
	while (dy--) {
		if (error >= 0) {
			x+= xdir;
			error += dxX2mdyX2;
		} else {
			error += dxX2;
		}
		y++;
		draw_pixel(x,y, color);
	}
}

void draw_line(int x1, int y1, int x2, int y2, int color)
{
	int dx,dy;
	
	if ( y1 > y2) {
		int t = y1;
		y1 = y2;
		y2 = t;
		t = x1;
		x1 = x2;
		x2 = t;
	}
	
	dx = x2-x1;
	dy = y2-y1;
	
	if (dx > 0) {
		if (dx > dy)
			draw_xish_line(x1, y1, dx, dy, 1, color);
		else
			draw_yish_line(x1, y1, dx, dy, 1, color);
	} else {
		dx = -dx;
		if (dx > dy)
			draw_xish_line(x1, y1, dx, dy, -1, color);
		else
			draw_yish_line(x1, y1, dx, dy, -1, color);
	}
	
	
}

/* One of Abrash's ellipse algorithms  */

void draw_ellipse(int x, int y, int a, int b, int color)
{
	int wx, wy;
	int thresh;
	int asq = a * a;
	int bsq = b * b;
	int xa, ya;
	
	draw_pixel(x, y+b, color);
	draw_pixel(x, y-b, color);
	
	wx = 0;
	wy = b;
	xa = 0;
	ya = asq * 2 * b;
	thresh = asq / 4 - asq * b;
	
	for (;;) {
		thresh += xa + bsq;
		
		if (thresh >= 0) {
			ya -= asq * 2;
			thresh -= ya;
			wy--;
		}
		
		xa += bsq * 2;
		wx++;
		
		if (xa >= ya)
		  break;
		
		
		draw_pixel(x+wx, y-wy, color);
		draw_pixel(x-wx, y-wy, color);
		draw_pixel(x+wx, y+wy, color);
		draw_pixel(x-wx, y+wy, color);
	}
	
	draw_pixel(x+a, y, color);
	draw_pixel(x-a, y, color);
	
	wx = a;
	wy = 0;
	xa = bsq * 2 * a;
	
	ya = 0;
	thresh = bsq / 4 - bsq * a;
	
	for (;;) {
		thresh += ya + asq;
		
		if (thresh >= 0) {
			xa -= bsq * 2;
			thresh = thresh - xa;
			wx--;
		}
		
		ya += asq * 2;
		wy++;
		
		if (ya > xa)
		  break;
		 
		draw_pixel(x+wx, y-wy, color);
		draw_pixel(x-wx, y-wy, color);
		draw_pixel(x+wx, y+wy, color);
		draw_pixel(x-wx, y+wy, color);
	}
}

/* Composites */

void draw_rectangle(int x1, int y1, int x2, int y2, int color)
{
	draw_line(x1, y1, x2, y1, color);
	draw_line(x2, y1, x2, y2, color);
	draw_line(x2, y2, x1, y2, color);
	draw_line(x1, y2, x1, y1, color);
}

void draw_filled_rectangle(int x1, int y1, int x2, int y2, int color)
{
	int y;
	if (y1>y2) {
		y = y2;
		y2 = y1;
		y1 = y;
	}
	for (y=y1;y<y2;y++)
		draw_line(x1, y, x2, y, color);
}

/* Sketch out a Lissajous figure using a moving path of blips */

void draw_lissajous(void)
{
	float t, a, b, d, n, ap, bp;
	int x, y;
	
	static struct {int x, y;} keep[400];
	
	int pos=0;
	
	
	n = M_PIf;
	d = 0.1;
	
	ap = screen_width/2;
	bp = screen_width/2;
	a = screen_width / M_PIf;
	b = screen_height / M_PIf;
	
	
	for (t=0.0; t<50.0; t+=0.04) {
		x = ap + a * cos(t);
		y = bp + b * sin(n * t - d);
		
		draw_rectangle(keep[pos].x-1, keep[pos].y-1, keep[pos].x+1, keep[pos].y+1, 0);
		keep[pos].x = x;
		keep[pos].y = y;
		pos = (pos + 1) % 100;;

		draw_rectangle(x-1, y-1, x+1, y+1, 1);
		draw_pixel(x, y, 0);

	}
}

int main(int argc, char *argv[])
{
	int i;
	
	screen_fd = open(device, O_RDWR);
	if (screen_fd == -1) {
		perror("Unable to open frame buffer device /dev/fb0");
		exit(-1);
	}
	
	
	if (ioctl(screen_fd, FBIOGET_VSCREENINFO, &screeninfo)==-1) {
		perror("Unable to retrieve framebuffer information");
		exit(0);
	}
	screen_width = screeninfo.xres_virtual;
	screen_height = screeninfo.yres_virtual;
	
	screen_ptr = mmap(0, screen_height * screen_width / 8, PROT_READ|PROT_WRITE, MAP_SHARED, screen_fd, 0);
	
	if (screen_ptr==MAP_FAILED) {
		perror("Unable to mmap frame buffer");
		close (screen_fd);
		exit (errno);
	}
	
	draw_filled_rectangle(0,0, screen_width-1, screen_height-1, 1);
	draw_filled_rectangle(1,1, screen_width-2, screen_height-2, 0);

	draw_lissajous();

	close(screen_fd);
	
	return 0;
}

