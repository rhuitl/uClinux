/* edit.h -- declarations for bitmap file parameter block editing */
/*
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#ifndef EDIT_H
#define EDIT_H

#include "common.h"
#include "bitmap.h"
#define semi (temp_check(CSOURCE)?"":".")

int get_std_headers(int fd,
	BITMAPFILEHEADER *fh,
	BITMAPHEADER *bmh,
	BITMAPLILOHEADER *lh);


int put_std_bmpfile(int fd, int ifd,
	BITMAPFILEHEADER *fh,
	BITMAPHEADER *bmh,
	BITMAPLILOHEADER *lh);
	
void do_bitmap_edit(char *bitmap_file);
	
#endif
