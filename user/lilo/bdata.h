/* bdata.h */
/*
Copyright 2000-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/

#ifndef _BDATA_H
#define _BDATA_H

#define PROBE_VERSION 6

/* GET_VIDEO defines how much video information to retrieve
 *
 *	0 = none
 *	1 = mode info
 *	2 = VGA adapter info
 *	3 = VESA checks, too
 */
#define BD_GET_VIDEO 3

/* maximun number of floppy drives to check for 2 or 4 */
#define BD_MAX_FLOPPY 2

/* maximum number of hard drives to check for 2 to 16  */
#define BD_MAX_HARD 16



#endif	/* _BDATA_H  */
