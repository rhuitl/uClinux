/*****************************************************************************/

/*
 *	flatfs3.h -- support for version 3 flat FLASH file systems.
 *
 *	Copyright (C) 1999-2006, Greg Ungerer (gerg@snapgear.com).
 *	Copyright (C) 2001-2002, SnapGear (www.snapgear.com)
 *	Copyright (C) 2005 CyberGuard Corporation (www.cyberguard.com)
 */

/*****************************************************************************/
#ifndef flatfs3_h
#define flatfs3_h
/*****************************************************************************/

/*
 *	Magic numbers used in flat file-system.
 */
#define	FLATFS_MAGIC_V3		0xcafe4567
#define	FLATFS_MAGIC_V4		0xcafe4568

/*
 * Flat file-system header structure. The version 1/2 file entry header
 * is used for each file.
 */
struct flathdr3 {
	unsigned int	magic;
	unsigned int	chksum;
	unsigned int 	nrparts;
	unsigned int	tstamp;
};

struct flatent2 {
	unsigned int	length;
	unsigned int	mode;
	unsigned int	uid;
	unsigned int	gid;
	unsigned int	atime;
	unsigned int	mtime;
};

extern unsigned int flat3_gethdr(void);
extern int flat3_checkfs(void);
extern int flat3_restorefs(int version, int dowrite);
extern int flat3_savefs(int dowrite, unsigned int *total);

/*****************************************************************************/
#endif
