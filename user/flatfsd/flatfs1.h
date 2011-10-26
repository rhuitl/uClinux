/*****************************************************************************/

/*
 *	flatfs1.h -- support for version 1 flat FLASH file systems.
 *
 *	(C) Copyright 1999, Greg Ungerer (gerg@snapgear.com).
 *	(C) Copyright 2000, Lineo Inc. (www.lineo.com)
 *	(C) Copyright 2001-2002, SnapGear (www.snapgear.com)
 */

/*****************************************************************************/
#ifndef flatfs1_h
#define flatfs1_h
/*****************************************************************************/

/*
 *	Magic numbers used in flat file-system.
 */
#define	FLATFS_MAGIC	0xcafe1234
#define	FLATFS_MAGIC_V2	0xcafe2345
#define	FLATFS_EOF	0xffffffff

/*
 * Flat file-system header structures.
 */
struct flathdr1 {
	unsigned int	magic;
	unsigned int	chksum;
};

struct flatent {
	unsigned int	namelen;
	unsigned int	filelen;
};


extern unsigned int flat1_gethdr(void);
extern int flat1_checkfs(void);
extern int flat1_restorefs(int version, int dowrite);
extern int flat1_savefs(int dowrite, unsigned int *total);

/*****************************************************************************/
#endif
