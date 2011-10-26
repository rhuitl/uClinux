/*****************************************************************************/

/*
 *	gettyd.h -- simple getty for support dial in PPP.
 *
 *	(C) Copyright 1999, Greg Ungerer (gerg@snapgear.com).
 * 	(C) Copyright 2000, Lineo Inc. (www.lineo.com)
 */

/*****************************************************************************/
#ifndef gettyd_h
#define	gettyd_h
/*****************************************************************************/

/*
 *	State and configuration info for each dialin line...
 */
struct line {
	char	*device;
	int	pid;
};

/*****************************************************************************/
#endif /* gettyd_h */
