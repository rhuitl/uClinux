/*      $Id: hw_logitech.h,v 1.3 1999/09/06 14:56:04 columbus Exp $      */

/****************************************************************************
 ** hw_logitech.h **********************************************************
 ****************************************************************************
 *
 * routines for Logitech receiver 
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *	modified for logitech receiver by Isaac Lauer <inl101@alumni.psu.edu>
 */

#ifndef _HW_LOGITECH_H
#define _HW_LOGITECH_H

#include <linux/lirc.h>

int logitech_decode(struct ir_remote *remote,
		  ir_code *prep,ir_code *codep,ir_code *postp,
		  int *repeat_flagp,lirc_t *remaining_gapp);
int logitech_init(void);
int logitech_deinit(void);
char *logitech_rec(struct ir_remote *remotes);

#endif
