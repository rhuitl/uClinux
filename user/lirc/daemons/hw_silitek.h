/****************************************************************************
 ** hw_silitek.h ************************************************************
 ****************************************************************************
 *
 * routines for Silitek receiver
 *
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *	modified for logitech receiver by Isaac Lauer <inl101@alumni.psu.edu>
 *	        modified for silitek receiver by Krister Wicksell <krister.wicksell@spray.se>
 */

#ifndef _HW_SILITEK_H
#define _HW_SILITEK_H

#include <linux/lirc.h>

int silitek_decode(struct ir_remote *remote,
		  ir_code *prep,ir_code *codep,ir_code *postp,
		  int *repeat_flagp,lirc_t *remaining_gapp);
int silitek_init(void);
int silitek_deinit(void);
char *silitek_rec(struct ir_remote *remotes);

#endif
