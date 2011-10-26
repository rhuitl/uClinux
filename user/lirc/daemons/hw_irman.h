/*      $Id: hw_irman.h,v 5.1 1999/09/06 14:56:04 columbus Exp $      */

/****************************************************************************
 ** hw_irman.h **************************************************************
 ****************************************************************************
 *
 * routines for Irman
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifndef _HW_IRMAN_H
#define _HW_IRMAN_H

#include <linux/lirc.h>

int irman_decode(struct ir_remote *remote,
		  ir_code *prep,ir_code *codep,ir_code *postp,
		  int *repeat_flagp,lirc_t *remaining_gapp);
int irman_init(void);
int irman_deinit(void);
char *irman_rec(struct ir_remote *remotes);

#endif
