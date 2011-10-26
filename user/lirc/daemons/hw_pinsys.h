
/****************************************************************************
 ** hw_pinsys.h *************************************************************
 ****************************************************************************
 *
 * adapted routines for Pinnacle Systems PCTV (pro) receiver
 * 
 * Original routines from hw_pixelview.h :
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 * Adapted by Bart Alewijnse <scarfman@geocities.com>
 */

#ifndef _HW_PINSYS_H
#define _HW_PINSYS_H

#include <linux/lirc.h>

int is_it_is_it_huh(int port);
int autodetect(void);

int pinsys_decode(struct ir_remote *remote,
		  ir_code *prep,ir_code *codep,ir_code *postp,
		  int *repeat_flagp,lirc_t *remaining_gapp);
int pinsys_init(void);
int pinsys_deinit(void);
char *pinsys_rec(struct ir_remote *remotes);

#endif








