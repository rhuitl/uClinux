/*      $Id: hardware.h,v 5.3 2000/12/08 23:36:29 columbus Exp $      */

/****************************************************************************
 ** hardware.h **************************************************************
 ****************************************************************************
 *
 * hardware.h - internal hardware interface
 *
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */ 

#ifndef _HARDWARE_H
#define _HARDWARE_H

#include <linux/lirc.h>
#include "ir_remote.h"

struct hardware
{
	char *device;
	int fd;
	unsigned long features;
	unsigned long send_mode;
	unsigned long rec_mode;
	unsigned long code_length;
	int (*init_func)(void);
	int (*deinit_func)(void);
	int (*send_func)(struct ir_remote *remote,struct ir_ncode *code);
	char *(*rec_func)(struct ir_remote *remotes);
	int (*decode_func)(struct ir_remote *remote,
			   ir_code *prep,ir_code *codep,ir_code *postp,
			   int *repeat_flag,lirc_t *remaining_gapp);
};

#endif
