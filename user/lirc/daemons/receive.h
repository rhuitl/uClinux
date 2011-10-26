/*      $Id: receive.h,v 5.3 2000/09/03 14:34:45 columbus Exp $      */

/****************************************************************************
 ** receive.h ***************************************************************
 ****************************************************************************
 *
 * functions that decode IR codes
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */


#ifndef _RECEIVE_H
#define _RECEIVE_H

#include "ir_remote.h"

#define RBUF_SIZE (256)

#define REC_SYNC 8

struct rbuf
{
	lirc_t data[RBUF_SIZE];
	ir_code decoded;
	int rptr;
	int wptr;
	int too_long;
	int is_biphase;
	lirc_t pendingp;
	lirc_t pendings;
	lirc_t sum;
};

inline lirc_t lirc_t_max(lirc_t a,lirc_t b);
void init_rec_buffer();
int clear_rec_buffer(void);
int receive_decode(struct ir_remote *remote,
		   ir_code *prep,ir_code *codep,ir_code *postp,
		   int *repeat_flag,lirc_t *remaining_gapp);
int clear_rec_buffer(void);
void rewind_rec_buffer(void);

#endif
