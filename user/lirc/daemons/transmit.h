/*      $Id: transmit.h,v 5.3 2000/09/03 14:34:45 columbus Exp $      */

/****************************************************************************
 ** transmit.h **************************************************************
 ****************************************************************************
 *
 * functions that prepare IR codes for transmitting
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifndef _TRANSMIT_H
#define _TRANSMIT_H

#include "ir_remote.h"

#define WBUF_SIZE (256)

struct sbuf
{
	lirc_t data[WBUF_SIZE];
	int wptr;
	int too_long;
	int is_biphase;
	lirc_t pendingp;
	lirc_t pendings;
	lirc_t sum;
};

static inline lirc_t time_left(struct timeval *current,struct timeval *last,
			lirc_t gap)
{
	unsigned long secs,usecs,diff;
	
	secs=current->tv_sec-last->tv_sec;
	usecs=current->tv_usec-last->tv_usec;
	
	diff=1000000*secs+usecs;
	
	return((lirc_t) (diff<gap ? gap-diff:0));
}

void init_send_buffer(void);
inline void set_bit(ir_code *code,int bit,int data);
int init_send(struct ir_remote *remote,struct ir_ncode *code);

extern struct sbuf send_buffer;

#endif
