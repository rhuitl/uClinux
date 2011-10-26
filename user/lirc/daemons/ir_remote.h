/*      $Id: ir_remote.h,v 5.17 2001/02/28 17:25:01 columbus Exp $      */

/****************************************************************************
 ** ir_remote.h *************************************************************
 ****************************************************************************
 *
 * ir_remote.h - describes and decodes the signals from IR remotes
 *
 * Copyright (C) 1996,97 Ralph Metzler <rjkm@thp.uni-koeln.de>
 * Copyright (C) 1998 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */ 

#ifndef _IR_REMOTE_H
#define _IR_REMOTE_H

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>

#include <linux/lirc.h>

struct hardware;

#ifdef LONG_IR_CODE
typedef unsigned long long ir_code;
#else
typedef unsigned long ir_code;
#endif

/*
  Code with name string
*/

struct ir_ncode {
	char *name;
	ir_code code;
        int length;
        lirc_t *signals;
};

/*
  struct ir_remote
  defines the encoding of a remote control 
*/

/* definitions for flags */

/* Don't forget to take a look at config_file.h when adding new flags */

#define RC5             0x0001    /* IR data follows RC5 protocol */

/* Hm, RC6 protocols seem to have changed the biphase semantics so
   that lircd will calculate the bit-wise complement of the codes. But
   this is only a guess as I did not have a datasheet... */

#define RC6             0x0002    /* IR data follows RC6 protocol */
#define RCMM            0x0004    /* IR data follows RC-MM protocol */
#define SPACE_ENC	0x0008	  /* IR data is space encoded */
#define REVERSE		0x0010
#define NO_HEAD_REP	0x0020	  /* no header for key repeats */
#define NO_FOOT_REP	0x0040	  /* no foot for key repeats */
#define CONST_LENGTH    0x0080    /* signal length+gap is always constant */
#define RAW_CODES       0x0100    /* for internal use only */
#define REPEAT_HEADER   0x0200    /* header is also sent before repeat code */

#define SHIFT_ENC	   RC5    /* IR data is shift encoded (name obsolete) */

/* stop repeating after 600 signals (approx. 1 minute) */
#define REPEAT_MAX 600

struct ir_remote 
{
	char *name;                 /* name of remote control */
	struct ir_ncode *codes;
	int bits;                   /* bits (length of code) */
	int flags;                  /* flags */
	int eps;                    /* eps (_relative_ tolerance) */
	int aeps;                   /* detecing _very short_ pulses is
				       difficult with relative tolerance
				       for some remotes,
				       this is an _absolute_ tolerance
				       to solve this problem
				       usually you can say 0 here */
	
	/* pulse and space lengths of: */
	
	lirc_t phead,shead;         /* header */
	lirc_t pthree,sthree;       /* 3 (only used for RC-MM) */
	lirc_t ptwo,stwo;           /* 2 (only used for RC-MM) */
	lirc_t pone,sone;           /* 1 */
	lirc_t pzero,szero;         /* 0 */
	lirc_t plead;		    /* leading pulse */
	lirc_t ptrail;              /* trailing pulse */
	lirc_t pfoot,sfoot;         /* foot */
	lirc_t prepeat,srepeat;	    /* indicate repeating */

	int pre_data_bits;          /* length of pre_data */
	ir_code pre_data;           /* data which the remote sends before
				       actual keycode */
	int post_data_bits;         /* length of post_data */
	ir_code post_data;          /* data which the remote sends after
				       actual keycode */
	lirc_t pre_p,pre_s;         /* signal between pre_data and keycode */
	lirc_t post_p, post_s;      /* signal between keycode and post_code */

	lirc_t gap;                 /* time between signals in usecs */
	lirc_t repeat_gap;          /* time between two repeat codes
				       if different from gap */
	int toggle_bit;             /* 1..bits */
	int min_repeat;             /* code is repeated at least x times
				       code sent once -> min_repeat=0 */
	unsigned int freq;          /* modulation frequency */
	unsigned int duty_cycle;    /* 0<duty cycle<=100 */
	
	/* end of user editable values */
	
        int repeat_state;
	int repeat_countdown;
	struct ir_ncode *last_code;
	int reps;
	struct timeval last_send;
	lirc_t remaining_gap;       /* remember gap for CONST_LENGTH remotes */
        struct ir_remote *next;
};

static inline ir_code reverse(ir_code data,int bits)
{
	int i;
	ir_code c;
	
	c=0;
	for(i=0;i<bits;i++)
	{
		c|=(ir_code) (((data & (((ir_code) 1)<<i)) ? 1:0))
						     << (bits-1-i);
	}
	return(c);
}

static inline int is_pulse(lirc_t data)
{
	return(data&PULSE_BIT ? 1:0);
}

static inline int is_space(lirc_t data)
{
	return(!is_pulse(data));
}

static inline int has_repeat(struct ir_remote *remote)
{
	if(remote->prepeat>0 && remote->srepeat>0) return(1);
	else return(0);
}

static inline int is_raw(struct ir_remote *remote)
{
	if(remote->flags&RAW_CODES) return(1);
	else return(0);
}

static inline int is_biphase(struct ir_remote *remote)
{
	if(remote->flags&RC5 || remote->flags&RC6) return(1);
	else return(0);
}

static inline int is_rc5(struct ir_remote *remote)
{
	if(remote->flags&RC5) return(1);
	else return(0);
}

static inline int is_rc6(struct ir_remote *remote)
{
	if(remote->flags&RC6) return(1);
	else return(0);
}

static inline int is_rcmm(struct ir_remote *remote)
{
	if(remote->flags&RCMM) return(1);
	else return(0);
}

static inline int is_const(struct ir_remote *remote)
{
	if(remote->flags&CONST_LENGTH) return(1);
	else return(0);
}

static inline int has_repeat_gap(struct ir_remote *remote)
{
	if(remote->repeat_gap>0) return(1);
	else return(0);
}

static inline int has_pre(struct ir_remote *remote)
{
	if(remote->pre_data_bits>0) return(1);
	else return(0);
}

static inline int has_post(struct ir_remote *remote)
{
	if(remote->post_data_bits>0) return(1);
	else return(0);
}

static inline int has_header(struct ir_remote *remote)
{
	if(remote->phead>0 && remote->shead>0) return(1);
	else return(0);
}

static inline int has_foot(struct ir_remote *remote)
{
	if(remote->pfoot>0 && remote->sfoot>0) return(1);
	else return(0);
}

/* check if delta is inside exdelta +/- exdelta*eps/100 */

static inline int expect(struct ir_remote *remote,lirc_t delta,lirc_t exdelta)
{
	if(abs(exdelta-delta)<exdelta*remote->eps/100 ||
	   abs(exdelta-delta)<remote->aeps)
		return 1;
	return 0;
}

static inline unsigned long time_elapsed(struct timeval *last,
					 struct timeval *current)
{
	unsigned long secs,usecs,diff;
	
	secs=current->tv_sec-last->tv_sec;
	usecs=current->tv_usec-last->tv_usec;
	
	diff=1000000*secs+usecs;
	
	return(diff);
}

static inline ir_code gen_mask(int bits)
{
	int i;
	ir_code mask;

	mask=0;
	for(i=0;i<bits;i++)
	{
		mask<<=1;
		mask|=1;
	}
	return(mask);
}

static inline int map_code(struct ir_remote *remote,
			   ir_code *prep,ir_code *codep,ir_code *postp,
			   int pre_bits,ir_code pre,
			   int bits,ir_code code,
			   int post_bits,ir_code post)
{
	ir_code all;
	
	if(pre_bits+bits+post_bits!=
	   remote->pre_data_bits+remote->bits+remote->post_data_bits)
	{
		return(0);
	}
	all=(pre&gen_mask(pre_bits));
	all<<=bits;
	all|=(code&gen_mask(bits));
	all<<=post_bits;
	all|=(post&gen_mask(post_bits));
	
	*postp=(all&gen_mask(remote->post_data_bits));
	all>>=remote->post_data_bits;
	*codep=(all&gen_mask(remote->bits));
	all>>=remote->bits;
	*prep=(all&gen_mask(remote->pre_data_bits));
	return(1);
}

struct ir_remote *get_ir_remote(struct ir_remote *remotes,char *name);
struct ir_ncode *get_ir_code(struct ir_remote *remote,char *name);
struct ir_ncode *get_code(struct ir_remote *remote,
			  ir_code pre,ir_code code,ir_code post,
			  int *toggle_bit);
unsigned long long set_code(struct ir_remote *remote,struct ir_ncode *found,
			    int repeat_state,int repeat_flag,
			    lirc_t remaining_gap);
char *decode_all(struct ir_remote *remotes);

#endif
