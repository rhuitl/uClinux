/*      $Id: transmit.c,v 5.5 2000/09/03 14:34:45 columbus Exp $      */

/****************************************************************************
 ** transmit.c **************************************************************
 ****************************************************************************
 *
 * functions that prepare IR codes for transmitting
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "lircd.h"
#include "transmit.h"

extern struct ir_remote *repeat_remote;
struct sbuf send_buffer;

inline void set_bit(ir_code *code,int bit,int data)
{
	(*code)&=~((((ir_code) 1)<<bit));
	(*code)|=((ir_code) (data ? 1:0)<<bit);
}

/*
  sending stuff
*/

void init_send_buffer(void)
{
	memset(&send_buffer,0,sizeof(send_buffer));
}

inline void clear_send_buffer(void)
{
	send_buffer.wptr=0;
	send_buffer.too_long=0;
	send_buffer.is_biphase=0;
	send_buffer.pendingp=0;
	send_buffer.pendings=0;
	send_buffer.sum=0;
}

inline void add_send_buffer(lirc_t data)
{
	if(send_buffer.wptr<WBUF_SIZE)
	{
		send_buffer.sum+=data;
		send_buffer.data[send_buffer.wptr]=data;
		send_buffer.wptr++;
	}
	else
	{
		send_buffer.too_long=1;
	}
}

inline void send_pulse(lirc_t data)
{
	if(send_buffer.pendingp>0)
	{
		send_buffer.pendingp+=data;
	}
	else
	{
		if(send_buffer.pendings>0)
		{
			add_send_buffer(send_buffer.pendings);
			send_buffer.pendings=0;
		}
		send_buffer.pendingp=data;
	}
}

inline void send_space(lirc_t data)
{
	if(send_buffer.wptr==0 && send_buffer.pendingp==0)
	{
		LOGPRINTF(1,"first signal is a space!");
		return;
	}
	if(send_buffer.pendings>0)
	{
		send_buffer.pendings+=data;
	}
	else
	{
		if(send_buffer.pendingp>0)
		{
			add_send_buffer(send_buffer.pendingp);
			send_buffer.pendingp=0;
		}
		send_buffer.pendings=data;
	}
}

static inline int bad_send_buffer(void)
{
	if(send_buffer.too_long!=0) return(1);
	if(send_buffer.wptr==WBUF_SIZE && send_buffer.pendingp>0)
	{
		return(1);
	}
	return(0);
}

static inline void sync_send_buffer(void)
{
	if(send_buffer.pendingp>0)
	{
		add_send_buffer(send_buffer.pendingp);
		send_buffer.pendingp=0;
	}
	if(send_buffer.wptr>0 && send_buffer.wptr%2==0) send_buffer.wptr--;
}

inline void send_header(struct ir_remote *remote)
{
	if(has_header(remote))
	{
		send_pulse(remote->phead);
		send_space(remote->shead);
	}
}

inline void send_foot(struct ir_remote *remote)
{
	if(has_foot(remote))
	{
		send_space(remote->sfoot);
		send_pulse(remote->pfoot);
	}
}

inline void send_lead(struct ir_remote *remote)
{
	if(remote->plead!=0)
	{
		send_pulse(remote->plead);
	}
}

inline void send_trail(struct ir_remote *remote)
{
	if(remote->ptrail!=0)
	{
		send_pulse(remote->ptrail);
	}
}

inline void send_data(struct ir_remote *remote,ir_code data,int bits)
{
	int i;

	data=reverse(data,bits);
	for(i=0;i<bits;i++)
	{
		if(data&1)
		{
			if(is_biphase(remote))
			{
				if(is_rc6(remote) && i+1==remote->toggle_bit)
				{
					send_space(2*remote->sone);
					send_pulse(2*remote->pone);
				}
				else
				{
					send_space(remote->sone);
					send_pulse(remote->pone);
				}
			}
			else
			{
				send_pulse(remote->pone);
				send_space(remote->sone);
			}
		}
		else
		{
			if(is_rc6(remote) && i+1==remote->toggle_bit)
			{
				send_pulse(2*remote->pzero);
				send_space(2*remote->szero);
			}
			else
			{
				send_pulse(remote->pzero);
				send_space(remote->szero);
			}
		}
		data=data>>1;
	}
}

inline void send_pre(struct ir_remote *remote)
{
	if(has_pre(remote))
	{
		ir_code pre;

		pre=remote->pre_data;
		if(remote->toggle_bit>0)
		{
			if(remote->toggle_bit<=remote->pre_data_bits)
			{
				set_bit(&pre,
					remote->pre_data_bits
					-remote->toggle_bit,
					remote->repeat_state);
			}
		}

		send_data(remote,pre,remote->pre_data_bits);
		if(remote->pre_p>0 && remote->pre_s>0)
		{
			send_pulse(remote->pre_p);
			send_space(remote->pre_s);
		}
	}
}

inline void send_post(struct ir_remote *remote)
{
	if(has_post(remote))
	{
		ir_code post;

		post=remote->post_data;
		if(remote->toggle_bit>0)
		{
			if(remote->toggle_bit>remote->pre_data_bits
			   +remote->bits
			   &&
			   remote->toggle_bit<=remote->pre_data_bits
			   +remote->bits
			   +remote->post_data_bits)
			{
				set_bit(&post,
					remote->pre_data_bits
					+remote->bits
					+remote->post_data_bits
					-remote->toggle_bit,
					remote->repeat_state);
			}
		}
		
		if(remote->post_p>0 && remote->post_s>0)
		{
			send_pulse(remote->post_p);
			send_space(remote->post_s);
		}
		send_data(remote,post,remote->post_data_bits);
	}
}

inline void send_repeat(struct ir_remote *remote)
{
	send_lead(remote);
	send_pulse(remote->prepeat);
	send_space(remote->srepeat);
	send_trail(remote);
}

inline void send_code(struct ir_remote *remote,ir_code code)
{
	if(remote->toggle_bit>0)
	{
		if(remote->toggle_bit>remote->pre_data_bits
		   &&
		   remote->toggle_bit<=remote->pre_data_bits
		   +remote->bits)
		{
			set_bit(&code,
				remote->pre_data_bits
				+remote->bits
				-remote->toggle_bit,
				remote->repeat_state);
		}
		else if(remote->toggle_bit>remote->pre_data_bits
			+remote->bits
			+remote->post_data_bits)
		{
			logprintf(LOG_ERR,"bad toggle_bit");
		}
	}

	if(repeat_remote==NULL || !(remote->flags&NO_HEAD_REP))
		send_header(remote);
	send_lead(remote);
	send_pre(remote);
	send_data(remote,code,remote->bits);
	send_post(remote);
	send_trail(remote);
	if(repeat_remote==NULL || !(remote->flags&NO_FOOT_REP))
		send_foot(remote);

	if(repeat_remote==NULL && (remote->flags&(NO_HEAD_REP|CONST_LENGTH)))
	{
		send_buffer.sum-=remote->phead+remote->shead;
	}
}

int init_send(struct ir_remote *remote,struct ir_ncode *code)
{
	if(is_rcmm(remote))
	{
		logprintf(LOG_ERR,"sorry, can't send this protocol yet");
		return(0);
	}
	clear_send_buffer();
	if(is_biphase(remote))
	{
		send_buffer.is_biphase=1;
	}
	
	if(repeat_remote!=NULL && has_repeat(remote))
	{
		if(remote->flags&REPEAT_HEADER && has_header(remote))
		{
			send_header(remote);
		}
		send_repeat(remote);
	}
	else
	{
		if(!is_raw(remote))
		{
			send_code(remote,code->code);
		}
	}
	sync_send_buffer();
	if(bad_send_buffer())
	{
		logprintf(LOG_ERR,"buffer too small");
		return(0);
	}
	if(is_const(remote))
	{
		if(remote->gap>send_buffer.sum)
		{
			remote->remaining_gap=remote->gap
			-send_buffer.sum;
		}
		else
		{
			logprintf(LOG_ERR,"too short gap: %lu",remote->gap);
			remote->remaining_gap=remote->gap;
			return(0);
		}
	}
	else
	{
		if(has_repeat_gap(remote) &&
		   repeat_remote!=NULL &&
		   has_repeat(remote))
		{
			remote->remaining_gap=remote->repeat_gap;
		}
		else
		{
			remote->remaining_gap=remote->gap;
		}
	}
	return(1);
}
