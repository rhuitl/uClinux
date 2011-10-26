/*      $Id: receive.c,v 5.6 2000/09/03 14:34:45 columbus Exp $      */

/****************************************************************************
 ** receive.c ***************************************************************
 ****************************************************************************
 *
 * functions that decode IR codes
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "hardware.h"
#include "lircd.h"
#include "receive.h"

lirc_t readdata(void);

extern struct hardware hw;
extern struct ir_remote *last_remote;

struct rbuf rec_buffer;

inline lirc_t lirc_t_max(lirc_t a,lirc_t b)
{
	return(a>b ? a:b);
}

lirc_t get_next_rec_buffer(unsigned long maxusec)
{
	if(rec_buffer.rptr<rec_buffer.wptr)
	{
		LOGPRINTF(3,"<%lu",(unsigned long)
			  rec_buffer.data[rec_buffer.rptr]&(PULSE_MASK));
		rec_buffer.sum+=rec_buffer.data[rec_buffer.rptr]&(PULSE_MASK);
		return(rec_buffer.data[rec_buffer.rptr++]);
	}
	else
	{
		if(rec_buffer.wptr<RBUF_SIZE)
		{
			lirc_t data;
			
			if(!waitfordata(maxusec)) return(0);
			data=readdata();
                        rec_buffer.data[rec_buffer.wptr]=data;
                        if(rec_buffer.data[rec_buffer.wptr]==0) return(0);
                        rec_buffer.sum+=rec_buffer.data[rec_buffer.rptr]
				&(PULSE_MASK);
                        rec_buffer.wptr++;
                        rec_buffer.rptr++;
			LOGPRINTF(3,"+%lu",(unsigned long)
				  rec_buffer.data[rec_buffer.rptr-1]
				  &(PULSE_MASK));
                        return(rec_buffer.data[rec_buffer.rptr-1]);
		}
		else
		{
			rec_buffer.too_long=1;
			return(0);
		}
	}
	return(0);
}

void init_rec_buffer()
{
	memset(&rec_buffer,0,sizeof(rec_buffer));
}

int clear_rec_buffer()
{
	int move,i;

	if(hw.rec_mode==LIRC_MODE_LIRCCODE)
	{
		unsigned char buffer[sizeof(ir_code)];
		size_t count;
		
		count=hw.code_length/CHAR_BIT;
		if(hw.code_length%CHAR_BIT) count++;
		
		if(read(hw.fd,buffer,count)!=count)
		{
			logprintf(LOG_ERR,"reading in mode "
				  "LIRC_MODE_LIRCCODE failed");
			return(0);
		}
		for(i=0,rec_buffer.decoded=0;i<count;i++)
		{
			rec_buffer.decoded=(rec_buffer.decoded<<CHAR_BIT)+
			((ir_code) buffer[i]);
		}
	}
	else if(hw.rec_mode==LIRC_MODE_CODE)
	{
		unsigned char c;
		
		if(read(hw.fd,&c,1)!=1)
		{
			logprintf(LOG_ERR,"reading in mode LIRC_MODE_CODE "
				  "failed");
			return(0);
		}
		rec_buffer.decoded=(ir_code) c;
	}
	else
	{
		lirc_t data;
		
		move=rec_buffer.wptr-rec_buffer.rptr;
		if(move>0 && rec_buffer.rptr>0)
		{
			memmove(&rec_buffer.data[0],
				&rec_buffer.data[rec_buffer.rptr],
				sizeof(rec_buffer.data[0])*move);
			rec_buffer.wptr-=rec_buffer.rptr;
		}
		else
		{
			rec_buffer.wptr=0;
		}
		
		data=readdata();
		
		LOGPRINTF(3,"c%lu",(unsigned long) data&(PULSE_MASK));
		
		rec_buffer.data[rec_buffer.wptr]=data;
		rec_buffer.wptr++;
	}
	rec_buffer.rptr=0;
	
	rec_buffer.too_long=0;
	rec_buffer.is_biphase=0;
	rec_buffer.pendingp=0;
	rec_buffer.pendings=0;
	rec_buffer.sum=0;
	
	return(1);
}

void rewind_rec_buffer()
{
	rec_buffer.rptr=0;
	rec_buffer.too_long=0;
	rec_buffer.pendingp=0;
	rec_buffer.pendings=0;
	rec_buffer.sum=0;
}

inline void unget_rec_buffer(int count)
{
	if(count==1 || count==2)
	{
		rec_buffer.rptr-=count;
		rec_buffer.sum-=rec_buffer.data[rec_buffer.rptr]&(PULSE_MASK);
		if(count==2)
		{
			rec_buffer.sum-=rec_buffer.data[rec_buffer.rptr+1]
			&(PULSE_MASK);
		}
	}
}

inline lirc_t get_next_pulse()
{
	lirc_t data;

	data=get_next_rec_buffer(0);
	if(data==0) return(0);
	if(!is_pulse(data))
	{
		LOGPRINTF(2,"pulse expected");
		return(0);
	}
	return(data&(PULSE_MASK));
}

inline lirc_t get_next_space()
{
	lirc_t data;

	data=get_next_rec_buffer(0);
	if(data==0) return(0);
	if(!is_space(data))
	{
		LOGPRINTF(2,"space expected");
		return(0);
	}
	return(data);
}

int expectpulse(struct ir_remote *remote,int exdelta)
{
	lirc_t deltas,deltap;
	int retval;
	
	if(rec_buffer.pendings>0)
	{
		deltas=get_next_space();
		if(deltas==0) return(0);
		retval=expect(remote,deltas,rec_buffer.pendings);
		if(!retval) return(0);
		rec_buffer.pendings=0;
	}
	
	deltap=get_next_pulse();
	if(deltap==0) return(0);
	if(rec_buffer.pendingp>0)
	{
		retval=expect(remote,deltap,
			      rec_buffer.pendingp+exdelta);
		if(!retval) return(0);
		rec_buffer.pendingp=0;
	}
	else
	{
		retval=expect(remote,deltap,exdelta);
	}
	return(retval);
}

int expectspace(struct ir_remote *remote,int exdelta)
{
	lirc_t deltas,deltap;
	int retval;

	if(rec_buffer.pendingp>0)
	{
		deltap=get_next_pulse();
		if(deltap==0) return(0);
		retval=expect(remote,deltap,rec_buffer.pendingp);
		if(!retval) return(0);
		rec_buffer.pendingp=0;
	}
	
	deltas=get_next_space();
	if(deltas==0) return(0);
	if(rec_buffer.pendings>0)
	{
		retval=expect(remote,deltas,
			      rec_buffer.pendings+exdelta);
		if(!retval) return(0);
		rec_buffer.pendings=0;
	}
	else
	{
		retval=expect(remote,deltas,exdelta);
	}
	return(retval);
}

inline int expectone(struct ir_remote *remote,int bit)
{
	if(is_biphase(remote))
	{
		if(is_rc6(remote) &&
		   remote->toggle_bit>0 &&
		   bit==remote->toggle_bit-1)
		{
			if(remote->sone>0 &&
			   !expectspace(remote,2*remote->sone))
			{
				unget_rec_buffer(1);
				return(0);
			}
			rec_buffer.pendingp=2*remote->pone;
		}
		else
		{
			if(remote->sone>0 && !expectspace(remote,remote->sone))
			{
				unget_rec_buffer(1);
				return(0);
			}
			rec_buffer.pendingp=remote->pone;
		}
	}
	else
	{
		if(remote->pone>0 && !expectpulse(remote,remote->pone))
		{
			unget_rec_buffer(1);
			return(0);
		}
		if(remote->ptrail>0)
		{
			if(remote->sone>0 &&
			   !expectspace(remote,remote->sone))
			{
				unget_rec_buffer(2);
				return(0);
			}
		}
		else
		{
			rec_buffer.pendings=remote->sone;
		}
	}
	return(1);
}

inline int expectzero(struct ir_remote *remote,int bit)
{
	if(is_biphase(remote))
	{
		if(is_rc6(remote) &&
		   remote->toggle_bit>0 &&
		   bit==remote->toggle_bit-1)
		{
			if(!expectpulse(remote,2*remote->pzero))
			{
				unget_rec_buffer(1);
				return(0);
			}
			rec_buffer.pendings=2*remote->szero;
			
		}
		else
		{
			if(!expectpulse(remote,remote->pzero))
			{
				unget_rec_buffer(1);
				return(0);
			}
			rec_buffer.pendings=remote->szero;
		}
	}
	else
	{
		if(!expectpulse(remote,remote->pzero))
		{
			unget_rec_buffer(1);
			return(0);
		}
		if(remote->ptrail>0)
		{
			if(!expectspace(remote,remote->szero))
			{
				unget_rec_buffer(2);
				return(0);
			}
		}
		else
		{
			rec_buffer.pendings=remote->szero;
		}
	}
	return(1);
}

inline lirc_t sync_rec_buffer(struct ir_remote *remote)
{
	int count;
	lirc_t deltas,deltap;
	
	count=0;
	deltas=get_next_space();
	if(deltas==0) return(0);
	
	if(last_remote!=NULL && !is_rcmm(remote))
	{
		while(deltas<last_remote->remaining_gap*
		      (100-last_remote->eps)/100 &&
		      deltas<last_remote->remaining_gap-last_remote->aeps)
		{
			deltap=get_next_pulse();
			if(deltap==0) return(0);
			deltas=get_next_space();
			if(deltas==0) return(0);
			count++;
			if(count>REC_SYNC) /* no sync found, 
					      let's try a diffrent remote */
			{
				return(0);
			}
		}
	}
	rec_buffer.sum=0;
	return(deltas);
}

inline int get_header(struct ir_remote *remote)
{
	if(is_rcmm(remote))
	{
		lirc_t deltap,deltas,sum;
		deltap=get_next_pulse();
		if(deltap==0)
		{
			unget_rec_buffer(1);
			return(0);
		}
		deltas=get_next_space();
		if(deltas==0)
		{
			unget_rec_buffer(2);
			return(0);
		}
		sum=deltap+deltas;
		if(expect(remote,sum,remote->phead+remote->shead))
		{
			return(1);
		}
		unget_rec_buffer(2);
		return(0);
	}
	if(!expectpulse(remote,remote->phead))
	{
		unget_rec_buffer(1);
		return(0);
	}
	if(!expectspace(remote,remote->shead))
	{
		unget_rec_buffer(2);
		return(0);
	}
	return(1);
}

inline int get_foot(struct ir_remote *remote)
{
	if(!expectspace(remote,remote->sfoot)) return(0);
	if(!expectpulse(remote,remote->pfoot)) return(0);
	return(1);
}

inline int get_lead(struct ir_remote *remote)
{
	if(remote->plead==0) return(1);
	rec_buffer.pendingp=remote->plead;
	return(1);	
}

inline int get_trail(struct ir_remote *remote)
{
	if(remote->ptrail!=0)
	{
		if(!expectpulse(remote,remote->ptrail)) return(0);
	}
	if(rec_buffer.pendingp>0)
	{
		if(!expectpulse(remote,0)) return(0);
	}
	return(1);
}

inline int get_gap(struct ir_remote *remote,lirc_t gap)
{
	lirc_t data;
	
	LOGPRINTF(2,"sum: %ld",rec_buffer.sum);
	data=get_next_rec_buffer(gap*(100-remote->eps)/100);
	if(data==0) return(1);
	if(!is_space(data))
	{
		LOGPRINTF(2,"space expected");
		return(0);
	}
	if(data<gap*(100-remote->eps)/100 &&
	   data<gap-remote->aeps)
	{
		LOGPRINTF(1,"end of signal not found");
		return(0);
	}
	else
	{
		unget_rec_buffer(1);
	}
	return(1);	
}

inline int get_repeat(struct ir_remote *remote)
{
	if(!get_lead(remote)) return(0);
	if(is_biphase(remote))
	{
		if(!expectspace(remote,remote->srepeat)) return(0);
		if(!expectpulse(remote,remote->prepeat)) return(0);
	}
	else
	{
		if(!expectpulse(remote,remote->prepeat)) return(0);
		rec_buffer.pendings=remote->srepeat;
	}
	if(!get_trail(remote)) return(0);
	if(!get_gap(remote,
		    is_const(remote) ? 
		    (remote->gap>rec_buffer.sum ? remote->gap-rec_buffer.sum:0):
		    (has_repeat_gap(remote) ? remote->repeat_gap:remote->gap)
		    )) return(0);
	return(1);
}

ir_code get_data(struct ir_remote *remote,int bits,int done)
{
	ir_code code;
	int i;
	
	code=0;
	
	if(is_rcmm(remote))
	{
		lirc_t deltap,deltas,sum;
		
		if(bits%2 || done%2)
		{
			logprintf(LOG_ERR,"invalid bit number.");
			return((ir_code) -1);
		}
		for(i=0;i<bits;i+=2)
		{
			code<<=2;
			deltap=get_next_pulse();
			deltas=get_next_space();
			if(deltap==0 || deltas==0) 
			{
				logprintf(LOG_ERR,"failed on bit %d",
					  done+i+1);
			}
			sum=deltap+deltas;
			LOGPRINTF(3,"rcmm: sum %ld",(unsigned long) sum);
			if(expect(remote,sum,remote->pzero+remote->szero))
			{
				code|=0;
				LOGPRINTF(2,"00");
			}
			else if(expect(remote,sum,remote->pone+remote->sone))
			{
				code|=1;
				LOGPRINTF(2,"01");
			}
			else if(expect(remote,sum,remote->ptwo+remote->stwo))
			{
				code|=2;
				LOGPRINTF(2,"10");
			}
			else if(expect(remote,sum,remote->pthree+remote->sthree))
			{
				code|=3;
				LOGPRINTF(2,"11");
			}
			else
			{
				LOGPRINTF(2,"no match for %ld+%ld=%ld",
					 deltap,deltas,sum);
				return((ir_code) -1);
			}
		}
		return(code);
	}

	for(i=0;i<bits;i++)
	{
		code=code<<1;
		if(expectone(remote,done+i))
		{
			LOGPRINTF(2,"1");
			code|=1;
		}
		else if(expectzero(remote,done+i))
		{
			LOGPRINTF(2,"0");
			code|=0;
		}
		else
		{
			LOGPRINTF(1,"failed on bit %d",done+i+1);
			return((ir_code) -1);
		}
	}
	return(code);
}

ir_code get_pre(struct ir_remote *remote)
{
	ir_code pre;

	pre=get_data(remote,remote->pre_data_bits,0);

	if(pre==(ir_code) -1)
	{
		LOGPRINTF(1,"failed on pre_data");
		return((ir_code) -1);
	}
	if(remote->pre_p>0 && remote->pre_s>0)
	{
		if(!expectpulse(remote,remote->pre_p))
			return((ir_code) -1);
		rec_buffer.pendings=remote->pre_s;
	}
	return(pre);
}

ir_code get_post(struct ir_remote *remote)
{
	ir_code post;

	if(remote->post_p>0 && remote->post_s>0)
	{
		if(!expectpulse(remote,remote->post_p))
			return((ir_code) -1);
		rec_buffer.pendings=remote->post_s;
	}

	post=get_data(remote,remote->post_data_bits,remote->pre_data_bits+
		      remote->bits);

	if(post==(ir_code) -1)
	{
		LOGPRINTF(1,"failed on post_data");
		return((ir_code) -1);
	}
	return(post);
}

int receive_decode(struct ir_remote *remote,
		   ir_code *prep,ir_code *codep,ir_code *postp,
		   int *repeat_flagp,lirc_t *remaining_gapp)
{
	ir_code pre,code,post,code_mask=0,post_mask=0;
	lirc_t sync;
	int header;

	sync=0; /* make compiler happy */
	code=pre=post=0;
	header=0;

	if(hw.rec_mode==LIRC_MODE_MODE2 ||
	   hw.rec_mode==LIRC_MODE_PULSE ||
	   hw.rec_mode==LIRC_MODE_RAW)
	{
		rewind_rec_buffer();
		rec_buffer.is_biphase=is_biphase(remote) ? 1:0;
		
		/* we should get a long space first */
		if(!(sync=sync_rec_buffer(remote)))
		{
			LOGPRINTF(1,"failed on sync");
			return(0);
		}

		LOGPRINTF(1,"sync");

		if(has_repeat(remote) && last_remote==remote)
		{
			if(remote->flags&REPEAT_HEADER && has_header(remote))
			{
				if(!get_header(remote))
				{
					LOGPRINTF(1,"failed on repeat "
						  "header");
					return(0);
				}
				LOGPRINTF(1,"repeat header");
			}
			if(get_repeat(remote))
			{
				if(remote->last_code==NULL)
				{
					logprintf(LOG_NOTICE,"repeat code "
						  "without last_code "
						  "received");
					return(0);
				}

				*prep=remote->pre_data;
				*codep=remote->last_code->code;
				*postp=remote->post_data;
				*repeat_flagp=1;

				*remaining_gapp=
				is_const(remote) ? 
				(remote->gap>rec_buffer.sum ?
				 remote->gap-rec_buffer.sum:0):
				(has_repeat_gap(remote) ?
				 remote->repeat_gap:remote->gap);
				return(1);
			}
			else
			{
				LOGPRINTF(1,"no repeat");
				rewind_rec_buffer();
				sync_rec_buffer(remote);
			}

		}

		if(has_header(remote))
		{
			header=1;
			if(!get_header(remote))
			{
				header=0;
				if(!(remote->flags&NO_HEAD_REP && 
				     (sync<=remote->gap+remote->gap*remote->eps/100
				      || sync<=remote->gap+remote->aeps)))
				{
					LOGPRINTF(1,"failed on header");
					return(0);
				}
			}
			LOGPRINTF(1,"header");
		}
	}

	if(is_raw(remote))
	{
		struct ir_ncode *codes,*found;
		int i;

		if(hw.rec_mode==LIRC_MODE_CODE ||
		   hw.rec_mode==LIRC_MODE_LIRCCODE)
			return(0);

		codes=remote->codes;
		found=NULL;
		while(codes->name!=NULL && found==NULL)
		{
			found=codes;
			for(i=0;i<codes->length;)
			{
				if(!expectpulse(remote,codes->signals[i++]))
				{
					found=NULL;
					rewind_rec_buffer();
					sync_rec_buffer(remote);
					break;
				}
				if(i<codes->length &&
				   !expectspace(remote,codes->signals[i++]))
				{
					found=NULL;
					rewind_rec_buffer();
					sync_rec_buffer(remote);
					break;
				}
			}
			codes++;
		}
		if(found!=NULL)
		{
			if(!get_gap(remote,
				    is_const(remote) ? 
				    remote->gap-rec_buffer.sum:
				    remote->gap)) 
				found=NULL;
		}
		if(found==NULL) return(0);
		code=found->code;
	}
	else
	{
		if(hw.rec_mode==LIRC_MODE_CODE ||
		   hw.rec_mode==LIRC_MODE_LIRCCODE)
		{
			int i;
 			lirc_t sum;
 			struct timeval current;

#                       ifdef LONG_IR_CODE
			LOGPRINTF(1,"decoded: %llx",rec_buffer.decoded);
#                       else
			LOGPRINTF(1,"decoded: %lx",rec_buffer.decoded);
#                       endif
			if((hw.rec_mode==LIRC_MODE_CODE &&
			    hw.code_length<remote->pre_data_bits
			    +remote->bits+remote->post_data_bits)
			   ||
			   (hw.rec_mode==LIRC_MODE_LIRCCODE && 
			    hw.code_length!=remote->pre_data_bits
			    +remote->bits+remote->post_data_bits))
			{
				return(0);
			}
			
			for(i=0;i<remote->post_data_bits;i++)
			{
				post_mask=(post_mask<<1)+1;
			}
			post=rec_buffer.decoded&post_mask;
			post_mask=0;
			rec_buffer.decoded=
			rec_buffer.decoded>>remote->post_data_bits;
			for(i=0;i<remote->bits;i++)
			{
				code_mask=(code_mask<<1)+1;
			}
			code=rec_buffer.decoded&code_mask;
			code_mask=0;
			pre=rec_buffer.decoded>>remote->bits;
			gettimeofday(&current,NULL);
			sum=remote->phead+remote->shead+
				lirc_t_max(remote->pone+remote->sone,
					   remote->pzero+remote->szero)*
				(remote->bits+
				 remote->pre_data_bits+
				 remote->post_data_bits)+
				remote->plead+
				remote->ptrail+
				remote->pfoot+remote->sfoot+
				remote->pre_p+remote->pre_s+
				remote->post_p+remote->post_s;
			
			rec_buffer.sum=sum>=remote->gap ? remote->gap-1:sum;
			sync=time_elapsed(&remote->last_send,&current)-
 				rec_buffer.sum;
		}
		else
		{
			if(!get_lead(remote))
			{
				LOGPRINTF(1,"failed on leading pulse");
				return(0);
			}
			
			if(has_pre(remote))
			{
				pre=get_pre(remote);
				if(pre==(ir_code) -1)
				{
					LOGPRINTF(1,"failed on pre");
					return(0);
				}
#                               ifdef LONG_IR_CODE
				LOGPRINTF(1,"pre: %llx",pre);
#                               else
				LOGPRINTF(1,"pre: %lx",pre);
#                               endif
			}
			
			code=get_data(remote,remote->bits,
				      remote->pre_data_bits);
			if(code==(ir_code) -1)
			{
				LOGPRINTF(1,"failed on code");
				return(0);
			}
#                       ifdef LONG_IR_CODE
			LOGPRINTF(1,"code: %llx",code);
#                       else
			LOGPRINTF(1,"code: %lx",code);
#                       endif
			
			if(has_post(remote))
			{
				post=get_post(remote);
				if(post==(ir_code) -1)
				{
					LOGPRINTF(1,"failed on post");
					return(0);
				}
#                               ifdef LONG_IR_CODE
				LOGPRINTF(1,"post: %llx",post);
#                               else
				LOGPRINTF(1,"post: %lx",post);
#                               endif
			}
			if(!get_trail(remote))
			{
				LOGPRINTF(1,"failed on trailing pulse");
				return(0);
			}
			if(has_foot(remote))
			{
				if(!get_foot(remote))
				{
					LOGPRINTF(1,"failed on foot");
					return(0);
				}
			}
			if(header==1 && is_const(remote) &&
			   (remote->flags&NO_HEAD_REP))
			{
				rec_buffer.sum-=remote->phead+remote->shead;
			}
			if(is_rcmm(remote))
			{
				if(!get_gap(remote,1000))
					return(0);
			}
			else if(is_const(remote))
			{
				if(!get_gap(remote,
					    remote->gap>rec_buffer.sum ?
					    remote->gap-rec_buffer.sum:0))
					return(0);
			}
			else
			{
				if(!get_gap(remote,remote->gap))
					return(0);
			}
		} /* end of mode specific code */
	}
	*prep=pre;*codep=code;*postp=post;
	if(sync<=remote->remaining_gap*(100+remote->eps)/100
	   || sync<=remote->remaining_gap+remote->aeps)
		*repeat_flagp=1;
	else
		*repeat_flagp=0;
	if(is_const(remote))
	{
		*remaining_gapp=remote->gap>rec_buffer.sum ?
			remote->gap-rec_buffer.sum:0;
	}
	else
	{
		*remaining_gapp=remote->gap;
	}
	return(1);
}
