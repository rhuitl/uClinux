/*      $Id: dump_config.c,v 5.7 2001/01/20 13:32:00 columbus Exp $      */

/****************************************************************************
 ** dump_config.c ***********************************************************
 ****************************************************************************
 *
 * dump_config.c - dumps data structures into file
 *
 * Copyright (C) 1998 Pablo d'Angelo <pablo@ag-trek.allgaeu.org>
 *
 */ 

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "dump_config.h"
#include "config_file.h"

static char buffer[160];
#define fprintf(f, a...) \
		(fflush(f), memset(buffer, 0, sizeof(buffer)), sprintf(buffer, ##a), write(fileno(f), buffer, strlen(buffer)))

void fprint_comment(FILE *f,struct ir_remote *rem)
{
	time_t timet;
	struct tm *tmp;

	timet=time(NULL);
	tmp=localtime(&timet);
	fprintf(f,
		"#\n"
		"# this config file was automatically generated\n"
		"# using lirc-%s(%s) on %s"
		"#\n"
		"# contributed by \n"
		"#\n"
		"# brand:             %s\n"
		"# model:             \n"
		"# supported devices: \n"
		"#\n\n",VERSION,LIRC_DRIVER,asctime(tmp),
		rem->name);
}

void fprint_flags(FILE *f, int flags)
{
	int i;
	int begin=0;

	for(i=0;all_flags[i].flag;i++)
	{
		if(flags&all_flags[i].flag)
		{
			flags&=(~all_flags[i].flag);
			if(begin==0) fprintf(f, "  flags ");
			else if(begin==1) fprintf(f,"|");
			fprintf(f,"%s",all_flags[i].name);
			begin=1;
		}
	}
	if(begin==1) fprintf(f,"\n");
}

void fprint_remotes(FILE *f, struct ir_remote *all){

    	while(all)
	{
                fprint_remote(f, all);
                fprintf(f, "\n\n");
                all=all->next;
        }
}

void fprint_remote_head(FILE *f, struct ir_remote *rem)
{
	fprintf(f, "begin remote\n\n");
	if(!is_raw(rem)){
		fprintf(f, "  name  %s\n",rem->name);
		fprintf(f, "  bits        %5d\n",rem->bits);
		fprint_flags(f,rem->flags);
		fprintf(f, "  eps         %5d\n",rem->eps);
		fprintf(f, "  aeps        %5d\n\n",rem->aeps);
		if(has_header(rem))
		{
			fprintf(f, "  header      %5lu %5lu\n",
				(unsigned long) rem->phead,
				(unsigned long) rem->shead);
		}
		if(rem->pthree!=0 || rem->sthree!=0)
			fprintf(f, "  three       %5lu %5lu\n",
				(unsigned long) rem->pthree,
				(unsigned long) rem->sthree);
		if(rem->ptwo!=0 || rem->stwo!=0)
			fprintf(f, "  two         %5lu %5lu\n",
				(unsigned long) rem->ptwo,
				(unsigned long)  rem->stwo);
		fprintf(f, "  one         %5lu %5lu\n",
			(unsigned long) rem->pone,
			(unsigned long) rem->sone);
		fprintf(f, "  zero        %5lu %5lu\n",
			(unsigned long) rem->pzero,
			(unsigned long)  rem->szero);
		if(rem->ptrail!=0)
		{
			fprintf(f, "  ptrail      %5lu\n",
				(unsigned long) rem->ptrail);
		}
		if(rem->plead!=0)
		{
			fprintf(f, "  plead       %5lu\n",
				(unsigned long) rem->plead);
		}
		if(has_foot(rem))
		{
			fprintf(f, "  foot        %5lu %5lu\n",
				(unsigned long) rem->pfoot,
				(unsigned long) rem->sfoot);
		}
		if(has_repeat(rem))
		{
			fprintf(f, "  repeat      %5lu %5lu\n",
				(unsigned long) rem->prepeat,
				(unsigned long) rem->srepeat);
		}
		if(rem->pre_data_bits>0)
		{
			fprintf(f, "  pre_data_bits   %d\n",rem->pre_data_bits);
#                       ifdef LONG_IR_CODE
			fprintf(f, "  pre_data       0x%llX\n",rem->pre_data);
#                       else
			fprintf(f, "  pre_data       0x%lX\n",rem->pre_data);
#                       endif
		}
		if(rem->post_data_bits>0)
		{
			fprintf(f, "  post_data_bits  %d\n",rem->post_data_bits);
#                       ifdef LONG_IR_CODE
			fprintf(f, "  post_data      0x%llX\n",rem->post_data);
#                       else
			fprintf(f, "  post_data      0x%lX\n",rem->post_data);
#                       endif
		}
		if(rem->pre_p!=0 && rem->pre_s!=0)
		{
			fprintf(f, "  pre         %5lu %5lu\n",
				(unsigned long) rem->pre_p,
				(unsigned long) rem->pre_s);
		}
		if(rem->post_p!=0 && rem->post_s!=0)
		{
			fprintf(f, "  post        %5lu %5lu\n",
				(unsigned long) rem->post_p,
				(unsigned long) rem->post_s);
		}
		fprintf(f, "  gap          %lu\n",
			(unsigned long) rem->gap);
		if(has_repeat_gap(rem))
		{
			fprintf(f, "  repeat_gap   %lu\n",
				(unsigned long) rem->repeat_gap);
		}
		if(rem->min_repeat>0)
		{
			fprintf(f, "  min_repeat      %d\n",rem->min_repeat);
		}
		fprintf(f, "  toggle_bit      %d\n\n",rem->toggle_bit);
	}
	else
	{
		fprintf(f, "  name   %s\n",rem->name);
		fprint_flags(f,rem->flags);
		fprintf(f, "  eps         %5d\n",rem->eps);
		fprintf(f, "  aeps        %5d\n\n",rem->aeps);
		fprintf(f, "  ptrail      %5lu\n",(unsigned long) rem->ptrail);
		fprintf(f, "  repeat %5lu %5lu\n",
			(unsigned long) rem->prepeat,
			(unsigned long) rem->srepeat);
		fprintf(f, "  gap    %lu\n",(unsigned long) rem->gap);
	}
	if(rem->freq!=0)
	{
		fprintf(f, "  frequency    %u\n",rem->freq);
	}
	if(rem->duty_cycle!=0)
	{
		fprintf(f, "  duty_cycle   %u\n",rem->duty_cycle);
	}
	fprintf(f,"\n");
}

void fprint_remote_foot(FILE *f, struct ir_remote *rem)
{
	fprintf(f, "end remote\n");
}

void fprint_remote_signal_head(FILE *f, struct ir_remote *rem)
{
	if(!is_raw(rem))
		fprintf(f, "      begin codes\n");
	else
		fprintf(f, "      begin raw_codes\n\n");
}

void fprint_remote_signal_foot(FILE *f, struct ir_remote *rem)
{
	if(!is_raw(rem))
		fprintf(f, "      end codes\n\n");
	else
		fprintf(f, "      end raw_codes\n\n");
}

void fprint_remote_signal(FILE *f,struct ir_remote *rem, struct ir_ncode *codes)
{
	int i,j;

	if(!is_raw(rem))
	{
#               ifdef LONG_IR_CODE
		fprintf(f, "          %-24s 0x%016llX\n",codes->name, codes->code);
#               else
		fprintf(f, "          %-24s 0x%016lX\n",codes->name, codes->code);
#               endif
	}
	else
	{
		fprintf(f, "          name %s\n",codes->name);
		j=0;
		for(i=0;i<codes->length;i++){
			if (j==0){
				fprintf(f, "          %7lu",
					(unsigned long) codes->signals[i]);
			}else if (j<5){
				fprintf(f, " %7lu",
					(unsigned long) codes->signals[i]);
			}else{
				fprintf(f, " %7lu\n",
					(unsigned long) codes->signals[i]);
				j=-1;
			}
			j++;
		}
		codes++;
		if (j==0)
		{
			fprintf(f,"\n");
		}else
		{
			fprintf(f,"\n\n");
			j=0;
		}
	}
}

void fprint_remote_signals(FILE *f, struct ir_remote *rem)
{
        struct ir_ncode *codes;
	
	fprint_remote_signal_head(f,rem);
	codes=rem->codes;
	while(codes->name!=NULL)
	{
		fprint_remote_signal(f,rem,codes);
		codes++;
	}
	fprint_remote_signal_foot(f,rem);
}


void fprint_remote(FILE *f, struct ir_remote *rem)
{	
	fprint_comment(f,rem);
	fprint_remote_head(f,rem);
	fprint_remote_signals(f,rem);
	fprint_remote_foot(f,rem);
}
