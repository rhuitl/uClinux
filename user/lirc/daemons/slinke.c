/*      $Id: slinke.c,v 5.1 2000/07/13 19:01:41 columbus Exp $      */

/****************************************************************************
 ** slinke.c ****************************************************************
 ****************************************************************************
 *
 * slinke - simple hack to convert Nirvis Systems Device Files to LIRC
 + config files
 *
 * Copyright (C) 2000 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "ir_remote.h"
#include "config_file.h"
#include "dump_config.h"

const char *usage="Usage: %s --help | --version | [options] file\n";
char *progname;

#define MAX_LINE_WIDTH 300
#define MAX_CODES 100

int debug=0;

void logprintf(int prio,char *format_str, ...) {}
void logperror(int prio,const char *s) {}

int get_val(char *buffer, ...)
{
	va_list ap;
	char *next;
	int count,flag;
	int *n;

	va_start(ap,buffer);
	count=0;
	flag=1;
	
	next=strtok(buffer," \t");
	while(next!=NULL)
	{
		if(flag)
		{
			n=va_arg(ap,int *);
			if(n!=NULL)
			{
				*n=atoi(next);
			}
			else
			{
				flag=0;
			}
		}
		next=strtok(NULL," \t");
		count++;
	}
	return(count);
}

int get_data(char *s,ir_code *data,int *bits)
{
	*data=0;
	*bits=0;
	while(*s)
	{
		*data<<=1;
		if(*s=='1')
		{
			*data|=1;
		}
		else if(*s!='0' && !isspace(*s))
		{
			return(0);
		}
		s++;
		(*bits)++;
	}
	return(1);
}

void strtoupper(char *s)
{
	while(*s)
	{
		*s=toupper(*s);
		s++;
	}
}

int append_code(struct ir_remote *r,ir_code code,char *name)
{
	struct ir_ncode *codes;
	int count;
	
	count=0;
	codes=r->codes;
	while(codes->name!=NULL)
	{
		count++;
		codes++;
	}
	if(count>MAX_CODES) return(0);
	
	codes->name=strdup(name);
	strtoupper(codes->name);
	codes->code=code;
	return(1);
}

char *trim(char *s)
{
	char *end;
	
	while(isspace(*s)) s++;
	end=s+strlen(s)-1;
	while(end>=s)
	{
		if(!isspace(*end))
		{
			end++;
			*end=0;
			break;
		}
		end--;
	}
	return(s);
}

int fill_struct(struct ir_remote *r,FILE *f,char **desc)
{
	char buffer[MAX_LINE_WIDTH],backup[MAX_LINE_WIDTH];
	char *eq,*dp,*cr,*s;
	
	while((s=fgets(buffer,MAX_LINE_WIDTH,f))!=NULL)
	{
		cr=strrchr(buffer,'\r');
		if(cr!=NULL) *cr=0;
		cr=strrchr(buffer,'\n');
		if(cr!=NULL) *cr=0;
		printf("%s\n",buffer);
		cr=strchr(buffer,'#');
		if(cr!=NULL) *cr=0;

		strcpy(backup,buffer);
		eq=strchr(buffer,'=');
		if(eq!=NULL)
		{
			*eq=0;
			eq++;
			eq=trim(eq);
			if(strcasecmp(buffer,"desc")==0)
			{
				/* todo */
				if(*desc!=NULL)
				{
					fprintf(stderr,"%s: mulitple "
						"descriptions\n",progname);
					break;
				}
				*desc=strdup(eq);
				continue;
			}
			else if(strcasecmp(buffer,"name")==0)
			{
				if(r->name!=NULL)
				{
					fprintf(stderr,"%s: multiple names\n",
						progname);
					break;
				}
				if(strlen(eq)==0) continue;
				r->name=strdup(eq);
				if(r->name==NULL)
				{
					fprintf(stderr,"%s: out of memory\n",
						progname);
				}
				strtoupper(r->name);
				continue;
			}
			else if(strcasecmp(buffer,"type")==0)
			{
				continue;
			}
			else if(strcasecmp(buffer,"group")==0)
			{
				continue;
			}
			else if(strcasecmp(buffer,"carrier")==0)
			{
				r->freq=(unsigned long) atof(eq);
				continue;
			}
			else if(strcasecmp(buffer,"repeat")==0)
			{
				r->min_repeat=atoi(eq);
				continue;
			}
			else if(strcasecmp(buffer,"pause")==0)
			{
				int n,gap;

				n=get_val(eq,&gap,0);
				if(n>1) break;
				if(n==0) continue;
				/* may be zero for now, but we have to
                                   check at the end */
				if(gap>0)
				{
					break;
				}
				r->gap=abs(gap);
				continue;
			}
			else if(strcasecmp(buffer,"sleep")==0)
			{
				int n,gap;
				
				/* no equivalent in LIRC */
				if(r->gap==0) 
				{
					n=get_val(eq,&gap,0);
					if(n==1 && gap<0)
					{
						r->gap=(lirc_t) abs(gap);
					}
				}
				continue;
			}
			else if(strcasecmp(buffer,"zero")==0)
			{
				int a,b;

				if(get_val(eq,&a,&b,0)!=2 ||
				   a<=0 || b>=0)
				{
					break;
				}
				r->pzero=(lirc_t) a;
				r->szero=(lirc_t) abs(b);
				continue;
			}
			else if(strcasecmp(buffer,"one")==0)
			{
				int a,b;

				if(get_val(eq,&a,&b,0)!=2)
				{
					break;
				}
				if(a<0 && b>0)
				{
					r->pone=(lirc_t) b;
					r->sone=(lirc_t) abs(a);
					r->flags&=~SPACE_ENC;
					r->flags|=RC5;
					continue;
				}
				r->pone=(lirc_t) a;
				r->sone=(lirc_t) abs(b);
				continue;
			}
			else if(strcasecmp(buffer,"start")==0)
			{
				int a,b,n;
				
				n=get_val(eq,&a,&b,0);
				if(is_rc5(r) && n==1)
				{
					if(a<=0)
					{
						break;
					}
					r->plead=(lirc_t) a;
					continue;
				}
				if(n==0)
				{
					continue;
				}
				if(n!=2 || a<=0 || b>=0)
				{
					break;
				}
				r->phead=(lirc_t) a;
				r->shead=(lirc_t) abs(b);
				continue;
			}
			else if(strcasecmp(buffer,"stop")==0)
			{
				int n;
				int a,b,c,d,e;
				
				n=get_val(eq,&a,&b,&c,&d,&e,0);
				if(n==5)
				{
					
					if(a>0 && c>0 && e>0 &&
					   b<0 && d<0 && 
					   a==e)
					{
						r->ptrail=(lirc_t) a;
						r->gap=(lirc_t) abs(b);
						r->prepeat=(lirc_t) c;
						r->srepeat=(lirc_t) abs(d);
						if(e!=a)
						{
							break;
						}
						continue;
					}
				}
				if(n==0)
				{
					r->ptrail=(lirc_t) 0;
					continue;
				}
				if(n>2 || a<=0 )
				{
					break;
				}
				if(n==2 && b<0)
				{
					if(r->gap==0) r->gap=abs(b);
				}
				r->ptrail=(lirc_t) a;
				continue;
			}
			else if(strcasecmp(buffer,"prefix")==0)
			{
				if(has_pre(r))
				{
					fprintf(stderr,"warning: multiple prefix tokens\n");
					continue;
				}
				if(!get_data(eq,&r->pre_data,
					     &r->pre_data_bits))
				{
					break;
				}
				continue;
			}
			else if(strcasecmp(buffer,"suffix")==0)
			{
				if(has_post(r))
				{
					fprintf(stderr,"warning: multiple suffix tokens\n");
					continue;
				}
				if(!get_data(eq,&r->post_data,
					     &r->post_data_bits))
				{
					break;
				}
				continue;
			}
			else if(strcasecmp(buffer,"include")==0)
			{
				FILE *nf;
				
				nf=fopen(eq,"r");
				if(nf==NULL)
				{
					fprintf(stderr,"%s: could not open "
						"file %s\n",progname,eq);
					perror(progname);
					break;
				}
				if(!fill_struct(r,nf,desc))
				{
					fclose(nf);
					return(0);
				}
				fclose(nf);
				continue;
			}
		}
		dp=strchr(buffer,':');
		if(dp!=NULL)
		{
			int bits;
			ir_code code;

			*dp=0;
			dp++;
			dp=trim(dp);
			get_data(buffer,&code,&bits);
			if(r->bits==0) r->bits=bits;
			else if(r->bits!=bits)
			{
				fprintf(stderr,"%s: variable bit length!\n",
					progname);
				break;
			}
			if(!append_code(r,code,dp))
			{
				break;
			}
			continue;
			
		}
		if(strtok(buffer," \t")==NULL)
		{
			continue;
		}
		printf("%s\n",buffer);
	}
	if(s==NULL)
	{
		if(r->gap==0)
		{
			if(r->repeat_gap!=0)
			{
				r->gap=r->repeat_gap;
				r->repeat_gap=0;
			}
			else
			{
				fprintf(stderr,"%s: no gap!\n",progname);
				return(0);
			}
		}
		return(1);
	}
	
	fprintf(stderr,"%s: can't convert \"%s\"\n",progname,backup);
	free_config(r);
	return(0);
}

struct ir_remote *read_slinke(char *filename,char **desc)
{
	struct ir_remote *r;
	FILE *f;
	
	r=malloc(sizeof(*r));
	if(r==NULL)
	{
		fprintf(stderr,"%s: out of memory\n",progname);
		return(NULL);
	}
	/* set defaults */
	memset(r,0,sizeof(*r));
	r->flags=SPACE_ENC;
	r->eps=20;
	r->aeps=200;

	r->codes=malloc(sizeof(struct ir_ncode)*(MAX_CODES+1));
	if(r->codes==NULL)
	{
		fprintf(stderr,"%s: out of memory\n",progname);
		free(r);
		return(NULL);
	}
	memset(r->codes,0,sizeof(struct ir_ncode)*(MAX_CODES+1));
	f=fopen(filename,"r");
	if(f==NULL)
	{
		fprintf(stderr,"%s: could not open file %s\n",
			progname,filename);
		perror(progname);
		free(r->codes);
		free(r);
		return(NULL);
	}
	if(!fill_struct(r,f,desc))
	{
		fclose(f);
		return(NULL);
	}
	fclose(f);
	return(r);
}

void get_pre_data(struct ir_remote *remote)
{
	struct ir_ncode *codes;
	ir_code mask,last;
	int count,i;
	
	if(remote->bits==0) return;

	mask=(-1);
	codes=remote->codes;
	if(codes->name!=NULL)
	{
		last=codes->code;
		codes++;
	}
	if(codes->name==NULL) return; /* at least 2 codes needed */
	while(codes->name!=NULL)
	{
		mask&=~(last^codes->code);
		last=codes->code;
		codes++;
	}
	count=0;
#ifdef LONG_IR_CODE
	while(mask&0x8000000000000000LL)
#else
	while(mask&0x80000000L)
#endif
	{
		count++;
		mask=mask<<1;
	}
	count-=sizeof(ir_code)*CHAR_BIT-remote->bits;
	if(count>0)
	{
		mask=0;
		for(i=0;i<count;i++)
		{
			mask=mask<<1;
			mask|=1;
		}
		remote->bits-=count;
		mask=mask<<(remote->bits);
		remote->pre_data_bits=count;
		remote->pre_data=(last&mask)>>(remote->bits);

		codes=remote->codes;
		while(codes->name!=NULL)
		{
			codes->code&=~mask;
			codes++;
		}
	}
}

void get_post_data(struct ir_remote *remote)
{
	struct ir_ncode *codes;
	ir_code mask,last;
	int count,i;
	
	if(remote->bits==0) return;

	mask=(-1);
	codes=remote->codes;
	if(codes->name!=NULL)
	{
		last=codes->code;
		codes++;
	}
	if(codes->name==NULL) return; /* at least 2 codes needed */
	while(codes->name!=NULL)
	{
		mask&=~(last^codes->code);
		last=codes->code;
		codes++;
	}
	count=0;
	while(mask&0x1)
	{
		count++;
		mask=mask>>1;
	}
	if(count>0)
	{
		mask=0;
		for(i=0;i<count;i++)
		{
			mask=mask<<1;
			mask|=1;
		}
		remote->bits-=count;
		remote->post_data_bits=count;
		remote->post_data=last&mask;

		codes=remote->codes;
		while(codes->name!=NULL)
		{
			codes->code=codes->code>>count;
			codes++;
		}
	}
}

int main(int argc,char **argv)
{
	char *filename,*model,*brand,*description,*path,cwd[PATH_MAX+1];
	struct ir_remote *remote;
	int fd;
	FILE *fout;
	int pre,post;
	
	progname=argv[0];
	model=brand=NULL;
	pre=post=0;
	while(1)
	{
		int c;
		static struct option long_options[] =
		{
			{"help",no_argument,NULL,'h'},
			{"version",no_argument,NULL,'v'},
			{"brand",required_argument,NULL,'b'},
			{"model",required_argument,NULL,'m'},
			{"pre",no_argument,NULL,'p'},
			{"post",no_argument,NULL,'P'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc,argv,"hvb:m:pP",long_options,NULL);
		if(c==-1)
			break;
		switch (c)
		{
		case 'h':
			printf(usage,progname);
			printf("\t -h --help\t\tdisplay this message\n");
			printf("\t -v --version\t\tdisplay version\n\n");
			printf("\t -b --brand\t\tremote control "
			       "manufacturer\n");
			printf("\t -m --model\t\tremote control model "
			       "= name of new file\n");
			exit(EXIT_SUCCESS);
		case 'v':
			printf("slinke-%s\n",VERSION);
			exit(EXIT_SUCCESS);
		case 'b':
			brand=optarg;
			break;
		case 'm':
			model=optarg;
			break;
		case 'p':
			pre=1;
			break;
		case 'P':
			post=1;
			break;
		default:
			printf("Try %s -h for help!\n",progname);
			exit(EXIT_FAILURE);
		}
	}
	if(argc==1)
	{
		printf(usage,progname);
	}
	if(optind+1!=argc)
	{
		fprintf(stderr,"%s: invalid argument count\n",progname);
		exit(EXIT_FAILURE);
	}
	filename=argv[optind];
	
	path=strrchr(filename,'/');
	if(path!=NULL)
	{
		char *help;

		*path=0;
		help=path+1;
		path=filename;
		filename=help;
		if(getcwd(cwd,PATH_MAX)==NULL)
		{
			fprintf(stderr,"%s: can't get current "
				"work directory\n",progname);
			perror(progname);
			return(EXIT_FAILURE);
		}
		chdir(path);
	}
	description=NULL;
	remote=read_slinke(filename,&description);
	if(remote==NULL)
	{
		exit(EXIT_FAILURE);
	}
	if(model!=NULL)
	{
		if(remote->name!=NULL) free(remote->name);
		remote->name=strdup(model);
		if(remote->name==NULL)
		{
			free_config(remote);
			exit(EXIT_FAILURE);
		}
	}
	if(pre) get_pre_data(remote);
	if(post) get_post_data(remote);
	
	if(remote->name==NULL)
	{
		char newname[100];
		char *cr;
		
		if(description!=NULL)
		{
			printf("Description: %s\n",description);
		}
		printf("Please enter name: ");fflush(stdout);
		if(fgets(newname,100,stdin)==NULL)
		{
			free_config(remote);
			exit(EXIT_FAILURE);
		}
		cr=strrchr(newname,'\n');
		if(cr!=NULL) *cr=0;
		cr=strrchr(newname,'\r');
		if(cr!=NULL) *cr=0;
		
		remote->name=strdup(newname);
		if(remote->name==NULL)
		{
			fprintf(stderr,"%s: out of memory\n",progname);
			free_config(remote);
			exit(EXIT_FAILURE);
		}
		
	}
	if(path!=NULL)
	{
		chdir(cwd);
	}
	fd=open(remote->name,O_CREAT|O_EXCL|O_RDWR);
	if(fd==-1)
	{
		fprintf(stderr,"%s: could not open output file\n",progname);
		perror(progname);
		free_config(remote);
		if(description!=NULL) free(description);
		exit(EXIT_FAILURE);
	}
	fout=fdopen(fd,"w");
	if(fout==NULL)
	{
		fprintf(stderr,"%s: could not reopen output file\n",progname);
		perror(progname);
		free_config(remote);
		if(description!=NULL) free(description);
		exit(EXIT_FAILURE);
	}
	fprintf(fout,
"#\n"
"# This config file has been automatically converted from a device file\n"
"# found in the 06/26/00 release of the Windows Slink-e software\n"
"# package.\n"
"#\n"
"# Many thanks to Colby Boles of Nirvis Systems Inc. for allowing us to\n"
"# use these files.\n"
"#\n"
"# The original filename was: \"%s\"\n",filename);
	if(description!=NULL)
	{
		fprintf(fout,
"#\n"
"# The original description for this device was:\n"
"#\n"
"# %s\n"
"#\n",description);
		free(description);
	}
	fprintf(fout,"\n\n");
	fprint_remote_head(fout,remote);
	fprint_remote_signals(fout,remote);
	fprint_remote_foot(fout,remote);
	fclose(fout);

	free_config(remote);
	exit(EXIT_SUCCESS);
}
