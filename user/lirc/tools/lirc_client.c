/*      $Id: lirc_client.c,v 5.11 2001/02/10 12:15:33 columbus Exp $      */

/****************************************************************************
 ** lirc_client.c ***********************************************************
 ****************************************************************************
 *
 * lirc_client - common routines for lircd clients
 *
 * Copyright (C) 1998 Trent Piepho <xyzzy@u.washington.edu>
 * Copyright (C) 1998 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */ 

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lirc_client.h"

/* internal functions */
char *lirc_startupmode(struct lirc_config_entry *first);
void lirc_freeconfigentries(struct lirc_config_entry *first);
void lirc_clearmode(struct lirc_config *config);
char *lirc_execute(struct lirc_config *config,struct lirc_config_entry *scan);
int lirc_iscode(struct lirc_config_entry *scan,char *remote,char *button,
		 int rep);

static int lirc_lircd;
static int lirc_verbose=0;
static char *lirc_prog=NULL;
static char *lirc_buffer=NULL;

void lirc_printf(char *format_str, ...)
{
	va_list ap;  
	
	if(!lirc_verbose) return;
	
	va_start(ap,format_str);
	vfprintf(stderr,format_str,ap);
	va_end(ap);
}

void lirc_perror(const char *s)
{
	if(!lirc_verbose) return;

	perror(s);
}

int lirc_init(char *prog,int verbose)
{
	struct sockaddr_un addr;

	/* connect to lircd */

	if(prog==NULL || lirc_prog!=NULL) return(-1);
	lirc_prog=strdup(prog);
	lirc_verbose=verbose;
	if(lirc_prog==NULL)
	{
		lirc_printf("%s: out of memory\n",prog);
		return(-1);
	}
	
	addr.sun_family=AF_UNIX;
	strcpy(addr.sun_path,LIRCD);
	lirc_lircd=socket(AF_UNIX,SOCK_STREAM,0);
	if(lirc_lircd==-1)
	{
		lirc_printf("%s: could not open socket\n",lirc_prog);
		lirc_perror(lirc_prog);
		free(lirc_prog);
		lirc_prog=NULL;
		return(-1);
	}
	if(connect(lirc_lircd,(struct sockaddr *)&addr,sizeof(addr))==-1)
	{
		close(lirc_lircd);
		lirc_printf("%s: could not connect to socket\n",lirc_prog);
		lirc_perror(lirc_prog);
		free(lirc_prog);
		lirc_prog=NULL;
		return(-1);
	}
	return(lirc_lircd);
}

int lirc_deinit(void)
{
	if(lirc_prog!=NULL)
	{
		free(lirc_prog);
		lirc_prog=NULL;
	}
	if(lirc_buffer!=NULL)
	{
		free(lirc_buffer);
		lirc_buffer=NULL;
	}
	return(close(lirc_lircd));
}

#define LIRC_READ 255

int lirc_readline(char **line,FILE *f)
{
	char *newline,*ret,*enlargeline;
	int len;
	
	newline=(char *) malloc(LIRC_READ+1);
	if(newline==NULL)
	{
		lirc_printf("%s: out of memory\n",lirc_prog);
		return(-1);
	}
	len=0;
	while(1)
	{
		ret=fgets(newline+len,LIRC_READ+1,f);
		if(ret==NULL)
		{
			if(feof(f) && len>0)
			{
				*line=newline;
			}
			else
			{
				free(newline);
				*line=NULL;
			}
			return(0);
		}
		len=strlen(newline);
		if(newline[len-1]=='\n')
		{
			newline[len-1]=0;
			*line=newline;
			return(0);
		}
		
		enlargeline=(char *) realloc(newline,len+1+LIRC_READ);
		if(enlargeline==NULL)
		{
			free(newline);
			lirc_printf("%s: out of memory\n",lirc_prog);
			return(-1);
		}
		newline=enlargeline;
	}
}

char *lirc_trim(char *s)
{
	int len;
	
	while(s[0]==' ' || s[0]=='\t') s++;
	len=strlen(s);
	while(len>0)
	{
		len--;
		if(s[len]==' ' || s[len]=='\t') s[len]=0;
		else break;
	}
	return(s);
}

/* parse standard C escape sequences + \@,\A-\Z is ^@,^A-^Z */

char lirc_parse_escape(char **s,int line)
{

	char c;
	unsigned int i,overflow,count;
	int digits_found,digit;

	c=**s;
	(*s)++;
	switch(c)
	{
	case 'a':
		return('\a');
	case 'b':
		return('\b');
	case 'e':
#if 0
	case 'E': /* this should become ^E */
#endif
		return(033);
	case 'f':
		return('\f');
	case 'n':
		return('\n');
	case 'r':
		return('\r');
	case 't':
		return('\t');
	case 'v':
		return('\v');
	case '\n':
		return(0);
	case 0:
		(*s)--;
		return 0;
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
		i=c-'0';
		count=0;
		
		while(++count<3)
		{
			c=*(*s)++;
			if(c>='0' && c<='7')
			{
				i=(i << 3)+c-'0';
			}
			else
			{
				(*s)--;
				break;
			}
		}
		if(i>(1<<CHAR_BIT)-1)
		{
			i&=(1<<CHAR_BIT)-1;
			lirc_printf("%s: octal escape sequence "
				    "out of range in line %d\n",lirc_prog,
				    line);
		}
		return((char) i);
	case 'x':
		{
			i=0;
			overflow=0;
			digits_found=0;
			for (;;)
			{
				c = *(*s)++;
				if(c>='0' && c<='9')
					digit=c-'0';
				else if(c>='a' && c<='f')
					digit=c-'a'+10;
				else if(c>='A' && c<='F')
					digit=c-'A'+10;
				else
				{
					(*s)--;
					break;
				}
				overflow|=i^(i<<4>>4);
				i=(i<<4)+digit;
				digits_found=1;
			}
			if(!digits_found)
			{
				lirc_printf("%s: \\x used with no "
					    "following hex digits in line %d\n",
					    lirc_prog,line);
			}
			if(overflow || i>(1<<CHAR_BIT)-1)
			{
				i&=(1<<CHAR_BIT)-1;
				lirc_printf("%s: hex escape sequence out "
					    "of range in line %d\n",
					    lirc_prog,line);
			}
			return((char) i);
		}
	default:
		if(c>='@' && c<='Z') return(c-'@');
		return(c);
	}
}

void lirc_parse_string(char *s,int line)
{
	char *t;

	t=s;
	while(*s!=0)
	{
		if(*s=='\\')
		{
			s++;
			*t=lirc_parse_escape(&s,line);
			t++;
		}
		else
		{
			*t=*s;
			s++;
			t++;
		}
	}
	*t=0;
}

int lirc_mode(char *token,char *token2,char **mode,
	      struct lirc_config_entry **new_config,
	      struct lirc_config_entry **first_config,
	      struct lirc_config_entry **last_config,
	      int (check)(char *s),
	      int line)
{
	struct lirc_config_entry *new_entry;
	
	new_entry=*new_config;
	if(strcasecmp(token,"begin")==0)
	{
		if(token2==NULL)
		{
			if(new_entry==NULL)
			{
				new_entry=(struct lirc_config_entry *)
				malloc(sizeof(struct lirc_config_entry));
				if(new_entry==NULL)
				{
					lirc_printf("%s: out of memory\n",
						    lirc_prog);
					return(-1);
				}
				else
				{
					new_entry->prog=NULL;
					new_entry->code=NULL;
					new_entry->rep=0;
					new_entry->config=NULL;
					new_entry->change_mode=NULL;
					new_entry->flags=none;
					new_entry->mode=NULL;
					new_entry->next_config=NULL;
					new_entry->next_code=NULL;
					new_entry->next=NULL;

					*new_config=new_entry;
				}
			}
			else
			{
				lirc_printf("%s: bad file format, "
					    "line %d\n",lirc_prog,line);
				return(-1);
			}
		}
		else
		{
			if(new_entry==NULL && *mode==NULL)
			{
				*mode=strdup(token2);
				if(*mode==NULL)
				{
					return(-1);
				}
			}
			else
			{
				lirc_printf("%s: bad file format, "
					    "line %d\n",lirc_prog,line);
				return(-1);
			}
		}
	}
	else if(strcasecmp(token,"end")==0)
	{
		if(token2==NULL)
		{
			if(new_entry!=NULL)
			{
#if 0
				if(new_entry->prog==NULL)
				{
					lirc_printf("%s: prog missing in "
						    "config before line %d\n",
						    lirc_prog,line);
					lirc_freeconfigentries(new_entry);
					*new_config=NULL;
					return(-1);
				}
				if(strcasecmp(new_entry->prog,lirc_prog)!=0)
				{
					lirc_freeconfigentries(new_entry);
					*new_config=NULL;
					return(0);
				}
#endif
				new_entry->next_code=new_entry->code;
				new_entry->next_config=new_entry->config;
				if(*last_config==NULL)
				{
					*first_config=new_entry;
					*last_config=new_entry;
				}
				else
				{
					(*last_config)->next=new_entry;
					*last_config=new_entry;
				}
				*new_config=NULL;

				if(*mode!=NULL) 
				{
					new_entry->mode=strdup(*mode);
					if(new_entry->mode==NULL)
					{
						lirc_printf("%s: out of "
							    "memory\n",
							    lirc_prog);
						return(-1);
					}
				}

				if(check!=NULL &&
				   new_entry->prog!=NULL &&
				   strcasecmp(new_entry->prog,lirc_prog)==0)
				{					
					struct lirc_list *list;

					list=new_entry->config;
					while(list!=NULL)
					{
						if(check(list->string)==-1)
						{
							return(-1);
						}
						list=list->next;
					}
				}
				
			}
			else
			{
				lirc_printf("%s: line %d: 'end' without "
					    "'begin'\n",lirc_prog,line);
				return(-1);
			}
		}
		else
		{
			if(*mode!=NULL)
			{
				if(new_entry!=NULL)
				{
					lirc_printf("%s: line %d: missing "
						    "'end' token\n",lirc_prog,
						    line);
					return(-1);
				}
				if(strcasecmp(*mode,token2)==0)
				{
					free(*mode);
					*mode=NULL;
				}
				else
				{
					lirc_printf("%s: \"%s\" doesn't "
						    "match mode \"%s\"\n",
						    lirc_prog,token2,*mode);
					return(-1);
				}
			}
			else
			{
				lirc_printf("%s: line %d: 'end %s' without "
					    "'begin'\n",lirc_prog,line,
					    token2);
				return(-1);
			}
		}
	}
	else
	{
		lirc_printf("%s: unknown token \"%s\" in line %d ignored\n",
			    lirc_prog,token,line);
	}
	return(0);
}

unsigned int lirc_flags(char *string)
{
	char *s;
	unsigned int flags;

	flags=none;
	s=strtok(string," \t|");
	while(s)
	{
		if(strcasecmp(s,"once")==0)
		{
			flags|=once;
		}
		else if(strcasecmp(s,"quit")==0)
		{
			flags|=quit;
		}
		else if(strcasecmp(s,"mode")==0)
		{
			flags|=mode;
		}
		else if(strcasecmp(s,"startup_mode")==0)
		{
			flags|=startup_mode;
		}
		else
		{
			lirc_printf("%s: unknown flag \"%s\"\n",lirc_prog,s);
		}
		s=strtok(NULL," \t");
	}
	return(flags);
}

int lirc_readconfig(char *file,
		    struct lirc_config **config,
		    int (check)(char *s))
{
	char *home,*filename,*string,*eq,*token,*token2,*token3;
	FILE *fin;
	struct lirc_config_entry *new_entry,*first,*last;
	char *mode,*remote;
	int line,ret;
	
	if(file==NULL)
	{
		home=getenv("HOME");
		filename=(char *) malloc(strlen(home)+1+strlen(LIRCCFGFILE)+1);
		if(filename==NULL)
			return(-1);
		strcpy(filename,home);
		if(strlen(home)>0 && filename[strlen(filename)-1]!='/')
		{
			strcat(filename,"/");
		}
		strcat(filename,LIRCCFGFILE);
	}
	else
	{
		filename=file;
	}

	fin=fopen(filename,"r");
	if(file==NULL) free(filename);
	if(fin==NULL)
	{
		lirc_printf("%s: could not open config file\n",lirc_prog);
		lirc_perror(lirc_prog);
		return(-1);
	}
	line=1;
	first=new_entry=last=NULL;
	mode=NULL;
	remote=LIRC_ALL;
	while((ret=lirc_readline(&string,fin))!=-1 && string!=NULL)
	{
		eq=strchr(string,'=');
		if(eq==NULL)
		{
			token=strtok(string," \t");
			if(token==NULL)
			{
				/* ignore empty line */
			}
			else if(token[0]=='#')
			{
				/* ignore comment */
			}
			else
			{
				token2=strtok(NULL," \t");
				if(token2!=NULL && 
				   (token3=strtok(NULL," \t"))!=NULL)
				{
					lirc_printf("%s: unexpected "
						    "token in line %d\n",
						    lirc_prog,line);
				}
				else
				{
					ret=lirc_mode(token,token2,&mode,
						      &new_entry,&first,&last,
						      check,
						      line);
					if(ret==0)
					{
						if(remote!=LIRC_ALL)
							free(remote);
						remote=LIRC_ALL;
					}
					else
					{
						if(mode!=NULL)
						{
							free(mode);
							mode=NULL;
						}
						if(new_entry!=NULL)
						{
							lirc_freeconfigentries
								(new_entry);
							new_entry=NULL;
						}
					}
				}
			}
		}
		else
		{
			eq[0]=0;
			token=lirc_trim(string);
			token2=lirc_trim(eq+1);
			if(token[0]=='#')
			{
				/* ignore comment */
			}
			else if(new_entry==NULL)
			{
				lirc_printf("%s: bad file format, "
					    "line %d\n",lirc_prog,line);
				ret=-1;
			}
			else
			{
				token2=strdup(token2);
				if(token2==NULL)
				{
					lirc_printf("%s: out of memory\n",
						    lirc_prog);
					ret=-1;
				}
				else if(strcasecmp(token,"prog")==0)
				{
					if(new_entry->prog!=NULL) free(new_entry->prog);
					new_entry->prog=token2;
				}
				else if(strcasecmp(token,"remote")==0)
				{
					if(remote!=LIRC_ALL)
						free(remote);
					
					if(strcasecmp("*",token2)==0)
					{
						remote=LIRC_ALL;
						free(token2);
					}
					else
					{
						remote=token2;
					}
				}
				else if(strcasecmp(token,"button")==0)
				{
					struct lirc_code *code;
					
					code=(struct lirc_code *)
					malloc(sizeof(struct lirc_code));
					if(code==NULL)
					{
						free(token2);
						lirc_printf("%s: out of "
							    "memory\n",
							    lirc_prog);
						ret=-1;
					}
					else
					{
						code->remote=remote;
						if(strcasecmp("*",token2)==0)
						{
							code->button=LIRC_ALL;
							free(token2);
						}
						else
						{
							code->button=token2;
						}
						code->next=NULL;

						if(new_entry->code==NULL)
						{
							new_entry->code=code;
						}
						else
						{
							new_entry->next_code->next
							=code;
						}
						new_entry->next_code=code;
						if(remote!=LIRC_ALL)
						{
							remote=strdup(remote);
							if(remote==NULL)
							{
								lirc_printf("%s: out of memory\n",lirc_prog);
								ret=-1;
							}
						}
					}
				}
				else if(strcasecmp(token,"repeat")==0)
				{
					char *end;

					errno=ERANGE+1;
					new_entry->rep=strtoul(token2,&end,0);
					if((new_entry->rep==ULONG_MAX 
					    && errno==ERANGE)
					   || end[0]!=0
					   || strlen(token2)==0)
					{
						lirc_printf("%s: \"%s\" not"
							    " a  valid number for "
							    "repeat\n",lirc_prog,
							    token2);
					}
					free(token2);
				}
				else if(strcasecmp(token,"config")==0)
				{
					struct lirc_list *new_list;

					new_list=(struct lirc_list *) 
					malloc(sizeof(struct lirc_list));
					if(new_list==NULL)
					{
						free(token2);
						lirc_printf("%s: out of "
							    "memory\n",
							    lirc_prog);
						ret=-1;
					}
					else
					{
						lirc_parse_string(token2,line);
						new_list->string=token2;
						new_list->next=NULL;
						if(new_entry->config==NULL)
						{
							new_entry->config=new_list;
						}
						else
						{
							new_entry->next_config->next
							=new_list;
						}
						new_entry->next_config=new_list;
					}
				}
				else if(strcasecmp(token,"mode")==0)
				{
					if(new_entry->change_mode!=NULL) free(new_entry->change_mode);
					new_entry->change_mode=token2;
				}
				else if(strcasecmp(token,"flags")==0)
				{
					new_entry->flags=lirc_flags(token2);
					free(token2);
				}
				else
				{
					free(token2);
					lirc_printf("%s: unknown token "
						    "\"%s\" in line %d ignored\n",
						    lirc_prog,token,line);
				}
			}
		}
		free(string);
		line++;
		if(ret==-1) break;
	}
	if(remote!=LIRC_ALL)
		free(remote);
	if(new_entry!=NULL)
	{
		if(ret==0)
		{
			ret=lirc_mode("end",NULL,&mode,&new_entry,
				      &first,&last,check,line);
			lirc_printf("%s: warning: end token missing at end "
				    "of file\n",lirc_prog);
		}
		else
		{
			lirc_freeconfigentries(new_entry);
			new_entry=NULL;
		}
	}
	if(mode!=NULL)
	{
		if(ret==0)
		{
			lirc_printf("%s: warning: no end token found for mode "
				    "\"%s\"\n",lirc_prog,mode);
		}
		free(mode);
	}
	fclose(fin);
	if(ret==0)
	{
		*config=(struct lirc_config *)
			malloc(sizeof(struct lirc_config));
		if(*config==NULL)
		{
			lirc_freeconfigentries(first);
			return(-1);
		}
		(*config)->first=first;
		(*config)->next=first;
		(*config)->current_mode=lirc_startupmode((*config)->first);
	}
	else
	{
		*config=NULL;
		lirc_freeconfigentries(first);
	}
	return(ret);
}

char *lirc_startupmode(struct lirc_config_entry *first)
{
	struct lirc_config_entry *scan;
	char *startupmode;

	startupmode=NULL;
	scan=first;
	/* Set a startup mode based on flags=startup_mode */
	while(scan!=NULL)
	{
		if(scan->flags&startup_mode) {
			if(scan->change_mode!=NULL) {
				startupmode=scan->change_mode;
				/* Remove the startup mode or it confuses lirc mode system */
				scan->change_mode=NULL;
				break;
			}
			else {
				lirc_printf("%s: startup_mode flags requires 'mode ='\n",
					    lirc_prog);
			}
		}
		scan=scan->next;
	}

	/* Set a default mode if we find a mode = client app name */
	if(startupmode==NULL) {
		scan=first;
		while(scan!=NULL)
		{
			if(scan->mode!=NULL &&strcasecmp(lirc_prog,scan->mode)==0)
			{
				startupmode=lirc_prog;
				break;
			}
			scan=scan->next;
		}
	}

	if(startupmode==NULL) return(NULL);
	scan=first;
	while(scan!=NULL)
	{
		if(scan->change_mode!=NULL && scan->flags&once &&
		   strcasecmp(startupmode,scan->change_mode)==0)
		{
			scan->flags|=ecno;
		}
		scan=scan->next;
	}
	return(startupmode);
}

void lirc_freeconfig(struct lirc_config *config)
{
	if(config!=NULL)
	{
		lirc_freeconfigentries(config->first);
		free(config);
	}
}

void lirc_freeconfigentries(struct lirc_config_entry *first)
{
	struct lirc_config_entry *c,*config_temp;
	struct lirc_list *list,*list_temp;
	struct lirc_code *code,*code_temp;

	c=first;
	while(c!=NULL)
	{
		if(c->prog) free(c->prog);
		if(c->change_mode) free(c->change_mode);
		if(c->mode) free(c->mode);

		code=c->code;
		while(code!=NULL)
		{
			if(code->remote!=NULL && code->remote!=LIRC_ALL)
				free(code->remote);
			if(code->button!=NULL && code->button!=LIRC_ALL)
				free(code->button);
			code_temp=code->next;
			free(code);
			code=code_temp;
		}

		list=c->config;
		while(list!=NULL)
		{
			if(list->string) free(list->string);
			list_temp=list->next;
			free(list);
			list=list_temp;
		}
		config_temp=c->next;
		free(c);
		c=config_temp;
	}
}

void lirc_clearmode(struct lirc_config *config)
{
	struct lirc_config_entry *scan;

	if(config->current_mode==NULL)
	{
		return;
	}
	scan=config->first;
	while(scan!=NULL)
	{
		if(scan->change_mode!=NULL)
		{
			if(strcasecmp(scan->change_mode,config->current_mode)==0)
			{
				scan->flags&=~ecno;
			}
		}
		scan=scan->next;
	}
	config->current_mode=NULL;
}

char *lirc_execute(struct lirc_config *config,struct lirc_config_entry *scan)
{
	char *s;
	int do_once=1;
	
	if(scan->flags&quit)
	{
		config->next=NULL;
	}
	else
	{
		config->next=scan->next;
	}
	if(scan->flags&mode)
	{
		lirc_clearmode(config);
	}
	if(scan->change_mode!=NULL)
	{
		config->current_mode
		=scan->change_mode;
		if(scan->flags&once)
		{
			if(scan->flags&ecno)
			{
				do_once=0;
			}
			else
			{
				scan->flags|=ecno;
			}
		}
	}
	if(scan->next_config!=NULL &&
	   scan->prog!=NULL &&
	   strcasecmp(scan->prog,lirc_prog)==0 &&
	   do_once==1)
	{
		s=scan->next_config->string;
		scan->next_config
		=scan->next_config->next;
		if(scan->next_config==NULL)
			scan->next_config
			=scan->config;
		return(s);
	}
	return(NULL);
}

int lirc_iscode(struct lirc_config_entry *scan,char *remote,char *button,int rep)
{
	struct lirc_code *codes;
	
	if(scan->code==NULL)
		return(1);

	if(scan->next_code->remote==LIRC_ALL || 
	   strcasecmp(scan->next_code->remote,remote)==0)
	{
		if(scan->next_code->button==LIRC_ALL || 
		   strcasecmp(scan->next_code->button,button)==0)
		{
			if(scan->code->next==NULL || rep==0)
			{
				scan->next_code=scan->next_code->next;
			}
			if(scan->next_code==NULL)
			{
				scan->next_code=scan->code;
                                if(scan->code->next!=NULL || 
                                   (scan->rep==0 ? rep==0:(rep%scan->rep)==0))
                                {
                                        return(1);
                                }
                                else
                                {
                                        return(0);
                                }
                        }
			else
			{
				return(0);
			}
		}
	}
        if(rep!=0) return(0);
	codes=scan->code;
        if(codes==scan->next_code) return(0);
	codes=codes->next;
	while(codes!=scan->next_code->next)
	{
                struct lirc_code *prev,*next;
                int flag=1;

                prev=scan->code;
                next=codes;
                while(next!=scan->next_code)
                {
                        if(prev->remote==LIRC_ALL ||
                           strcasecmp(prev->remote,next->remote)==0)
                        {
                                if(prev->button==LIRC_ALL ||
                                   strcasecmp(prev->button,next->button)==0)
                                {
                                        prev=prev->next;
                                        next=next->next;
                                }
                                else
                                {
                                        flag=0;break;
                                }
                        }
                        else
                        {
                                flag=0;break;
                        }
                }
                if(flag==1)
                {
                        if(prev->remote==LIRC_ALL ||
                           strcasecmp(prev->remote,remote)==0)
                        {
                                if(prev->button==LIRC_ALL ||
                                   strcasecmp(prev->button,button)==0)
                                {
                                        if(rep==0)
                                        {
                                                scan->next_code=prev->next;
                                                return(0);
                                        }
                                }
                        }
                }
                codes=codes->next;
	}
	scan->next_code=scan->code;
	return(0);
}

char *lirc_ir2char(struct lirc_config *config,char *code)
{
	static int warning=1;
	char *string;
	
	if(warning)
	{
		fprintf(stderr,"%s: warning: lirc_ir2char() is obsolete\n",
			lirc_prog);
		warning=0;
	}
	if(lirc_code2char(config,code,&string)==-1) return(NULL);
	return(string);
}

int lirc_code2char(struct lirc_config *config,char *code,char **string)
{
	int rep;
	char *backup;
	char *remote,*button;
	struct lirc_config_entry *scan;

	*string=NULL;
	if(sscanf(code,"%*llx %x %*s %*s\n",&rep)==1)
	{
		backup=strdup(code);
		if(backup==NULL) return(-1);

		strtok(backup," ");
		strtok(NULL," ");
		button=strtok(NULL," ");
		remote=strtok(NULL,"\n");

		if(button==NULL || remote==NULL)
		{
			free(backup);
			return(0);
		}
		
		scan=config->next;
		while(scan!=NULL)
		{
			if(lirc_iscode(scan,remote,button,rep) &&
			   (scan->mode==NULL ||
			    (scan->mode!=NULL && 
			     config->current_mode!=NULL &&
			     strcasecmp(scan->mode,config->current_mode)==0))
			   )
			{
				char *s;
				s=lirc_execute(config,scan);
				if(s!=NULL)
				{
					free(backup);
					*string=s;
					return(0);
				}
			}
			if(config->next!=NULL)
			{
				scan=scan->next;
			}
			else
			{
				scan=NULL;
			}
		}
		free(backup);
	}
	config->next=config->first;
	return(0);
}

#define PACKET_SIZE 100

char *lirc_nextir(void)
{
	static int warning=1;
	char *code;
	int ret;
	
	if(warning)
	{
		fprintf(stderr,"%s: warning: lirc_nextir() is obsolete\n",
			lirc_prog);
		warning=0;
	}
	ret=lirc_nextcode(&code);
	if(ret==-1) return(NULL);
	return(code);
}


int lirc_nextcode(char **code)
{
	static int packet_size=PACKET_SIZE;
	static int end_len=0;
	ssize_t len=0;
	char *end,c;

	*code=NULL;
	if(lirc_buffer==NULL)
	{
		lirc_buffer=(char *) malloc(packet_size+1);
		if(lirc_buffer==NULL)
		{
			return(-1);
		}
		lirc_buffer[0]=0;
	}
	while((end=strchr(lirc_buffer,'\n'))==NULL)
	{
		if(end_len>=packet_size)
		{
			char *new_buffer;

			packet_size+=PACKET_SIZE;
			new_buffer=(char *) realloc(lirc_buffer,packet_size);
			if(new_buffer==NULL)
			{
				return(-1);
			}
			lirc_buffer=new_buffer;
		}
		len=read(lirc_lircd,lirc_buffer+end_len,packet_size-end_len);
		if(len<=0)
		{
			if(len==-1 && errno==EAGAIN) return(0);
			else return(-1);
		}
		end_len+=len;
		lirc_buffer[end_len]=0;
		/* return if next code not yet available completely */
		if((end=strchr(lirc_buffer,'\n'))==NULL)
		{
			return(0);
		}
	}
	/* copy first line to buffer (code) and move remaining chars to
	   lirc_buffers start */
	end++;
	end_len=strlen(end);
	c=end[0];
	end[0]=0;
	*code=strdup(lirc_buffer);
	end[0]=c;
	memmove(lirc_buffer,end,end_len+1);
	if(*code==NULL) return(-1);
	return(0);
}
