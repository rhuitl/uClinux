/*      $Id: lircd.c,v 5.27 2001/02/22 08:05:59 columbus Exp $      */

/****************************************************************************
 ** lircd.c *****************************************************************
 ****************************************************************************
 *
 * lircd - LIRC Decoder Daemon
 * 
 * Copyright (C) 1996,97 Ralph Metzler <rjkm@thp.uni-koeln.de>
 * Copyright (C) 1998,99 Christoph Bartelmus <lirc@bartelmus.de>
 *
 *  =======
 *  HISTORY
 *  =======
 *
 * 0.1:  03/27/96  decode SONY infra-red signals
 *                 create mousesystems mouse signals on pipe /dev/lircm
 *       04/07/96  send ir-codes to clients via socket (see irpty)
 *       05/16/96  now using ir_remotes for decoding
 *                 much easier now to describe new remotes
 *
 * 0.5:  09/02/98 finished (nearly) complete rewrite (Christoph)
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

/* disable daemonise if maintainer mode SIM_REC / SIM_SEND defined */
#if defined(SIM_REC) || defined (SIM_SEND)
# undef DAEMONIZE
#endif

#define __USE_BSD

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/file.h>

#include "lircd.h"
#include "ir_remote.h"
#include "config_file.h"
#include "hardware.h"

struct ir_remote *remotes;
struct ir_remote *free_remotes=NULL;

extern struct ir_remote *decoding;
extern struct ir_remote *last_remote;
extern struct ir_remote *repeat_remote;
extern struct ir_ncode *repeat_code;

static int repeat_fd=-1;
static char *repeat_message=NULL;

#ifdef LIRC_NETWORK_ONLY
struct hardware hw=
{
	"/dev/null",        /* default device */
	-1,                 /* fd */
	0,                  /* features */
	0,                  /* send_mode */
	0,                  /* rec_mode */
	0,                  /* code_length */
	NULL,               /* init_func */
	NULL,               /* deinit_func */
	NULL,               /* send_func */
	NULL,               /* rec_func */
	NULL,               /* decode_func */
};
#else
extern struct hardware hw;
#endif

char *progname="lircd-"VERSION;
char *configfile=LIRCDCFGFILE;
char *logfile=LOGFILE;
FILE *pidfile;

struct protocol_directive directives[] =
{
	{"LIST",list},
	{"SEND_ONCE",send_once},
	{"SEND_START",send_start},
	{"SEND_STOP",send_stop},
	{"VERSION",version},
	{NULL,NULL}
	/*
	{"DEBUG",debug},
	{"DEBUG_LEVEL",debug_level},
	*/
};

enum protocol_string_num {
	P_BEGIN=0,
	P_DATA,
	P_END,
	P_ERROR,
	P_SUCCESS,
	P_SIGHUP
};

char *protocol_string[] = 
{
	"BEGIN\n",
	"DATA\n",
	"END\n",
	"ERROR\n",
	"SUCCESS\n",
	"SIGHUP\n"
};

#ifndef USE_SYSLOG
#define HOSTNAME_LEN 128
char hostname[HOSTNAME_LEN+1];

FILE *lf=NULL;
#endif

/* fixme: */
#define MAX_PEERS	100

int sockfd, sockinet;
int clis[FD_SETSIZE-5-MAX_PEERS]; /* substract one for lirc, sockfd, sockinet, logfile, pidfile */

#define CT_LOCAL  1
#define CT_REMOTE 2

int cli_type[FD_SETSIZE-5-MAX_PEERS];
int clin=0;

int listen_tcpip=0;
unsigned short int port=LIRC_INET_PORT;

struct	peer_connection *peers[MAX_PEERS];
int	peern = 0;

int debug=0;
int daemonized=0;

static sig_atomic_t term=0,hup=0,alrm=0;
static int termsig;

inline int max(int a,int b)
{
	return(a>b ? a:b);
}

/* cut'n'paste from fileutils-3.16: */

#define isodigit(c) ((c) >= '0' && (c) <= '7')

/* Return a positive integer containing the value of the ASCII
   octal number S.  If S is not an octal number, return -1.  */

static int
oatoi (s)
     char *s;
{
  register int i;

  if (*s == 0)
    return -1;
  for (i = 0; isodigit (*s); ++s)
    i = i * 8 + *s - '0';
  if (*s)
    return -1;
  return i;
}

/* A safer write(), since sockets might not write all but only some of the
   bytes requested */

inline int write_socket(int fd, char *buf, int len)
{
	int done,todo=len;

	while(todo)
	{
		done=write(fd,buf,todo);
		if(done<=0) return(done);
		buf+=done;
		todo-=done;
	}
	return(len);
}

inline int write_socket_len(int fd, char *buf)
{
	int len;

	len=strlen(buf);
	if(write_socket(fd,buf,len)<len) return(0);
	return(1);
}

inline int read_timeout(int fd,char *buf,int len,int timeout)
{
	fd_set fds;
	struct timeval tv;
	int ret,n;
	
	FD_ZERO(&fds);
	FD_SET(fd,&fds);
	tv.tv_sec=timeout;
	tv.tv_usec=0;
	
	/* CAVEAT: (from libc documentation)
     Any signal will cause `select' to return immediately.  So if your
     program uses signals, you can't rely on `select' to keep waiting
     for the full time specified.  If you want to be sure of waiting
     for a particular amount of time, you must check for `EINTR' and
     repeat the `select' with a newly calculated timeout based on the
     current time.  See the example below.

     Obviously the timeout is not recalculated in the example because
     this is done automatically on Linux systems...
	*/
     
	do
	{
		ret=select(fd+1,&fds,NULL,NULL,&tv);
	}
	while(ret==-1 && errno==EINTR);
	if(ret==-1)
	{
		logprintf(LOG_ERR,"select() failed");
		logperror(LOG_ERR,NULL);
		return(-1);
	}
	else if(ret==0) return(0); /* timeout */
	n=read(fd,buf,len);
	if(n==-1)
	{
		logprintf(LOG_ERR,"read() failed");
		logperror(LOG_ERR,NULL);
		return(-1);
	}
	return(n);
}

void sigterm(int sig)
{
	/* all signals are blocked now */
	if(term) return;
	term=1;
	termsig=sig;
}

void dosigterm(int sig)
{
	int i;
	
	signal(SIGALRM,SIG_IGN);
	
	if(free_remotes!=NULL)
	{
		free_config(free_remotes);
	}
	free_config(remotes);
	logprintf(LOG_NOTICE,"caught signal");
	for (i=0; i<clin; i++)
	{
		shutdown(clis[i],2);
		close(clis[i]);
	};
	shutdown(sockfd,2);
	close(sockfd);
	if(listen_tcpip)
	{
		shutdown(sockinet,2);
		close(sockinet);
	}
	fclose(pidfile);
	(void) unlink(PIDFILE);
	if(clin>0 && hw.deinit_func) hw.deinit_func();
#ifdef USE_SYSLOG
	closelog();
#else
	if(lf) fclose(lf);
#endif
	signal(sig,SIG_DFL);
	raise(sig);
}

void sighup(int sig)
{
	hup=1;
}

void dosighup(int sig)
{
#ifndef USE_SYSLOG
	struct stat s;
#endif
	int i;

	/* reopen logfile first */
#ifdef USE_SYSLOG
	/* we don't need to do anyting as this is syslogd's task */
#else
	logprintf(LOG_INFO,"closing logfile");
	if(-1==fstat(fileno(lf),&s))		
	{
		dosigterm(SIGTERM); /* shouldn't ever happen */
	}
	fclose(lf);
	lf=fopen(logfile,"a");
	if(lf==NULL)
	{
		/* can't print any error messagees */
		dosigterm(SIGTERM);
	}
	logprintf(LOG_INFO,"reopened logfile");
	if(-1==fchmod(fileno(lf),s.st_mode))
	{
		logprintf(LOG_WARNING,"could not set file permissions");
		logperror(0,NULL);
	}
#endif

	config();
	
	for (i=0; i<clin; i++)
	{
		if(!(write_socket_len(clis[i],protocol_string[P_BEGIN]) &&
		     write_socket_len(clis[i],protocol_string[P_SIGHUP]) &&
		     write_socket_len(clis[i],protocol_string[P_END])))
		{
			remove_client(clis[i]);
			i--;
		}
	}
      /* restart all connection timers */
      for (i=0; i<peern; i++)
      {
              if (peers[i]->socket == -1)
              {
                      gettimeofday(&peers[i]->reconnect, NULL);
                      peers[i]->connection_failure = 0;
              }
      }
}

void config(void)
{
	FILE *fd;
	struct ir_remote *config_remotes;
	
	if(free_remotes!=NULL)
	{
		logprintf(LOG_ERR,"cannot read config file");
		logprintf(LOG_ERR,"old config is still in use");
		return;
	}
	fd=fopen(configfile,"r");
	if(fd==NULL)
	{
		logprintf(LOG_ERR,"could not open config file '%s'",
			  configfile);
		logperror(LOG_ERR,NULL);
		return;
	}
	config_remotes=read_config(fd);
	fclose(fd);
	if(config_remotes==(void *) -1)
	{
		logprintf(LOG_ERR,"reading of config file failed");
	}
	else
	{
		LOGPRINTF(1,"config file read");
		if(config_remotes==NULL)
		{
			logprintf(LOG_WARNING,"config file contains no "
				  "valid remote control definition");
		}
		/* I cannot free the data structure
		   as they could still be in use */
		free_remotes=remotes;
		remotes=config_remotes;
	}
}

void nolinger(int sock)
{
	static struct linger  linger = {0, 0};
	int lsize  = sizeof(struct linger);
	setsockopt(sock, SOL_SOCKET, SO_LINGER, (void *)&linger, lsize);
}

void remove_client(int fd)
{
	int i;

	for(i=0;i<clin;i++)
	{
		if(clis[i]==fd)
		{
			shutdown(clis[i],2);
			close(clis[i]);
			logprintf(LOG_INFO,"removed client");
			
			clin--;
			if(clin==0 &&
			   repeat_remote==NULL &&
			   hw.deinit_func)
			{
				hw.deinit_func();
			}
			for(;i<clin;i++)
			{
				clis[i]=clis[i+1];
			}
			return;
		}
	}
	LOGPRINTF(1,"internal error in remove_client: no such fd");
}

void add_client(int sock)
{
	int fd;
	int clilen;
	struct sockaddr client_addr;

	clilen=sizeof(client_addr);
	fd=accept(sock,(struct sockaddr *)&client_addr,&clilen);
	if(fd==-1) 
	{
		logprintf(LOG_ERR,"accept() failed for new client");
		logperror(LOG_ERR,NULL);
		dosigterm(SIGTERM);
	};

	if(fd>=FD_SETSIZE)
	{
		logprintf(LOG_ERR,"connection rejected");
		shutdown(fd,2);
		close(fd);
		return;
	}
	nolinger(fd);
	if(client_addr.sa_family==AF_UNIX)
	{
		cli_type[clin]=CT_LOCAL;
		logprintf(LOG_NOTICE,"accepted new client on %s",LIRCD);
	}
	else if(client_addr.sa_family==AF_INET)
	{
		cli_type[clin]=CT_REMOTE;
		logprintf(LOG_NOTICE,"accepted new client from %s",
			  inet_ntoa(((struct sockaddr_in *)&client_addr)->sin_addr));
	}
	else
	{
		cli_type[clin]=0; /* what? */
	}
	clis[clin++]=fd;
	if(clin==1 && repeat_remote==NULL)
	{
		if(hw.init_func)
		{
			if(!hw.init_func())
			{
				shutdown(clis[0],2);
				close(clis[0]);
				clin=0;
				dosigterm(SIGTERM);
			}
		}
	}
}

int add_peer_connection(char *server)
{
	char *sep;
	struct servent *service;
	
	if(peern<MAX_PEERS)
	{
		peers[peern]=malloc(sizeof(struct peer_connection));
		if(peers[peern]!=NULL)
		{
			gettimeofday(&peers[peern]->reconnect,NULL);
			peers[peern]->connection_failure = 0;
			sep=strchr(server,':');
			if(sep!=NULL)
			{
				*sep=0;sep++;
				peers[peern]->host=strdup(server);
				service=getservbyname(sep,"tcp");
				if(service)
				{
					peers[peern]->port=
						ntohs(service->s_port);
				}
				else
				{
					long p;
					char *endptr;
				
					p=strtol(sep,&endptr,10);
					if(!*sep || *endptr ||
					   p<1 || p>USHRT_MAX)
					{
						fprintf(stderr,
							"%s: bad port number \"%s\"\n",
							progname,sep);
						return(0);
					}
					
					peers[peern]->port=
						(unsigned short int) p;
				}
			}
			else
			{
				peers[peern]->host=strdup(server);
				peers[peern]->port=LIRC_INET_PORT;
			}
			if(peers[peern]->host==NULL)
			{
				fprintf(stderr, "%s: out of memory\n",progname);
			}
		}
		else
		{
			fprintf(stderr, "%s: out of memory\n",progname);
			return(0);
		}
		peers[peern]->socket=-1;
		peern++;
		return(1);
	}
	else
	{
		fprintf(stderr,"%s: too many client connections\n",
			progname);
	}
	return(0);
}

void connect_to_peers()
{
	int	i;
	struct	hostent *host;
	struct	sockaddr_in	addr;
	struct timeval now;
	
	gettimeofday(&now,NULL);
	for(i=0;i<peern;i++)
	{
		if(peers[i]->socket!=-1)
			continue;
		if(timercmp(&peers[i]->reconnect,&now,<=))
		{
			peers[i]->socket=socket(AF_INET, SOCK_STREAM,0);
			host=gethostbyname(peers[i]->host);
			if(host==NULL)
			{
				logprintf(LOG_ERR,"name lookup failure "
					  "connecting to %s",peers[i]->host);
				peers[i]->connection_failure++;
				gettimeofday(&peers[i]->reconnect,NULL);
				peers[i]->reconnect.tv_sec+=
					5*peers[i]->connection_failure;
				close(peers[i]->socket);
				peers[i]->socket=-1;
				continue;
			}
			
			addr.sin_family=host->h_addrtype;;
			addr.sin_addr=*((struct in_addr *)host->h_addr);
			addr.sin_port=htons(peers[i]->port);
			
			if(connect(peers[i]->socket,(struct sockaddr *) &addr,
				   sizeof(addr))==-1)
			{
				logprintf(LOG_ERR, "failure connecting to %s",
					  peers[i]->host);
				logperror(LOG_ERR, NULL);
				peers[i]->connection_failure++;
				gettimeofday(&peers[i]->reconnect,NULL);
				peers[i]->reconnect.tv_sec+=
					5*peers[i]->connection_failure;
				close(peers[i]->socket);
				peers[i]->socket=-1;
				continue;
			}
			peers[i]->connection_failure=0;
		}
	}
}

int get_peer_message(struct peer_connection *peer)
{
	int length;
	char buffer[PACKET_SIZE+1];
	char *end;
	int	i;

	length=read_timeout(peer->socket,buffer,PACKET_SIZE,0);
	if(length)
	{
		buffer[length]=0;
		end=strchr(buffer,'\n');
		if(end==NULL)
		{
			logprintf(LOG_ERR,"bad send packet: \"%s\"",buffer);
			/* remove clients that behave badly */
			return(0);
		}
		end++;	/* include the \n */
		end[0]=0;
		LOGPRINTF(1,"received peer message: \"%s\"",buffer);
		for(i=0;i<clin;i++)
		{
			/* don't relay messages to remote clients */
			if(cli_type[i]==CT_REMOTE)
				continue;
			LOGPRINTF(1,"writing to client %d",i);
			if(write_socket(clis[i],buffer,length)<length)
			{
				remove_client(clis[i]);
				i--;
			}			
		}
	}

	if(length==0) /* EOF: connection closed by client */
	{
		return(0);
	}
	return(1);
}

void start_server(mode_t permission,int nodaemon)
{
	struct sockaddr_un serv_addr;
	struct sockaddr_in serv_addr_in;
	struct stat s;
	int ret;
	int new=1;
	int fd;
	
	/* create pid lockfile in /var/run */
	if((fd=open(PIDFILE,O_RDWR|O_CREAT,0644))==-1 ||
	   (pidfile=fdopen(fd,"r+"))==NULL)
	{
		fprintf(stderr,"%s: can't open or create %s\n",
			progname,PIDFILE);
		perror(progname);
		exit(EXIT_FAILURE);
	}
	if(flock(fd,LOCK_EX|LOCK_NB)==-1)
	{
		int otherpid;
		
		if(fscanf(pidfile,"%d\n",&otherpid)>0)
		{
			fprintf(stderr,"%s: there seems to already be "
				"a lircd process with pid %d\n",
				progname,otherpid);
			fprintf(stderr,"%s: otherwise delete stale "
				"lockfile %s\n",progname,PIDFILE);
		}
		else
		{
			fprintf(stderr,"%s: invalid %s encountered\n",
				progname,PIDFILE);
		}
		exit(EXIT_FAILURE);
	}
	(void) fcntl(fd,F_SETFD,FD_CLOEXEC);
	rewind(pidfile);
	(void) fprintf(pidfile,"%d\n",getpid());
	(void) fflush(pidfile);
	(void) ftruncate(fileno(pidfile),ftell(pidfile));

	/* create socket*/
	sockfd=socket(AF_UNIX,SOCK_STREAM,0);
	if(sockfd==-1)
	{
		close(sockfd);
		fclose(pidfile);
		(void) unlink(PIDFILE);
		fprintf(stderr,"%s: could not create socket\n",progname);
		perror(progname);
		exit(EXIT_FAILURE);
	};
	
	/* 
	   get owner, permissions, etc.
	   so new socket can be the same since we
	   have to delete the old socket.  
	*/
	ret=stat(LIRCD,&s);
	if(ret==-1 && errno!=ENOENT)
	{
		close(sockfd);
		fclose(pidfile);
		(void) unlink(PIDFILE);
		fprintf(stderr,"%s: could not get file information for %s\n",
			progname,LIRCD);
		perror(progname);
		exit(EXIT_FAILURE);
	}
	if(ret!=-1)
	{
		new=0;
		ret=unlink(LIRCD);
		if(ret==-1)
		{
			close(sockfd);
			fclose(pidfile);
			(void) unlink(PIDFILE);
			fprintf(stderr,"%s: could not delete %s\n",
				progname,LIRCD);
			perror(NULL);
			exit(EXIT_FAILURE);
		}
	}
	
	serv_addr.sun_family=AF_UNIX;
	strcpy(serv_addr.sun_path,LIRCD);
	if(bind(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr))==-1)
	{
		close(sockfd);
		fclose(pidfile);
		(void) unlink(PIDFILE);
		fprintf(stderr,"%s: could not assign address to socket\n",
			progname);
		perror(progname);
		exit(EXIT_FAILURE);
	}
	
	if(new ?
	   chmod(LIRCD,permission):
	   (chmod(LIRCD,s.st_mode)==-1 || chown(LIRCD,s.st_uid,s.st_gid)==-1)
	   )
	{
		close(sockfd);
		fclose(pidfile);
		(void) unlink(PIDFILE);
		fprintf(stderr,"%s: could not set file permissions\n",
			progname);
		perror(progname);
		exit(EXIT_FAILURE);
	}
	
	listen(sockfd,3);
	nolinger(sockfd);

	if(listen_tcpip)
	{
		/* create socket*/
		sockinet=socket(AF_INET,SOCK_STREAM,0);
		if(sockinet==-1)
		{
			close(sockfd);
			fclose(pidfile);
			(void) unlink(PIDFILE);
			fprintf(stderr,"%s: could not create TCP/IP socket\n",
				progname);
			perror(progname);
			exit(EXIT_FAILURE);
		};
		
		serv_addr_in.sin_family=AF_INET;
		serv_addr_in.sin_addr.s_addr=htonl(INADDR_ANY);
		serv_addr_in.sin_port=htons(port);
		
		if(bind(sockinet,(struct sockaddr *) &serv_addr_in,
			sizeof(serv_addr_in))==-1)
		{
			close(sockinet);
			close(sockfd);
			fclose(pidfile);
			(void) unlink(PIDFILE);
			fprintf(stderr,"%s: could not assign address to socket\n",
				progname);
			perror(progname);
			exit(EXIT_FAILURE);
		}
		
		listen(sockinet,3);
		nolinger(sockinet);
	}
	
#ifdef USE_SYSLOG
#ifdef DAEMONIZE
	if(nodaemon)
	{
		openlog(progname,LOG_CONS|LOG_PID|LOG_PERROR,LIRC_SYSLOG);
	}
	else
	{
		openlog(progname,LOG_CONS|LOG_PID,LIRC_SYSLOG);
	}
#else
	openlog(progname,LOG_CONS|LOG_PID|LOG_PERROR,LIRC_SYSLOG);
#endif
#else
	lf=fopen(logfile,"a");
	if(lf==NULL)
	{
		if(listen_tcpip)
		{
			close(sockinet);
		}
		close(sockfd);
		fclose(pidfile);
		(void) unlink(PIDFILE);
		fprintf(stderr,"%s: could not open logfile\n",progname);
		perror(progname);
		exit(EXIT_FAILURE);
	}
	gethostname(hostname,HOSTNAME_LEN);
#endif
	LOGPRINTF(1,"started server socket");
}

#ifndef USE_SYSLOG
void logprintf(int prio,char *format_str, ...)
{
	time_t current;
	char *currents;
	va_list ap;  
	
	current=time(&current);
	currents=ctime(&current);
	
	if(lf) fprintf(lf,"%15.15s %s %s: ",currents+4,hostname,progname);
	if(!daemonized) fprintf(stderr,"%s: ",progname);
	va_start(ap,format_str);
	if(lf)
	{
		if(prio==LOG_WARNING) fprintf(lf,"WARNING: ");
		vfprintf(lf,format_str,ap);
		fputc('\n',lf);fflush(lf);
	}
	if(!daemonized)
	{
		if(prio==LOG_WARNING) fprintf(stderr,"WARNING: ");
		vfprintf(stderr,format_str,ap);
		fputc('\n',stderr);fflush(stderr);
	}
	va_end(ap);
}

void logperror(int prio,const char *s)
{
	if(s!=NULL)
	{
		logprintf(prio,"%s: %s",s,strerror(errno));
	}
	else
	{
		logprintf(prio,"%s",strerror(errno));
	}
}
#endif

#ifdef DAEMONIZE

void daemonize(void)
{
	if(daemon(0,0)==-1)
	{
		logprintf(LOG_ERR,"daemon() failed");
		logperror(LOG_ERR,NULL);
		dosigterm(SIGTERM);
	}
	umask(0);
	rewind(pidfile);
	(void) fprintf(pidfile,"%d\n",getpid());
	(void) fflush(pidfile);
	(void) ftruncate(fileno(pidfile),ftell(pidfile));
	daemonized=1;
}

#endif DAEMONIZE

void sigalrm(int sig)
{
	alrm=1;
}

void dosigalrm(int sig)
{
	struct itimerval repeat_timer;
	
	if(repeat_remote->last_code!=repeat_code)
	{
		/* we received a different code from the original
		   remote control we could repeat the wrong code so
		   better stop repeating */
		repeat_remote=NULL;
		repeat_code=NULL;
		repeat_fd=-1;
		if(repeat_message!=NULL)
		{
			free(repeat_message);
			repeat_message=NULL;
		}
		if(clin==0 && repeat_remote==NULL && hw.deinit_func)
		{
			hw.deinit_func();
		}
		return;
	}
	repeat_remote->repeat_countdown--;
	if(hw.send_func(repeat_remote,repeat_code) &&
	   repeat_remote->repeat_countdown>0)
	{
		repeat_timer.it_value.tv_sec=0;
		repeat_timer.it_value.tv_usec=repeat_remote->remaining_gap;
		repeat_timer.it_interval.tv_sec=0;
		repeat_timer.it_interval.tv_usec=0;
		
		setitimer(ITIMER_REAL,&repeat_timer,NULL);
		return;
	}
	repeat_remote=NULL;
	repeat_code=NULL;
	if(repeat_fd!=-1)
	{
		send_success(repeat_fd,repeat_message);
		free(repeat_message);
		repeat_message=NULL;
		repeat_fd=-1;
	}
	if(clin==0 && repeat_remote==NULL && hw.deinit_func)
	{
		hw.deinit_func();
	}
}

int parse_rc(int fd,char *message,char *arguments,struct ir_remote **remote,
	     struct ir_ncode **code,int n)
{
	char *name=NULL,*command=NULL;

	*remote=NULL;
	*code=NULL;
	if(arguments==NULL) return(1);

	name=strtok(arguments,WHITE_SPACE);
	if(name==NULL) return(1);
	*remote=get_ir_remote(remotes,name);
	if(*remote==NULL)
	{
		return(send_error(fd,message,"unknown remote: \"%s\"\n",
				  name));
	}
	command=strtok(NULL,WHITE_SPACE);
	if(command==NULL) return(1);
	*code=get_ir_code(*remote,command);
	if(*code==NULL)
	{
		return(send_error(fd,message,"unknown command: \"%s\"\n",
				  command));
	}
	if(strtok(NULL,WHITE_SPACE)!=NULL)
	{
		return(send_error(fd,message,"bad send packet\n"));
	}
	if(n>0 && *remote==NULL)
	{
		return(send_error(fd,message,"remote missing\n"));
	}
	if(n>1 && *code==NULL)
	{
		return(send_error(fd,message,"code missing\n"));
	}
	return(1);
}

int send_success(int fd,char *message)
{
	if(!(write_socket_len(fd,protocol_string[P_BEGIN]) &&
	     write_socket_len(fd,message) &&
	     write_socket_len(fd,protocol_string[P_SUCCESS]) &&
	     write_socket_len(fd,protocol_string[P_END]))) return(0);
	return(1);
}

int send_error(int fd,char *message,char *format_str, ...)
{
	char lines[4],buffer[PACKET_SIZE+1];
	int i,n,len;
	va_list ap;  
	char *s1,*s2;
	
	va_start(ap,format_str);
	vsprintf(buffer,format_str,ap);
	va_end(ap);
	
	s1=strrchr(message,'\n');
	s2=strrchr(buffer,'\n');
	if(s1!=NULL) s1[0]=0;
	if(s2!=NULL) s2[0]=0;
	logprintf(LOG_ERR,"error processing command: %s",message);
	logprintf(LOG_ERR,"%s",buffer);
	if(s1!=NULL) s1[0]='\n';
	if(s2!=NULL) s2[0]='\n';

	n=0;
	len=strlen(buffer);
	for(i=0;i<len;i++) if(buffer[i]=='\n') n++;
	sprintf(lines,"%d\n",n);
	
	if(!(write_socket_len(fd,protocol_string[P_BEGIN]) &&
	     write_socket_len(fd,message) &&
	     write_socket_len(fd,protocol_string[P_ERROR]) &&
	     write_socket_len(fd,protocol_string[P_DATA]) &&
	     write_socket_len(fd,lines) &&
	     write_socket_len(fd,buffer) &&
	     write_socket_len(fd,protocol_string[P_END]))) return(0);
	return(1);
}

int send_remote_list(int fd,char *message)
{
	char buffer[PACKET_SIZE+1];
	struct ir_remote *all;
	int n,len;
	
	n=0;
	all=remotes;
	while(all)
	{
		n++;
		all=all->next;
	}

	if(!(write_socket_len(fd,protocol_string[P_BEGIN]) &&
	     write_socket_len(fd,message) &&
	     write_socket_len(fd,protocol_string[P_SUCCESS]))) return(0);
	
	if(n==0)
	{
		return(write_socket_len(fd,protocol_string[P_END]));
	}
	sprintf(buffer,"%d\n",n);
	len=strlen(buffer);
	if(!(write_socket_len(fd,protocol_string[P_DATA]) &&
	     write_socket_len(fd,buffer))) return(0);

	all=remotes;
	while(all)
	{
		len=snprintf(buffer,PACKET_SIZE+1,"%s\n",all->name);
		if(len==PACKET_SIZE+1)
		{
			len=sprintf(buffer,"name_too_long\n");
		}
		if(write_socket(fd,buffer,len)<len) return(0);
		all=all->next;
	}
	return(write_socket_len(fd,protocol_string[P_END]));
}

int send_remote(int fd,char *message,struct ir_remote *remote)
{
	struct ir_ncode *codes;
	char buffer[PACKET_SIZE+1];
	int n,len;

	n=0;
	codes=remote->codes;
	if(codes!=NULL)
	{
		while(codes->name!=NULL)
		{
			n++;
			codes++;
		}
	}

	if(!(write_socket_len(fd,protocol_string[P_BEGIN]) &&
	     write_socket_len(fd,message) &&
	     write_socket_len(fd,protocol_string[P_SUCCESS]))) return(0);
	if(n==0)
	{
		return(write_socket_len(fd,protocol_string[P_END]));
	}
	sprintf(buffer,"%d\n",n);
	if(!(write_socket_len(fd,protocol_string[P_DATA]) &&
	     write_socket_len(fd,buffer))) return(0);

	codes=remote->codes;
	while(codes->name!=NULL)
	{
#ifdef __GLIBC__
		/* It seems you can't print 64-bit longs on glibc */
		
		len=snprintf(buffer,PACKET_SIZE+1,"%08lx%08lx %s\n",
			     (unsigned long) (codes->code>>32),
			     (unsigned long) (codes->code&0xFFFFFFFF),
			     codes->name);
#else
		len=snprintf(buffer,PACKET_SIZE,"%016llx %s\n",
			     codes->code,
			     codes->name);
#endif
		if(len==PACKET_SIZE+1)
		{
			len=sprintf(buffer,"code_too_long\n");
		}
		if(write_socket(fd,buffer,len)<len) return(0);
		codes++;
	}
	return(write_socket_len(fd,protocol_string[P_END]));
}

int send_name(int fd,char *message,struct ir_ncode *code)
{
	char buffer[PACKET_SIZE+1];
	int len;

	if(!(write_socket_len(fd,protocol_string[P_BEGIN]) &&
	     write_socket_len(fd,message) &&
	     write_socket_len(fd,protocol_string[P_SUCCESS]) && 
	     write_socket_len(fd,protocol_string[P_DATA]))) return(0);
#ifdef __GLIBC__
	/* It seems you can't print 64-bit longs on glibc */
	
	len=snprintf(buffer,PACKET_SIZE+1,"1\n%08lx%08lx %s\n",
		     (unsigned long) (code->code>>32),
		     (unsigned long) (code->code&0xFFFFFFFF),
		     code->name);
#else
	len=snprintf(buffer,PACKET_SIZE,"1\n%016llx %s\n",
		     code->code,
		     code->name);
#endif
	if(len==PACKET_SIZE+1)
	{
		len=sprintf(buffer,"1\ncode_too_long\n");
	}
	if(write_socket(fd,buffer,len)<len) return(0);
	return(write_socket_len(fd,protocol_string[P_END]));
}

int list(int fd,char *message,char *arguments)
{
	struct ir_remote *remote;
	struct ir_ncode *code;

	if(parse_rc(fd,message,arguments,&remote,&code,0)==0) return(0);

	if(remote==NULL)
	{
		return(send_remote_list(fd,message));
	}
	if(code==NULL)
	{
		return(send_remote(fd,message,remote));
	}
	return(send_name(fd,message,code));
}

int send_once(int fd,char *message,char *arguments)
{
	return(send_core(fd,message,arguments,1));
}

int send_start(int fd,char *message,char *arguments)
{
	return(send_core(fd,message,arguments,0));
}

int send_core(int fd,char *message,char *arguments,int once)
{
	struct ir_remote *remote;
	struct ir_ncode *code;
	struct itimerval repeat_timer;
	
	if(hw.send_mode==0) return(send_error(fd,message,"hardware does not "
					      "support sending\n"));
	
	if(parse_rc(fd,message,arguments,&remote,&code,2)==0) return(0);
	
	if(remote==NULL || code==NULL) return(1);
	if(once)
	{
		if(remote==repeat_remote)
		{
			return(send_error(fd,message,"remote is repeating\n"));
		}
	}
	else
	{
		if(repeat_remote!=NULL)
		{
			return(send_error(fd,message,"already repeating\n"));
		}
	}
	if(remote->toggle_bit>0)
		remote->repeat_state=
		!remote->repeat_state;
	if(!hw.send_func(remote,code))
	{
		return(send_error(fd,message,"transmission failed\n"));
	}
	if(once)
	{
		remote->repeat_countdown=remote->min_repeat;
	}
	else
	{
		/* you've been warned, now we have a limit */
		remote->repeat_countdown=REPEAT_MAX;
	}
	if(remote->repeat_countdown>0)
	{
		repeat_remote=remote;
		repeat_code=code;
		repeat_timer.it_value.tv_sec=0;
		repeat_timer.it_value.tv_usec=
			remote->remaining_gap;
		repeat_timer.it_interval.tv_sec=0;
		repeat_timer.it_interval.tv_usec=0;
		if(once)
		{
			repeat_message=strdup(message);
			if(repeat_message==NULL)
			{
				repeat_remote=NULL;
				repeat_code=NULL;
				return(send_error(fd,message,
						  "out of memory\n"));
			}
			repeat_fd=fd;
		}
		else if(!send_success(fd,message))
		{
			repeat_remote=NULL;
			repeat_code=NULL;
			return(0);
		}
		setitimer(ITIMER_REAL,&repeat_timer,NULL);
		return(1);
	}
	else
	{
		return(send_success(fd,message));
	}
}

int send_stop(int fd,char *message,char *arguments)
{
	struct ir_remote *remote;
	struct ir_ncode *code;
	struct itimerval repeat_timer;
	
	if(parse_rc(fd,message,arguments,&remote,&code,2)==0) return(0);
	
	if(remote==NULL || code==NULL) return(1);
	if(repeat_remote && repeat_code &&
	   strcasecmp(remote->name,repeat_remote->name)==0 && 
	   strcasecmp(code->name,repeat_code->name)==0)
	{
		int done;

		done=REPEAT_MAX-remote->repeat_countdown;
		if(done<remote->min_repeat)
		{
			/* we still have some repeats to do */
			remote->repeat_countdown=remote->min_repeat-done;
			return(send_success(fd,message));
		}
		repeat_timer.it_value.tv_sec=0;
		repeat_timer.it_value.tv_usec=0;
		repeat_timer.it_interval.tv_sec=0;
		repeat_timer.it_interval.tv_usec=0;
		
		setitimer(ITIMER_REAL,&repeat_timer,NULL);
		
		repeat_remote=NULL;
		repeat_code=NULL;
		/* clin!=0, so we don't have to deinit hardware */
		alrm=0;
		return(send_success(fd,message));
	}
	else
	{
		return(send_error(fd,message,"not repeating\n"));
	}
}

int version(int fd,char *message,char *arguments)
{
	char buffer[PACKET_SIZE+1];

	if(arguments!=NULL)
	{
		return(send_error(fd,message,"bad send packet\n"));
	}
	sprintf(buffer,"1\n%s\n",VERSION);
	if(!(write_socket_len(fd,protocol_string[P_BEGIN]) &&
	     write_socket_len(fd,message) &&
	     write_socket_len(fd,protocol_string[P_SUCCESS]) &&
	     write_socket_len(fd,protocol_string[P_DATA]) &&
	     write_socket_len(fd,buffer) &&
	     write_socket_len(fd,protocol_string[P_END]))) return(0);
	return(1);
}

int get_command(int fd)
{
	int length;
	char buffer[PACKET_SIZE+1],backup[PACKET_SIZE+1];
	char *end;
	int packet_length,i;
	char *directive;

	length=read_timeout(fd,buffer,PACKET_SIZE,0);
	packet_length=0;
	while(length>packet_length)
	{
		buffer[length]=0;
		end=strchr(buffer,'\n');
		if(end==NULL)
		{
			logprintf(LOG_ERR,"bad send packet: \"%s\"",buffer);
			/* remove clients that behave badly */
			return(0);
		}
		end[0]=0;
		LOGPRINTF(1,"received command: \"%s\"",buffer);
		packet_length=strlen(buffer)+1;

		strcpy(backup,buffer);strcat(backup,"\n");
		directive=strtok(buffer,WHITE_SPACE);
		if(directive==NULL)
		{
			if(!send_error(fd,backup,"bad send packet\n"))
				return(0);
			goto skip;
		}
		for(i=0;directives[i].name!=NULL;i++)
		{
			if(strcasecmp(directive,directives[i].name)==0)
			{
				if(!directives[i].
				   function(fd,backup,strtok(NULL,"")))
					return(0);
				goto skip;
			}
		}
		
		if(!send_error(fd,backup,"unknown directive: \"%s\"\n",
			       directive))
			return(0);
	skip:
		if(length>packet_length)
		{
			int new_length;

			memmove(buffer,buffer+packet_length,
				length-packet_length+1);
			if(strchr(buffer,'\n')==NULL)
			{
				new_length=read_timeout(fd,buffer+length-
							packet_length,
							PACKET_SIZE-
							(length-
							 packet_length),5);
				if(new_length>0)
				{
					length=length-packet_length+new_length;
				}
				else
				{
					length=new_length;
				}
			}
			else
			{
				length-=packet_length;
			}
			packet_length=0;
		}
	}

	if(length==0) /* EOF: connection closed by client */
	{
		return(0);
	}
	return(1);
}

void free_old_remotes()
{
	struct ir_remote *scan_remotes,*found;
	struct ir_ncode *code;

	if(last_remote!=NULL)
	{
		scan_remotes=free_remotes;
		while(scan_remotes!=NULL)
		{
			if(last_remote==scan_remotes)
			{
				found=get_ir_remote(remotes,last_remote->name);
				if(found!=NULL)
				{
					code=get_ir_code(found,last_remote->last_code->name);
					if(code!=NULL)
					{
						found->reps=last_remote->reps;
						found->repeat_state=last_remote->repeat_state;
						found->remaining_gap=last_remote->remaining_gap;
						last_remote=found;
						last_remote->last_code=code;
					}
				}
				break;
			}
			scan_remotes=scan_remotes->next;
		}
		if(scan_remotes==NULL) last_remote=NULL;
	}
	/* check if last config is still needed */
	found=NULL;
	if(repeat_remote!=NULL)
	{
		scan_remotes=free_remotes;
		while(scan_remotes!=NULL)
		{
			if(repeat_remote==scan_remotes)
			{
				found=repeat_remote;
				break;
			}
			scan_remotes=scan_remotes->next;
		}
		if(found!=NULL)
		{
			found=get_ir_remote(remotes,repeat_remote->name);
			if(found!=NULL)
			{
				code=get_ir_code(found,repeat_code->name);
				if(code!=NULL)
				{
					struct itimerval repeat_timer;

					repeat_timer.it_value.tv_sec=0;
					repeat_timer.it_value.tv_usec=0;
					repeat_timer.it_interval.tv_sec=0;
					repeat_timer.it_interval.tv_usec=0;

					found->last_code=code;
					found->last_send=repeat_remote->last_send;
					found->repeat_state=repeat_remote->repeat_state;
					found->remaining_gap=repeat_remote->remaining_gap;

					setitimer(ITIMER_REAL,&repeat_timer,&repeat_timer);
					/* "atomic" (shouldn't be necessary any more) */
					repeat_remote=found;
					repeat_code=code;
					/* end "atomic" */
					setitimer(ITIMER_REAL,&repeat_timer,NULL);
					found=NULL;
				}
			}
			else
			{
				found=repeat_remote;
			}
		}
	}
	if(found==NULL && decoding!=free_remotes)
	{
		free_config(free_remotes);
		free_remotes=NULL;
	}
	else
	{
		LOGPRINTF(1,"free_remotes still in use");
	}
}


int waitfordata(unsigned long maxusec)
{
	fd_set fds;
	int maxfd,i,ret,reconnect;
	struct timeval tv,start,now;

	while(1)
	{
		do{
				/* handle signals */
			if(term)
			{
				dosigterm(termsig);
				/* never reached */
			}
			if(hup)
			{
				dosighup(SIGHUP);
				hup=0;
			}
			if(alrm)
			{
				dosigalrm(SIGALRM);
				alrm=0;
			}
			FD_ZERO(&fds);
			FD_SET(sockfd,&fds);

			maxfd=sockfd;
			if(listen_tcpip)
			{
				FD_SET(sockinet,&fds);
				maxfd=max(maxfd,sockinet);
			}
			if(clin>0 && hw.rec_mode!=0)
			{
				FD_SET(hw.fd,&fds);
				maxfd=max(maxfd,hw.fd);
			}
			
			for(i=0;i<clin;i++)
			{
				/* Ignore this client until codes have been
				   sent and it will get an answer. Otherwise
				   we could mix up answer packets and send
				   them back in the wrong order.*/
				if(clis[i]!=repeat_fd)
				{
					FD_SET(clis[i],&fds);
					maxfd=max(maxfd,clis[i]);
				}
			}
			timerclear(&tv);
			reconnect=0;
			for(i=0;i<peern;i++)
			{
				if(peers[i]->socket!=-1)
				{
					FD_SET(peers[i]->socket,&fds);
					maxfd=max(maxfd,peers[i]->socket);
				}
				else
				{
					if(timerisset(&tv))
					{
						if(timercmp(&tv,
							    &peers[i]->reconnect,
							    >))
						{
							tv=peers[i]->reconnect;
						}
					}
					else
					{
						tv=peers[i]->reconnect;
					}
				}
			}
			if(timerisset(&tv))
			{
				gettimeofday(&now,NULL);
				if(timercmp(&now,&tv,>=))
				{
					timerclear(&tv);
				}
				else
				{
					timersub(&tv,&now,&start);
					tv=start;
				}
				reconnect=1;
			}
			gettimeofday(&start,NULL);
			if(maxusec>0)
			{
				tv.tv_sec=0;
				tv.tv_usec=maxusec;
			}
			if(timerisset(&tv) || reconnect)
			{
				ret=select(maxfd+1,&fds,NULL,NULL,&tv);
			}
			else
			{
				ret=select(maxfd+1,&fds,NULL,NULL,NULL);
			}
			gettimeofday(&now,NULL);
			if(free_remotes!=NULL)
			{
				free_old_remotes();
			}
			if(maxusec>0)
			{
				if(ret==0)
				{
					return(0);
				}
				if(time_elapsed(&start,&now)>=maxusec)
				{
					return(0);
				}
				else
				{
					maxusec-=time_elapsed(&start,&now);
				}
				
			}
			if(reconnect)
			{
				connect_to_peers();
			}
		}
		while(ret==-1 && errno==EINTR);
		if(ret==-1)
		{
			logprintf(LOG_ERR,"select() failed");
			logperror(LOG_ERR,NULL);
			continue;
		}
		
		for(i=0;i<clin;i++)
		{
			if(FD_ISSET(clis[i],&fds))
			{
				FD_CLR(clis[i],&fds);
				if(get_command(clis[i])==0)
				{
					remove_client(clis[i]);
					i--;
				}
			}
		}
		for(i=0;i<peern;i++)
		{
			if(peers[i]->socket!=-1 &&
			   FD_ISSET(peers[i]->socket,&fds))
			{
				if(get_peer_message(peers[i])==0)
				{
					shutdown(peers[i]->socket,2);
					close(peers[i]->socket);
					peers[i]->socket=-1;
					peers[i]->connection_failure = 1;
					gettimeofday(&peers[i]->reconnect,NULL);
					peers[i]->reconnect.tv_sec+=5;
				}
			}
		}

		if(FD_ISSET(sockfd,&fds))
		{
			LOGPRINTF(1,"registering local client");
			add_client(sockfd);
		}
		if(listen_tcpip && FD_ISSET(sockinet,&fds))
		{
			LOGPRINTF(1,"registering inet client");
			add_client(sockinet);
		}
                if(clin>0 && hw.rec_mode!=0 && FD_ISSET(hw.fd,&fds))
                {
                        /* we will read later */
			return(1);
                }
	}
}

void loop()
{
	char *message;
	int len,i;
	
	logprintf(LOG_NOTICE,"lircd(%s) ready",LIRC_DRIVER);
	while(1)
	{
		(void) waitfordata(0);
		if(!hw.rec_func) continue;
		message=hw.rec_func(remotes);
		
		if(message!=NULL)
		{
			len=strlen(message);
			
			for (i=0; i<clin; i++)
			{
				LOGPRINTF(1,"writing to client %d",i);
				if(write_socket(clis[i],message,len)<len)
				{
					remove_client(clis[i]);
					i--;
				}			
			}
		}
	}
}

int main(int argc,char **argv)
{
	struct sigaction act;
	int nodaemon=0;
	mode_t permission=S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;

	while(1)
	{
		int c;
		static struct option long_options[] =
		{
			{"help",no_argument,NULL,'h'},
			{"version",no_argument,NULL,'v'},
			{"nodaemon",no_argument,NULL,'n'},
			{"permission",required_argument,NULL,'p'},
			{"device",required_argument,NULL,'d'},
			{"listen",optional_argument,NULL,'l'},
			{"connect",required_argument,NULL,'c'},
#                       ifdef DEBUG
			{"debug",optional_argument,NULL,'D'},
#                       endif
			{0, 0, 0, 0}
		};
#               ifdef DEBUG
		c = getopt_long(argc,argv,"hvnp:d:l::c:D::",long_options,NULL);
#               else
		c = getopt_long(argc,argv,"hvnp:d:l::c:",long_options,NULL);
#               endif
		if(c==-1)
			break;
		switch (c)
		{
		case 'h':
			printf("Usage: %s [options] [config-file]\n",progname);
			printf("\t -h --help\t\t\tdisplay this message\n");
			printf("\t -v --version\t\t\tdisplay version\n");
			printf("\t -n --nodaemon\t\t\tdon't fork to background\n");
			printf("\t -p --permission=mode\t\tfile permissions for " LIRCD "\n");
			printf("\t -d --device=device\t\tread from given device\n");
			printf("\t -l --listen[=port]\t\tlisten for network connections on port\n");
			printf("\t -c --connect=host[:port]\t\tconnect to remote lircd server\n");
#                       ifdef DEBUG
			printf("\t -D[debug_level] --debug[=debug_level]\n");
#                       endif
			return(EXIT_SUCCESS);
		case 'v':
			printf("%s\n",progname);
			return(EXIT_SUCCESS);
		case 'n':
			nodaemon=1;
			break;
		case 'p':
			if(oatoi(optarg)==-1)
			{
				fprintf(stderr,"%s: invalid mode\n",progname);
				return(EXIT_FAILURE);
			}
			permission=oatoi(optarg);
			break;
		case 'd':
			hw.device=optarg;
			break;
		case 'l':
			listen_tcpip=1;
			if(optarg)
			{
				long p;
				char *endptr;
				
				p=strtol(optarg,&endptr,10);
				if(!*optarg || *endptr || p<1 || p>USHRT_MAX)
				{
					fprintf(stderr,
						"%s: bad port number \"%s\"\n",
						progname,optarg);
					return(EXIT_FAILURE);
				}
				port=(unsigned short int) p;
			}
			else
			{
				port=LIRC_INET_PORT;
			}
			break;
		case 'c':
			if(!add_peer_connection(optarg))
				return(EXIT_FAILURE);
			break;
#               ifdef DEBUG
		case 'D':
			if(optarg==NULL) debug=1;
			else
			{
				/* don't check for errors */
				debug=atoi(optarg);
			}
			break;
#               endif
		default:
			printf("Usage: %s [options] [config-file]\n",progname);
			return(EXIT_FAILURE);
		}
	}
	if(optind==argc-1)
	{
	        configfile=argv[optind];
	}
	else if(optind!=argc)
	{
		fprintf(stderr,"%s: invalid argument count\n",progname);
		return(EXIT_FAILURE);
	}
	
#ifdef LIRC_NETWORK_ONLY
	if(peern==0)
	{
		fprintf(stderr,"%s: there's no hardware I can use and "
			"no peers are specified\n",progname);
		return(EXIT_FAILURE);
	}
#endif
	signal(SIGPIPE,SIG_IGN);
	
	start_server(permission,nodaemon);
	
	act.sa_handler=sigterm;
	sigfillset(&act.sa_mask);
	act.sa_flags=SA_RESTART;           /* don't fiddle with EINTR */
	sigaction(SIGTERM,&act,NULL);
	sigaction(SIGINT,&act,NULL);
	
	act.sa_handler=sigalrm;
	sigemptyset(&act.sa_mask);
	act.sa_flags=SA_RESTART;           /* don't fiddle with EINTR */
	sigaction(SIGALRM,&act,NULL);
	
	remotes=NULL;
	config();                          /* read config file */
	
	act.sa_handler=sighup;
	sigemptyset(&act.sa_mask);
	act.sa_flags=SA_RESTART;           /* don't fiddle with EINTR */
	sigaction(SIGHUP,&act,NULL);
	
#ifdef DAEMONIZE
	/* ready to accept connections */
	if(!nodaemon) daemonize();
#endif
	
#if defined(SIM_SEND) && !defined(DAEMONIZE)
	{
		struct ir_remote *r;
		struct ir_ncode *c;
		
		if(hw.init_func)
		{
			if(!hw.init_func()) dosigterm(SIGTERM);
		}
		
		printf("space 1000000\n");
		r=remotes;
		while(r!=NULL)
		{
			c=r->codes;
			while(c->name!=NULL)
			{
				repeat_remote=NULL;
				repeat_code=NULL;
				hw.send_func(r,c);
				repeat_remote=r;
				repeat_code=c;
				hw.send_func(r,c);
				hw.send_func(r,c);
				hw.send_func(r,c);
				hw.send_func(r,c);
				c++;
			}
			r=r->next;
		}
		fflush(stdout);
		if(hw.deinit_func) hw.deinit_func();
	}
	fprintf(stderr,"Ready.\n");
	dosigterm(SIGTERM);
#endif
	loop();

	/* never reached */
	return(EXIT_SUCCESS); 
}
