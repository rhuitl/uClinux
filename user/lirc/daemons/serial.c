/*      $Id: serial.c,v 5.6 2000/10/02 10:54:53 columbus Exp $      */

/****************************************************************************
 ** serial.c ****************************************************************
 ****************************************************************************
 *
 * common routines for hardware that uses the standard serial port driver
 * 
 * Copyright (C) 1999 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "lircd.h"

int tty_reset(int fd)
{
	struct termios options;

	if(tcgetattr(fd,&options)==-1)
	{
		LOGPRINTF(1,"tty_reset(): tcgetattr() failed");
		LOGPERROR(1,"tty_reset()");
		return(0);
	}
	cfmakeraw(&options);
	if(tcsetattr(fd,TCSAFLUSH,&options)==-1)
	{
		LOGPRINTF(1,"tty_reset(): tcsetattr() failed");
		LOGPERROR(1,"tty_reset()");
		return(0);
	}
	return(1);
}

int tty_setrtscts(int fd,int enable)
{
	struct termios options;

	if(tcgetattr(fd,&options)==-1)
	{
		LOGPRINTF(1,"tty_reset(): tcgetattr() failed");
		LOGPERROR(1,"tty_reset()");
		return(0);
	}
	if(enable)
	{
		options.c_cflag|=CRTSCTS;
		options.c_cflag|=CSTOPB;
	}
	else
	{
		options.c_cflag&=~CRTSCTS;
		options.c_cflag&=~CSTOPB;
	}
	if(tcsetattr(fd,TCSAFLUSH,&options)==-1)
	{
		LOGPRINTF(1,"tty_reset(): tcsetattr() failed");
		LOGPERROR(1,"tty_reset()");
		return(0);
	}
	return(1);
}

int tty_setbaud(int fd,int baud)
{
	struct termios options;
	int speed;

	switch(baud)
	{
	case 300:
		speed=B300;
		break;
	case 1200:
		speed=B1200;
		break;
	case 2400:
                speed=B2400;
                break;
	case 4800:
                speed=B4800;
                break;
	case 9600:
                speed=B9600;
                break;
	case 19200:
                speed=B19200;
                break;
	case 38400:
                speed=B38400;
                break;
	case 57600:
                speed=B57600;
                break;
	case 115200:
                speed=B115200;
                break;
	default:
		LOGPRINTF(1,"tty_setbaud(): bad baud rate %d",baud);
		return(0);
	}		
	if(tcgetattr(fd, &options)==-1)
	{
		LOGPRINTF(1,"tty_setbaud(): tcgetattr() failed");
		LOGPERROR(1,"tty_setbaud()");
		return(0);
	}
	(void) cfsetispeed(&options,speed);
	(void) cfsetospeed(&options,speed);
	if(tcsetattr(fd,TCSAFLUSH,&options)==-1)
	{
		LOGPRINTF(1,"tty_setbaud(): tcsetattr() failed");
		LOGPERROR(1,"tty_setbaud()");
		return(0);
	}
	return(1);
}

int tty_create_lock(char *name)
{
	char filename[FILENAME_MAX+1];
	char symlink[FILENAME_MAX+1];
	char cwd[FILENAME_MAX+1];
	char *last,*s;
	char id[10+1+1];
	int lock;
	int len;
	
	strcpy(filename,"/var/lock/LCK..");
	
	last=strrchr(name,'/');
	if(last!=NULL)
		s=last+1;
	else
		s=name;
	
	if(strlen(filename)+strlen(s)>FILENAME_MAX)
	{
		logprintf(LOG_ERR,"%s: invalid filename \"%s%s\"",
			  filename,s);
		return(0);
	}
	strcat(filename,s);
	
	if((len=snprintf(id,10+1+1,"%10d\n",getpid()))==-1)
	{
		logprintf(LOG_ERR,"invalid pid \"%d\"",getpid());
		return(0);
	}

	lock=open(filename,O_CREAT|O_EXCL|O_WRONLY,0644);
	if(lock==-1)
	{
		logprintf(LOG_ERR,"could not create lock file \"%s\"",
			  filename);
		logperror(LOG_ERR,NULL);
		lock=open(filename,O_RDONLY);
		if(lock!=-1)
		{
			len=read(lock,id,10+1);
			if(len==10+1)
			{
				if(read(lock,id,1)==0)
				{
					logprintf(LOG_ERR,
						  "%s is locked by PID %s",
						  name,id);
				}
			}
			close(lock);
		}
		return(0);
	}
	if(write(lock,id,len)!=len)
	{
		logprintf(LOG_ERR,"%s: could not write pid to lock file");
		logperror(LOG_ERR,NULL);
		close(lock);
		if(unlink(filename)==-1)
		{
			logprintf(LOG_ERR,"could not delete file \"%s\"",
				  filename);
			logperror(LOG_ERR,NULL);
			/* FALLTHROUGH */
		}
		return(0);
	}
	if(close(lock)==-1)
	{
		logprintf(LOG_ERR,"could not close lock file");
		logperror(LOG_ERR,NULL);
		if(unlink(filename)==-1)
		{
			logprintf(LOG_ERR,"could not delete file \"%s\"",
				  filename);
			logperror(LOG_ERR,NULL);
			/* FALLTHROUGH */
		}
		return(0);
	}

	if((len=readlink(name,symlink,FILENAME_MAX))==-1)
	{
		if(errno!=EINVAL) /* symlink */
		{
			logprintf(LOG_ERR,"readlink() failed for \"%s\"",name);
			logperror(LOG_ERR,NULL);
			if(unlink(filename)==-1)
			{
				logprintf(LOG_ERR,"could not delete file \"%s\"",
					  filename);
				logperror(LOG_ERR,NULL);
				/* FALLTHROUGH */
			}
			return(0);
		}
	}
	else
	{
		symlink[len]=0;

		if(last)
		{
			char dirname[FILENAME_MAX+1];

			if(getcwd(cwd,FILENAME_MAX)==NULL)
			{
				logprintf(LOG_ERR,"getcwd() failed");
				logperror(LOG_ERR,NULL);
				if(unlink(filename)==-1)
				{
					logprintf(LOG_ERR,"%s: could not delete "
						  "file \"%s\"",filename);
					logperror(LOG_ERR,NULL);
				        /* FALLTHROUGH */
				}
				return(0);
			}
			
			strcpy(dirname,name);
			dirname[strlen(name)-strlen(last)]=0;
			if(chdir(dirname)==-1)
			{
				logprintf(LOG_ERR,"chdir() to \"%s\" "
					  "failed",dirname);
				logperror(LOG_ERR,NULL);
				if(unlink(filename)==-1)
				{
					logprintf(LOG_ERR,"could not delete "
						  "file \"%s\"",filename);
					logperror(LOG_ERR,NULL);
				        /* FALLTHROUGH */
				}
				return(0);
			}
		}
		if(tty_create_lock(symlink)==-1)
		{
			if(unlink(filename)==-1)
			{
				logprintf(LOG_ERR,"could not delete file "
					  "\"%s\"",filename);
				logperror(LOG_ERR,NULL);
				/* FALLTHROUGH */
			}
			return(0);
		}
		if(last)
		{
			if(chdir(cwd)==-1)
			{
				logprintf(LOG_ERR,"chdir() to \"%s\" "
					  "failded ",cwd);
				logperror(LOG_ERR,NULL);
				if(unlink(filename)==-1)
				{
					logprintf(LOG_ERR,"could not delete "
						  "file \"%s\"",filename);
					logperror(LOG_ERR,NULL);
				        /* FALLTHROUGH */
				}
				return(0);
			}
		}
	}
	return(1);
}

int tty_delete_lock(void)
{
	DIR *dp;
	struct dirent *ep;
	int lock;
	int len;
	char id[20+1],*endptr;
	char filename[FILENAME_MAX+1];
	long pid;
	int retval=1;
	
	dp=opendir("/var/lock/");
	if(dp!=NULL)
	{
		while((ep=readdir(dp)))
		{
			strcpy(filename,"/var/lock/");
			if(strlen(filename)+strlen(ep->d_name)>FILENAME_MAX) 
			{retval=0;continue;}
			strcat(filename,ep->d_name);
			lock=open(filename,O_RDONLY);
			if(lock==-1) {retval=0;continue;}
			len=read(lock,id,20);
			close(lock);
			if(len<=0) {retval=0;continue;}
			id[len]=0;
			pid=strtol(id,&endptr,10);
			if(!*id || *endptr!='\n')
			{
				logprintf(LOG_WARNING,"invalid lockfile (%s) "
					  "detected",filename);
				retval=0;
				continue;
			}
			if(pid==getpid())
			{
				if(unlink(filename)==-1)
				{
					logprintf(LOG_ERR,"could not delete "
						  "file \"%s\"",filename);
					logperror(LOG_ERR,NULL);
					retval=0;
					continue;
				}
			}
		}
		closedir(dp);
	}
	else
	{
		logprintf(LOG_ERR,"could not open directory \"/var/lock/\"");
		return(0);
	}
	return(retval);
}

int tty_set(int fd,int rts,int dtr)
{
	int mask;
	
	mask=rts ? TIOCM_RTS:0;
	mask|=dtr ? TIOCM_DTR:0;
	if(ioctl(fd,TIOCMBIS,&mask)==-1)
	{
		LOGPRINTF(1,"tty_set(): ioctl() failed");
		LOGPERROR(1,"tty_set()");
		return(0);
	}
	return(1);
}

int tty_clear(int fd,int rts,int dtr)
{
	int mask;
	
	mask=rts ? TIOCM_RTS:0;
	mask|=dtr ? TIOCM_DTR:0;
	if(ioctl(fd,TIOCMBIC,&mask)==-1)
	{
		LOGPRINTF(1,"tty_clear(): ioctl() failed");
		LOGPERROR(1,"tty_clear()");
		return(0);
	}
	return(1);
}

int tty_write(int fd,char byte)
{
	if(write(fd,&byte,1)!=1) 
	{
		LOGPRINTF(1,"tty_write(): write() failed");
		LOGPERROR(1,"tty_write()");
		return(-1);
	}	
	/* wait until the stop bit of Control Byte is sent
	   (for 9600 baud rate, it takes about 100 msec */
	usleep(100*1000);
	
	/* we don´t wait because tcdrain() does this for us */
	/* tcdrain(fd); */ 
	/* but unfortunately this does not seem to be
	   implemented in 2.0.x kernels ... */
	return(1);
}

int tty_read(int fd,char *byte)
{
	fd_set fds;
	int ret;
	struct timeval tv;
	
	FD_ZERO(&fds);
	FD_SET(fd,&fds);
	
	tv.tv_sec=1;    /* timeout after 1 sec */
	tv.tv_usec=0;
	ret=select(fd+1,&fds,NULL,NULL,&tv);
	if(ret==0)
	{
		logprintf(LOG_ERR,"tty_read(): timeout");
		return(-1); /* received nothing, bad */
	}
	else if(ret!=1)
	{
		LOGPRINTF(1,"tty_read(): select() failed");
		LOGPERROR(1,"tty_read()");
		return(-1);
	}
	if(read(fd,byte,1)!=1)
	{
		LOGPRINTF(1,"tty_read(): read() failed");
		LOGPERROR(1,"tty_read()");
		return(-1);		
	}
	return(1);
}

int tty_write_echo(int fd,char byte)
{
	char reply;

	if(tty_write(fd,byte)==-1) return(-1);
	if(tty_read(fd,&reply)==-1) return(-1);
	LOGPRINTF(1,"sent: A%u D%01x reply: A%u D%01x",
		  (((unsigned int) (unsigned char) byte)&0xf0)>>4,
		  ((unsigned int) (unsigned char) byte)&0x0f,
		  (((unsigned int) (unsigned char) reply)&0xf0)>>4,
		  ((unsigned int) (unsigned char) reply)&0x0f);
	if(byte!=reply)
	{
		logprintf(LOG_ERR,"Command mismatch.");
	}
	return(1);
}
