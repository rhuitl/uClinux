/*
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 * Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>
 * 
 * dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <setjmp.h>
#include "dhcpcd.h"
#include "client.h"
#include "pathnames.h"

extern char		*ProgramName;
extern char		*IfName;
extern int		DebugFlag;
extern jmp_buf		env;
extern void		*(*currState)();
/*****************************************************************************/
void killPid(sig)
int sig;
{
  FILE *fp;
  pid_t pid;
  char pidfile[48];
  sprintf(pidfile,PID_FILE_PATH,IfName);
  fp=fopen(pidfile,"r");
  if ( fp == NULL ) goto ntrn;
  fscanf(fp,"%u",&pid);
  fclose(fp);
  if ( kill(pid,sig) )
    {
      unlink(pidfile);
ntrn: if ( sig == SIGALRM ) return;
      fprintf(stderr,"****  %s: not running\n",ProgramName);
      die(1);
    }
  die(0);
}
/*****************************************************************************/
void writePidFile(pid_t pid)
{
  FILE *fp;
  char pidfile[48];
  sprintf(pidfile,PID_FILE_PATH,IfName);
  fp=fopen(pidfile,"w");
  if ( fp == NULL )
    {
      syslog(LOG_ERR,"writePidFile: fopen: %m\n");
      die(1);
    }
  fprintf(fp,"%u\n",pid);
  fclose (fp);
}
/*****************************************************************************/
void deletePidFile()
{
  char pidfile[48];
  sprintf(pidfile,PID_FILE_PATH,IfName);
  unlink(pidfile);
}
/*****************************************************************************/
void sigHandler(sig)
int sig;
{
  if( sig == SIGCHLD )
    {
      waitpid(-1,NULL,WNOHANG);
      return;
    }
  if ( sig == SIGALRM )
    {
      if ( currState == &dhcpBound )
        siglongjmp(env,1); /* this timeout is T1 */
      else
        {
          if ( currState == &dhcpRenew )
            siglongjmp(env,2); /* this timeout is T2 */
          else
	    {
	      if ( currState == &dhcpRebind )
	        siglongjmp(env,3);  /* this timeout is dhcpIpLeaseTime */
	      else
		{
		  if ( currState == &dhcpReboot )
		    siglongjmp(env,4);  /* failed to acquire the same IP address */
		  else
	            syslog(LOG_ERR,"timed out waiting for a valid DHCP server response\n");
		}
	    }
        }
    }
  else
    {
      if ( sig == SIGHUP ) 
	{
	  dhcpRelease();
	  /* allow time for final packets to be transmitted before shutting down     */
	  /* otherwise 2.0 drops unsent packets. fixme: find a better way than sleep */
	  sleep(1);
	}
	syslog(LOG_ERR,"terminating on signal %d\n",sig);
    }
  dhcpStop();
  deletePidFile();
  die(sig);
}
/*****************************************************************************/
void signalSetup()
{
  int i;
  struct sigaction action;
  sigaction(SIGHUP,NULL,&action);
  action.sa_handler= &sigHandler;
  action.sa_flags = 0;
  for (i=1;i<16;i++) sigaction(i,&action,NULL);
  sigaction(SIGCHLD,&action,NULL);
}
