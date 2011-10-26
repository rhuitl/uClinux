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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dhcpcd.h"
#include "client.h"
#include "signals.h"

#include <linux/autoconf.h>
#ifdef CONFIG_LEDMAN
#include <linux/ledman.h>
#endif

struct in_addr  inform_ipaddr;
char		*ProgramName	=	NULL;
char            **ProgramEnviron=       NULL;
char		*IfName		=	DEFAULT_IFNAME;
int		IfName_len	=	DEFAULT_IFNAME_LEN;
char		*HostName	=	NULL;
int		HostName_len	=	0;
char		*Cfilename	=	NULL;
unsigned char	*ClassID	=	NULL;
int		ClassID_len	=	0;
unsigned char	*ClientID	=	NULL;
int		ClientID_len	=	0;
void		*(*currState)()	=	&dhcpReboot;
int		DebugFlag	=	0;
int		BeRFC1541	=	0;
unsigned	LeaseTime	=	DEFAULT_LEASETIME;
int		ReplResolvConf	=	1;
int		SetDomainName	=	0;
int		SetHostName	=	0;
int             BroadcastResp   =       0;
time_t          TimeOut         =	DEFAULT_TIMEOUT;
int 		magic_cookie    =       0;
unsigned short  dhcpMsgSize     =       0;
unsigned        nleaseTime      =       0;
int		DoCheckSum	=	0;
int		TestCase	=	0;
int		Persistent	=	0;
int		DoArpCheck	=	1;

/*****************************************************************************/
void print_version()
{
  fprintf(stderr,"\
DHCP Client Daemon v."VERSION"\n\
Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>\n\
Copyright (C) January, 1998 Sergei Viznyuk <sv@phystech.com>\n\
Location: http://www.phystech.com/download/\n");
}
/*****************************************************************************/
int dhcpcdmain(argn,argc,argv)
int argn;
char *argc[],*argv[];
{
  int killFlag		=	0;
  int versionFlag	=	0;
  int s			=	1;
  int k			=	1;
  int i			=	1;
 
  if ( getuid() )
    {
      fprintf(stderr,"****  %s: not a superuser\n",argc[0]);
      exit(1);
    }

  while ( argc[i] )
    if ( argc[i][0]=='-' )
prgs: switch ( argc[i][s] )
	{
	  case 0:
	    i++;
	    s=1;
	    break;
	  case 'k':
	    s++;
	    killFlag=SIGHUP;
	    goto prgs;
	  case 'n':
	    s++;
	    killFlag=SIGALRM;
	    goto prgs;
	  case 'd':
	    s++;
	    DebugFlag=1;
	    goto prgs;
	  case 'a':
	    s++;
	    DoArpCheck = 1;
	    break;
	  case 'p':
	    s++;
	    Persistent = 1;
	    break;
	  case 'r':
	    s++;
	    BeRFC1541=1;
	    goto prgs;
	  case 'D':
	    s++;
	    SetDomainName=1;
	    goto prgs;
	  case 'H':
	    s++;
	    SetHostName=1;
	    goto prgs;
	  case 'R':
	    s++;
	    ReplResolvConf=0;
	    goto prgs;
	  case 'V':
	    s++;
	    versionFlag=1;
	    goto prgs;
	  case 'c':
	    i++;
	    Cfilename=argc[i++];
	    if ( Cfilename == NULL || Cfilename[0] == '-' ) goto usage;
	    s=1;
	    break;
	  case 'i':
	    i++;
	    ClassID=argc[i++];
	    if ( ClassID == NULL || ClassID[0] == '-' ) goto usage;
	    s=1;
	    if ( (ClassID_len=strlen(ClassID)) < CLASS_ID_MAX_LEN+1 ) break;
	    fprintf(stderr,"****  %s: too long ClassID string: strlen=%d\n",
	    argc[0],ClassID_len);
	    goto usage;
	  case 'I':
	    i++;
	    ClientID=argc[i++];
	    if ( ClientID == NULL || ClientID[0] == '-' ) goto usage;
	    s=1;
	    if ( (ClientID_len=strlen(ClientID)) < CLIENT_ID_MAX_LEN ) break;
	    fprintf(stderr,"****  %s: too long ClientID string: strlen=%d\n",
	    argc[0],ClientID_len);
	    goto usage;
	  case 'h':
	    i++;
	    HostName=argc[i++];
	    if ( HostName == NULL || HostName[0] == '-' ) goto usage;
	    s=1;
	    if ( (HostName_len=strlen(HostName)+1) < HOSTNAME_MAX_LEN ) break;
	    fprintf(stderr,"****  %s: too long HostName string: strlen=%d\n",
	    argc[0],HostName_len);
	    break;
	  case 't':
	    i++;
	    if ( argc[i] )
	      TimeOut=atol(argc[i++]);
	    else
	      goto usage;
	    s=1;
	    if ( TimeOut > 0 ) break;
	    goto usage;
	  case 's':
	    if ( argc[i][s+1] ) goto usage;
	    i++;
	    if ( argc[i] && inet_aton(argc[i],&inform_ipaddr) )
	      i++;
	    else
	      memset(&inform_ipaddr,0,sizeof(inform_ipaddr));
	    currState = &dhcpInform;
	    s=1;
	    break;
	  case 'B':
	    s++;
	    BroadcastResp=1;
	    goto prgs;
	  case 'C':
	    s++;
	    DoCheckSum=1;
	    goto prgs;
	  case 'T':
	    s++;
	    TestCase=1;
	    goto prgs;
	  case 'l':
	    i++;
	    if ( argc[i] )
	      LeaseTime=atol(argc[i++]);
	    else
	      goto usage;
	    s=1;
	    if ( LeaseTime > 0 ) break;
          default:
usage:	    print_version();
fprintf(stderr,
"Usage: dhcpcd [-dkapnrBCDHRT] [-l leasetime] [-h hostname] [-t timeout]\n\
[-i vendorClassID] [-I ClientID] [-c filename] [-s [ipaddr]] [interface]\n");
	    exit(1);
	}
    else
      argc[k++]=argc[i++];
  if ( k > 1 )
    {
      if ( (IfName_len=strlen(argc[1])) > IFNAMSIZ )
        goto usage;
      else
        IfName=argc[1];
    }
  ProgramName=argc[0];
  ProgramEnviron=argv;
#ifdef CONFIG_LEDMAN
  if (strchr(IfName, '0')) {
	ledman_cmd(LEDMAN_CMD_ALT_ON, LEDMAN_LAN1_DHCP);
	ledman_cmd(LEDMAN_CMD_FLASH | LEDMAN_CMD_ALTBIT, LEDMAN_LAN1_DHCP);
  } else if (strchr(IfName, '1')) {
	ledman_cmd(LEDMAN_CMD_ALT_ON, LEDMAN_LAN2_DHCP);
	ledman_cmd(LEDMAN_CMD_FLASH | LEDMAN_CMD_ALTBIT, LEDMAN_LAN2_DHCP);
  }
#endif
  if ( killFlag ) killPid(killFlag);
  checkIfAlreadyRunning();
  if ( versionFlag ) print_version();
  openlog(PROGRAM_NAME,LOG_PID|LOG_CONS,LOG_LOCAL0);
  signalSetup();
  magic_cookie = htonl(MAGIC_COOKIE);
  dhcpMsgSize = htons(sizeof(dhcpMessage));
  nleaseTime = htonl(LeaseTime);
  if (!Persistent)
    alarm(TimeOut);
  do
    if ( (currState=(void *(*)())currState()) == NULL ) die(1);
  while ( currState != &dhcpBound );
  if ( TestCase ) die(0);
  alarm(0);
#ifdef DEBUG
  writePidFile(getpid());
#else
  s=fork();
  if ( s )
    {
      writePidFile(s);
      die(0); /* got into bound state. */
    }
  setsid();
  if ( (i=open("/dev/null",O_RDWR,0)) >= 0 )
    {
      (void)dup2(i,STDIN_FILENO);
      (void)dup2(i,STDOUT_FILENO);
      (void)dup2(i,STDERR_FILENO);
      if ( i > 2 ) (void)close(i);
    }
#endif
  chdir("/");
  do currState=(void *(*)())currState(); while ( currState );
  deletePidFile();
  die(1);
}

int die(int rc)
{
#ifdef CONFIG_LEDMAN
    if (strchr(IfName, '0'))
	  ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_LAN1_DHCP);
	else if (strchr(IfName, '1'))
	  ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_LAN2_DHCP);
#endif
	exit(rc);
}

