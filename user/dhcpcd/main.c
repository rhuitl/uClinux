/* $Id: main.c,v 1.15 2002-03-07 02:29:14 gerg Exp $
 *
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
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
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#ifdef CONFIG_NETtel
#include <asm/nettel.h>
#include <linux/ledman.h>
#endif
#include "if.h"
#include "dhcp.h"
#include "signal-handler.h"
#include "error-handler.h"
#include "daemon.h"
#include "client.h"
#include "memory.h"

#define DEFAULT_IF	"eth0"

char *CommandFile = NULL;		/* invoked command file name when dhcpcd
								 * succeeds in getting an IP address
								 */
int	  BeRFC1541 = 0;			/* default is InternetDraft mode */
char *Hostname = NULL;			/* hostname in the DHCP msg for xmit */
int   Persistent = 0;			/* Keep trying until you get address */
int   ArpCheck = 1;				/* Check if address already used? */

#ifdef LLIP_SUPPORT
#include "llip.h"
int	AutoIP	= 0;
#endif

char  pidfile[128];			/* file name in which pid is stored */
static char VersionStr[] = "dhcpcd 0.70\n";

void	usage();

char  Ifname[16];			/* global interface name */


int
main(argc, argv)
int argc;
char *argv[];
{
	char  ifname[16];			/* interface name */
	char *clientId = NULL;		/* ptr to client identifier user specified */
	int   killFlag = 0;			/* if 1: kill the running proc and exit */

	int res;
	DebugFlag = 0;				/* default is NON debug mode */
	srand((u_int)time(NULL));
	signalSetup();
	umask(0);					/* clear umask */
	classIDsetup(NULL);			/* setup default class identifier */
	/* option handling
	 */
	while ( *++argv ) {
		if ( **argv == '-' ) {
			switch ( argv[0][1] ) {
			  case 'c':
				if ( *++argv == NULL ) {
					usage();
				}
				if ( (CommandFile = malloc(strlen(*argv)+1)) == NULL ) {
					usage();
				}
				strcpy(CommandFile, *argv);
				break;
			  case 'd':
				DebugFlag = 1;
				break;
			  case 'p':
				Persistent = 1;
				break;
			  case 'a':
				ArpCheck = 0;
				break;
			  case 'h':
				if ( *++argv == NULL ) {
					usage();
				}
				Hostname = smalloc(strlen(*argv)+1);
				strcpy(Hostname, *argv);
				break;
			  case 'i':
				if ( *++argv == NULL ) {
					usage();
				}
				classIDsetup(*argv); /* overwrite class identifier */
				break;
			  case 'I':
				if ( *++argv == NULL ) {
					usage();
				}
				clientId = *argv;
				break;
			  case 'k':
				killFlag = 1;	/* kill running process and exit */
				break;
			  case 'l':
				++argv;
				if ( *argv == NULL || **argv == '-' ) {
					usage();
				}
				SuggestLeaseTime = atol(*argv);
				break;
			  case 'r':
				BeRFC1541 = 1;	/* Be RFC1541 compliant */
				break;
			  case 'v':
				fflush(stdout);
				fputs(VersionStr, stderr);
				fflush(NULL);
				exit(0);
#ifdef LLIP_SUPPORT
			case 'A': /* auto IP support if no dhcp lease is obtained */
				AutoIP=1;
				Persistent=1;
				break;
#else
			case 'A': /* auto IP support option is ignored but logged */
				syslog(LOG_WARNING, "-A (enable auto IP) option was specified but will be ignored.");
				break;
#endif
			  default:
				usage();
			}
		} else {
			break;
		}
	}

#if defined(CONFIG_NETtel) && defined(CONFIG_M5307)
	/*
	 *	If hard wired boot switch is flipped then we should just
	 *	hard configure an address, and do no DHCP now. We beleive
	 *	that on old boards this should always float low...
	 */
#if 0 /* disabled until we config option it or work out a safer mechanism */
	if (*((unsigned short *) (MCF_MBAR + MCFSIM_PADAT)) & 0x0010) {
		launch_script("/etc/ip.static");
		exit(0);
	}
#endif
	if(Hostname == NULL) {
		Hostname = smalloc(32);
		/*bzero(Hostname,32);*/
		gethostname(Hostname, 32);
	}
#endif

	if ( getuid() != 0 && geteuid() != 0 ) {
		errQuit("Must be root");
	}
	if ( *argv ) {
		strncpy(ifname, *argv, sizeof(ifname));
	} else {
		strncpy(ifname, DEFAULT_IF, sizeof(ifname));
	}
#ifdef CONFIG_NETtel
	sprintf(pidfile, PIDFILE, ifname);
	if((res = writePidFile()) == -2){
		fprintf(stderr, "Already running on %s.\n", ifname);
		syslog(LOG_ERR, "already running on %s.",ifname);
		return;
	}else if(res>0){
		fprintf(stderr, "Warning - stale pid file found for %s - cleaned.\n", ifname);
		syslog(LOG_INFO, "Stale pid file found and cleaned up.");
	}else if(res == -1){
		fprintf(stderr, "Failed to create pid file - exiting.\n");
		syslog(LOG_ERR, "we failed to create a pid-file -%d.", errno);
		return;
	}
	if (strchr(ifname, '0')) {
		ledman_cmd(LEDMAN_CMD_ALT_ON, LEDMAN_LAN1_DHCP);
		ledman_cmd(LEDMAN_CMD_FLASH|LEDMAN_CMD_ALTBIT, LEDMAN_LAN1_DHCP);
		strcpy(Ifname, ifname);
	} else if (strchr(ifname, '1')) {
		ledman_cmd(LEDMAN_CMD_ALT_ON, LEDMAN_LAN2_DHCP);
		ledman_cmd(LEDMAN_CMD_FLASH|LEDMAN_CMD_ALTBIT, LEDMAN_LAN2_DHCP);
		strcpy(Ifname, ifname);
	} else
		strcpy(Ifname, "");
#endif
#ifndef EMBED
	/*
	 * Don't do this for now...
	 */
	if ( killFlag ) {
		sprintf(pidfile, PIDFILE, ifname);
		killCurProc(pidfile);
	}
	if ( !DebugFlag ) {
		sprintf(pidfile, PIDFILE, ifname);
		daemonInit(pidfile);
	}
#endif
	sleep(1);
	logOpen("dhcpcd", LOG_PID, LOG_LOCAL0);
	ifReset(ifname);			/* reset interface, 'Ifbuf' */
	clientIDsetup(clientId, ifname);
	dhcpMsgInit(ifname);
	dhcpClient();
	exit(0);
}

void
usage()
{
	fflush(stdout);
#ifndef LLIP_SUPPORT
	fputs("Usage: dhcpcd [-c filename] [-dpa] [-i classIdentifier] [-I clientIdentifier] [-k] [-l leasetime] [-h hostname] [ifname]\n",
		  stderr);
#else
	fputs("Usage: dhcpcd [-c filename] [-dpaA] [-i classIdentifier] [-I clientIdentifier] [-k] [-l leasetime] [-h hostname] [ifname]\n", stderr);
#endif
	fflush(NULL);
	exit(1);
}

void die(int rc)
{
#ifdef CONFIG_NETtel
	if (strchr(Ifname, '0'))
		ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_LAN1_DHCP);
	else if (strchr(Ifname, '0'))
		ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_LAN2_DHCP);
#endif
/*
 * Kill the pid file.
 */
	unlink(pidfile);
	exit(rc);
}

/*
 * Write out the pid into the file specified by pidfile.
 * return code:    0   - everything worked like a dream
 *                 1   - there was a stale PID file
 *                -1   - something went wrong
 *                -2   - the program is already running
 */ 
int writePidFile()
{
	FILE	*file;
	pid_t	pid;
	int	fd, rc, old = 0;

	pid = getpid();
	fd = open(pidfile, O_CREAT | O_EXCL | O_RDWR, S_IRWXU);
	if (fd < 0) {
		if (errno == EEXIST) {
			/* See if the old program is still alive */
			if ((rc = isOldPid()) < 0) {
				return(-1);
			} else if (rc == 1) {
				old = 1;
			}else {
				return(-2);
			}
		} else {
			fprintf(stderr, "DHCPCD: unexpected errno value"
				" - %d\n", errno);
			return(-1);
		}
	}
	close(fd);

	if ((file = fopen(pidfile, "w")) == NULL) {
		fprintf(stderr, "DHCPCD: open pid file errno=%d\n", errno);
		return(-1);
	}
	rc = fprintf(file, "%d\n",  pid);
	fclose(file);

	if (rc <= 0) {
		fprintf(stderr, "DHCPCD: pif file errno=%d\n", errno);
		return(-1);
	}

	return(old);
}


/*
 * Check whether a pidfile contains the pid for a current active dhcpcd, or an
 * old defunct one (which would hang around in the case of a -9)
 * return code:   1  - the pidfile is NOT a currently active dhcpcd
 *                0  - the pidfile is a currently active dhcpcd
 */
int isOldPid()
{
	FILE	*file;
	char	fileName[48];
	char	oldCmd[7] = {'\0'};
	pid_t	pid;
	int	rc;

	if ((file = fopen(pidfile, "r")) == NULL)
		return(-1);
	rc = fscanf(file, "%d", &pid);
	fclose(file);

	if (rc <= 0)
		return(-1);

	sprintf(fileName, "/proc/%d/cmdline", pid);
	if ((file = fopen(fileName, "r")) == NULL)
		return(1);
	rc = fread(oldCmd, sizeof(oldCmd) - 1, 1, file);
	fclose(file);

	if (rc != 1)
		return(1);

	oldCmd[6] = '\0';
	if(strcmp("dhcpcd", oldCmd) == 0)
		return(0);
	return(1);
}
