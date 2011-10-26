/* $Id: hostinfo.c,v 1.2 2009-01-23 00:31:52 davidm Exp $
 *
 * dhcpcd - DHCP client daemon -
 * Copyright (C) 1996 - 1997 Yoichi Hariguchi <yoichi@fore.com>
 *
 * Dhcpcd is an RFC2131 and RFC1541 compliant DHCP client daemon.
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
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dhcp.h"
#include "dhcp-options.h"
#include "error-handler.h"
#include "signal-handler.h"
#include "hostinfo.h"
#include "if.h"
#include "memory.h"

#define MAXLEN 256

extern char *CommandFile;

void
setupOptInfo(u_char *dest[], const u_char *src[])
{
	int i;

	for ( i = 0; i < MAXNOPT; ++i ) {
		if ( src[i] != NULL ) {
			if ( dest[i] != NULL ) {
				free(dest[i]);
			}
			dest[i] = smalloc(*src[i]+1);
			bcopy(src[i], dest[i], *src[i]+1);
		}
	}
}


void
freeOptInfo(u_char *optp[])
{
    int i;

	for ( i = 0; i < MAXNOPT; ++i ) {
		if ( optp[i] != NULL ) {
			free(optp[i]);
			optp[i] = NULL;
		}
	}
}

void
saveHostInfo(const u_char *optp[])
{
	int fd;
	char path[MAXLEN];
	char buf[MAXLEN];
	
#ifndef EMBED
	/* hostname
	 */
	if ( optp[OhostName] != NULL ) {
		strncpy(path, optp[OhostName]+1, *optp[OhostName]);
		if ( sethostname(path, *optp[OhostName]) < 0 ) {
			logSysRet("sethostname (setupHostInfo)");
		}
	}
	/* NIS domain name
	 */
	if ( optp[OnisDomName] != NULL ) {
		strncpy(path, optp[OnisDomName]+1, *optp[OnisDomName]);
		if ( setdomainname(path, *optp[OnisDomName]) < 0 ) {
			logSysRet("setdomainname (setupHostInfo)");
		}
	}
#endif
	/* default route (routers)
	 */
	if ( optp[Orouter] != NULL ) {
		setDefRoute(optp[Orouter], &Ifbuf);
	}
#ifndef EMBED
	/* make directory for resolv.conf and  hostinfo file
	 */
	if ( !setupHostInfoDir(HOST_INFO_DIR) ) {
		return;
	}
	/* ntp.conf
	 */
	if ( optp[OntpServer] != NULL ) {
		mkNTPconf(optp[OntpServer]);
	}
#endif
	/* resolv.conf
	 */
#ifdef CONFIG_NETtel
	if ( optp[Odns] != NULL || optp[OdomainName] != NULL ) {
#else
	if ( optp[Odns] != NULL && optp[OdomainName] != NULL ) {
#endif
		mkResolvConf(optp[Odns], optp[OdomainName]);
	}
#ifndef EMBED
	/* hostinfo file
	 */
	strncpy(path, HOST_INFO_DIR, MAXLEN);
	strncat(path, "/", MAXLEN);
	strncat(path, HOST_INFO_FILE, MAXLEN);
	strncat(path, "-", MAXLEN);
	strncat(path, Ifbuf.ifname, MAXLEN);
	if ( (fd = creat(path,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0 ) {
		logSysRet("creat (setupHostInfo)");
		return;
	}
	sprintf(buf, "LEASETIME=%ld\n", ntohl(LeaseTime));
	sprintf(buf+strlen(buf), "RENEWALTIME=%ld\n", ntohl(RenewTime));
	sprintf(buf+strlen(buf), "REBINDTIME=%ld\n", ntohl(RebindTime));
	sprintf(buf+strlen(buf), "IPADDR=%s\n",
			inet_ntoa(*((struct in_addr *)&Ifbuf.addr)));
	sprintf(buf+strlen(buf), "NETMASK=%s\n",
			inet_ntoa(*((struct in_addr *)&Ifbuf.mask)));
	sprintf(buf+strlen(buf), "BROADCAST=%s\n",
			inet_ntoa(*((struct in_addr *)&Ifbuf.bcast)));
	if ( write(fd, buf, strlen(buf)) < 0 ) {
		logSysRet("write (setupHostInfo)");
	}
	if ( optp[OhostName] != NULL ) {
		addHostInfo(fd, OT_STRING, "HOSTNAME", optp[OhostName]);
	}
	if ( optp[OnisDomName] != NULL ) {
		addHostInfo(fd, OT_STRING, "NISDOMAINNAME", optp[OnisDomName]);
	}
	if ( optp[OlprServer] != NULL ) {
		addHostInfo(fd, OT_ADDR, "LPRSERVER", optp[OlprServer]);
	}
	if ( optp[OntpServer] != NULL ) {
		addHostInfo(fd, OT_ADDR, "NTPSERVER", optp[OntpServer]);
	}
	if ( optp[OtimeServer] != NULL ) {
		addHostInfo(fd, OT_ADDR, "TIMESERVR", optp[OtimeServer]);
	}
	if ( optp[Orouter] != NULL ) {
		addHostInfo(fd, OT_ADDR, "ROUTER", optp[Orouter]);
	}
	close(fd);
#endif
}

#ifndef EMBED

int
setupHostInfoDir(const char *dir)
{
	struct stat stbuf;

	if ( stat(dir, &stbuf) < 0 ) {
		if ( errno == ENOENT ) {
			if ( mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR |
					   S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0 ) {
				logSysRet("mkdir (setupHostInfoDir)");
				return 0;
			}
			return 1;
		} else {
		  logSysRet("stat (setupHostInfoDir)");
		  return 0;
		}
	}
	if ( !S_ISDIR(stbuf.st_mode) ) {
		chmod(dir, S_IRUSR | S_IWUSR);
		if ( unlink(dir) < 0 ) {
			logSysRet("unlink (setupHostInfoDir)");
			return 0;
		}
		if ( mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR |
				   S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0 ) {
			logSysRet("mkdir (setupHostInfoDir)");
			return 0;
		}
	}
	if ( chmod(dir, S_IRUSR | S_IWUSR | S_IXUSR |
			   S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0 ) {
		logSysRet("chmod (setupHostInfoDir)");
		return 0;
	}
	return 1;
}

void
addHostInfo(int fd, const int flag, const char *name, const u_char *optp)
{
	char	buf[MAXLEN];
	char	env[MAXLEN];
	int		i;
	u_int  *p;

	switch ( flag ) {
	  case OT_STRING:
		strncpy(env, optp+1, *optp);
		if ( setenv(name, env, 1) < 0 ) {
			logRet("setenv (addHostInfo): insufficient space");
		}
		strcpy(buf, name);
		strcat(buf, "=");
		strncat(buf, optp+1, *optp);
		strcat(buf, "\n");
		break;
	  case OT_ADDR:
		p = (u_int *)(optp + 1);
		if ( setenv(name, inet_ntoa(*((struct in_addr *)p)), 1) < 0 ) {
			logRet("setenv (addHostInfo): insufficient space");
		}
		strcpy(buf, name);
		strcat(buf, "=");
		strcat(buf, inet_ntoa(*((struct in_addr *)p)));
		++p;
		strcat(buf, "\n");
		for ( i = 1; i < *optp/4; ++i ) {
			sprintf(env, "%s%d", name, i+1);
			if ( setenv(env, inet_ntoa(*((struct in_addr *)p)), 1) < 0 ) {
				logRet("setenv (addHostInfo): insufficient space");
			}
			sprintf(buf+strlen(buf), "%s%d=%s\n", name, i+1,
					inet_ntoa(*((struct in_addr *)p)));
			++p;
		}
		break;
	  default:
		return;
	}
	if ( write(fd, buf, strlen(buf)) < 0 ) {
		logSysRet("write (addHostInfo)");
	}
}

void
mkNTPconf(const u_char *addr)
{
	char buf[MAXLEN];
	int  fd;
	int  i;
	u_int *p;

	strcpy(buf, HOST_INFO_DIR);
	strcat(buf, "/");
	strcat(buf, "ntp.conf");
	if ( (fd = creat(buf,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0 ) {
		logSysRet("creat (mkNTPconf)");
		return;
	}
	/* TODO: check whether NTP service is working on those addresses
	 */
	p = (u_int *)(addr + 1);
	*buf = '\0';
	for ( i = 0; i < *addr/4; ++i ) {
		sprintf(buf+strlen(buf), "server %s\n",
				inet_ntoa(*((struct in_addr *)p)));
		++p;
	}
	if ( write(fd, buf, strlen(buf)) < 0 ) {
		logSysRet("write (mkNTPconf)");
	}
	close(fd);
}

#endif /* EMBED */

void
mkResolvConf(const u_char *addr, const u_char *domName)
{
	char buf[MAXLEN];
	int  fd;
	int  i;
	u_int *p;

	strcpy(buf, HOST_INFO_DIR);
	strcat(buf, "/");
	strcat(buf, "resolv.conf");
	if ( (fd = creat(buf,  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0 ) {
		logSysRet("creat (mkResolvConf)");
		return;
	}
	/* TODO: check whether name server is working on those addresses
	 */
#ifdef CONFIG_NETtel
	if(domName != NULL) {
		strcpy(buf, "domain ");
		strncat(buf, domName+1, *domName);
		strcat(buf, "\n");
	} else {
		buf[0] = '\0';
	}
	
	if(addr != NULL) {
		p = (u_int *)(addr + 1);
		for ( i = 0; i < *addr/4; ++i ) {
			sprintf(buf+strlen(buf), "nameserver %s\n\0",
					inet_ntoa(*((struct in_addr *)p)));
			++p;
		}
	}
#else
	strcpy(buf, "domain ");
	strncat(buf, domName+1, *domName);
	strcat(buf, "\n");
	p = (u_int *)(addr + 1);
	for ( i = 0; i < *addr/4; ++i ) {
		sprintf(buf+strlen(buf), "nameserver %s\n",
				inet_ntoa(*((struct in_addr *)p)));
		++p;
	}
#endif
	if ( write(fd, buf, strlen(buf)) < 0 ) {
		logSysRet("write (mkResolvConf)");
	}
	close(fd);
}

void
execCommandFile()
{
	pid_t pid;

	if ( CommandFile == NULL ) {
		return;
	}
#ifdef __uClinux__
	if ( (pid = vfork()) < 0 )
#else
	if ( (pid = fork()) < 0 )
#endif
	{
		logSysRet("first fork (execCommandFile)");
	} else if ( pid == 0 ) {
#ifdef __uClinux__
		if ( (pid = vfork()) < 0 )
#else
		if ( (pid = fork()) < 0 )
#endif
		{
			logSysRet("second fork (execCommandFile)");
		} else if ( pid > 0 ) {
			/* we're the 1st child. let's just exit
			 */
			exit(0);
		}
		/* we are the second child. let's exec the command file
		 */
		if ( execlp(CommandFile, CommandFile, NULL) < 0 ) {
			logSysRet("execlp (execCommandFile)");
		}
	}
	/* we're the parent (original process).
	 * let's wait for the first child
	 */
	if ( waitpid(pid, NULL, 0) != pid ) {
		logSysRet("waitpid (execCommandFile)");
	}
}

