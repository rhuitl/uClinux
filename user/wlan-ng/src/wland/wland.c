/* src/wland/wland.c
*
* wireless lan daemon
*
* Copyright (C) 1999 AbsoluteValue Systems, Inc.  All Rights Reserved.
* --------------------------------------------------------------------
*
* linux-wlan
*
*   The contents of this file are subject to the Mozilla Public
*   License Version 1.1 (the "License"); you may not use this file
*   except in compliance with the License. You may obtain a copy of
*   the License at http://www.mozilla.org/MPL/
*
*   Software distributed under the License is distributed on an "AS
*   IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
*   implied. See the License for the specific language governing
*   rights and limitations under the License.
*
*   Alternatively, the contents of this file may be used under the
*   terms of the GNU Public License version 2 (the "GPL"), in which
*   case the provisions of the GPL are applicable instead of the
*   above.  If you wish to allow the use of your version of this file
*   only under the terms of the GPL and not to allow others to use
*   your version of this file under the MPL, indicate your decision
*   by deleting the provisions above and replace them with the notice
*   and other provisions required by the GPL.  If you do not delete
*   the provisions above, a recipient may use your version of this
*   file under either the MPL or the GPL.
*
* --------------------------------------------------------------------
*
* Inquiries regarding the linux-wlan Open Source project can be
* made directly to:
*
* AbsoluteValue Systems Inc.
* info@linux-wlan.com
* http://www.linux-wlan.com
*
* --------------------------------------------------------------------
*
* Portions of the development of this software were funded by 
* Intersil Corporation as part of PRISM(R) chipset product development.
*
* --------------------------------------------------------------------
*/

#if 0
#ifndef __linux__
#include <pcmcia/u_compat.h>
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Ugly hack for LinuxPPC R4, don't have time to figure it out right now */
#if defined(__WLAN_PPC__)
#undef __GLIBC__
#endif

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/file.h>
#include <sys/param.h>

#include <asm/types.h>
#include <linux/netlink.h>

#include <wlan/wlan_compat.h>
#include <wlan/version.h>
#include <wlan/p80211types.h>
#include <wlan/p80211meta.h>
#include <wlan/p80211metamsg.h>
#include <wlan/p80211metamib.h>
#include <wlan/p80211msg.h>
#include <wlan/p80211ioctl.h>

/*----------------------------------------------------------------
*	Function Prototyes
----------------------------------------------------------------*/
static int	daemon_init(void);
static int	execute_as_daemon(char *cmd);
static int	execute_as_user(char *cmd);
static int	msg2command( UINT8 *msg, UINT8 *cmd, UINT32 msgcode );
static int	netlink_init(void);
static void	process_messages(void);
static void	signal_handler( int signo );
static void	usage(char *prog_name);

/*----------------------------------------------------------------
*	Global Variables
----------------------------------------------------------------*/
static	FILE		*msgfp;
static	int		nlfd;
static	int		user_process;
static	char		*wland_path = "/etc/wlan";

/*----------------------------------------------------------------
* main
*
* wland entry point.
*
* Arguments:
*	argc	number of command line arguments
*	argv	array of argument strings
*
* Returns: 
*	0	- success 
*	~0	- failure
----------------------------------------------------------------*/
int main(int argc, char *argv[])
{
	int errflg;
	int optch;

	errflg = 0;

	/* Set Globals */
	msgfp = NULL;
	nlfd = -1;
	user_process = 0;

	while ((optch = getopt(argc, argv, "Vvd:u")) != -1) {
		switch (optch) {
		case 'V':
		case 'v':
			fprintf(stderr, "wland version %s\n", WLAN_RELEASE);
			return 0;
			break;
		case 'd':
			wland_path = strdup(optarg);
			break;
		case 'u':
			user_process = 1;
			break;
		default:
			errflg = 1; break;
		}
	}

	if (errflg || (optind < argc)) {
		usage(argv[0]);
		exit(1);
	}

	if ( chdir(wland_path) < 0 ) {
		fprintf(stderr, "wland: ERROR changing to directory %s\n",
			wland_path);
		exit(1);
	}

	if ( !user_process ) {
		if ( !(daemon_init()) ) {
			exit(1);
		}
	}

	if ( !(netlink_init()) ) {
		exit(1);
	}

	process_messages();

	return 0;
}


/*----------------------------------------------------------------
* daemon_init
*
* This function performs the necessary steps to make the program
* behave as a daemon.
*
* Arguments:
*	none
*
* Returns: 
*	!0 - success
*	0 - no success
*
----------------------------------------------------------------*/
static int daemon_init(void)
{
	int ret;
	int retval;

	retval = 1;

	if ((ret = fork()) > 0) {
		return 0;
	}

	openlog("wland", LOG_PID, LOG_USER );

	if (ret < 0) {
		syslog(LOG_ERR, "forking: %m");
		retval = 0;
	}

	if (setsid() < 0) {
		syslog(LOG_ERR, "detaching from tty: %m");
		retval = 0;
	}


	umask(0);

	syslog(LOG_INFO, "wland daemon init successful");

	return retval;
} 


/*----------------------------------------------------------------
* usage
*
* This function prints the proper syntax for executing the program.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
*
----------------------------------------------------------------*/
static void usage(char *prog_name)
{
	fprintf(stderr, "usage: %s [-V|-v] [-d wlandpath] [-u]\n",
		prog_name);
}


/*----------------------------------------------------------------
* process_messages
*
* This function sits in a loop receiving messages from the Linux
* WLAN driver indicating an event has happened.  The appropriate
* program is called based on the message code (i.e. the
* event/indication) received from the Linux WLAN driver.
*
* Arguments:
*	none
*
* Returns: 
*	nothing
*
----------------------------------------------------------------*/
static void process_messages(void)
{
	UINT8		msgbuf[MSG_BUFF_LEN];
	UINT8		cmdbuf[MSG_BUFF_LEN];
	int		recvlen;
	int		m2c;


	if ( user_process ) {
		if ( (msgfp = fopen("wlandmsg.out", "w")) == NULL ) {
			fprintf(stderr, "Could not open message output file\n");
			return;
		}
	}

	/* loop forever receiving and processing messages */
	for(;;) {
		if ((recvlen = recv( nlfd, msgbuf, sizeof(msgbuf), 0 ))
			> -1 ) {

			m2c = msg2command(msgbuf, cmdbuf,
					((p80211msg_t *)msgbuf)->msgcode);

			if ( !user_process ) {
				if ( m2c ) {
					execute_as_daemon( cmdbuf );
				} else {
					syslog( LOG_ERR, 
						"process_message: %s", cmdbuf);
				}
			} else {
				fprintf(msgfp,"%s\n", cmdbuf);
				execute_as_user( cmdbuf );
				fflush(msgfp);
			}
		} else {
			if ( !user_process ) {
				syslog( LOG_ERR, "recv: %m");
			} else {
				fprintf( msgfp,
					"ERROR receiving msg from socket\n");
				fflush(msgfp);
			}
		}
	}
}


/*----------------------------------------------------------------
* netlink_init
*
* This function establishes the ability to allow the Linux WLAN
* driver to notify the daemon of events.
*
* Arguments:
*	none
*
* Returns: 
*	!0 - success
*	0 - no success
*
----------------------------------------------------------------*/
static int netlink_init(void)
{
	int			i;
	int			retval;
	struct sockaddr_nl	nlskaddr;

	/* set up the signal handler */
	for ( i = 1; i < _NSIG; i++) {
		signal( i, signal_handler);
	}

	retval = 1;

	/* open the netlink socket */
	if ( (nlfd = socket( PF_NETLINK, SOCK_RAW, P80211_NL_SOCK_IND ))
		!= -1 ) {
		memset ( &nlskaddr, 0 , sizeof( nlskaddr ));
		nlskaddr.nl_family = (sa_family_t)PF_NETLINK;
		nlskaddr.nl_pid = (__u32)getpid();
		nlskaddr.nl_groups = P80211_NL_MCAST_GRP_MLME;

		/* bind the netlink socket */
		if ((bind( nlfd, (struct sockaddr*)&nlskaddr,
			sizeof(nlskaddr))) != -1 ) {
			syslog(LOG_INFO,
			"netlink socket opened and bound successfully");
		} else {
			syslog(LOG_ERR, "bind: %m");
			retval = 0;
		}
	} else {
		syslog(LOG_ERR, "netlink socket: %m");
		retval = 0;
	}

	return retval;
}


/*----------------------------------------------------------------
* msg2command
*
* Traverse the message and build a command to be executed.
*
* Arguments:
*	msg	buffer containing a complete msg
*	cmd	buffer containing a complete command
*	msgcode	integer identifying the msg
*
* Returns: 
*	!0	- success 
*	0	- no success
----------------------------------------------------------------*/
static int msg2command( UINT8 *msg, UINT8 *cmd, UINT32 msgcode )
{
	UINT8			tmpitem[MSG_BUFF_LEN];
	UINT8			*msgptr;
	UINT8			*start;
	INT			i;
	INT			retval;
	grplistitem_t		*grp;
	catlistitem_t		*cat;
	UINT32			narg;
	UINT32			offset;
	UINT32			tmpdid;
	p80211meta_t		*alist;

	retval = 1;
	msgptr = msg;

	/* acquire the msg argument metadata list */
	if ( (cat = p80211_did2cat(msg_catlist, msgcode)) != NULL ) {
		if ( (grp = p80211_did2grp(msg_catlist, msgcode)) != NULL ) {
			alist = grp->itemlist;
			narg = GETMETASIZE(alist);
		} else {
			sprintf( cmd,
				"msg2command: Invalid grp in msgcode %lu\n",
				msgcode);
			return 0;
		}
	} else {
		sprintf( cmd,
			"msg2command: Invalid cat in msgcode %lu\n",
			msgcode);
		return 0;
	}

	sprintf( cmd, "%s_%s %s", cat->name, grp->name,
		((p80211msg_t *)msg)->devname);

	start =  msg + sizeof(p80211msg_t);

	for ( i = 1; i < narg; i++ ) {
		tmpdid = msgcode | P80211DID_MKITEM(i) | alist[i].did;
		offset =p80211item_getoffset(msg_catlist, tmpdid);
		msgptr = start + offset;
		
		/* pass tmpdid since the 'totext' functions */
		/* expect a non-zero did */
		if ( ((p80211item_t *)msgptr)->status ==
			P80211ENUM_msgitem_status_data_ok ) {
			if ( alist[i].totextptr != NULL ) {
				(*(alist[i].totextptr))
					( msg_catlist, tmpdid, msgptr, tmpitem);
				strcat( cmd, " ");
				strcat( cmd, tmpitem);
			} else {
				p80211_error2text(
				P80211ENUM_msgitem_status_missing_print_func,
					tmpitem);
				strcat( cmd, tmpitem);
				retval = 0;
			}
		} else {
			p80211_error2text( ((p80211item_t *)msgptr)->status,
				tmpitem);
			strcat( cmd, tmpitem);
			retval = 0;
		}
	} /* for each argument in the metadata */

	return retval;
}


/*----------------------------------------------------------------
* execute_as_daemon
*
* This function comes directly from David Hind's cardmgr.c in
* his pcmcia code (with only a few minor modifications).
*
* Arguments:
*	cmd	buffer containing a complete shell command
*
* Returns: 
*	!(-1)	- success 
*	-1	- no success
----------------------------------------------------------------*/
static int execute_as_daemon(char *cmd)
{
	int	msglen;
	int	ret;
	FILE	*f;
	char	line[MSG_BUFF_LEN];
	char	msg[82];


	msglen = (strchr( cmd, ' ' )) - cmd;
	strncpy( msg, cmd, msglen);
	msg[msglen] = '\0';

	syslog(LOG_INFO, "executing: '%s'", msg);
	strcat(cmd, " 2>&1");
	f = popen(cmd, "r");

	while (fgets(line, MSG_BUFF_LEN - 1, f)) {
		line[strlen(line)-1] = '\0';
		syslog(LOG_INFO, "%s: %s", msg, line);
	}

	ret = pclose(f);

	if (WIFEXITED(ret)) {
		if (WEXITSTATUS(ret)) {
			syslog(LOG_INFO, "%s exited with status %d",
				msg, WEXITSTATUS(ret));
		}
		return WEXITSTATUS(ret);

	} else {
		syslog(LOG_INFO, "%s exited on signal %d",
			msg, WTERMSIG(ret));
	}

	return -1;
}


/*----------------------------------------------------------------
* execute_as_user
*
* This function comes directly from David Hind's cardmgr.c in
* his pcmcia code (with only a few minor modifications).
*
* Arguments:
*	cmd	buffer containing a complete shell command
*
* Returns: 
*	!(-1)	- success 
*	-1	- no success
----------------------------------------------------------------*/
static int execute_as_user(char *cmd)
{
	int	msglen;
	int	ret;
	FILE	*f;
	char	line[MSG_BUFF_LEN];
	char	msg[82];


	msglen = (strchr( cmd, ' ' )) - cmd;
	strncpy( msg, cmd, msglen);
	msg[msglen] = '\0';

	fprintf(msgfp, "executing: '%s'\n", msg);
	strcat(cmd, " 2>&1");
	f = popen(cmd, "r");

	while (fgets(line, MSG_BUFF_LEN - 1, f)) {
		line[strlen(line)-1] = '\0';
		fprintf(msgfp, "%s: %s\n", msg, line);
	}

	ret = pclose(f);

	if (WIFEXITED(ret)) {
		if (WEXITSTATUS(ret)) {
			fprintf(msgfp, "%s exited with status %d",
				msg, WEXITSTATUS(ret));
		}
		return WEXITSTATUS(ret);

	} else {
		fprintf(msgfp, "%s exited on signal %d",
			msg, WTERMSIG(ret));
	}

	return -1;
}


/*----------------------------------------------------------------
* signal_handler
*
* This function is called when a signal is generated and sent
* to the program.
*
* Arguments:
*	signo	signal number
*
* Returns: 
*	Nothing
*
----------------------------------------------------------------*/
static void signal_handler( int signo )
{
	if ( signo != SIGCHLD ) {
		if ( msgfp == NULL ) { 
			syslog(LOG_ERR,
				"signal: Terminating with signal %d", signo);
		} else {
			fprintf( msgfp,
				"signal: Terminating with signal %d\n", signo);
			fflush( msgfp );
			fclose( msgfp );
		}

		close( nlfd );

		exit( 0 );
	}

	return;
}
