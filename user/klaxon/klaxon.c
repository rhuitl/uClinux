/*
 * Copyright (c) 1983, 1988 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * Modified to provide counterintelligence
 * by Doug Hughes - Auburn University
 */

/*
 * Modified Dec 5 - converted strcpy to strncpy as premptive measure against
 * possible future reverse DNS spoofing attacks leading to buffer overflows
 */

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1983, 1988 The Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)rshd.c	5.17.1.2 (Berkeley) 2/7/89";
#endif /* not lint */

/*
 * Remote shell server.  We're invoked by the rexecd(8C) function.
 */

#include	<sys/types.h>
#include	<sys/socket.h>
#include    <sys/param.h>
#include 	<sys/fcntl.h>
#include	<sys/termios.h>
#include	<netinet/in.h>
#include	<arpa/inet.h>
#include	<stdio.h>
#include	<varargs.h>
#include	<signal.h>
#include	<netdb.h>
#include	<syslog.h>
#include	<errno.h>
#include	<string.h>
#ifdef RPC
#define	REXPROG ((unsigned long)(100017))
#define	REXVERS ((unsigned long)(1))
#include	<sys/conf.h>
#include	<sys/stropts.h>
#include	<rpc/rpc.h>
#define SOCK_RPC	6
#endif
extern int	errno;

/* globals */
int protoval, protovallen;

#ifdef RPC
static void
reqprog_1(rqstp, transp)
	struct svc_req *rqstp;
	register SVCXPRT *transp;
{
# ifdef SYSV
	struct netbuf *caller = NULL;

	if ((caller = svc_getrpccaller(transp)) == NULL) {
		my_error("svc_getcaller failed: %d", errno);
		_exit();
	}
	doit(caller->buf, "rexd");
# else
	struct sockaddr_in *cli_addrp;

	if ((cli_addrp = (struct sockaddr_in *)svc_getcaller(transp)) == NULL) {
		my_error("svc_getcaller failed: %d", errno);
		_exit();
	}
	doit(cli_addrp, "rexd");
# endif

}
#endif


/*ARGSUSED*/
main(argc, argv)
int	argc;
char	**argv;		/* argv1 is the service name */
{
	int			addrlen;
	struct sockaddr_in	cli_addr, *cli_addrp;
	char 		tbuf[1500];
#ifdef RPC
	SVCXPRT *transp;
	struct netconfig *nconf = NULL;
#endif

	openlog("klaxon", LOG_PID | LOG_ODELAY, LOG_DAEMON);

	/*
	 * We assume we're invoked by inetd, so the socket that the connection
	 * is on, is open on descriptors 0, 1 and 2.
	 *
	 * First get the Internet address of the client process.
	 * This is required for all the authentication we perform.
	 */

	addrlen = sizeof(cli_addr);
	protovallen = sizeof(int);

	
	if (getsockopt(0, SOL_SOCKET, SO_TYPE, (char *)&protoval, &protovallen) <0
			|| strncmp(argv[1], "rpc", 3) == 0){
		/* Could be RPC */
#ifdef RPC
# ifdef SYSV
		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			my_error("svc_tli_create failed: %d", errno);
			_exit(1);
		}

		if (!svc_reg(transp, REXPROG, REXVERS, reqprog_1, 0)) {
			my_error("can't register rexprog: %d", errno);
			exit(1);
		}
# else
		int pid;
		(void) pmap_unset(REXPROG, REXVERS);

		if (protoval == SOCK_DGRAM) {
			if ((transp = svcudp_create(RPC_ANYSOCK)) == NULL) {
				my_error("svcudp_create failed: %d", errno);
				_exit(1);
			}
			if (!svc_register(transp, REXPROG, REXVERS, reqprog_1, IPPROTO_UDP)) {
				my_error("can't register udp rexprog: %d", errno);
				_exit(1);
			}
		} else {
			if ((transp = svctcp_create(RPC_ANYSOCK, 0, 0)) == NULL) {
				my_error("svctcp_create failed: %d", errno);
				_exit(1);
			}
			if (!svc_register(transp, REXPROG, REXVERS, reqprog_1, IPPROTO_TCP)) {
				my_error("can't register tcp rexprog: %d", errno);
				_exit(1);
			}
		}
		
# endif
		
		svc_run();
		exit(0);
#else
		my_error("getting socket options: %d", errno);
		_exit(1);
#endif
	}

	switch(protoval) {
		case SOCK_STREAM:
			if (getpeername(0, (struct sockaddr *) &cli_addr, &addrlen) < 0) {
				my_error("getpeername: %d", errno);
				_exit(1);
			}
			break;
		case SOCK_DGRAM:
			if (recvfrom(0, (char *) &tbuf, sizeof(tbuf), 0, 
						(struct sockaddr *) &cli_addr, &addrlen) < 0) {
				my_error("recvfrom UDP socket: %d", errno);
				_exit(1);
			}
			break;
		default:
			syslog(LOG_AUTH|LOG_NOTICE, "inetd connection using unknown protocol type, %d", protoval);
			_exit(1);
			break;
	}

	doit(&cli_addr, argv[1]);

}

doit(cli_addrp, service)
struct sockaddr_in	*cli_addrp;	/* client's Internet address */
char *service;
{
	char			hostname[MAXHOSTNAMELEN];
	char			remotehost[2 * MAXHOSTNAMELEN + 1];
	char			machine[MAXHOSTNAMELEN];
	char			username[128];
	struct sockaddr_in myaddr;
	int				myaddrlen = sizeof(struct sockaddr_in);
	char			buf[BUFSIZ];
	struct hostent		*hp;

	signal(SIGINT, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	
#ifdef DEBUG
	{
		int t = open("/dev/tty", 2);
		if (t >= 0) {
			ioctl(t, TIOCNOTTY, (char *) 0);
			close(t);
		}
	}
#endif


	/*
	 * Verify that the client's address is an Internet address.
	 */

	if (cli_addrp->sin_family != AF_INET) {
		syslog(LOG_ERR, "malformed from address\n");
		_exit(1);
	}

	/*
	 * Get the "name" of the client from its Internet address.
	 * This is used for the authentication below.
	 */

	hp = gethostbyaddr((char *) &cli_addrp->sin_addr,
				sizeof(struct in_addr), cli_addrp->sin_family);

	if (hp) {
		/*
		 * If the name returned by gethostbyaddr() is in our domain,
		 * attempt to verify that we haven't been fooled by someone
		 * in a remote net.  Look up the name and check that this
		 * address corresponds to the name.
		 */

		if (local_domain(hp->h_name)) {
			strncpy(remotehost, hp->h_name, sizeof(remotehost) - 1);
			remotehost[sizeof(remotehost) - 1] = 0;
			if ( (hp = gethostbyname(remotehost)) == NULL) {
				syslog(LOG_INFO,
				    "Couldn't look up address for %s port %s",
				    		remotehost, service);
				my_error("Couldn't look up addr for your host");
				exit(1);
			}
	
			for ( ; ; hp->h_addr_list++) {
				if (memcmp(hp->h_addr_list[0],
			    		      (caddr_t) &cli_addrp->sin_addr,
			    		      sizeof(cli_addrp->sin_addr)) == 0)
					break;	/* equal, OK */

				if (hp->h_addr_list[0] == NULL) {
					syslog(LOG_NOTICE,
				  	  "Host addr %s not listed for host %s using port %s",
				    		inet_ntoa(cli_addrp->sin_addr),
				    		hp->h_name, service);
					my_error("Host address mismatch");
					exit(1);
				}
			}
		}
		strncpy(hostname, hp->h_name, sizeof(hostname));
	} else
		strncpy(hostname, inet_ntoa(cli_addrp->sin_addr), sizeof(hostname));


#	ifdef USE_IDENT
	getsockname(0, (struct sockaddr *) &myaddr, &myaddrlen);
	if (protoval == SOCK_STREAM) {
		rfc931(cli_addrp, &myaddr, &username);
		sprintf(buf, "ALERT: user %s@%s accessing port %s", username, hostname, service);
	} else {
		sprintf(buf, "ALERT: host %s accessing port %s", hostname, service);
	}
#else
	sprintf(buf, "ALERT: host %s accessing port %s", hostname, service);
#endif
		
	syslog(LOG_AUTH|LOG_NOTICE, buf);

	exit(0);
	return(0);	/* just to clean up lint */
}

/*
 * Send an error message back to the rcmd() client.
 * The first byte we send must be binary 1, followed by the ASCII
 * error message, followed by a newline.
 */

my_error(va_alist)
va_dcl
{
	va_list		args;
	char		*fmt, buff[BUFSIZ];

	va_start(args);
	fmt = va_arg(args, char *);
	vsprintf(buff, fmt, args);
	va_end(args);

	syslog(LOG_ERR, buff);	/* fd 2 = socket, from inetd */
}

/*
 * Check whether the specified host is in our local domain, as determined
 * by the part of the name following the first period, in its name and in ours.
 * If either name is unqualified (contains no period), assume that the host
 * is local, as it will be interpreted as such.
 */

int				/* return 1 if local domain, else return 0 */
local_domain(host)
char	*host;
{
	register char	*ptr1, *ptr2;
	char		localhost[MAXHOSTNAMELEN];

	if ( (ptr1 = strchr(host, '.')) == NULL)
		return(1);		/* no period in remote host name */

	gethostname(localhost, sizeof(localhost));
	if ( (ptr2 = strchr(localhost, '.')) == NULL)
		return(1);		/* no period in local host name */

	/*
	 * Both host names contain a period.  Now compare both names,
	 * starting with the first period in each name (i.e., the names
	 * of their respective domains).  If equal, then the remote domain
	 * equals the local domain, return 1.
	 */

	if (strcasecmp(ptr1, ptr2) == 0)	/* case insensitive compare */
		return(1);

	return(0);
}
