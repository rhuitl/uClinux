/*
 * diald.c - Demand dialing daemon for ppp.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 *
 * Portions of this code were derived from the code for pppd copyright
 * (c) 1989 Carnegie Mellon University. The copyright notice on this code
 * is reproduced below.
 *
 * Copyright (c) 1989 Carnegie Mellon University.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by Carnegie Mellon University.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "diald.h"
#include "version.h"

int call_start_time;
int fifo_fd;
int fwdfd;
int fwunit;
int orig_disc;
char packet[4096];
int pppd_argc;
char **pppd_argv;
int proxy_mfd;
FILE *proxy_mfp;
int proxy_sfd;
char *req_dev;
int req_pid;
int txtotal, rxtotal;
char snoop_dev[10];
int snoopfd;
int use_req;

/* intialized variables. */
int modem_fd = -1;		/* modem device fp (for proxy reads) */
MONITORS *monitors = 0;		/* Monitor pipes */
int modem_hup = 0;		/* have we seen a modem HUP? */
int sockfd = -1;		/* controling socket */
int delayed_quit = 0;		/* has the user requested a delayed quit? */
int request_down = 0;		/* has the user requested link down? */
int request_up = 0;		/* has the user requested link down? */
int forced = 0;			/* has the user requested the link forced up? */
int link_pid = 0;		/* current protocol control command pid */
int dial_pid = 0;		/* current dial command pid */
int running_pid = 0;		/* current system command pid */
int running_status = 0;		/* status of last system command */
int dial_status = 0;		/* status from last dial command */
int state_timeout = -1;		/* state machine timeout counter */
int proxy_iface = 0;		/* Interface for the proxy */
int link_iface = -1;		/* Interface for the link */
int force_dynamic = 0;		/* true if connect passed back an addr */
int redial_rtimeout = -1;	/* initialized value */
int dial_failures = 0;		/* count of dialing failures */
int ppp_half_dead = 0;		/* is the ppp link half dead? */
int terminate = 0;
char *pidfile = 0;
static PIPE fifo_pipe;
int argc_save;
char **argv_save;

void do_config(void)
{
    init_vars();
    flush_prules();
    flush_vars();
    flush_strvars();
    flush_filters();
    /* Get the default defs and config files first */
    parse_options_file(DIALD_DEFS_FILE);
    parse_options_file(DIALD_CONFIG_FILE);
    /* Get the command line modifications */
    parse_args(argc_save-1,argv_save+1);
    /* Do validity checks on the setup */
    check_setup();

    if (orig_local_ip)
	free(orig_local_ip);
    if (orig_remote_ip)
	free(orig_remote_ip);
    orig_local_ip = strdup(local_ip);
    orig_remote_ip = strdup(remote_ip);
}

int main(int argc, char *argv[])
{
    int sel;
    struct timeval timeout;
    fd_set readfds;

    argc_save = argc;
    argv_save = argv;

    /* initialize system log interface */
    openlog("diald", LOG_PID | LOG_NDELAY | LOG_PERROR,  LOG_LOCAL2);

    /* initialize a firewall unit so we can store our options */
    /* If I get things into a device this should be an "open" */
    fwunit = ctl_firewall(IP_FW_OPEN,0);

    parse_init();
    do_config();

    become_daemon();

    /* Get an internet socket for doing socket ioctls. */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
      {
	syslog(LOG_ERR, "Couldn't create IP socket: %m");
	die(1);
      }

    open_fifo();

    if (debug&DEBUG_VERBOSE)
        syslog(LOG_INFO,"Starting diald version %s",VERSION);

    signal_setup();
    filter_setup();

    /* get a pty and open up a proxy link on it */
    if (openpty(&proxy_mfd,&proxy_sfd, NULL, NULL, NULL) < 0)
		die (-1);
#ifndef USE_BSD_PTYS
	fcntl(proxy_mfd,F_SETFL,fcntl(proxy_mfd,F_GETFL)|O_NONBLOCK);
#endif
    proxy_mfp = fdopen(proxy_mfd,"r+");
    proxy_up();
    idle_filter_proxy();

    if (debug&DEBUG_VERBOSE)
	syslog(LOG_INFO,"Diald initial setup completed.");

    /* main loop */
    timeout.tv_sec = PAUSETIME;
    timeout.tv_usec = 0;
    while (!terminate) {
	/* wait up to a second for an event */
        FD_ZERO(&readfds);
	if (fifo_fd != -1)
	    FD_SET(fifo_fd,&readfds);
        FD_SET(proxy_mfd,&readfds);
        FD_SET(snoopfd,&readfds);
	sel = select(100,&readfds,0,0,&timeout);
	if (sel > 0) {
	    /* read user commands off the fifo */
	    if (fifo_fd != -1 && FD_ISSET(fifo_fd,&readfds)) fifo_read();

	    /* update the connection filters */
	    if (FD_ISSET(snoopfd,&readfds)) filter_read();

	    /* deal with packets coming into the pty proxy link */
	    if (FD_ISSET(proxy_mfd,&readfds)) proxy_read();
	}
	if (timeout.tv_sec == 0 && timeout.tv_usec == 0) {
	    /* advance the clock 1 second */
	    timeout.tv_sec = PAUSETIME;
	    timeout.tv_usec = 0;
	    if (state_timeout > 0) state_timeout--;
	    if (debug&DEBUG_TICK)
	        syslog(LOG_DEBUG,"--- tick --- state %d block %d state_timeout %d",state,blocked,state_timeout);
	    //monitor_queue();
	}
	change_state();
    }
    die(0);
}

/* Write the pid and optionally the proxy interface to the pid file */

void create_pidfile(int iface)
{
    FILE *fp;
    if ((fp = fopen(pidfile,"w")) != NULL) {
        fprintf(fp,"%d\n",getpid());
	if (iface)
        	fprintf(fp,"sl%d\n",proxy_iface);
        fclose(fp);
    } else {
	syslog(LOG_ERR,"Unable to create run file %s: %m",pidfile);
    }
}

/*
 * Change into a daemon.
 * Get rid of the stdio streams, and disassociate from the original
 * controling terminal, and become a group leader.
 */

void become_daemon()
{
#ifndef __uClinux__
    pid_t pid;
    if (dodaemon) {
        close(0);
        close(1);
        close(2);
	/* go into the background */
	if ((pid = fork()) < 0) {
	    syslog(LOG_ERR,"Could not fork into background: %m");
	    die(1);
	}
	/* parent process is finished */
	if (pid != 0) exit(0);
    }
#endif /* __uClinux__ */
    if (pidlog[0] == '/') {
	pidfile = pidlog;
    }
    else {
	pidfile = malloc(strlen(RUN_PREFIX) + strlen(pidlog) + 2);
	sprintf(pidfile,"%s/%s",RUN_PREFIX,pidlog);
    }
    create_pidfile(0);
}

/* Open the command fifo, if any */

void open_fifo()
{
    struct stat sbuf;

    if (fifoname) {
	if (stat(fifoname,&sbuf) < 0 || !(sbuf.st_mode&S_IFIFO)) {
	    syslog(LOG_INFO,"Creating FIFO");
	    /* Create the fifo. */
	    mknod(fifoname, S_IFIFO|0277, 0);
	    chmod(fifoname, 0600);
	}
	/* We need to open this RDWR to make select() work the
         * way we want in kernels after 1.3.81. In particular
	 * we don't want select() to return 1 whenever there
	 * are no writers on the remote side of the command fifo.
	 * This guarantees that there is always at least one writer...
         */
	if ((fifo_fd = open(fifoname, O_RDWR | O_NDELAY)) >= 0) {
	    if (debug&DEBUG_VERBOSE)
	   	 syslog(LOG_INFO,"Using fifo %s",fifoname);
	    pipe_init(fifo_fd,&fifo_pipe);
	} else {
	    syslog(LOG_ERR,"Could not open fifo file %s",fifoname);
	    fifo_fd = -1;
	}
    } else {
	/* make sure to invalidate the fifo_fd if we don't open one. */
	fifo_fd = -1;
    }
}


/*
 * Set up the signal handlers.
 */
static sigset_t sig_mask;

void signal_setup()
{
    struct sigaction sa;
    /* set up signal handlers */

    sigemptyset(&sig_mask);
    sigaddset(&sig_mask, SIGHUP);
    sigaddset(&sig_mask, SIGINT);
    sigaddset(&sig_mask, SIGTERM);
    sigaddset(&sig_mask, SIGUSR1);
    sigaddset(&sig_mask, SIGUSR2);
    sigaddset(&sig_mask, SIGCHLD);
    sigaddset(&sig_mask, SIGALRM);
    sigaddset(&sig_mask, SIGPIPE);

#define SIGNAL(s, handler)      { \
        sa.sa_handler = handler; \
        if (sigaction(s, &sa, NULL) < 0) { \
            syslog(LOG_ERR, "sigaction(%d): %m", s); \
            die(1); \
        } \
    }

    sa.sa_mask = sig_mask;
    sa.sa_flags = 0;

    SIGNAL(SIGHUP, sig_hup);            /* Hangup: modem went down. */
    SIGNAL(SIGINT, sig_intr);           /* Interrupt: take demand dialer down */
    SIGNAL(SIGTERM, sig_term);          /* Terminate: user take link down */
    SIGNAL(SIGUSR1, linkup);            /* User requests the link to go up */
    SIGNAL(SIGUSR2, print_filter_queue); /* dump the packet queue to the log */
    SIGNAL(SIGCHLD, sig_chld);		/* reap dead kids */
    SIGNAL(SIGPIPE, SIG_IGN);
}

void block_signals()
{
    sigprocmask(SIG_BLOCK, &sig_mask, NULL);
}

void default_sigacts()
{
    struct sigaction sa;
    sa.sa_mask = sig_mask;
    sa.sa_flags = 0;

    SIGNAL(SIGHUP, SIG_DFL);
    SIGNAL(SIGINT, SIG_DFL);
    SIGNAL(SIGTERM, SIG_DFL);
    SIGNAL(SIGUSR1, SIG_DFL);
    SIGNAL(SIGUSR2, SIG_DFL);
    SIGNAL(SIGCHLD, SIG_DFL);
    SIGNAL(SIGALRM, SIG_DFL);
    SIGNAL(SIGPIPE, SIG_DFL);
}

void unblock_signals()
{
    sigprocmask(SIG_UNBLOCK, &sig_mask, NULL);
}

#ifdef USE_BSD_PTYS
/*
 * Get a pty and open both the slave and master sides.
 */

int openpty(int *mfd, int *sfd, void *name, void *termios, void *win)
{
    char *ptys = "0123456789abcdef";
    int i,c;
    static char buf[128];

    for (c = 'p'; c <= 's'; c++)
        for (i = 0; i < 16; i++) {
	    sprintf(buf,"/dev/pty%c%c",c,ptys[i]);
	    if ((*mfd = open(buf,O_RDWR)) >= 0) {
	    	sprintf(buf,"/dev/tty%c%c",c,ptys[i]);
		if ((*sfd = open(buf,O_RDWR|O_NOCTTY|O_NDELAY)) < 0) {
		    syslog(LOG_ERR,"Can't open slave side of pty: %m");
			return -1;
		}
		return 0;
	    }
        }
	syslog(LOG_ERR,"No pty found in range pty[p-s][0-9a-f]\n");
	return -1;
}
#endif

/* Read a request off the fifo.
 * Valid requests are:
 *	block		- block diald from calling out.
 *	unblock		- unblock diald from calling out.
 *	down		- bring the link down.
 *	up		- bring the link up.
 *	delayed-quit	- quit next time diald is idle.
 *	quit		- stop diald in its tracks.
 *	queue		- dump the filter queue.
 *	debug level	- set the debug level.
 *	force		- force diald to put the connection up and keep it up.
 *	unforce		- remove the forced up requirement.
 *	connect pid dev	- go up on a connection to the named port.
 *			  We assume the connection negotiations are
 *			  already finished and any lock files are in place.
 *			  When the connection should be killed we send a
 *			  SIGTERM to the given pid.
 *	dynamic <lip> <rip> - pass back dynamic IP config info to diald.
 *	message <txt>	- set the message text from the connect script.
 *	monitor file	- start a monitoring program.
 *      reset		- reread the configuration information.
 */

void fifo_read()
{
    int i;
    int pid, dev, j,k,l;
    char *buf, *tail;

    i = pipe_read(&fifo_pipe);
    buf = tail = fifo_pipe.buf;
    if (i < 0) {
	fifo_fd = -1;
	return;
    }
    if (i == 0) return;

    while (i--) {
        if (*tail == '\n') {
            *tail = '\0';
	    /* Ok, we've got a line, now we need to "parse" it. */
	    if (strcmp(buf,"block") == 0) {
		char sbuf[sizeof(PATH_IFCONFIG SL_DOWN) + 10];
		syslog(LOG_INFO, "FIFO: Block request received.");
		snprintf(sbuf, sizeof(sbuf), PATH_IFCONFIG SL_DOWN, proxy_iface);
		system(sbuf);
		snprintf(sbuf, sizeof(sbuf), PATH_IFCONFIG SL_UP, proxy_iface);
		system(sbuf);
		blocked = 1;
	    } else if (strcmp(buf, "state") == 0) {
		output_state();
	    } else if (strcmp(buf,"unblock") == 0) {
		syslog(LOG_INFO, "FIFO: Unblock request received.");
		blocked = 0;
	    } else if (strcmp(buf,"force") == 0) {
		syslog(LOG_INFO, "FIFO: Force request received.");
		forced = 1;
	    } else if (strcmp(buf,"unforce") == 0) {
		syslog(LOG_INFO, "FIFO: Unforce request received.");
		forced = 0;
	    } else if (strcmp(buf,"down") == 0) {
		syslog(LOG_INFO, "FIFO: Link down request received.");
    		request_down = 1;
    		request_up = 0;
	    } else if (strcmp(buf,"up") == 0) {
    		syslog(LOG_INFO, "FIFO: Link up request received.");
    		request_down = 0;
    		request_up = 1;
	    } else if (strcmp(buf,"delayed-quit") == 0) {
    		syslog(LOG_INFO, "FIFO. Delayed termination request received.");
    		delayed_quit = 1;
	    } else if (strcmp(buf,"quit") == 0) {
    		syslog(LOG_INFO, "FIFO. Termination request received.");
    		terminate = 1;
	    } else if (strcmp(buf,"reset") == 0) {
    		syslog(LOG_INFO, "FIFO. Reset request received. Re-reading configuration.");
		do_config();
	    } else if (strcmp(buf,"queue") == 0) {
    		struct firewall_req req;
    		syslog(LOG_INFO,"FIFO. User requested dump of firewall queue.");
    		syslog(LOG_INFO,"--------------------------------------");
    		req.unit = fwunit;
    		ctl_firewall(IP_FW_PCONN,&req);
    		syslog(LOG_INFO,"--------------------------------------");
	    } else if (sscanf(buf,"debug %d", &pid) == 1) {
    		syslog(LOG_INFO,"FIFO. Changing debug flags to %d.",pid);
		debug = pid;
	    } else if (sscanf(buf,"dynamic %n%*s%n %n",&j,&k,&l) == 1) {
		buf[k] = 0;
		if (inet_addr(buf+j) == (unsigned long)0xffffffff
		||  inet_addr(buf+l) == (unsigned long)0xffffffff) {
		    syslog(LOG_INFO,"FIFO: bad parameters '%s' and '%s' to dynamic command ignored", buf+j,buf+l);
		} else {
		    if (local_ip)
			free(local_ip);
		    if (remote_ip)
			free(remote_ip);
		    local_ip = strdup(buf+j);
		    remote_ip = strdup(buf+l);
		    force_dynamic = 1;
		}
	    } else if (strncmp(buf,"monitor", 7) == 0) {
    		struct stat sbuf;
		int fd;
		MONITORS *new;

		k = 0;
		if (sscanf(buf,"monitor %d %n",&j,&k) == 1) {
		    syslog(LOG_INFO,"FIFO: monitor connection at info level %d to %s requested",
			    j,buf+k);
		} else if (buf[7] != 0 && buf[7] == ' ') {
		    syslog(LOG_INFO,"FIFO: full monitor connection to %s requested",
			buf+k);
		    j = 255;	/* Heavy weight connection requested */
		    k = 8;
		}
		if (k >= 8) {
		    /* Check list to see if this is just a status change */
		    new = monitors;
		    while (new) {
			if (strcmp(new->name,buf+k) == 0) {
			    new->level = j;
			    output_state();
			    break;
			}
			new = new->next;
		    }
		    if (!new) {
			if (stat(fifoname,&sbuf) < 0 || !sbuf.st_mode&S_IFIFO) {
			    syslog(LOG_INFO,"FIFO: %s not a pipe.",
				buf+k);
			} else if ((fd = open(buf+k,O_WRONLY))<0) {
			    syslog(LOG_INFO,"FIFO: could not open pipe %s: %m",
				buf+k);
			} else {
			    new = (MONITORS *)malloc(sizeof(MONITORS));
			    new->name = strdup(buf+k);
			    new->next = monitors;
			    new->fd = fd;
			    new->level = j;
			    monitors = new;
			    output_state();
			}
		    }
		} else {
		    syslog(LOG_INFO,"FIFO: empty monitor request ignored");
		}
	    } else if (strncmp(buf,"message ",8) == 0) {
		/* pass a message from the connector on to the monitor */
		if (monitors) {
		    mon_write(MONITOR_MESSAGE,"MESSAGE\n",8);
		    mon_write(MONITOR_MESSAGE,buf+8,strlen(buf+8));
		    mon_write(MONITOR_MESSAGE,"\n",1);
		}
            } else if (sscanf(buf,"connect %d %n", &pid, &dev) == 1) {
                if (pid > 1) {
		    if ((state != STATE_DOWN && state != STATE_CLOSE
			&& !give_way)
		    || state==STATE_UP || req_pid) {
                        /* somebody else already has this diald, tell 'em */
                        kill(pid, SIGTERM);
			syslog(LOG_INFO,"FIFO: link up requested but denied");
                    } else {
                        req_pid = pid;
                        req_dev = (char *)malloc(tail-(buf+dev)+1);
                        if (req_dev == 0) {
                            req_pid = 0;
                            syslog(LOG_ERR,"FIFO: no memory to store requested devce!");
                        } else {
                            strcpy(req_dev, buf+dev);
                            request_down = 0;
                            request_up = 1;
                            syslog(LOG_INFO,"FIFO: link up requested on device %s", req_dev);
                        }
                    }
                }
	    } else if (strncmp(buf, "interface ", 10) == 0) {
		syslog(LOG_INFO, "FIFO: interface set to %s.", buf+10);
		dev = strcspn(buf + 10, "0123456789");
		if (buf[dev])
		    link_iface = atoi(buf + (10 + dev));
            } else {
		syslog(LOG_ERR,"Unknown request '%s' made.", buf);
	    }
	   buf = tail+1;
       }
       tail++;
    }

    pipe_flush(&fifo_pipe,buf-fifo_pipe.buf);
}

/*
 * Deal with master side packet on the SLIP link.
 */
void proxy_read()
{
    char buffer[4096];
    int len;
    struct SOCKADDR to;

    /* read the SLIP packet */
    len = recv_packet(buffer,4096);

    if (!do_reroute) {
	/* if we are doing unsafe routing, all counting is in the filter.
	 * otherwise we can see transmitted bytes directly at this spot.
	 */
	txtotal += len;
	itxtotal += len;
	rxtotal -= len;	/* since it will double count on the snoop */
	irxtotal -= len;
    }

    /* If we get here with the link up and fwdfd not -1,
     * and we are rerouting, then it must be
     * that the external interface has gone down without
     * taking the link with it, and as a result our route
     * to the external interface got lost. (This CAN legally
     * happen with PPP). In this case we buffer the packet so
     * we can retransmit it when the link comes back up.
     * OR
     * the kernel is retransmitting something through sl0, despite
     * the existance of a route through another device...
     */

    /* if the external iface is up then probably we can send it on */
    if (link_iface != -1 && fwdfd != -1) {
	/* Make sure we try to restore the link to working condition now... */
	if (do_reroute && mode == MODE_PPP) {
	    /* Check if a route exists at this point through the ppp device. */
	    /* If not then we must be half dead. */
	    if (!ppp_route_exists()) {
		/* The external iface is down, buffer the packet so we can
	 	 * forward it when the iface comes up.
	  	 */
	        ppp_half_dead = 1;
		if (buffer_packets)
	    	    buffer_packet(len,buffer);
		return;
	    }
	}

	/* Ok, the interface is there, and the route is up,
  	 * so just send it on. This can happen when routing is switched
	 * in the middle of a retransmission sequence. (There is a race
	 * between the route switching and the forwarding I think.)
	 */

#ifdef HAS_SOCKADDR_PKT
	to.spkt_family = AF_INET;
	strcpy(to.spkt_device,snoop_dev);
	to.spkt_protocol = htons(ETH_P_IP);
#else
	to.sa_family = AF_INET;
	strcpy(to.sa_data,snoop_dev);
#endif
	if (debug&DEBUG_VERBOSE)
	    syslog(LOG_DEBUG,"Forwarding packet of length %d",len);
	if (sendto(fwdfd,buffer,len,0,(struct sockaddr *)&to,sizeof(struct SOCKADDR)) < 0) {
	    syslog(LOG_ERR,
		"Error forwarding data packet to physical device: %m");
	}
    } else {
	/* If the link isn't up, then we better buffer the packets */
	if (buffer_packets)
	    buffer_packet(len,buffer);
    }
}

/*
 * Terminate diald gracefully.
 */

static int in_die = 0;

void die(int i)
{
    int count;

    if (!in_die) {
	in_die = 1;
	/* We're killing without a care here. Uhggg. */
	if (link_pid) kill(link_pid,SIGINT);
	if (dial_pid) kill(dial_pid,SIGINT);
	if (running_pid) kill(running_pid,SIGINT);
	/* Wait up to 30 seconds for them to die */
        for (count = 0; (link_pid || dial_pid) && count < 30; count++)
	    sleep(1);
	/* If they aren't dead yet, kill them for sure */
	if (link_pid) kill(link_pid,SIGKILL);
	if (dial_pid) kill(dial_pid,SIGKILL);
	if (running_pid) kill(running_pid,SIGKILL);
	/* Give the system a second to send the signals */
	if (link_pid || dial_pid || running_pid) sleep(1);
	close_modem();
	interface_down();
    	proxy_down();
	unlink(pidfile);
    	exit(i);
    }
}

/*
 * Signal handlers.
 */

/*
 * Modem link went down.
 */
void sig_hup(int sig)
{
    syslog(LOG_INFO, "SIGHUP: modem got hung up on.");
    modem_hup = 1;
}

/*
 * User wants the link to go down.
 * (Perhaps there should be a 10 second delay? Configurable????)
 */
void sig_intr(int sig)
{
    syslog(LOG_INFO, "SIGINT: Link down request received.");
    request_down = 1;
    request_up = 0;
}

/*
 *  The user has requested that the link be put up.
 */
void linkup(int sig)
{
    syslog(LOG_INFO, "SIGUSR1. External link up request received.");
    request_down = 0;
    request_up = 1;
}

/*
 * A child process died. Find out which one.
 */
void sig_chld(int sig)
{
    int pid, status;
    static int seq = 0;
    ++seq;
    while ((pid = waitpid(-1,&status,WNOHANG)) > 0) {
        if (debug&DEBUG_VERBOSE)
	    syslog( LOG_DEBUG, "SIGCHLD[%d]: pid %d %s, status %d", seq, pid,
		    pid == link_pid ? "link"
		   	: pid == dial_pid ? "dial"
			: pid == running_pid ? "system"
			: "other",
		    status);
	if (pid == link_pid) link_pid = 0;
	else if (pid == dial_pid) { dial_status = status; dial_pid = 0; }
	else if (pid == running_pid) { running_status = status; running_pid = 0; }
	else if (!WIFEXITED(status))
   	    syslog(LOG_ERR,"Abnormal exit (status %d) on pid %d",status,pid);
	else if (WEXITSTATUS(status) != 0)
	    syslog(LOG_ERR,"Nonzero exit status (%d) on pid %d",
		WEXITSTATUS(status),pid);
	if (pid > 0) {
	    if (WIFSIGNALED(status)) {
		syslog(LOG_WARNING, "child process %d terminated with signal %d",
		       pid, WTERMSIG(status));
	    }
	}
    }
    if (pid && errno != ECHILD)
	syslog(LOG_ERR, "waitpid: %m");
    return;
}

/*
 * User wants diald to be terminated.
 */
void sig_term(int sig)
{
    syslog(LOG_INFO, "SIGTERM. Termination request received.");
    terminate = 1;
}

int report_system_result(int res,char *buf)
{
    if (res == -1)
   	syslog(LOG_ERR,"System call failure on command '%s'",buf);
    else if (!WIFEXITED(res))
   	syslog(LOG_ERR,"Abnormal exit (status %d) on command '%s'",res,buf);
    else if (WEXITSTATUS(res) != 0)
	syslog(LOG_ERR,"Nonzero exit status (%d) on command '%s'",WEXITSTATUS(res),buf);
    else
	return 0;
    return 1;
}


int system(const char *buf)
{
    int fd, pid;

    block_signals();

#ifdef __uClinux__
    pid = running_pid = vfork();
    if (pid > 0) {
    if (debug&DEBUG_VERBOSE)
	syslog(LOG_DEBUG, "running system pid=%d \"%s\"", pid, buf);
	}
#else
    if (debug&DEBUG_VERBOSE)
	syslog(LOG_DEBUG,"running '%s'",buf);
    pid = running_pid = fork();
#endif

    if (pid != 0) unblock_signals();

    if (pid < 0) {
        syslog(LOG_ERR, "failed to fork and run '%s': %m",buf);
		return -1;
    }

    if (pid == 0) {
        /* change the signal actions back to the defaults, then unblock them. */
        default_sigacts();
		unblock_signals();

        /* Leave the current location */
        (void) setsid();    /* No controlling tty. */
        (void) umask (S_IRWXG|S_IRWXO);
        (void) chdir ("/"); /* no current directory. */

	/* close all fd's the child should not see */
	close(0);
	close(1);
	close(2);
	if (modem_fd >= 0) close(modem_fd);
	close(proxy_mfd);      /* close the master pty endpoint */
	close(proxy_sfd);      /* close the slave pty endpoint */
	if (fifo_fd != -1) close(fifo_fd);
	if (monitors) {
	    MONITORS *c = monitors;
	    while (c) {
		close(c->fd);
		c = c->next;
	    }
	}

	/* make sure the stdin, stdout and stderr get directed to /dev/null */
	fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
	    if (fd != 0) {
	    	dup2(fd, 0);
		close(fd);
	    }
	    dup2(0, 1);
            dup2(0, 2);
        }

#ifdef EMBED
        execuc(buf);
        syslog(LOG_ERR, "could not exec program: errno=%d, buf=%s", errno, buf);
#else
        execl("/bin/sh", "sh", "-c", buf, (char *)0);
        syslog(LOG_ERR, "could not exec /bin/sh: %m");
#endif
        _exit(127);
        /* NOTREACHED */
    }
    while (running_pid) {
	pause();
    }
    return running_status;
}

void background_system(const char *buf)
{
    int fd, pid;

    block_signals();

#ifdef __uClinux__
    pid = vfork();
    if (pid > 0)
    if (debug&DEBUG_VERBOSE)
	syslog(LOG_NOTICE, "running background pid=%d \"%s\"", pid, buf);
#else
    if (debug&DEBUG_VERBOSE)
	syslog(LOG_DEBUG,"running '%s'",buf);
    pid = fork();
#endif

    if (pid != 0) unblock_signals();

    if (pid < 0) {
        syslog(LOG_ERR, "failed to fork and run '%s': %m",buf);
	return;
    }

    if (pid == 0) {
        /* change the signal actions back to the defaults, then unblock them. */
        default_sigacts();
	unblock_signals();

        /* Leave the current location */
        (void) setsid();    /* No controlling tty. */
        (void) umask (S_IRWXG|S_IRWXO);
        (void) chdir ("/"); /* no current directory. */

	/* close all fd's the child should not see */
	close(0);
	close(1);
	close(2);
	if (modem_fd >= 0) close(modem_fd);
	close(proxy_mfd);      /* close the master pty endpoint */
	close(proxy_sfd);      /* close the slave pty endpoint */
	if (fifo_fd != -1) close(fifo_fd);
	if (monitors) {
	    MONITORS *c = monitors;
	    while (c) {
		close(c->fd);
		c = c->next;
	    }
	}

	/* make sure the stdin, stdout and stderr get directed to /dev/null */
	fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
	    if (fd != 0) {
	    	dup2(fd, 0);
		close(fd);
	    }
	    dup2(0, 1);
            dup2(0, 2);
        }

#ifdef EMBED
	execuc(buf);
        syslog(LOG_ERR, "could not exec background: errno=%d buf=%s", errno, buf);
#else
        execl("/bin/sh", "sh", "-c", buf, (char *)0);
        syslog(LOG_ERR, "could not exec /bin/sh: %m");
#endif
        _exit(127);
        /* NOTREACHED */
    }
}

void mon_write(int level, char *message,int len)
{
    MONITORS *c = monitors, *p = 0, *cn;
    while (c) {
	cn = c->next;
	if (c->level&level) {
	    if (write(c->fd,message,len) < 0) {
		if (errno == EPIPE) {
		    syslog(LOG_INFO,"Monitor pipe %s closed.",c->name);
		} else {
		    /* Write error. The reader probably got swapped out
		     * or something and the pipe flooded. We'll just "loose"
		     * the data.
		     */
		     p = c;
		     continue;
		}
		close(c->fd);
		if (p) p->next = c->next;
		else monitors = c->next;
		free(c->name);
		free(c);
	    } else {
		p = c;
	    }
	}
	c = cn;
    }
}
