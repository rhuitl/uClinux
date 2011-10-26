/*
 * slip.c - Slip specific code in diald.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

static int dead = 1;
static int waiting_for_bootp = 0;
static int have_local, have_remote;
static int start_disc;
static FILE *bootpfp;
static PIPE bootp_pipe;

static int rx_count = -1;


static void start_bootp()
{
    char buf[128];

    idle_filter_init();

    sprintf(buf,"%s --dev sl%d",PATH_BOOTPC,link_iface);
    /* FIXME: there is still some possibility of a bad
     * interaction between the signal handlers and the command
     * running on the far side of the pipe. Probably I should
     * write my own popen() call the same way I have my open system() call.
     */
    if ((bootpfp = popen(buf,"r"))==NULL) {
	syslog(LOG_ERR,"Could not run command '%s': %m",buf);
	die(1);
    }
    pipe_init(fileno(bootpfp),&bootp_pipe);
    have_local = 0;
    have_remote = 0;
    waiting_for_bootp = 1;
}

static int fail;

static int grab_addr(char **var)
{
    int len, i = 0;
    int state = 0;
    unsigned char buffer[128];
    unsigned char c;

    while (1) {
	if ((len = read(modem_fd,&c,1)) < 0) {
	    if (fail) {
		syslog(LOG_ERR,"Timeout waiting for dynamic slip addresses");
		return 0;
	    }
	    if (errno != EINTR || terminate) {
	        syslog(LOG_ERR,"Error reading from modem: %m");
	        return 0;
            }
        }
	if (len == 1) {
	    switch (state) {
	    case 0:	/* wait for a number to come up */
		if (isdigit(c)) buffer[i++] = c, state = 1;
		break;
	    case 1:	/* wait for at least one '.' */
		if (isdigit(c)) buffer[i++] = c;
		else if (c == '.') buffer[i++] = c, state = 2;
		else i = 0, state = 0;
		break;
	    case 2:	/* we saw at least one '.', assume its an ip address */
		if (isdigit(c) || c == '.') buffer[i++] = c;
		else {
		    if (buffer[i-1] == '.') i--;   /* trim off trailing "." */
		    buffer[i++] = 0;
		    goto done;
		}
		break;
	    }
	    if (i >= 128)
		syslog(LOG_ERR,"Buffer overflow when reading IP address"),
		die(1);
	}
    }
done:
    *var = strdup(buffer);
    return 1;
}

/*
 * The SLIP configuration is essentially what slattach
 * does, but we do it here so we know what interface (sl*)
 * gets opened as a result. (slattach doesn't return this)
 */


void slip_start_fail(unsigned long data)
{
   fail = 1;
}

struct timer_lst failt;

void slip_start(void)
{
    char buf[128];
    int disc, sencap;
    int res;

    rx_count = -1;

    if (dynamic_addrs && !force_dynamic) {
	if (debug&DEBUG_VERBOSE)
	    syslog(LOG_INFO,"Fetching IP addresses from SLIP server");
	if (dynamic_mode != DMODE_BOOTP) {
	    fail = 0;
	    failt.data = 0;
	    failt.function = slip_start_fail;
	    failt.expires = 30;	/* give 30 seconds for this to work */
	    add_timer(&failt);
	    if (dynamic_mode == DMODE_REMOTE || dynamic_mode == DMODE_REMOTE_LOCAL)
		if (!grab_addr(&remote_ip)) return;
	    if (dynamic_mode != DMODE_REMOTE)
		if (!grab_addr(&local_ip)) return;
	    if (dynamic_mode == DMODE_LOCAL_REMOTE)
		if (!grab_addr(&remote_ip)) return;
	    del_timer(&failt);
	    syslog(LOG_INFO,"New addresses: local %s, remote %s.",
		local_ip,remote_ip);
	}
    }

    if (ioctl(modem_fd, TIOCGETD, &start_disc) < 0)
	syslog(LOG_ERR,"Can't get line discipline on proxy device: %m"), die(1);

    /* change line disciple to SLIP and set the SLIP encapsulation */
    disc = N_SLIP;
    if ((link_iface = ioctl(modem_fd, TIOCSETD, &disc)) < 0) {
	if (errno == ENFILE) {
	   syslog(LOG_ERR,"No free slip device available for link."), die(1);
	} else if (errno == EEXIST) {
	    syslog(LOG_ERR,"Link device already in slip mode!?");
	} else if (errno == EINVAL) {
	    syslog(LOG_ERR,"SLIP not supported by kernel, can't build link.");
	    die(1);
	} else
	   syslog(LOG_ERR,"Can't set line discipline: %m"), die(1);
    }

    if (ioctl(modem_fd, SIOCSIFENCAP, &slip_encap) < 0)
	syslog(LOG_ERR,"Can't set encapsulation: %m"), die(1);

#ifdef SIOCSKEEPALIVE
    if (keepalive && (ioctl(modem_fd, SIOCSKEEPALIVE, &keepalive) < 0))
      syslog(LOG_ERR, "Can't set keepalive: %m (ignoring error)");
#endif

#ifdef SIOCSOUTFILL
    if (outfill && (ioctl(modem_fd, SIOCSOUTFILL, &outfill) < 0))
      syslog(LOG_ERR, "Can't set outfill: %m (ignoring error)");
#endif

    /* verify that it worked */
    if (ioctl(modem_fd, TIOCGETD, &disc) < 0)
	syslog(LOG_ERR,"Can't get line discipline: %m"), die(1);
    if (ioctl(modem_fd, SIOCGIFENCAP, &sencap) < 0)
	syslog(LOG_ERR,"Can't get encapsulation: %m"), die(1);

    if (disc != N_SLIP || sencap != slip_encap)
        syslog(LOG_ERR,"Couldn't set up the slip link correctly!"), die(1);

    if (debug&DEBUG_VERBOSE)
        syslog(LOG_INFO,"Slip link established on interface sl%d",
	    link_iface);

    /* mark the interface as up */
    if (netmask) {
        sprintf(buf,"%s sl%d %s pointopoint %s netmask %s mtu %d metric %d up",
	    PATH_IFCONFIG,link_iface,local_ip,remote_ip,netmask,mtu, metric);
    } else {
        sprintf(buf,"%s sl%d %s pointopoint %s mtu %d metric %d up",
	    PATH_IFCONFIG,link_iface,local_ip,remote_ip,mtu, metric);
    }
    res = system(buf);
    report_system_result(res,buf);

    /* Set the routing for the new slip interface */
    set_ptp("sl",link_iface,remote_ip,metric);

    /* run bootp if it is asked for */
    if (dynamic_addrs && dynamic_mode == DMODE_BOOTP && !force_dynamic) start_bootp();

    dead = 0;
}

int slip_set_addrs()
{
    char buf[128];
    char type[30];
    char addr[30];
    int res;

    if (waiting_for_bootp && (!have_local || !have_remote)) {
	int i;
	char *buf, *tail;
	buf = tail = bootp_pipe.buf;
	i = pipe_read(&bootp_pipe);
	if (i <= 0) return 0;
	while (i--) {
	   if (*tail == '\n') {
		*tail = 0;
		/* Got a line, deal with it */
		if (sscanf(buf,"%[^=]=%s\n",type,addr) == 2) {
		    if (strcmp(type,"SERVER")==0) {
			have_remote = 1;
			remote_ip = strdup(addr);
		    } else if (strcmp(type,"IPADDR")==0) {
			have_local = 1;
			local_ip = strdup(addr);
		    }
		}
		buf = tail+1;
	   }
	   tail++;
	}
	pipe_flush(&bootp_pipe,buf-bootp_pipe.buf);
    }

    if (waiting_for_bootp && (!have_local || !have_remote))
        return 0;

    if (waiting_for_bootp) {
        pclose(bootpfp);
	syslog(LOG_INFO,"New addresses: local %s, remote %s.",
	    local_ip,remote_ip);
    	waiting_for_bootp = 0;
    }

    if (route_wait) {
	/* set the initial rx counter once the link is up */
	if (rx_count == -1) rx_count = slip_rx_count();

	/* check if we got the routing packet yet */
	if (slip_rx_count() == rx_count) return 0;
    }

    /* redo the interface marking and the routing since BOOTP will change it */
    if (netmask) {
        sprintf(buf,"%s sl%d %s pointopoint %s netmask %s mtu %d up",
	    PATH_IFCONFIG,link_iface,local_ip,remote_ip,netmask,mtu);
    } else {
        sprintf(buf,"%s sl%d %s pointopoint %s mtu %d up",
	    PATH_IFCONFIG,link_iface,local_ip,remote_ip,mtu);
    }
    res = system(buf);
    report_system_result(res,buf);

    /* Set the routing for the new slip interface */
    set_ptp("sl",link_iface,remote_ip,metric);

    if (dynamic_addrs || force_dynamic) {
	local_addr = inet_addr(local_ip);
	/* have to reset the proxy if we won't be rerouting... */
	if (!do_reroute) {
	    proxy_config(local_ip,remote_ip);
    	    set_ptp("sl",proxy_iface,remote_ip,metric+1);
	    add_routes("sl",proxy_iface,local_ip,remote_ip,drmetric+1);
	}
    }

    if (do_reroute)
        add_routes("sl",link_iface,local_ip,remote_ip,drmetric);

    return 1;
}

int slip_dead()
{
    if (dead)
	slip_reroute();
    return (dead);
}

/* Stop the slip interface. I'm not sure this needs to do anything
 * other than down the interface. In fact I'm not even sure I need to do that...
 */
void slip_stop()
{
    /* set the line discipline back to the starting discipline */
    ioctl(modem_fd, TIOCSETD, &start_disc);
    dead = 1;
}

void slip_reroute()
{
    /* Restore the original proxy routing */
    proxy_config(orig_local_ip,orig_remote_ip);
    set_ptp("sl",proxy_iface,orig_remote_ip,metric+1);
    add_routes("sl",proxy_iface,orig_local_ip,orig_remote_ip,drmetric+1);
    local_addr = inet_addr(orig_local_ip);
    /* If we did routing on the slip link, remove it */
    if (do_reroute && link_iface != -1) /* just in case we get called twice */
    	del_routes("sl",link_iface,local_ip,remote_ip,drmetric);
    link_iface = -1;
}

int slip_rx_count()
{
    char buf[128];
    int packets = 0;
    FILE *fp;
    sprintf(buf,"%s sl%d",PATH_IFCONFIG,link_iface);
    if ((fp = popen(buf,"r"))==NULL) {
        syslog(LOG_ERR,"Could not run command '%s': %m",buf);
	return 0;	/* assume half dead in this case... */
    }

    while (fgets(buf,128,fp)) {
	if (sscanf(buf," RX packets:%d",&packets) == 1) {
	    break;
	}
    }
    fclose(fp);
    return packets;
}


/* Dummy proc. This should never get called */
void slip_kill()
{
}

/* Dummy proc. This should never get called */
void slip_zombie()
{
}
