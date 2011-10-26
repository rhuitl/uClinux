/*
 * filter.c - Packet filtering for diald.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include "diald.h"

int itxtotal = 0;
int irxtotal = 0;

/*
 * Initialize the file descriptors for network monitoring sockets.
 */
void filter_setup()
{

    fwdfd = -1;

    if ((snoopfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
        syslog(LOG_ERR, "Could not get socket to do packet monitoring: %m");
        die(1);
    }
}

/*
 * Set up the idle filter mechanism for a connected link.
 */
void idle_filter_init()
{
    struct sockaddr to;

    if (mode == MODE_SLIP) {
	sprintf(snoop_dev,"sl%d",link_iface);
     } else if (mode == MODE_PPP) {
       sprintf(snoop_dev,"ppp%d",link_iface);
     } else if (mode == MODE_DEV) {
       sprintf(snoop_dev,"%s",device);
      }
    if (debug) syslog(LOG_INFO,"Changed snoop device to %s",snoop_dev);
    txtotal = rxtotal = 0;

    /* try to bind the snooping socket to a particular device */
    to.sa_family = AF_INET;
    strcpy(to.sa_data,snoop_dev);
    /* This bind may fail if the kernel isn't recent enough. */
    /* This will just mean more work for the kernel. */
    bind(snoopfd,&to,sizeof(struct sockaddr));

    if (fwdfd != -1) {
	close(fwdfd);
	fwdfd = -1;
    }
    if ((fwdfd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
        syslog(LOG_ERR, "Could not get socket to do packet forwarding: %m");
        die(1);
    }
    /* This bind may fail if the kernel isn't recent enough. */
    /* This will just mean more work for the kernel. */
    bind(fwdfd,&to,sizeof(struct sockaddr));
}

/*
 * Point the idle filter to proxy link.
 */
void idle_filter_proxy()
{
    struct sockaddr to;

    if (fwdfd != -1) {
        if (debug) syslog(LOG_INFO,"Closed fwdfd");
	close(fwdfd);
	fwdfd = -1;
    }
    sprintf(snoop_dev,"sl%d",proxy_iface);
    if (debug) syslog(LOG_INFO,"Changed snoop device to %s",snoop_dev);

    /* try to bind the snooping socket to a particular device */
    /* Most likely this should close the old socket and open a new one first */
    to.sa_family = AF_INET;
    strcpy(to.sa_data,snoop_dev);
    /* This bind may fail if the kernel isn't recent enough. */
    /* This will just mean more work for the kernel. */
    bind(snoopfd,&to,sizeof(struct sockaddr));
}

/*
 * We got a packet on the snooping socket.
 * Read the packet. Return 1 if the packet means the link should be up 0
 * otherwise. At the same time record the packet in the idle filter structure.
 */
void filter_read()
{
    struct sockaddr from;
    int from_len = sizeof(struct sockaddr);
    int len;

    if ((len = recvfrom(snoopfd,packet,4096,0,&from,&from_len)) > 0) {
	/* FIXME: really if the bind succeeds, then I don't need
	 * this check. How can I shortcut this effectly?
	 * perhaps two different filter_read routines?
         */
	if (strcmp(snoop_dev,from.sa_data) == 0) {
	    if (do_reroute) {
		/* If we are doing unsafe routing, then we cannot count
		 * the transmitted packets on the forwarding side of the
		 * transitter (since there is none!), so we attempt to
		 * count them here. However, we can only tell packets
		 * that are leaving our interface from this machine,
		 * forwarded packets all get counted as received bytes.
		 */
		if (((struct iphdr *)packet)->saddr == local_addr) {
		    txtotal += len;
		    itxtotal += len;
		} else {
		    rxtotal += len;
		    irxtotal += len;
		}
	    } else {
	    	rxtotal += len;
		irxtotal += len;
	    }
	
            if ((ntohs(((struct iphdr *)packet)->frag_off) & 0x1fff) == 0) {
	        /* Mark passage of first packet */
	        if (check_firewall(fwunit,packet,len) && state == STATE_UP)
	            state_timeout = -1;
	    }
	}
    }
}

void flush_timeout_queue()
{
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_QFLUSH,&req);
}

void interface_up()
{
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_UP,&req);
}

void interface_down()
{
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_DOWN,&req);
}

int queue_empty()
{
    struct firewall_req req;
    req.unit = fwunit;
    return ctl_firewall(IP_FW_QCHECK,&req);
}

int fw_wait()
{
    struct firewall_req req;
    req.unit = fwunit;
    return ctl_firewall(IP_FW_WAIT,&req);
}

int fw_reset_wait()
{
    struct firewall_req req;
    req.unit = fwunit;
    return ctl_firewall(IP_FW_RESET_WAITING,&req);
}


void print_filter_queue(int sig)
{
    struct firewall_req req;
    syslog(LOG_INFO,"User requested dump of firewall queue.");
    syslog(LOG_INFO,"--------------------------------------");
    req.unit = fwunit;
    ctl_firewall(IP_FW_PCONN,&req);
    syslog(LOG_INFO,"--------------------------------------");
}

void monitor_queue()
{
    char buf[100];
    struct firewall_req req;
    req.unit = fwunit;
    ctl_firewall(IP_FW_MCONN,&req);
    sprintf(buf,"LOAD\n%d\n%d\n",itxtotal,irxtotal);
    itxtotal = irxtotal = 0;
    mon_write(MONITOR_LOAD,buf,strlen(buf));
}
