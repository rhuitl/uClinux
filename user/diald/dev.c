/*
 * dev.c - A ethernet Device.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 *
 * Patched from ppp.c to support ethernet devices
 * like isdn4linux 
 * Wim Bonis bonis@kiss.de
 *
 * Further modifications by Eric Schenk to merge into diald mainline
 * sources.
 *
 */

#include "diald.h"

static int dead = 1;

/* internal flag to shortcut repeated calls to setaddr */
static int rx_count = -1;

void dev_start()
{
    link_iface = -1 ;
    rx_count = -1;
    syslog(LOG_INFO, "Open device %s%d",device_node,device_iface);
    dead = 0;
}

/*
 * SET_SA_FAMILY - set the sa_family field of a struct sockaddr,
 * if it exists.
 */

#define SET_SA_FAMILY(addr, family)                     \
    memset ((char *) &(addr), '\0', sizeof(addr));      \
    addr.sa_family = (family);


/*
 * Find the interface number of the ppp device that pppd opened up and
 * do any routing we might need to do.
 * If pppd has not yet opened the device, then return 0, else return 1.
 */

int dev_set_addrs()
{
    ulong laddr = 0, raddr = 0;
    char sbuf[sizeof(PATH_IFCONFIG SL_DOWN) + 10];

    /* Try to get the interface number if we don't know it yet. */
    if (link_iface == -1) {
	link_iface = device_iface;
	syslog(LOG_INFO,"Old %s , New device : %s %d",device,device_node,device_iface); 
    }


    /* Ok then, see if pppd has upped the interface yet. */
    if (link_iface != -1) {
	struct ifreq   ifr; 

	SET_SA_FAMILY (ifr.ifr_addr,    AF_INET); 
	SET_SA_FAMILY (ifr.ifr_dstaddr, AF_INET); 
	SET_SA_FAMILY (ifr.ifr_netmask, AF_INET); 
	sprintf(ifr.ifr_name, device);
	if (ioctl(snoopfd, SIOCGIFFLAGS, (caddr_t) &ifr) == -1) {
	   syslog(LOG_ERR,"failed to read interface status from device %s",device);
	   return 0;
	}
	if (!(ifr.ifr_flags & IFF_UP))
	    return 0;	/* interface is not up yet */

	if (route_wait) {
            /* set the initial rx counter once the link is up */
            if (rx_count == -1) rx_count = dev_rx_count();

            /* check if we got the routing packet yet */
            if (dev_rx_count() == rx_count) return 0;
	}

	/* Ok, the interface is up, grab the addresses. */
	if (ioctl(snoopfd, SIOCGIFADDR, (caddr_t) &ifr) == -1)
		syslog(LOG_ERR,"failed to get local address from device %s: %m",device);
	else
       	    laddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

	if (ioctl(snoopfd, SIOCGIFDSTADDR, (caddr_t) &ifr) == -1) 
	   syslog(LOG_ERR,"failed to get remote address: %m");
	else
	   raddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;

	/* Set the ptp routing for the new interface */
	set_ptp(device_node,link_iface,remote_ip,metric);

	if (dynamic_addrs) {
	    /* only do the configuration in dynamic mode. */
	    struct in_addr addr;
	    addr.s_addr = raddr;
	    strcpy(remote_ip,inet_ntoa(addr));
	    addr.s_addr = laddr;
	    strcpy(local_ip,inet_ntoa(addr));
	    local_addr = laddr;
	    syslog(LOG_INFO,"New addresses: local %s, remote %s.",
		local_ip,remote_ip);
	    if (!do_reroute) {
	        proxy_config(local_ip,remote_ip);
    		set_ptp("sl",proxy_iface,remote_ip,metric+1);
                add_routes("sl",proxy_iface,local_ip,remote_ip,drmetric+1);
	    }
	}

	if (do_reroute)
             add_routes(device_node,link_iface,local_ip,remote_ip,drmetric);
	/*
	 * bring down the sl link here, and then bring it back up.
	 */
	snprintf(sbuf, sizeof(sbuf), PATH_IFCONFIG SL_DOWN, proxy_iface);
	system(sbuf);
	snprintf(sbuf, sizeof(sbuf), PATH_IFCONFIG SL_UP, proxy_iface);
	system(sbuf);
        return 1;
    }
    return 0;
}

int dev_dead()
{
    if (dead)
	dev_reroute();
    return (dead);
}

int dev_rx_count()
{
    char buf[128];
    int packets = 0;
    FILE *fp;
    sprintf(buf,"%s %s%d",PATH_IFCONFIG,device_node,link_iface);
    if ((fp = popen(buf,"r"))==NULL) {
        syslog(LOG_ERR,"Could not run command '%s': %m",buf);
        return 0;       /* assume half dead in this case... */
    }

    while (fgets(buf,128,fp)) {
        if (sscanf(buf," RX packets:%d",&packets) == 1) {
            break;
        }
    }
    fclose(fp);
    return packets;
}

void dev_stop()
{
    /* FIXME: There should be something here that actually can shut
     * down whatever is driving the ether device, or at least try.
     * [The trick used by the ISDN people seems to be to hang up
     * in the delroute scripts. The ip-down scripts make sense
     * for this as well. This might well be good enough.]
     */
    dead = 1;
}

void dev_reroute()
{
    /* Kill the alternate routing */
    if (do_reroute && link_iface != -1)
        del_routes(device_node,link_iface,local_ip,remote_ip,drmetric);
    link_iface = -1;

    /* Restore the original proxy routing */
    proxy_config(orig_local_ip,orig_remote_ip);
    set_ptp("sl",proxy_iface,orig_remote_ip,metric+1);
    add_routes("sl",proxy_iface,orig_local_ip,orig_remote_ip,drmetric+1);
    local_addr = inet_addr(orig_local_ip);
}

/* Dummy proc. This should never get called */
void dev_kill()
{
}

/* Dummy proc. This should never get called */
void dev_zombie()
{
}
